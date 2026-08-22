"""SentinelLog Real-Time File Tailing and Event Monitor

Continuously tails log files using efficient file seek/tell pointers,
handles log rotation, parses incoming lines, triggers detection rules,
persists records to SQLite, and notifies live event subscribers.
"""

import os
import time
import threading
import queue
from typing import Optional, Callable, List, Dict, Any, Tuple

from core.models import LogEvent, ThreatAlert
from core.parser import LogParser
from core.detector import ThreatDetector
from database.database import Database


class LogMonitor:
    """Real-time log tailing and event dispatching engine."""

    def __init__(
        self,
        log_path: str,
        parser: Optional[LogParser] = None,
        detector: Optional[ThreatDetector] = None,
        database: Optional[Database] = None,
        tail_from_end: bool = True,
        poll_interval: float = 0.5
    ):
        self.log_path = log_path
        self.parser = parser or LogParser()
        self.detector = detector or ThreatDetector()
        self.database = database or Database()
        self.tail_from_end = tail_from_end
        self.poll_interval = poll_interval

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._subscribers: List[queue.Queue] = []
        self._subscribers_lock = threading.Lock()
        self._callbacks: List[Callable[[LogEvent, List[ThreatAlert]], None]] = []

    def add_subscriber(self, q: queue.Queue):
        """Add a Queue subscriber (e.g., SSE live web feed)."""
        with self._subscribers_lock:
            if q not in self._subscribers:
                self._subscribers.append(q)

    def remove_subscriber(self, q: queue.Queue):
        """Remove a Queue subscriber."""
        with self._subscribers_lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def add_callback(self, cb: Callable[[LogEvent, List[ThreatAlert]], None]):
        """Add a direct callback function."""
        if cb not in self._callbacks:
            self._callbacks.append(cb)

    def start(self):
        """Start the background monitor thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop monitoring."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    @property
    def is_running(self) -> bool:
        return self._running

    def process_raw_line(self, line: str) -> Optional[Tuple[LogEvent, List[ThreatAlert]]]:
        """Manually parse a line, detect threats, and persist to database."""
        event = self.parser.parse_line(line)
        if not event:
            return None

        # Insert event into DB
        event_id = self.database.insert_event(event)
        event.id = event_id

        # Run through detection engine
        alerts = self.detector.process_event(event)
        for alert in alerts:
            self.database.insert_or_update_alert(alert)

        # Broadcast to subscribers and callbacks
        self._broadcast(event, alerts)
        return event, alerts

    def process_event_directly(self, event: LogEvent) -> List[ThreatAlert]:
        """Directly ingest a LogEvent (e.g. from Demo generator)."""
        event_id = self.database.insert_event(event)
        event.id = event_id

        alerts = self.detector.process_event(event)
        for alert in alerts:
            self.database.insert_or_update_alert(alert)

        self._broadcast(event, alerts)
        return alerts

    def _broadcast(self, event: LogEvent, alerts: List[ThreatAlert]):
        """Distribute event and alerts to all active listeners."""
        payload = {
            "event": event.to_dict(),
            "alerts": [a.to_dict() for a in alerts]
        }

        # Send to queue subscribers (web SSE)
        with self._subscribers_lock:
            dead_queues = []
            for q in self._subscribers:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    dead_queues.append(q)
                except Exception:
                    dead_queues.append(q)
            for dq in dead_queues:
                if dq in self._subscribers:
                    self._subscribers.remove(dq)

        # Execute registered callbacks (CLI, logging)
        for cb in self._callbacks:
            try:
                cb(event, alerts)
            except Exception:
                pass

    def _monitor_loop(self):
        """Continuous file tail loop with log rotation detection."""
        last_inode = None
        file_obj = None

        while self._running:
            try:
                # Wait for file existence
                if not os.path.exists(self.log_path):
                    time.sleep(self.poll_interval)
                    continue

                # Check inode / file identity
                stat = os.stat(self.log_path)
                current_inode = (stat.st_ino, stat.st_dev)

                if file_obj is None or current_inode != last_inode:
                    if file_obj:
                        file_obj.close()
                    file_obj = open(self.log_path, "r", encoding="utf-8", errors="replace")
                    last_inode = current_inode

                    if self.tail_from_end:
                        file_obj.seek(0, os.SEEK_END)

                # Read available lines
                while self._running:
                    line = file_obj.readline()
                    if not line:
                        # Check for truncation or rotation
                        try:
                            cur_stat = os.stat(self.log_path)
                            if (cur_stat.st_ino, cur_stat.st_dev) != last_inode or cur_stat.st_size < file_obj.tell():
                                # File rotated or truncated
                                break
                        except Exception:
                            break

                        time.sleep(self.poll_interval)
                        continue

                    # Process log line
                    self.process_raw_line(line)

            except Exception:
                time.sleep(self.poll_interval)
            finally:
                if file_obj:
                    try:
                        file_obj.close()
                    except Exception:
                        pass
                    file_obj = None
