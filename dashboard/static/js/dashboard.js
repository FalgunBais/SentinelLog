/**
 * SentinelLog — SOC Dashboard Client Engine
 * Handles real-time SSE stream, Chart.js visualizations,
 * IP forensic investigation, and threat alert management.
 */

// Global State
let eventSource = null;
let isLiveFeedActive = true;
let currentAlertTab = 'ACTIVE';
let currentSearch = '';
let currentSeverityFilter = 'ALL';

// Chart Instances
let authRatioChart = null;
let timelineChart = null;
let severityChart = null;
let topIpsChart = null;

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  fetchInitialData();
  initSSE();
  
  // Periodic background refresh for charts and status sync (every 5s)
  setInterval(refreshDashboardStats, 5000);
});

/* =========================================================================
   1. CHART INITIALIZATION
   ========================================================================= */
function initCharts() {
  const chartDefaults = {
    color: '#94a3b8',
    font: { family: "'Inter', sans-serif", size: 11 }
  };
  Chart.defaults.color = chartDefaults.color;
  Chart.defaults.font.family = chartDefaults.font.family;

  // Chart 1: Auth Status Donut
  const ctxAuth = document.getElementById('authRatioChart').getContext('2d');
  authRatioChart = new Chart(ctxAuth, {
    type: 'doughnut',
    data: {
      labels: ['Success', 'Failed', 'Invalid User'],
      datasets: [{
        data: [0, 0, 0],
        backgroundColor: ['#10b981', '#f43f5e', '#f59e0b'],
        borderWidth: 0,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'bottom', labels: { boxWidth: 12, padding: 12 } }
      },
      cutout: '70%'
    }
  });

  // Chart 2: Timeline Line/Area
  const ctxTimeline = document.getElementById('timelineChart').getContext('2d');
  timelineChart = new Chart(ctxTimeline, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        {
          label: 'Total Events',
          data: [],
          borderColor: '#38bdf8',
          backgroundColor: 'rgba(56, 189, 248, 0.1)',
          fill: true,
          tension: 0.35,
          borderWidth: 2
        },
        {
          label: 'Failed Logins',
          data: [],
          borderColor: '#f43f5e',
          backgroundColor: 'rgba(244, 63, 94, 0.1)',
          fill: true,
          tension: 0.35,
          borderWidth: 2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { maxTicksLimit: 8 } },
        y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, beginAtZero: true }
      },
      plugins: {
        legend: { position: 'top', labels: { boxWidth: 12 } }
      }
    }
  });

  // Chart 3: Severity Breakdown Bar
  const ctxSev = document.getElementById('severityChart').getContext('2d');
  severityChart = new Chart(ctxSev, {
    type: 'bar',
    data: {
      labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      datasets: [{
        label: 'Events',
        data: [0, 0, 0, 0],
        backgroundColor: ['#10b981', '#f59e0b', '#f97316', '#f43f5e'],
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false } },
        y: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, beginAtZero: true }
      }
    }
  });

  // Chart 4: Top Attacking IPs Horizontal Bar
  const ctxTopIps = document.getElementById('topIpsChart').getContext('2d');
  topIpsChart = new Chart(ctxTopIps, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Failed Attempts',
        data: [],
        backgroundColor: 'rgba(244, 63, 94, 0.75)',
        hoverBackgroundColor: '#f43f5e',
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, beginAtZero: true },
        y: { grid: { display: false } }
      },
      onClick: (e, elements) => {
        if (elements.length > 0) {
          const index = elements[0].index;
          const ip = topIpsChart.data.labels[index];
          if (ip) openIpModal(ip);
        }
      }
    }
  });
}

/* =========================================================================
   2. INITIAL DATA LOADING
   ========================================================================= */
async function fetchInitialData() {
  await Promise.all([
    refreshDashboardStats(),
    refreshEvents(),
    refreshAlerts()
  ]);
}

async function refreshDashboardStats() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const stats = await res.json();

    // Update KPI counters
    updateCounter('kpiTotalEvents', stats.total_events);
    updateCounter('kpiSuccessLogins', stats.successful_logins);
    updateCounter('kpiFailedLogins', stats.failed_logins + stats.invalid_logins);
    document.getElementById('kpiInvalidSub').textContent = `${stats.invalid_logins}`;
    updateCounter('kpiActiveThreats', stats.active_threats);
    document.getElementById('kpiHighCritSub').textContent = `${stats.high_critical_alerts}`;
    updateCounter('kpiUniqueIps', stats.unique_ips);

    // Update System Status
    updateSystemStatus(stats.system_status);

    // Update Demo toggle button state
    if (stats.is_demo_running !== undefined) {
      const btn = document.getElementById('btnDemoToggle');
      const icon = document.getElementById('demoToggleIcon');
      const txt = document.getElementById('demoToggleText');
      if (stats.is_demo_running) {
        icon.textContent = '⏸️';
        txt.textContent = 'Pause Demo Stream';
      } else {
        icon.textContent = '▶️';
        txt.textContent = 'Resume Demo Stream';
      }
    }

    // Update Charts
    updateChartsFromStats(stats);
  } catch (err) {
    console.error('Failed to fetch stats:', err);
  }
}

function updateCounter(id, value) {
  const el = document.getElementById(id);
  if (el) {
    el.textContent = Number(value).toLocaleString();
  }
}

function updateSystemStatus(status) {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  if (!dot || !text) return;

  dot.className = 'status-dot';
  if (status === 'THREATS_DETECTED') {
    dot.classList.add('red');
    text.textContent = 'THREATS DETECTED';
  } else if (status === 'WARNING') {
    dot.classList.add('yellow');
    text.textContent = 'SYSTEM WARNING';
  } else {
    dot.classList.add('green');
    text.textContent = 'SYSTEM MONITORING';
  }
}

function updateChartsFromStats(stats) {
  // 1. Auth Donut
  if (authRatioChart) {
    authRatioChart.data.datasets[0].data = [
      stats.successful_logins || 0,
      stats.failed_logins || 0,
      stats.invalid_logins || 0
    ];
    authRatioChart.update();
  }

  // 2. Timeline
  if (timelineChart && stats.timeline) {
    const labels = stats.timeline.map(t => {
      const parts = t.time.split('T');
      return parts.length > 1 ? parts[1].substring(0, 5) : t.time;
    });
    const totalData = stats.timeline.map(t => t.total);
    const failData = stats.timeline.map(t => t.failure);

    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = totalData;
    timelineChart.data.datasets[1].data = failData;
    timelineChart.update();
  }

  // 3. Severity Distribution
  if (severityChart && stats.severity_counts) {
    severityChart.data.datasets[0].data = [
      stats.severity_counts.LOW || 0,
      stats.severity_counts.MEDIUM || 0,
      stats.severity_counts.HIGH || 0,
      stats.severity_counts.CRITICAL || 0
    ];
    severityChart.update();
  }

  // 4. Top IPs
  if (topIpsChart && stats.top_ips) {
    topIpsChart.data.labels = stats.top_ips.map(i => i.ip);
    topIpsChart.data.datasets[0].data = stats.top_ips.map(i => i.failures);
    topIpsChart.update();
  }
}

/* =========================================================================
   3. REAL-TIME SERVER-SENT EVENTS (SSE)
   ========================================================================= */
function initSSE() {
  if (eventSource) {
    eventSource.close();
  }

  eventSource = new EventSource('/api/stream');

  eventSource.onmessage = (e) => {
    try {
      const payload = JSON.parse(e.data);
      if (payload.type === 'event' && payload.data) {
        handleIncomingLiveEvent(payload.data);
      }
    } catch (err) {
      console.error('Error handling SSE message:', err);
    }
  };

  eventSource.onerror = (err) => {
    console.warn('SSE connection closed/error, retrying in 3s...', err);
    eventSource.close();
    setTimeout(initSSE, 3000);
  };
}

function handleIncomingLiveEvent(data) {
  const event = data.event;
  const alerts = data.alerts || [];

  // 1. Add event to Live Feed Table
  if (event && passesCurrentFilters(event)) {
    prependEventRow(event);
  }

  // 2. Add alerts if generated
  if (alerts.length > 0) {
    alerts.forEach(alert => {
      prependAlertCard(alert);
      showToast(`🚨 Threat Detected: ${alert.threat_type} from ${alert.source_ip}`, 'danger');
    });
  }

  // 3. Incremental KPI bump
  incrementKpiCounter('kpiTotalEvents');
  if (event.auth_status === 'SUCCESS') {
    incrementKpiCounter('kpiSuccessLogins');
  } else {
    incrementKpiCounter('kpiFailedLogins');
  }
}

function incrementKpiCounter(id) {
  const el = document.getElementById(id);
  if (el) {
    let current = parseInt(el.textContent.replace(/,/g, ''), 10) || 0;
    el.textContent = (current + 1).toLocaleString();
  }
}

function passesCurrentFilters(ev) {
  if (currentSeverityFilter !== 'ALL' && ev.severity !== currentSeverityFilter) {
    return false;
  }
  if (currentSearch) {
    const s = currentSearch.toLowerCase();
    const match = (ev.ip && ev.ip.toLowerCase().includes(s)) ||
                  (ev.username && ev.username.toLowerCase().includes(s)) ||
                  (ev.message && ev.message.toLowerCase().includes(s));
    if (!match) return false;
  }
  return true;
}

function prependEventRow(ev) {
  const tbody = document.getElementById('eventsTableBody');
  if (!tbody) return;

  const row = createEventRowElement(ev);
  row.classList.add('new-arrival');
  tbody.insertBefore(row, tbody.firstChild);

  // Cap visible table rows to 100
  if (tbody.children.length > 100) {
    tbody.removeChild(tbody.lastChild);
  }
}

function createEventRowElement(ev) {
  const tr = document.createElement('tr');

  // Format timestamp
  const tsFormatted = formatTimestamp(ev.timestamp);

  // Severity badge class
  const sevClass = `badge-${ev.severity.toLowerCase()}`;
  
  // Status badge class
  let statusClass = 'badge-failure';
  if (ev.auth_status === 'SUCCESS') statusClass = 'badge-success';
  else if (ev.auth_status === 'INVALID') statusClass = 'badge-invalid';

  tr.innerHTML = `
    <td style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${tsFormatted}</td>
    <td><span class="ip-clickable" onclick="openIpModal('${ev.ip}')">${escapeHtml(ev.ip)}</span></td>
    <td><span class="user-tag">${escapeHtml(ev.username)}</span></td>
    <td><span style="font-family: var(--font-mono); font-size: 0.74rem;">${escapeHtml(ev.event_type)}</span></td>
    <td><span style="color: var(--text-muted); font-size: 0.75rem;">${escapeHtml(ev.service || 'sshd')}</span></td>
    <td><span class="badge ${sevClass}">${escapeHtml(ev.severity)}</span></td>
    <td><span class="badge ${statusClass}">${escapeHtml(ev.auth_status)}</span></td>
    <td style="font-size: 0.72rem; color: var(--text-muted); max-width: 250px; overflow: hidden; text-overflow: ellipsis;" title="${escapeHtml(ev.raw_log || ev.message)}">
      ${escapeHtml(ev.message || ev.raw_log)}
    </td>
  `;
  return tr;
}

/* =========================================================================
   4. EVENTS & ALERTS MANAGEMENT
   ========================================================================= */
async function refreshEvents() {
  try {
    const params = new URLSearchParams();
    params.set('limit', '50');
    if (currentSeverityFilter !== 'ALL') params.set('severity', currentSeverityFilter);
    if (currentSearch) params.set('search', currentSearch);

    const res = await fetch(`/api/events?${params.toString()}`);
    if (!res.ok) return;
    const data = await res.json();

    const tbody = document.getElementById('eventsTableBody');
    tbody.innerHTML = '';
    data.events.forEach(ev => {
      tbody.appendChild(createEventRowElement(ev));
    });
  } catch (err) {
    console.error('Failed to load events:', err);
  }
}

async function refreshAlerts() {
  try {
    const params = new URLSearchParams();
    params.set('limit', '40');
    if (currentAlertTab !== 'ALL') params.set('status', currentAlertTab);

    const res = await fetch(`/api/alerts?${params.toString()}`);
    if (!res.ok) return;
    const data = await res.json();

    const container = document.getElementById('alertsList');
    container.innerHTML = '';

    if (data.alerts.length === 0) {
      container.innerHTML = `<div style="text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.85rem;">No alerts in ${currentAlertTab.toLowerCase()} status.</div>`;
      return;
    }

    data.alerts.forEach(alert => {
      container.appendChild(createAlertCardElement(alert));
    });
  } catch (err) {
    console.error('Failed to load alerts:', err);
  }
}

function prependAlertCard(alert) {
  const container = document.getElementById('alertsList');
  if (!container) return;

  // Check if alert already exists in DOM
  const existing = document.getElementById(`alert-${alert.alert_id}`);
  if (existing) {
    existing.remove();
  }

  const card = createAlertCardElement(alert);
  container.insertBefore(card, container.firstChild);
}

function createAlertCardElement(alert) {
  const div = document.createElement('div');
  div.className = `alert-card ${alert.severity} ${alert.status}`;
  div.id = `alert-${alert.alert_id}`;

  const tsFormatted = formatTimestamp(alert.timestamp);
  const isAck = alert.status === 'ACKNOWLEDGED' || alert.status === 'CLEARED';

  div.innerHTML = `
    <div class="alert-header">
      <span class="alert-type">${escapeHtml(alert.threat_type)}</span>
      <span class="badge badge-${alert.severity.toLowerCase()}">${escapeHtml(alert.severity)} (${alert.risk_score})</span>
    </div>
    <div class="alert-meta">
      <span>IP: <strong class="ip-clickable" onclick="openIpModal('${alert.source_ip}')">${escapeHtml(alert.source_ip)}</strong></span>
      <span>Target: <strong class="user-tag">${escapeHtml(alert.username)}</strong></span>
      <span>${tsFormatted}</span>
    </div>
    <div class="alert-reason">${escapeHtml(alert.reason)}</div>
    <div class="alert-action">${escapeHtml(alert.recommended_action)}</div>
    <div class="alert-footer">
      <span style="font-size: 0.7rem; color: var(--text-muted); font-family: var(--font-mono);">${escapeHtml(alert.alert_id)}</span>
      ${!isAck ? `
        <button class="btn btn-sm btn-warning" onclick="acknowledgeAlert('${alert.alert_id}')">
          ✓ Acknowledge
        </button>
      ` : `
        <span class="badge" style="background: rgba(255,255,255,0.06); color: var(--text-muted);">Acknowledged</span>
      `}
    </div>
  `;
  return div;
}

async function acknowledgeAlert(alertId) {
  try {
    const res = await fetch(`/api/alerts/${alertId}/ack`, { method: 'POST' });
    if (res.ok) {
      showToast(`Alert ${alertId} acknowledged`, 'info');
      refreshAlerts();
      refreshDashboardStats();
    }
  } catch (err) {
    showToast('Failed to acknowledge alert', 'danger');
  }
}

async function clearAcknowledgedAlerts() {
  try {
    const res = await fetch('/api/alerts/clear-ack', { method: 'POST' });
    const data = await res.json();
    showToast(`Cleared ${data.cleared_count || 0} acknowledged alerts`, 'info');
    refreshAlerts();
    refreshDashboardStats();
  } catch (err) {
    showToast('Failed to clear alerts', 'danger');
  }
}

function switchAlertTab(tab) {
  currentAlertTab = tab;
  document.getElementById('tabAlertsActive').className = tab === 'ACTIVE' ? 'btn btn-sm btn-primary' : 'btn btn-sm';
  document.getElementById('tabAlertsAll').className = tab === 'ALL' ? 'btn btn-sm btn-primary' : 'btn btn-sm';
  document.getElementById('tabAlertsAck').className = tab === 'ACKNOWLEDGED' ? 'btn btn-sm btn-primary' : 'btn btn-sm';
  refreshAlerts();
}

/* =========================================================================
   5. IP INVESTIGATION DOSSIER MODAL
   ========================================================================= */
async function openIpModal(ip) {
  if (!ip || ip === 'UNKNOWN') return;

  try {
    const modal = document.getElementById('ipModal');
    document.getElementById('modalIpAddress').textContent = ip;
    document.getElementById('modalIpClassBadge').textContent = 'Loading...';
    modal.classList.add('active');

    const res = await fetch(`/api/ip/${encodeURIComponent(ip)}`);
    if (!res.ok) throw new Error('Failed to load profile');
    const data = await res.json();

    // Populate Dossier
    document.getElementById('modalIpClassBadge').textContent = data.classification || 'Public';
    document.getElementById('modalIpClassBadge').className = `badge ${data.is_private ? 'badge-low' : 'badge-high'}`;

    const scoreEl = document.getElementById('modalRiskScore');
    scoreEl.textContent = `${data.risk_score} / 100 (${data.severity})`;
    scoreEl.style.color = data.risk_score >= 85 ? '#f43f5e' : (data.risk_score >= 60 ? '#f97316' : (data.risk_score >= 30 ? '#f59e0b' : '#10b981'));

    document.getElementById('modalTotalAttempts').textContent = data.total_attempts;
    document.getElementById('modalFailedAttempts').textContent = data.failed_attempts + data.invalid_user_attempts;
    document.getElementById('modalSuccessAttempts').textContent = data.successful_attempts;
    document.getElementById('modalFirstSeen').textContent = formatTimestamp(data.first_seen);
    document.getElementById('modalLastSeen').textContent = formatTimestamp(data.last_seen);

    // Targeted Users
    const usersContainer = document.getElementById('modalTargetedUsers');
    usersContainer.innerHTML = '';
    if (data.targeted_usernames && data.targeted_usernames.length > 0) {
      data.targeted_usernames.forEach(u => {
        const span = document.createElement('span');
        span.className = 'badge';
        span.style.background = '#1e293b';
        span.textContent = u;
        usersContainer.appendChild(span);
      });
    } else {
      usersContainer.innerHTML = '<span style="color: var(--text-muted); font-size: 0.75rem;">None recorded</span>';
    }

    // Associated Alerts
    const alertsContainer = document.getElementById('modalAssociatedAlerts');
    alertsContainer.innerHTML = '';
    if (data.alerts && data.alerts.length > 0) {
      data.alerts.forEach(a => {
        const adiv = document.createElement('div');
        adiv.className = `badge badge-${a.severity.toLowerCase()}`;
        adiv.style.display = 'block';
        adiv.style.padding = '6px';
        adiv.textContent = `[${a.severity}] ${a.threat_type}: ${a.reason}`;
        alertsContainer.appendChild(adiv);
      });
    } else {
      alertsContainer.innerHTML = '<span style="color: var(--text-muted); font-size: 0.75rem;">No active alerts associated</span>';
    }

    // Recent Events Table
    const eventsTbody = document.getElementById('modalEventsTableBody');
    eventsTbody.innerHTML = '';
    if (data.recent_events && data.recent_events.length > 0) {
      data.recent_events.forEach(ev => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td style="font-family: var(--font-mono); font-size: 0.7rem;">${formatTimestamp(ev.timestamp)}</td>
          <td><span class="user-tag">${escapeHtml(ev.username)}</span></td>
          <td style="font-size: 0.72rem;">${escapeHtml(ev.event_type)}</td>
          <td><span class="badge ${ev.auth_status === 'SUCCESS' ? 'badge-success' : 'badge-failure'}">${ev.auth_status}</span></td>
          <td><span class="badge badge-${ev.severity.toLowerCase()}">${ev.severity}</span></td>
        `;
        eventsTbody.appendChild(tr);
      });
    } else {
      eventsTbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No events found</td></tr>';
    }

  } catch (err) {
    showToast('Failed to load IP profile', 'danger');
  }
}

function closeIpModal() {
  const modal = document.getElementById('ipModal');
  if (modal) modal.classList.remove('active');
}

/* =========================================================================
   6. DEMO CONTROLS & SCENARIO TRIGGERS
   ========================================================================= */
async function triggerScenario(scenario) {
  try {
    const res = await fetch('/api/demo/trigger', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: scenario })
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Triggered scenario '${scenario}' (${data.events_triggered} events generated)`, 'info');
      refreshDashboardStats();
    }
  } catch (err) {
    showToast('Failed to trigger simulation scenario', 'danger');
  }
}

async function toggleDemoStream() {
  const btn = document.getElementById('btnDemoToggle');
  const txt = document.getElementById('demoToggleText').textContent;
  const isRunning = txt.includes('Pause');

  try {
    const endpoint = isRunning ? '/api/demo/stop' : '/api/demo/start';
    const res = await fetch(endpoint, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(isRunning ? 'Demo stream paused' : 'Demo stream resumed', 'info');
      refreshDashboardStats();
    }
  } catch (err) {
    showToast('Failed to toggle demo stream', 'danger');
  }
}

async function resetDatabase() {
  if (!confirm('Are you sure you want to clear all processed events and threat alerts from SQLite?')) {
    return;
  }
  try {
    const res = await fetch('/api/clear', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast('Database reset successfully', 'info');
      document.getElementById('eventsTableBody').innerHTML = '';
      document.getElementById('alertsList').innerHTML = '';
      refreshDashboardStats();
    }
  } catch (err) {
    showToast('Failed to clear database', 'danger');
  }
}

/* =========================================================================
   7. UTILITIES & HELPERS
   ========================================================================= */
function handleSearch() {
  currentSearch = document.getElementById('eventSearch').value.trim();
  refreshEvents();
}

function handleFilterChange() {
  currentSeverityFilter = document.getElementById('severityFilter').value;
  refreshEvents();
}

function toggleExportMenu() {
  const dd = document.getElementById('exportDropdown');
  dd.style.display = dd.style.display === 'none' ? 'block' : 'none';
}

// Close dropdown if clicked outside
document.addEventListener('click', (e) => {
  const menu = document.getElementById('exportDropdown');
  const btn = document.getElementById('btnExportMenu');
  if (menu && btn && !menu.contains(e.target) && !btn.contains(e.target)) {
    menu.style.display = 'none';
  }
});

function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'toast';
  if (type === 'danger') toast.style.borderColor = 'rgba(244, 63, 94, 0.6)';
  if (type === 'warning') toast.style.borderColor = 'rgba(245, 158, 11, 0.6)';

  toast.innerHTML = `<span>${type === 'danger' ? '🚨' : (type === 'warning' ? '⚠️' : 'ℹ️')}</span> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function formatTimestamp(isoStr) {
  if (!isoStr) return '-';
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
  } catch (e) {
    return isoStr;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
