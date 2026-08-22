/**
 * SentinelLog — In-Browser Security Engine & SOC Dashboard
 * Mirrors the Python detection pipeline for client-side GitHub Pages deployment.
 */

// ==========================================
// 1. STATE & STORAGE
// ==========================================
const DB = {
  events: [],
  alerts: [],
  ipStats: {},
  maxEvents: 500
};

let isDemoRunning = true;
let demoTimer = null;
let currentSearch = '';
let currentSeverityFilter = 'ALL';
let currentAlertTab = 'ACTIVE';

// Chart.js instances
let authRatioChart = null;
let timelineChart = null;
let severityChart = null;
let topIpsChart = null;

// Target Lists for Simulation
const BENIGN_USERS = ["ubuntu", "alice", "bob", "sysadmin", "dev_sarah", "lead_dan", "deploy_bot"];
const ATTACK_USERS = ["root", "admin", "administrator", "guest", "test", "support", "oracle", "jenkins", "postgres", "ftpuser"];
const BENIGN_IPS = ["192.168.1.10", "192.168.1.25", "192.168.1.45", "10.0.0.15", "10.0.0.88", "172.16.4.12", "127.0.0.1"];
const THREAT_IPS = ["198.51.100.42", "203.0.113.88", "185.220.101.5", "45.142.214.19", "91.240.118.172", "194.26.29.112", "103.152.220.4", "185.156.73.54"];

// ==========================================
// 2. LOG PARSER ENGINE
// ==========================================
class ClientLogParser {
  static parseLine(line) {
    if (!line || !line.trim()) return null;
    line = line.trim();
    
    let timestamp = new Date().toISOString();
    let service = "sshd";
    let ip = "127.0.0.1";
    let user = "UNKNOWN";
    let eventType = "UNKNOWN";
    let authStatus = "INFO";
    let severity = "LOW";
    let riskScore = 0;
    let message = line;
    let port = null;

    // 1. SSH Failed password for invalid user
    const sshFailedInvalid = /Failed\s+password\s+for\s+invalid\s+user\s+(\S+)\s+from\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)(?:\s+port\s+(\d+))?/i.exec(line);
    if (sshFailedInvalid) {
      user = sshFailedInvalid[1];
      ip = sshFailedInvalid[2];
      port = sshFailedInvalid[3] ? parseInt(sshFailedInvalid[3]) : null;
      eventType = "INVALID_USER";
      authStatus = "INVALID";
      severity = "MEDIUM";
      riskScore = 15;
      message = `Failed authentication for non-existent/invalid user '${user}' from ${ip}`;
      return { timestamp, ip, username: user, event_type: eventType, auth_status: authStatus, service, port, severity, risk_score: riskScore, message, raw_log: line };
    }

    // 2. SSH Failed password for valid user
    const sshFailedValid = /Failed\s+(?:password|publickey|none)\s+for\s+(\S+)\s+from\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)(?:\s+port\s+(\d+))?/i.exec(line);
    if (sshFailedValid) {
      user = sshFailedValid[1];
      ip = sshFailedValid[2];
      port = sshFailedValid[3] ? parseInt(sshFailedValid[3]) : null;
      eventType = "FAILED_LOGIN";
      authStatus = "FAILURE";
      severity = "LOW";
      riskScore = 10;
      message = `Failed login attempt for user '${user}' from ${ip}`;
      return { timestamp, ip, username: user, event_type: eventType, auth_status: authStatus, service, port, severity, risk_score: riskScore, message, raw_log: line };
    }

    // 3. SSH Accepted login
    const sshAccepted = /Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)(?:\s+port\s+(\d+))?/i.exec(line);
    if (sshAccepted) {
      user = sshAccepted[2];
      ip = sshAccepted[3];
      port = sshAccepted[4] ? parseInt(sshAccepted[4]) : null;
      eventType = "SUCCESSFUL_LOGIN";
      authStatus = "SUCCESS";
      severity = "LOW";
      riskScore = 0;
      message = `Successful login for user '${user}' from ${ip}`;
      return { timestamp, ip, username: user, event_type: eventType, auth_status: authStatus, service, port, severity, risk_score: riskScore, message, raw_log: line };
    }

    // 4. SSH Invalid user probe
    const sshInvalidUser = /Invalid\s+user\s+(\S+)\s+from\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)/i.exec(line);
    if (sshInvalidUser) {
      user = sshInvalidUser[1];
      ip = sshInvalidUser[2];
      eventType = "INVALID_USER";
      authStatus = "INVALID";
      severity = "MEDIUM";
      riskScore = 15;
      message = `Invalid user lookup '${user}' from ${ip}`;
      return { timestamp, ip, username: user, event_type: eventType, auth_status: authStatus, service, severity, risk_score: riskScore, message, raw_log: line };
    }

    // 5. Sudo command execution
    const sudoCmd = /(?:sudo:\s+)?(\S+)\s*:\s*TTY=\S+\s*;\s*PWD=[^;]+\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)/i.exec(line);
    if (sudoCmd) {
      user = sudoCmd[1];
      eventType = "SUDO_COMMAND";
      authStatus = "SUCCESS";
      severity = "LOW";
      riskScore = 0;
      message = `User '${user}' executed sudo as '${sudoCmd[2]}': ${sudoCmd[3]}`;
      return { timestamp, ip: "127.0.0.1", username: user, event_type: eventType, auth_status: authStatus, service: "sudo", severity, risk_score: riskScore, message, raw_log: line };
    }

    // 6. Generic Fallback
    const ipMatch = /(?:[0-9]{1,3}\.){3}[0-9]{1,3}/.exec(line);
    if (ipMatch) ip = ipMatch[0];
    const userMatch = /(?:user|account)=['"]?([a-zA-Z0-9_\-\.]+)/i.exec(line);
    if (userMatch) user = userMatch[1];

    if (/fail|denied|bad|error/i.test(line)) {
      eventType = "FAILED_LOGIN";
      authStatus = "FAILURE";
      riskScore = 10;
    } else if (/accept|success|opened/i.test(line)) {
      eventType = "SUCCESSFUL_LOGIN";
      authStatus = "SUCCESS";
    }

    return { timestamp, ip, username: user, event_type: eventType, auth_status: authStatus, service: "generic", severity: "LOW", risk_score: riskScore, message: line.substring(0, 80), raw_log: line };
  }
}

// ==========================================
// 3. THREAT DETECTION & SCORING ENGINE
// ==========================================
class ClientThreatDetector {
  static processEvent(event) {
    const alerts = [];
    if (!event || event.ip === "UNKNOWN") return alerts;

    const ip = event.ip;
    const now = Date.now();
    const windowMs = 300 * 1000; // 5 minutes

    // Get or initialize IP sliding window
    if (!DB.ipStats[ip]) {
      DB.ipStats[ip] = {
        total: 0,
        failed: 0,
        success: 0,
        invalid: 0,
        users: new Set(),
        events: [],
        alerts: [],
        firstSeen: event.timestamp,
        lastSeen: event.timestamp,
        lastAlertTime: {}
      };
    }

    const stat = DB.ipStats[ip];
    stat.total++;
    stat.lastSeen = event.timestamp;
    if (event.username && event.username !== "UNKNOWN") stat.users.add(event.username);

    if (event.auth_status === "SUCCESS") stat.success++;
    else if (event.auth_status === "INVALID") stat.invalid++;
    else if (event.auth_status === "FAILURE") stat.failed++;

    // Add to sliding window
    stat.events.push({ ts: now, event });
    stat.events = stat.events.filter(e => now - e.ts <= windowMs);

    const recentFailures = stat.events.filter(e => e.event.auth_status === "FAILURE" || e.event.auth_status === "INVALID");
    const uniqueUsersInWindow = Array.from(new Set(stat.events.map(e => e.event.username).filter(u => u && u !== "UNKNOWN")));

    // Rule 1: Suspicious Success
    if (event.auth_status === "SUCCESS" && recentFailures.length >= 3) {
      const alertId = `ALT-${Math.floor(now/1000)}-${Math.random().toString(36).substring(2,7)}`;
      const alert = {
        alert_id: alertId,
        timestamp: event.timestamp,
        threat_type: "SUSPICIOUS_SUCCESS",
        source_ip: ip,
        username: event.username,
        severity: "CRITICAL",
        risk_score: 90,
        reason: `Successful login for user '${event.username}' immediately following ${recentFailures.length} failed login attempts from IP ${ip} within 5 minutes.`,
        recommended_action: `1. CRITICAL: Account '${event.username}' logged in successfully immediately following ${recentFailures.length} failures!\n2. Terminate active session immediately for '${event.username}'.\n3. Force password reset and require Multi-Factor Authentication (MFA).\n4. Inspect authorized_keys on target host.`,
        status: "ACTIVE"
      };
      alerts.push(alert);
      stat.alerts.push(alert);
    }

    // Rule 2: Brute Force Detection
    if (recentFailures.length >= 5) {
      const lastAlert = stat.lastAlertTime["BRUTE_FORCE"] || 0;
      if (now - lastAlert > 45000) {
        stat.lastAlertTime["BRUTE_FORCE"] = now;
        const score = Math.min(65 + (recentFailures.length - 5) * 5, 95);
        const sev = score >= 85 ? "CRITICAL" : "HIGH";
        const alertId = `ALT-${Math.floor(now/1000)}-${Math.random().toString(36).substring(2,7)}`;
        const alert = {
          alert_id: alertId,
          timestamp: event.timestamp,
          threat_type: "BRUTE_FORCE_ATTEMPT",
          source_ip: ip,
          username: Array.from(stat.users).slice(0, 3).join(", ") || event.username,
          severity: sev,
          risk_score: score,
          reason: `Brute-force attack detected: ${recentFailures.length} failed login attempts from source IP ${ip} within 5 minutes.`,
          recommended_action: `1. Temporarily ban source IP ${ip} via firewall/iptables.\n2. Check if accounts were compromised.\n3. Enforce SSH key-only authentication.`,
          status: "ACTIVE"
        };
        alerts.push(alert);
        stat.alerts.push(alert);
      }
    }

    // Rule 3: User Spraying
    if (uniqueUsersInWindow.length >= 3) {
      const lastAlert = stat.lastAlertTime["USER_SPRAYING"] || 0;
      if (now - lastAlert > 45000) {
        stat.lastAlertTime["USER_SPRAYING"] = now;
        const score = Math.min(70 + uniqueUsersInWindow.length * 5, 95);
        const sev = score >= 85 ? "CRITICAL" : "HIGH";
        const alertId = `ALT-${Math.floor(now/1000)}-${Math.random().toString(36).substring(2,7)}`;
        const alert = {
          alert_id: alertId,
          timestamp: event.timestamp,
          threat_type: "USER_SPRAYING",
          source_ip: ip,
          username: `${uniqueUsersInWindow.length} accounts (${uniqueUsersInWindow.slice(0,2).join(", ")}...)`,
          severity: sev,
          risk_score: score,
          reason: `Credential spraying attack detected: Source IP ${ip} probed ${uniqueUsersInWindow.length} distinct user accounts (${uniqueUsersInWindow.slice(0, 5).join(", ")}) within 5 minutes.`,
          recommended_action: `1. Source IP ${ip} is conducting a horizontal credential spray.\n2. Block ${ip} at perimeter firewall.\n3. Audit targeted accounts.`,
          status: "ACTIVE"
        };
        alerts.push(alert);
        stat.alerts.push(alert);
      }
    }

    return alerts;
  }
}

// ==========================================
// 4. INGESTION & DISPATCH PIPELINE
// ==========================================
function ingestEvent(event) {
  if (!event) return;

  // Store event
  DB.events.unshift(event);
  if (DB.events.length > DB.maxEvents) DB.events.pop();

  // Run detection
  const alerts = ClientThreatDetector.processEvent(event);
  alerts.forEach(a => {
    DB.alerts.unshift(a);
    showToast(`🚨 Threat Detected: ${a.threat_type} from ${a.source_ip}`, 'danger');
  });

  // Prepend to Live Table
  if (passesFilters(event)) {
    prependTableRow(event);
  }

  // Prepend Alerts
  alerts.forEach(a => prependAlertCard(a));

  // Update UI Stats
  updateDashboardKPIs();
}

function passesFilters(ev) {
  if (currentSeverityFilter !== 'ALL' && ev.severity !== currentSeverityFilter) return false;
  if (currentSearch) {
    const s = currentSearch.toLowerCase();
    return (ev.ip && ev.ip.toLowerCase().includes(s)) ||
           (ev.username && ev.username.toLowerCase().includes(s)) ||
           (ev.message && ev.message.toLowerCase().includes(s));
  }
  return true;
}

// ==========================================
// 5. REALISTIC DEMO TRAFFIC GENERATOR
// ==========================================
function startDemoStream() {
  if (demoTimer) clearInterval(demoTimer);
  demoTimer = setInterval(() => {
    if (!isDemoRunning) return;
    if (Math.random() < 0.35) {
      const scenarios = ["brute_force", "user_spraying", "compromise", "rapid_spike", "invalid_probe"];
      const chosen = scenarios[Math.floor(Math.random() * scenarios.length)];
      triggerScenario(chosen);
    } else {
      generateBenignEvent();
    }
  }, 2000);
}

function generateBenignEvent() {
  const user = BENIGN_USERS[Math.floor(Math.random() * BENIGN_USERS.length)];
  const ip = BENIGN_IPS[Math.floor(Math.random() * BENIGN_IPS.length)];
  const port = Math.floor(Math.random() * 35000) + 30000;
  const raw = `Aug 22 14:32:10 srv-prod-01 sshd[${Math.floor(Math.random()*20000)+10000}]: Accepted publickey for ${user} from ${ip} port ${port} ssh2`;
  const ev = ClientLogParser.parseLine(raw);
  ingestEvent(ev);
}

function triggerScenario(scenario) {
  const attackerIp = THREAT_IPS[Math.floor(Math.random() * THREAT_IPS.length)];
  
  if (scenario === 'brute_force') {
    const targetUser = ["root", "admin", "sysadmin"][Math.floor(Math.random() * 3)];
    for (let i = 0; i < 6; i++) {
      setTimeout(() => {
        const raw = `Aug 22 14:32:10 srv-prod-01 sshd[14210]: Failed password for ${targetUser} from ${attackerIp} port 49120 ssh2`;
        ingestEvent(ClientLogParser.parseLine(raw));
      }, i * 70);
    }
    showToast(`Triggered scenario 'SSH Brute-Force' from ${attackerIp}`, 'info');
  } else if (scenario === 'user_spraying') {
    const targets = ["admin", "root", "oracle", "deploy", "git", "support"];
    targets.forEach((u, i) => {
      setTimeout(() => {
        const raw = `Aug 22 14:32:10 srv-prod-01 sshd[14210]: Failed password for invalid user ${u} from ${attackerIp} port 49120 ssh2`;
        ingestEvent(ClientLogParser.parseLine(raw));
      }, i * 70);
    });
    showToast(`Triggered scenario 'Credential Spraying' from ${attackerIp}`, 'info');
  } else if (scenario === 'compromise') {
    const user = ["admin", "root", "ubuntu"][Math.floor(Math.random() * 3)];
    for (let i = 0; i < 4; i++) {
      setTimeout(() => {
        const raw = `Aug 22 14:32:10 srv-prod-01 sshd[14210]: Failed password for ${user} from ${attackerIp} port 49120 ssh2`;
        ingestEvent(ClientLogParser.parseLine(raw));
      }, i * 70);
    }
    setTimeout(() => {
      const rawSucc = `Aug 22 14:32:10 srv-prod-01 sshd[14210]: Accepted password for ${user} from ${attackerIp} port 49121 ssh2`;
      ingestEvent(ClientLogParser.parseLine(rawSucc));
    }, 350);
    showToast(`Triggered scenario 'Suspicious Compromise' on account '${user}'`, 'info');
  } else if (scenario === 'rapid_spike') {
    for (let i = 0; i < 9; i++) {
      setTimeout(() => {
        const raw = `Aug 22 14:32:10 srv-prod-01 sshd[14210]: Failed password for root from ${attackerIp} port 49120 ssh2`;
        ingestEvent(ClientLogParser.parseLine(raw));
      }, i * 40);
    }
    showToast(`Triggered scenario 'Velocity Burst' from ${attackerIp}`, 'info');
  } else if (scenario === 'invalid_probe') {
    const weird = ["nagios", "postfix", "mysql", "nobody"];
    weird.forEach((u, i) => {
      setTimeout(() => {
        const raw = `Aug 22 14:32:10 srv-prod-01 sshd[14210]: Invalid user ${u} from ${attackerIp} port 49120`;
        ingestEvent(ClientLogParser.parseLine(raw));
      }, i * 70);
    });
    showToast(`Triggered scenario 'Invalid User Probe' from ${attackerIp}`, 'info');
  } else {
    generateBenignEvent();
    showToast(`Generated benign authentication event`, 'info');
  }
}

function toggleDemoStream() {
  isDemoRunning = !isDemoRunning;
  const icon = document.getElementById('demoToggleIcon');
  const txt = document.getElementById('demoToggleText');
  if (isDemoRunning) {
    icon.textContent = '⏸️';
    txt.textContent = 'Pause Demo Stream';
    showToast('Demo stream resumed', 'info');
  } else {
    icon.textContent = '▶️';
    txt.textContent = 'Resume Demo Stream';
    showToast('Demo stream paused', 'info');
  }
}

// ==========================================
// 6. LOCAL LOG FILE UPLOAD
// ==========================================
function handleFileUpload(event) {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (e) => {
    const text = e.target.result;
    const lines = text.split('\n');
    showToast(`Processing ${lines.length} lines from ${file.name}...`, 'info');

    // Switch to live mode indicator
    document.getElementById('modeBadgeText').textContent = `LIVE LOG FILE — ${file.name}`;
    document.getElementById('modeBadge').className = 'mode-badge live';

    let count = 0;
    lines.forEach((line, index) => {
      if (line.trim()) {
        setTimeout(() => {
          const parsed = ClientLogParser.parseLine(line);
          if (parsed) ingestEvent(parsed);
        }, index * 20);
        count++;
      }
    });
  };
  reader.readAsText(file);
}

// ==========================================
// 7. CHARTS & KPIS
// ==========================================
function initCharts() {
  Chart.defaults.color = '#94a3b8';
  Chart.defaults.font.family = "'Inter', sans-serif";

  // 1. Auth Status Donut
  const ctxAuth = document.getElementById('authRatioChart').getContext('2d');
  authRatioChart = new Chart(ctxAuth, {
    type: 'doughnut',
    data: {
      labels: ['Success', 'Failed', 'Invalid User'],
      datasets: [{
        data: [0, 0, 0],
        backgroundColor: ['#10b981', '#f43f5e', '#f59e0b'],
        borderWidth: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, padding: 12 } } },
      cutout: '70%'
    }
  });

  // 2. Timeline Line/Area
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
      plugins: { legend: { position: 'top', labels: { boxWidth: 12 } } }
    }
  });

  // 3. Severity Bar
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

  // 4. Top IPs Horizontal Bar
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

function updateDashboardKPIs() {
  const total = DB.events.length;
  const success = DB.events.filter(e => e.auth_status === "SUCCESS").length;
  const failed = DB.events.filter(e => e.auth_status === "FAILURE").length;
  const invalid = DB.events.filter(e => e.auth_status === "INVALID").length;
  const activeThreats = DB.alerts.filter(a => a.status === "ACTIVE").length;
  const highCrit = DB.alerts.filter(a => (a.severity === "HIGH" || a.severity === "CRITICAL") && a.status === "ACTIVE").length;
  const uniqueIps = Object.keys(DB.ipStats).length;

  document.getElementById('kpiTotalEvents').textContent = total.toLocaleString();
  document.getElementById('kpiSuccessLogins').textContent = success.toLocaleString();
  document.getElementById('kpiFailedLogins').textContent = (failed + invalid).toLocaleString();
  document.getElementById('kpiInvalidSub').textContent = invalid.toLocaleString();
  document.getElementById('kpiActiveThreats').textContent = activeThreats.toLocaleString();
  document.getElementById('kpiHighCritSub').textContent = highCrit.toLocaleString();
  document.getElementById('kpiUniqueIps').textContent = uniqueIps.toLocaleString();

  // Status indicator
  const dot = document.getElementById('statusDot');
  const txt = document.getElementById('statusText');
  dot.className = 'status-dot';
  if (highCrit > 0) {
    dot.classList.add('red');
    txt.textContent = 'THREATS DETECTED';
  } else if (activeThreats > 0 || failed > 5) {
    dot.classList.add('yellow');
    txt.textContent = 'SYSTEM WARNING';
  } else {
    dot.classList.add('green');
    txt.textContent = 'SYSTEM MONITORING';
  }

  // Update Charts
  if (authRatioChart) {
    authRatioChart.data.datasets[0].data = [success, failed, invalid];
    authRatioChart.update();
  }

  if (severityChart) {
    const lowCount = DB.events.filter(e => e.severity === "LOW").length;
    const medCount = DB.events.filter(e => e.severity === "MEDIUM").length;
    const highCount = DB.alerts.filter(a => a.severity === "HIGH").length;
    const critCount = DB.alerts.filter(a => a.severity === "CRITICAL").length;
    severityChart.data.datasets[0].data = [lowCount, medCount, highCount, critCount];
    severityChart.update();
  }

  if (topIpsChart) {
    const sortedIps = Object.entries(DB.ipStats)
      .filter(([ip]) => ip !== "127.0.0.1" && ip !== "UNKNOWN")
      .sort((a, b) => (b[1].failed + b[1].invalid) - (a[1].failed + a[1].invalid))
      .slice(0, 5);

    topIpsChart.data.labels = sortedIps.map(([ip]) => ip);
    topIpsChart.data.datasets[0].data = sortedIps.map(([, s]) => s.failed + s.invalid);
    topIpsChart.update();
  }
}

// ==========================================
// 8. TABLE & ALERT RENDERING
// ==========================================
function prependTableRow(ev) {
  const tbody = document.getElementById('eventsTableBody');
  if (!tbody) return;

  const tr = document.createElement('tr');
  tr.className = 'new-arrival';

  const tsShort = formatTimestamp(ev.timestamp);
  const sevClass = `badge-${ev.severity.toLowerCase()}`;
  let statusClass = 'badge-failure';
  if (ev.auth_status === 'SUCCESS') statusClass = 'badge-success';
  else if (ev.auth_status === 'INVALID') statusClass = 'badge-invalid';

  tr.innerHTML = `
    <td style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${tsShort}</td>
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

  tbody.insertBefore(tr, tbody.firstChild);
  if (tbody.children.length > 80) tbody.removeChild(tbody.lastChild);
}

function renderEventsTable() {
  const tbody = document.getElementById('eventsTableBody');
  tbody.innerHTML = '';
  DB.events.filter(passesFilters).slice(0, 80).forEach(ev => {
    const tr = document.createElement('tr');
    const tsShort = formatTimestamp(ev.timestamp);
    const sevClass = `badge-${ev.severity.toLowerCase()}`;
    let statusClass = 'badge-failure';
    if (ev.auth_status === 'SUCCESS') statusClass = 'badge-success';
    else if (ev.auth_status === 'INVALID') statusClass = 'badge-invalid';

    tr.innerHTML = `
      <td style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${tsShort}</td>
      <td><span class="ip-clickable" onclick="openIpModal('${ev.ip}')">${escapeHtml(ev.ip)}</span></td>
      <td><span class="user-tag">${escapeHtml(ev.username)}</span></td>
      <td><span style="font-family: var(--font-mono); font-size: 0.74rem;">${escapeHtml(ev.event_type)}</span></td>
      <td><span style="color: var(--text-muted); font-size: 0.75rem;">${escapeHtml(ev.service || 'sshd')}</span></td>
      <td><span class="badge ${sevClass}">${escapeHtml(ev.severity)}</span></td>
      <td><span class="badge ${statusClass}">${escapeHtml(ev.auth_status)}</span></td>
      <td style="font-size: 0.72rem; color: var(--text-muted); max-width: 250px; overflow: hidden; text-overflow: ellipsis;">
        ${escapeHtml(ev.message || ev.raw_log)}
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function prependAlertCard(alert) {
  const container = document.getElementById('alertsList');
  if (!container) return;

  const div = document.createElement('div');
  div.className = `alert-card ${alert.severity} ${alert.status}`;
  div.id = `alert-${alert.alert_id}`;

  const tsFormatted = formatTimestamp(alert.timestamp);
  const isAck = alert.status === 'ACKNOWLEDGED';

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

  container.insertBefore(div, container.firstChild);
}

function acknowledgeAlert(alertId) {
  const a = DB.alerts.find(al => al.alert_id === alertId);
  if (a) {
    a.status = 'ACKNOWLEDGED';
    showToast(`Alert ${alertId} acknowledged`, 'info');
    renderAlertsList();
    updateDashboardKPIs();
  }
}

function clearAcknowledgedAlerts() {
  const prevCount = DB.alerts.length;
  DB.alerts = DB.alerts.filter(a => a.status !== 'ACKNOWLEDGED');
  showToast(`Cleared ${prevCount - DB.alerts.length} acknowledged alerts`, 'info');
  renderAlertsList();
  updateDashboardKPIs();
}

function switchAlertTab(tab) {
  currentAlertTab = tab;
  document.getElementById('tabAlertsActive').className = tab === 'ACTIVE' ? 'btn btn-sm btn-primary' : 'btn btn-sm';
  document.getElementById('tabAlertsAll').className = tab === 'ALL' ? 'btn btn-sm btn-primary' : 'btn btn-sm';
  document.getElementById('tabAlertsAck').className = tab === 'ACKNOWLEDGED' ? 'btn btn-sm btn-primary' : 'btn btn-sm';
  renderAlertsList();
}

function renderAlertsList() {
  const container = document.getElementById('alertsList');
  container.innerHTML = '';

  const filtered = DB.alerts.filter(a => currentAlertTab === 'ALL' || a.status === currentAlertTab);
  if (filtered.length === 0) {
    container.innerHTML = `<div style="text-align: center; padding: 2rem; color: var(--text-muted); font-size: 0.85rem;">No alerts in ${currentAlertTab.toLowerCase()} status.</div>`;
    return;
  }
  filtered.forEach(prependAlertCard);
}

// ==========================================
// 9. IP FORENSIC DOSSIER MODAL
// ==========================================
function openIpModal(ip) {
  if (!ip || ip === "UNKNOWN") return;
  const modal = document.getElementById('ipModal');
  const stat = DB.ipStats[ip] || { total: 1, failed: 0, success: 1, invalid: 0, users: new Set([ip]), alerts: [], firstSeen: "-", lastSeen: "-" };

  document.getElementById('modalIpAddress').textContent = ip;
  
  // IP Classification
  const isPrivate = ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.") || ip === "127.0.0.1";
  document.getElementById('modalIpClassBadge').textContent = isPrivate ? (ip === "127.0.0.1" ? "Loopback" : "Private / RFC1918") : "Public / External";
  document.getElementById('modalIpClassBadge').className = `badge ${isPrivate ? 'badge-low' : 'badge-high'}`;

  // Risk Score calculation
  const score = Math.min((stat.failed * 10) + (stat.invalid * 15) + (stat.alerts.length * 25), 100);
  const sev = score >= 85 ? "CRITICAL" : (score >= 60 ? "HIGH" : (score >= 30 ? "MEDIUM" : "LOW"));
  const scoreEl = document.getElementById('modalRiskScore');
  scoreEl.textContent = `${score} / 100 (${sev})`;
  scoreEl.style.color = score >= 85 ? '#f43f5e' : (score >= 60 ? '#f97316' : (score >= 30 ? '#f59e0b' : '#10b981'));

  document.getElementById('modalTotalAttempts').textContent = stat.total;
  document.getElementById('modalFailedAttempts').textContent = stat.failed + stat.invalid;
  document.getElementById('modalSuccessAttempts').textContent = stat.success;
  document.getElementById('modalFirstSeen').textContent = formatTimestamp(stat.firstSeen);
  document.getElementById('modalLastSeen').textContent = formatTimestamp(stat.lastSeen);

  // Targeted Users
  const userContainer = document.getElementById('modalTargetedUsers');
  userContainer.innerHTML = '';
  stat.users.forEach(u => {
    const s = document.createElement('span');
    s.className = 'badge';
    s.style.background = '#1e293b';
    s.textContent = u;
    userContainer.appendChild(s);
  });

  // Associated Alerts
  const alertContainer = document.getElementById('modalAssociatedAlerts');
  alertContainer.innerHTML = '';
  if (stat.alerts.length > 0) {
    stat.alerts.forEach(a => {
      const ad = document.createElement('div');
      ad.className = `badge badge-${a.severity.toLowerCase()}`;
      ad.style.display = 'block';
      ad.style.padding = '6px';
      ad.textContent = `[${a.severity}] ${a.threat_type}: ${a.reason}`;
      alertContainer.appendChild(ad);
    });
  } else {
    alertContainer.innerHTML = '<span style="color: var(--text-muted); font-size: 0.75rem;">No active alerts associated</span>';
  }

  // Events Trail
  const eventsTbody = document.getElementById('modalEventsTableBody');
  eventsTbody.innerHTML = '';
  const ipEvents = DB.events.filter(e => e.ip === ip).slice(0, 10);
  ipEvents.forEach(ev => {
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

  modal.classList.add('active');
}

function closeIpModal() {
  const m = document.getElementById('ipModal');
  if (m) m.classList.remove('active');
}

// ==========================================
// 10. EXPORTERS & UTILITIES
// ==========================================
function exportEventsCSV() {
  let csv = "timestamp,ip,username,event_type,auth_status,service,severity,risk_score,message\n";
  DB.events.forEach(e => {
    csv += `"${e.timestamp}","${e.ip}","${e.username}","${e.event_type}","${e.auth_status}","${e.service || 'sshd'}","${e.severity}",${e.risk_score},"${(e.message || '').replace(/"/g, '""')}"\n`;
  });
  downloadFile(csv, "sentinel_events.csv", "text/csv");
}

function exportAlertsJSON() {
  const json = JSON.stringify({ generated_at: new Date().toISOString(), alerts: DB.alerts }, null, 2);
  downloadFile(json, "sentinel_alerts.json", "application/json");
}

function exportReportMarkdown() {
  const total = DB.events.length;
  const success = DB.events.filter(e => e.auth_status === "SUCCESS").length;
  const failed = DB.events.filter(e => e.auth_status === "FAILURE").length;
  const invalid = DB.events.filter(e => e.auth_status === "INVALID").length;
  const activeThreats = DB.alerts.filter(a => a.status === "ACTIVE").length;

  let md = `# SentinelLog — Threat Intelligence & Incident Report\n`;
  md += `**Generated:** ${new Date().toUTCString()}\n\n`;
  md += `## Executive Summary\n\n`;
  md += `| Metric | Count |\n| :--- | :--- |\n`;
  md += `| **Total Events** | ${total} |\n| **Successful Logins** | ${success} |\n| **Failed Logins** | ${failed} |\n| **Invalid Probes** | ${invalid} |\n| **Active Threats** | ${activeThreats} |\n\n`;
  md += `## Active Threat Alerts\n\n`;
  DB.alerts.forEach(a => {
    md += `- **[${a.severity}] ${a.threat_type}** (Source: \`${a.source_ip}\`, User: \`${a.username}\`)\n  *Reason:* ${a.reason}\n  *Action:* ${a.recommended_action}\n\n`;
  });
  downloadFile(md, "sentinel_security_report.md", "text/markdown");
}

function downloadFile(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  showToast(`Downloaded ${filename}`, 'info');
}

function resetDatabase() {
  if (!confirm("Are you sure you want to clear all in-memory events and alerts?")) return;
  DB.events = [];
  DB.alerts = [];
  DB.ipStats = {};
  document.getElementById('eventsTableBody').innerHTML = '';
  document.getElementById('alertsList').innerHTML = '';
  updateDashboardKPIs();
  showToast('In-memory database cleared', 'info');
}

function handleSearch() {
  currentSearch = document.getElementById('eventSearch').value.trim();
  renderEventsTable();
}

function handleFilterChange() {
  currentSeverityFilter = document.getElementById('severityFilter').value;
  renderEventsTable();
}

function toggleExportMenu() {
  const dd = document.getElementById('exportDropdown');
  dd.style.display = dd.style.display === 'none' ? 'block' : 'none';
}

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
  toast.innerHTML = `<span>${type === 'danger' ? '🚨' : 'ℹ️'}</span> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

function formatTimestamp(isoStr) {
  if (!isoStr || isoStr === "-") return '-';
  try {
    const d = new Date(isoStr);
    return isNaN(d.getTime()) ? isoStr : d.toLocaleTimeString() + '.' + String(d.getMilliseconds()).padStart(3, '0');
  } catch (e) {
    return isoStr;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Initial Boot
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  
  // Seed initial realistic activity
  for (let i = 0; i < 5; i++) {
    generateBenignEvent();
  }
  
  // Start simulation stream
  startDemoStream();
});
