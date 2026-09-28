/**
 * DPI Security Gateway — Frontend Application
 * =============================================
 * Handles:
 *   - Packet simulation form submission
 *   - Predefined test scenarios
 *   - Live DPI verdict display
 *   - Inspection history table
 *   - Engine statistics polling
 *   - DPI pipeline animation
 *   - Tab switching
 */

"use strict";

const API = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
  ? "http://localhost:8000"
  : window.location.origin;

// ─────────────────────────────────────────────────────────────
// Predefined Test Scenarios
// ─────────────────────────────────────────────────────────────
const SCENARIOS = {
  normal: {
    source_ip:        "192.168.1.10",
    source_port:      54321,
    destination_ip:   "10.0.0.20",
    destination_port: 80,
    protocol:         "TCP",
    sni:              "example.com",
    payload:          "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
  },
  malicious_payload: {
    source_ip:        "192.168.1.45",
    source_port:      49812,
    destination_ip:   "198.51.100.5",
    destination_port: 443,
    protocol:         "TCP",
    sni:              "bad-domain.xyz",
    payload:          "MALICIOUS_TEST_SIGNATURE payload data",
  },
  blocked_sni: {
    source_ip:        "10.0.2.15",
    source_port:      58100,
    destination_ip:   "104.28.14.9",
    destination_port: 443,
    protocol:         "TCP",
    sni:              "malicious-test.example",
    payload:          "ClientHello TLSv1.3 SessionId: 4a8b1c",
  },
  blocked_ip: {
    source_ip:        "192.168.1.50",
    source_port:      61000,
    destination_ip:   "10.0.0.20",
    destination_port: 80,
    protocol:         "TCP",
    sni:              "safe-server.net",
    payload:          "GET /api/status HTTP/1.1",
  },
  suspicious: {
    source_ip:        "172.16.5.99",
    source_port:      31337,
    destination_ip:   "10.0.0.20",
    destination_port: 31337,
    protocol:         "UDP",
    sni:              "",
    payload:          "SUSPICIOUS_PAYLOAD_TEST backchannel probe",
  },
  youtube: {
    source_ip:        "192.168.1.88",
    source_port:      51234,
    destination_ip:   "142.250.185.206",
    destination_port: 443,
    protocol:         "TCP",
    sni:              "www.youtube.com",
    payload:          "ClientHello TLSv1.2",
  },
};

// ─────────────────────────────────────────────────────────────
// DOM Helpers
// ─────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);

function escHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function delay(ms) { return new Promise((r) => setTimeout(r, ms)); }

function animateValue(el, newVal) {
  if (!el) return;
  el.style.transform = "scale(1.25)";
  el.textContent = newVal;
  setTimeout(() => { el.style.transform = "scale(1)"; }, 200);
}

// ─────────────────────────────────────────────────────────────
// Pipeline Animation
// ─────────────────────────────────────────────────────────────
const PIPE_STEPS = [
  "pipe-input", "pipe-parse", "pipe-flow",
  "pipe-sni",   "pipe-payload", "pipe-rules", "pipe-verdict",
];

function resetPipeline() {
  PIPE_STEPS.forEach((id) => {
    const el = $(id);
    if (el) el.classList.remove("active", "pass", "fail");
  });
}

async function animatePipeline(verdict) {
  resetPipeline();
  const last = PIPE_STEPS.length - 1;
  for (let i = 0; i <= last; i++) {
    const el = $(PIPE_STEPS[i]);
    if (!el) continue;
    el.classList.add("active");
    await delay(100);
    if (i < last) {
      el.classList.remove("active");
      el.classList.add("pass");
    } else {
      el.classList.remove("active");
      el.classList.add(verdict.decision === "ALLOW" ? "pass" : "fail");
    }
  }
}

// ─────────────────────────────────────────────────────────────
// Health Check & Status Bar
// ─────────────────────────────────────────────────────────────
async function checkHealth() {
  try {
    const res = await fetch(`${API}/health`, { signal: AbortSignal.timeout(3000) });
    if (res.ok) {
      const dot   = $("status-dot");
      const label = $("status-label");
      if (dot)   dot.classList.add("active");
      if (label) label.textContent = "Engine Active";
      return true;
    }
  } catch (_) {}
  const dot   = $("status-dot");
  const label = $("status-label");
  if (dot)   dot.classList.remove("active");
  if (label) label.textContent = "Engine Offline";
  return false;
}

// ─────────────────────────────────────────────────────────────
// Stats Polling — updates ALL counter elements in the page
// ─────────────────────────────────────────────────────────────
async function refreshStats() {
  try {
    const res  = await fetch(`${API}/stats`);
    const data = await res.json();
    const s    = data.engine_stats;

    // Main workspace stat cards
    animateValue($("stat-total"),     s.total_inspected);
    animateValue($("stat-allow"),     s.total_allowed);
    animateValue($("stat-block"),     s.total_blocked);
    animateValue($("stat-alert"),     s.total_blocked);   // mirrors blocked count as alerts
    animateValue($("stat-flows"),     s.active_flows);

    // Hero section mini-telemetry
    animateValue($("hero-total"),     s.total_inspected);
    animateValue($("hero-block"),     s.total_blocked);
    animateValue($("hero-flows"),     s.active_flows);

  } catch (_) {}
}

// ─────────────────────────────────────────────────────────────
// Verdict Display  — matches the actual verdict-banner HTML
// ─────────────────────────────────────────────────────────────
function showVerdictResult(verdict) {
  const isAllow = verdict.decision === "ALLOW";

  // Verdict banner
  const banner = $("verdict-banner");
  if (banner) {
    banner.className = "verdict-banner " + (isAllow ? "banner-allow" : "banner-block");
  }

  // Badge
  const badge = $("verdict-badge");
  if (badge) {
    badge.textContent = verdict.decision;
    badge.className   = "badge badge-lg " + (isAllow ? "badge-allow" : "badge-block");
  }

  // Title
  const title = $("verdict-title");
  if (title) {
    title.textContent = isAllow ? "✓ Packet Allowed — No Threats Detected" : "🚫 Packet Blocked — Threat Detected";
  }

  // Reason
  const reason = $("verdict-reason");
  if (reason) {
    reason.textContent = verdict.reason;
  }

  // Timestamp
  const ts = $("verdict-timestamp");
  if (ts) {
    ts.textContent = new Date().toLocaleTimeString();
  }

  // Classified App
  const appEl = $("verdict-app");
  if (appEl && verdict.details) {
    appEl.textContent = verdict.details.app_type || "Generic";
  }

  // Latency
  const latEl = $("verdict-latency");
  if (latEl) {
    latEl.textContent = (verdict.inspection_time_ms || 0).toFixed(2) + " ms";
  }

  // Flow key
  const flowEl = $("verdict-flow");
  if (flowEl && verdict.details) {
    flowEl.textContent = verdict.details.flow || "--";
  }

  // Action text
  const actionEl = document.getElementById("verdict-action font-mono");
  if (actionEl) {
    actionEl.textContent = verdict.decision === "ALLOW" ? "TRAFFIC PERMITTED" : "TRAFFIC DENIED";
  }
}

// ─────────────────────────────────────────────────────────────
// History Table
// ─────────────────────────────────────────────────────────────
async function refreshHistory() {
  try {
    const res  = await fetch(`${API}/history?limit=100`);
    const data = await res.json();
    renderHistory(data.records || []);
  } catch (_) {}
}

function renderHistory(records) {
  const tbody = $("history-tbody");
  if (!tbody) return;

  if (!records.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="text-center text-muted" style="padding: 24px;">No packets inspected yet. Click a scenario button to start live telemetry.</td></tr>`;
    return;
  }

  tbody.innerHTML = records.map((r, i) => {
    const isAllow    = r.action === "ALLOW";
    const badgeCls   = isAllow ? "hist-badge-allow" : "hist-badge-block";
    const icon       = isAllow ? "✓" : "🚫";
    const isNew      = i === 0 ? "row-new" : "";
    const appType    = r.app_type || "Generic";
    const sniDisplay = r.sni && r.sni !== "(none)"
      ? escHtml(r.sni)
      : `<span style="color:#94a3b8;">—</span>`;

    return `
      <tr class="${isNew}">
        <td class="font-mono" style="font-size:0.8rem;color:#64748b;">${escHtml(r.timestamp)}</td>
        <td class="font-mono" style="font-size:0.83rem;">${escHtml(r.source_ip)}:<span style="color:#64748b;">${r.source_port}</span></td>
        <td class="font-mono" style="font-size:0.83rem;">${escHtml(r.destination_ip)}:<span style="color:#64748b;">${r.destination_port}</span></td>
        <td><span class="hist-proto-tag hist-proto-${(r.protocol||"").toLowerCase()}">${escHtml(r.protocol)}</span></td>
        <td class="font-mono" style="font-size:0.83rem;">${sniDisplay}</td>
        <td><span class="hist-app-tag">${escHtml(appType)}</span></td>
        <td><span class="hist-badge ${badgeCls}">${icon} ${escHtml(r.action)}</span></td>
        <td><span class="hist-reason-code">${escHtml(r.reason_code)}</span></td>
      </tr>`;
  }).join("");
}

// ─────────────────────────────────────────────────────────────
// Flow Table
// ─────────────────────────────────────────────────────────────
async function refreshFlows() {
  try {
    const res  = await fetch(`${API}/flows`);
    const data = await res.json();
    renderFlows(data.flows || []);
  } catch (_) {}
}

function renderFlows(flows) {
  const tbody = $("flow-tbody");
  if (!tbody) return;

  if (!flows.length) {
    tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding:20px;">No active TCP/UDP flows tracked in session table.</td></tr>`;
    return;
  }

  tbody.innerHTML = flows.map(f => `
    <tr>
      <td class="font-mono" style="font-size:0.78rem;">${escHtml(String(f.flow_key || "").substring(0,12))}…</td>
      <td class="font-mono" style="font-size:0.78rem;">${escHtml(f.tuple || "")}</td>
      <td><span class="${f.blocked ? 'hist-badge hist-badge-block' : 'hist-badge hist-badge-allow'}">${f.blocked ? 'BLOCKED' : 'ACTIVE'}</span></td>
      <td>${f.packets || 0}</td>
      <td>${f.bytes_seen || 0}</td>
      <td><span class="hist-app-tag">${escHtml(f.app_type || 'Unknown')}</span></td>
      <td class="font-mono" style="font-size:0.78rem;color:#64748b;">${escHtml(f.last_seen || "—")}</td>
    </tr>`
  ).join("");
}

// ─────────────────────────────────────────────────────────────
// Core: Send Packet to DPI Engine
// ─────────────────────────────────────────────────────────────
async function sendPacket(packetData) {
  // Show loading state on verdict banner
  const banner = $("verdict-banner");
  if (banner) banner.className = "verdict-banner banner-neutral";

  const badge = $("verdict-badge");
  if (badge) {
    badge.textContent = "INSPECTING…";
    badge.className   = "badge badge-lg";
  }

  const title = $("verdict-title");
  if (title) title.textContent = "Inspecting packet through DPI engine…";

  const reason = $("verdict-reason");
  if (reason) reason.textContent = "Running L3-L7 inspection pipeline…";

  // Disable submit button
  const btn = $("btn-send");
  if (btn) {
    btn.disabled = true;
    btn.querySelector("span:last-child").textContent = "INSPECTING…";
  }

  resetPipeline();

  try {
    const res = await fetch(`${API}/send-packet`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(packetData),
    });

    const verdict = await res.json();

    // Animate pipeline, then show result
    await animatePipeline(verdict);
    showVerdictResult(verdict);

    // Refresh stats and history
    await Promise.all([refreshStats(), refreshHistory()]);

  } catch (err) {
    const banner = $("verdict-banner");
    if (banner) banner.className = "verdict-banner banner-block";

    const badge = $("verdict-badge");
    if (badge) {
      badge.textContent = "ERROR";
      badge.className   = "badge badge-lg badge-block";
    }

    const title = $("verdict-title");
    if (title) title.textContent = "Cannot reach DPI Engine backend";

    const reason = $("verdict-reason");
    if (reason) reason.textContent = "Error: " + err.message + " — ensure the backend is running.";

  } finally {
    if (btn) {
      btn.disabled = false;
      btn.querySelector("span:last-child").textContent = "INSPECT PACKET THROUGH DPI ENGINE";
    }
  }
}

// ─────────────────────────────────────────────────────────────
// Load Scenario into Form & Send
// ─────────────────────────────────────────────────────────────
function loadScenario(name) {
  const s = SCENARIOS[name];
  if (!s) return;

  const srcIp   = $("pkt-src-ip");
  const srcPort = $("pkt-src-port");
  const dstIp   = $("pkt-dst-ip");
  const dstPort = $("pkt-dst-port");
  const proto   = $("pkt-protocol");
  const sni     = $("pkt-sni");
  const payload = $("pkt-payload");

  if (srcIp)   srcIp.value   = s.source_ip;
  if (srcPort) srcPort.value = s.source_port;
  if (dstIp)   dstIp.value   = s.destination_ip;
  if (dstPort) dstPort.value = s.destination_port;
  if (proto)   proto.value   = s.protocol;
  if (sni)     sni.value     = s.sni;
  if (payload) payload.value = s.payload;

  sendPacket(s);
}

// ─────────────────────────────────────────────────────────────
// Clear History
// ─────────────────────────────────────────────────────────────
async function clearHistory() {
  try {
    await fetch(`${API}/history`, { method: "DELETE" });
    renderHistory([]);
    await refreshStats();
  } catch (_) {}
}

// Expose to global scope for onclick attributes
window.clearHistory = clearHistory;
window.loadScenario = loadScenario;

// ─────────────────────────────────────────────────────────────
// Tab Switching
// ─────────────────────────────────────────────────────────────
function initTabs() {
  const buttons = document.querySelectorAll(".tab-btn");
  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.tab;

      // Deactivate all tabs and content
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => {
        c.classList.remove("active");
        c.classList.add("hidden");
      });

      // Activate clicked tab
      btn.classList.add("active");
      const target = $(targetId);
      if (target) {
        target.classList.remove("hidden");
        target.classList.add("active");
      }

      // Refresh flows when flows tab is opened
      if (targetId === "tab-flows") refreshFlows();
    });
  });
}

// ─────────────────────────────────────────────────────────────
// Scenario Pill Buttons
// ─────────────────────────────────────────────────────────────
function initScenarioPills() {
  const map = {
    "btn-normal":     "normal",
    "btn-malicious":  "malicious_payload",
    "btn-sni":        "blocked_sni",
    "btn-scan":       "suspicious",
    "btn-custom-sig": "youtube",
  };

  Object.entries(map).forEach(([btnId, scenario]) => {
    const btn = $(btnId);
    if (btn) {
      btn.addEventListener("click", () => loadScenario(scenario));
    }
  });
}

// ─────────────────────────────────────────────────────────────
// Form Submit Handler
// ─────────────────────────────────────────────────────────────
function initFormSubmit() {
  const form = $("packet-form");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const packetData = {
      source_ip:        ($("pkt-src-ip")    || {value: ""}).value.trim(),
      source_port:      parseInt(($("pkt-src-port")  || {value: "54321"}).value, 10),
      destination_ip:   ($("pkt-dst-ip")    || {value: ""}).value.trim(),
      destination_port: parseInt(($("pkt-dst-port")  || {value: "443"}).value, 10),
      protocol:         ($("pkt-protocol")  || {value: "TCP"}).value,
      sni:              ($("pkt-sni")       || {value: ""}).value.trim(),
      payload:          ($("pkt-payload")   || {value: ""}).value,
    };

    await sendPacket(packetData);
  });
}

// ─────────────────────────────────────────────────────────────
// Clear History Button
// ─────────────────────────────────────────────────────────────
function initClearHistory() {
  const btn = $("btn-clear-history");
  if (btn) btn.addEventListener("click", clearHistory);
}

// ─────────────────────────────────────────────────────────────
// Startup
// ─────────────────────────────────────────────────────────────
(async function init() {
  // Wire up UI
  initTabs();
  initScenarioPills();
  initFormSubmit();
  initClearHistory();

  // Check engine health
  await checkHealth();

  // Load initial stats & history
  await Promise.all([refreshStats(), refreshHistory()]);

  // Poll every 5 seconds
  setInterval(refreshStats, 5000);
  setInterval(refreshHistory, 8000);

  // Re-check health every 10 seconds
  setInterval(checkHealth, 10000);
})();
