/* app.js – Dashboard polling and interaction */

"use strict";

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleTimeString();
}

function fmtDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString();
}

function actionBadge(action) {
  const map = {
    ALLOWED: "bg-green-900 text-green-300",
    BLOCKED: "bg-red-900 text-red-300",
    FLAGGED: "bg-yellow-900 text-yellow-300",
  };
  const cls = map[action] || "bg-gray-800 text-gray-400";
  return `<span class="px-2 py-0.5 rounded-full text-xs font-medium ${cls}">${action}</span>`;
}

function alertTypeBadge(type) {
  const map = {
    PORT_SCAN: "bg-purple-900 text-purple-300",
    HIGH_FREQUENCY: "bg-red-900 text-red-300",
    SUSPICIOUS_PORT: "bg-yellow-900 text-yellow-300",
  };
  const cls = map[type] || "bg-gray-800 text-gray-400";
  return `<span class="px-2 py-0.5 rounded-full text-xs font-medium ${cls}">${type}</span>`;
}

function showToast(msg, isError = false) {
  const el = document.getElementById("toast");
  document.getElementById("toast-msg").textContent = msg;
  el.style.borderColor = isError ? "#dc2626" : "#16a34a";
  el.classList.add("show");
  clearTimeout(el._timer);
  el._timer = setTimeout(() => el.classList.remove("show"), 3500);
}

// ---------------------------------------------------------------------------
// Charts
// ---------------------------------------------------------------------------

let timelineChart, protocolChart;

function initCharts() {
  const tCtx = document.getElementById("timeline-chart").getContext("2d");
  timelineChart = new Chart(tCtx, {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Packets / min",
        data: [],
        borderColor: "#22d3ee",
        backgroundColor: "rgba(34,211,238,0.08)",
        fill: true,
        tension: 0.3,
        pointRadius: 3,
      }],
    },
    options: {
      animation: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#9ca3af", maxTicksLimit: 8 }, grid: { color: "#1f2937" } },
        y: { ticks: { color: "#9ca3af" }, grid: { color: "#1f2937" }, beginAtZero: true },
      },
    },
  });

  const pCtx = document.getElementById("protocol-chart").getContext("2d");
  protocolChart = new Chart(pCtx, {
    type: "doughnut",
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: ["#22d3ee", "#f59e0b", "#f43f5e", "#a78bfa", "#34d399"],
        borderWidth: 0,
      }],
    },
    options: {
      animation: false,
      plugins: {
        legend: { position: "bottom", labels: { color: "#9ca3af", padding: 10, boxWidth: 12 } },
      },
    },
  });
}

// ---------------------------------------------------------------------------
// Data fetching
// ---------------------------------------------------------------------------

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} → HTTP ${res.status}`);
  return res.json();
}

async function refreshStats() {
  const stats = await fetchJSON("/api/stats");
  document.getElementById("stat-total").textContent = stats.total ?? 0;
  document.getElementById("stat-blocked").textContent = stats.blocked ?? 0;
  document.getElementById("stat-flagged").textContent = stats.flagged ?? 0;
  document.getElementById("stat-blocked-ips").textContent = stats.blocked_ips ?? 0;
}

async function refreshTimeline() {
  const data = await fetchJSON("/api/stats/timeline?minutes=10");
  const labels = data.map(d => {
    const t = d.minute.split("T")[1] || d.minute;
    return t.slice(0, 5);
  });
  const counts = data.map(d => d.count);
  timelineChart.data.labels = labels;
  timelineChart.data.datasets[0].data = counts;
  timelineChart.update();
}

async function refreshProtocols() {
  const data = await fetchJSON("/api/stats/protocols");
  protocolChart.data.labels = data.map(d => d.protocol || "OTHER");
  protocolChart.data.datasets[0].data = data.map(d => d.count);
  protocolChart.update();
}

async function refreshTraffic() {
  const rows = await fetchJSON("/api/traffic?limit=100");
  const tbody = document.getElementById("traffic-body");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="px-4 py-6 text-center text-gray-600">No traffic yet</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td class="text-muted">${fmtTime(r.timestamp)}</td>
      <td>${r.src_ip || "—"}</td>
      <td class="text-muted">${r.dst_ip || "—"}</td>
      <td>${r.protocol || "—"}</td>
      <td class="text-muted">${r.src_port ?? "—"}</td>
      <td>${r.dst_port ?? "—"}</td>
      <td class="text-muted">${r.packet_size ?? "—"}</td>
      <td>${actionBadge(r.action)}</td>
    </tr>
  `).join("");
}

async function refreshBlocked() {
  const rows = await fetchJSON("/api/blocked");
  const tbody = document.getElementById("blocked-body");
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-gray-600">No blocked IPs</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td class="mono" style="color:#fca5a5">${r.ip_address}</td>
      <td class="text-muted">${r.reason || "—"}</td>
      <td class="text-muted">${fmtDateTime(r.blocked_at)}</td>
      <td class="text-muted">${r.unblock_at ? fmtDateTime(r.unblock_at) : "Never"}</td>
      <td>
        <button class="unblock-btn btn-sm" data-ip="${r.ip_address}">Unblock</button>
      </td>
    </tr>
  `).join("");

  // Attach unblock handlers
  document.querySelectorAll(".unblock-btn").forEach(btn => {
    btn.addEventListener("click", () => unblockIP(btn.dataset.ip));
  });
}

async function refreshAlerts() {
  const rows = await fetchJSON("/api/alerts?limit=20");
  const tbody = document.getElementById("alerts-body");
  document.getElementById("alert-count").textContent = `${rows.length} alert${rows.length !== 1 ? "s" : ""}`;
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-6 text-center text-gray-600">No alerts</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td class="text-muted">${fmtTime(r.timestamp)}</td>
      <td class="mono">${r.src_ip}</td>
      <td>${alertTypeBadge(r.alert_type)}</td>
      <td class="text-muted">${r.description || "—"}</td>
      <td>${actionBadge(r.action_taken)}</td>
    </tr>
  `).join("");
}

// ---------------------------------------------------------------------------
// Block / unblock
// ---------------------------------------------------------------------------

async function unblockIP(ip) {
  try {
    const res = await fetch(`/api/blocked/${encodeURIComponent(ip)}`, { method: "DELETE" });
    const data = await res.json();
    if (res.ok) {
      showToast(data.message || `${ip} unblocked`);
      await refreshBlocked();
      await refreshStats();
    } else {
      showToast(data.error || "Unblock failed", true);
    }
  } catch (e) {
    showToast("Network error", true);
  }
}

function initBlockModal() {
  const modal = document.getElementById("block-modal");
  const openBtn = document.getElementById("block-btn");
  const cancelBtn = document.getElementById("block-cancel");
  const confirmBtn = document.getElementById("block-confirm");
  const ipInput = document.getElementById("block-ip-input");
  const reasonInput = document.getElementById("block-reason-input");
  const errorEl = document.getElementById("block-error");

  openBtn.addEventListener("click", () => {
    ipInput.value = "";
    reasonInput.value = "";
    errorEl.style.display = "none";
    modal.classList.add("open");
    ipInput.focus();
  });

  const closeModal = () => modal.classList.remove("open");

  cancelBtn.addEventListener("click", closeModal);
  modal.addEventListener("click", e => { if (e.target === modal) closeModal(); });

  confirmBtn.addEventListener("click", async () => {
    const ip = ipInput.value.trim();
    const reason = reasonInput.value.trim() || "Manual block";

    if (!ip) {
      errorEl.textContent = "Please enter an IP address.";
      errorEl.style.display = "block";
      return;
    }

    confirmBtn.disabled = true;
    confirmBtn.textContent = "Blocking…";

    try {
      const res = await fetch("/api/blocked", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, reason }),
      });
      const data = await res.json();
      if (res.ok) {
        closeModal();
        showToast(data.message || `${ip} blocked`);
        await refreshBlocked();
        await refreshStats();
      } else {
        errorEl.textContent = data.error || "Block failed.";
        errorEl.style.display = "block";
      }
    } catch (e) {
      errorEl.textContent = "Network error.";
      errorEl.style.display = "block";
    } finally {
      confirmBtn.disabled = false;
      confirmBtn.textContent = "Block";
    }
  });
}

// ---------------------------------------------------------------------------
// Polling loop
// ---------------------------------------------------------------------------

async function refreshAll() {
  try {
    await Promise.all([
      refreshStats(),
      refreshTimeline(),
      refreshProtocols(),
      refreshTraffic(),
      refreshBlocked(),
      refreshAlerts(),
    ]);
    document.getElementById("last-updated").textContent =
      "Updated " + new Date().toLocaleTimeString();
  } catch (e) {
    console.error("Refresh error:", e);
  }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  initBlockModal();

  refreshAll();                       // immediate first load
  setInterval(refreshAll, 3000);      // then every 3 seconds
});
