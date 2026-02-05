// --- GLOBAL CONFIG ---
const API_STATS = "/api/stats";
const API_ALERTS = "/api/alerts";
const API_ALERTS_SEARCH = "/api/alerts/search";

document.addEventListener("DOMContentLoaded", () => {
  const path = window.location.pathname;
  updateClock();

  if (path === "/") initDashboard();
  else if (path === "/logs") initLogs();
});

// --- DASHBOARD LOGIC ---
function initDashboard() {
  let severityChart, sourceChart;

  const ctx1 = document.getElementById("severityChart").getContext("2d");
  severityChart = new Chart(ctx1, {
    type: "doughnut",
    data: {
      labels: ["CRITICAL", "HIGH", "MEDIUM", "INFO"],
      datasets: [
        {
          data: [0, 0, 0, 0],
          backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6"],
          borderWidth: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "right" } },
    },
  });

  const ctx2 = document.getElementById("sourceChart").getContext("2d");
  sourceChart = new Chart(ctx2, {
    type: "bar",
    data: {
      labels: [],
      datasets: [
        {
          label: "Events Count",
          data: [],
          backgroundColor: "#3b82f6",
          borderRadius: 4,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { beginAtZero: true, grid: { color: "#334155" } },
        x: { grid: { display: false } },
      },
    },
  });

  function updateDashboard() {
    fetch(API_STATS)
      .then((res) => res.json())
      .then((data) => {
        document.getElementById("val-critical").innerText = data.critical;
        document.getElementById("val-high").innerText = data.high;
        document.getElementById("val-ai").innerText = data.anomalies;
        document.getElementById("val-total").innerText = data.total;

        // Real data
        severityChart.data.datasets[0].data = [
          data.critical || 0,
          data.high || 0,
          data.medium || 0,
          data.info || 0,
        ];
        severityChart.update();
      });

    fetch(API_ALERTS)
      .then((res) => res.json())
      .then((data) => {
        const tbody = document.getElementById("mini-table-body");
        tbody.innerHTML = "";

        data.slice(0, 5).forEach((alert) => {
          const row = `
                        <tr>
                            <td>${new Date(alert.timestamp).toLocaleTimeString()}</td>
                            <td style="font-weight:bold">${alert.alert_name}</td>
                            <td><span style="color:${getColor(alert.severity)}">${alert.severity}</span></td>
                            <td>${alert.ip_address || "N/A"}</td>
                        </tr>
                    `;
          tbody.innerHTML += row;
        });

        const ipCounts = {};
        data.forEach((a) => {
          const ip = a.ip_address || "Unknown";
          ipCounts[ip] = (ipCounts[ip] || 0) + 1;
        });

        sourceChart.data.labels = Object.keys(ipCounts).slice(0, 5);
        sourceChart.data.datasets[0].data = Object.values(ipCounts).slice(0, 5);
        sourceChart.update();
      });
  }

  setInterval(updateDashboard, 3000);
  updateDashboard();
}

// --- LOGS PAGE LOGIC (Filter + Paging + Live) ---
function initLogs() {
  const tableBody = document.getElementById("logs-body");

  const btnFilterToggle = document.getElementById("btn-filter-toggle");
  const filterPanel = document.getElementById("filter-panel");
  const btnLiveToggle = document.getElementById("btn-live-toggle");

  const inpFrom = document.getElementById("filter-from");
  const inpTo = document.getElementById("filter-to");
  const inpSeverity = document.getElementById("filter-severity");
  const inpIp = document.getElementById("filter-ip");
  const inpMitre = document.getElementById("filter-mitre");
  const inpQ = document.getElementById("filter-q");

  const btnApply = document.getElementById("filter-apply");
  const btnClear = document.getElementById("filter-clear");

  const pageInfo = document.getElementById("page-info");
  const btnPrev = document.getElementById("page-prev");
  const btnNext = document.getElementById("page-next");
  const selPageSize = document.getElementById("page-size");

  const state = {
    page: 1,
    pageSize: parseInt(selPageSize.value, 10) || 50,
    from: "",
    to: "",
    severity: "",
    ip: "",
    mitre: "",
    q: "",
    live: true,
    timer: null,
    totalPages: 1,
  };

  function setLive(on) {
    state.live = on;
    btnLiveToggle.textContent = on ? "LIVE STREAM" : "PAUSED";
    btnLiveToggle.style.opacity = on ? "1" : "0.7";

    if (state.timer) {
      clearInterval(state.timer);
      state.timer = null;
    }

    if (on) {
      state.page = 1;
      fetchPage(1);
      state.timer = setInterval(() => fetchPage(1), 2000);
    }
  }

  function toIsoOrEmpty(datetimeLocalValue) {
    if (!datetimeLocalValue) return "";
    const d = new Date(datetimeLocalValue);
    if (Number.isNaN(d.getTime())) return "";
    return d.toISOString();
  }

  function readFiltersFromUI() {
    state.from = toIsoOrEmpty(inpFrom?.value);
    state.to = toIsoOrEmpty(inpTo?.value);

    state.severity = (inpSeverity?.value || "").trim();
    state.ip = (inpIp?.value || "").trim();
    state.mitre = (inpMitre?.value || "").trim();
    state.q = (inpQ?.value || "").trim();
    state.pageSize = parseInt(selPageSize.value, 10) || 50;
  }

  function buildQuery(page) {
    const params = new URLSearchParams();
    params.set("page", String(page));
    params.set("page_size", String(state.pageSize));

    if (state.from) params.set("from", state.from);
    if (state.to) params.set("to", state.to);

    if (state.severity) params.set("severity", state.severity);
    if (state.ip) params.set("ip", state.ip);
    if (state.mitre) params.set("mitre", state.mitre);
    if (state.q) params.set("q", state.q);

    return params.toString();
  }

  function render(items) {
    tableBody.innerHTML = "";
    items.forEach((a) => tableBody.appendChild(createRow(a)));
  }

  function updatePager(totalPages, total) {
    state.totalPages = Math.max(1, totalPages || 1);

    pageInfo.textContent = `Page ${state.page} / ${state.totalPages} • Total ${total || 0}`;
    btnPrev.disabled = state.page <= 1;
    btnNext.disabled = state.page >= state.totalPages;
    btnPrev.style.opacity = btnPrev.disabled ? "0.5" : "1";
    btnNext.style.opacity = btnNext.disabled ? "0.5" : "1";
  }

  function fetchPage(page) {
    state.page = Math.max(1, page);
    const effectivePage = state.live ? 1 : state.page;

    const url = `${API_ALERTS_SEARCH}?${buildQuery(effectivePage)}`;
    fetch(url)
      .then((res) => res.json())
      .then((data) => {
        render(data.items || []);
        updatePager(data.total_pages || 1, data.total || 0);
      });
  }

  btnFilterToggle?.addEventListener("click", () => {
    const visible = filterPanel.style.display !== "none";
    filterPanel.style.display = visible ? "none" : "block";
  });

  btnApply?.addEventListener("click", () => {
    readFiltersFromUI();
    setLive(false);
    fetchPage(1);
    filterPanel.style.display = "none";
  });

  btnClear?.addEventListener("click", () => {
    if (inpFrom) inpFrom.value = "";
    if (inpTo) inpTo.value = "";
    if (inpSeverity) inpSeverity.value = "";
    if (inpIp) inpIp.value = "";
    if (inpMitre) inpMitre.value = "";
    if (inpQ) inpQ.value = "";
    selPageSize.value = "50";
    readFiltersFromUI();
    setLive(true);
    filterPanel.style.display = "none";
  });

  selPageSize?.addEventListener("change", () => {
    readFiltersFromUI();
    setLive(false);
    fetchPage(1);
  });

  btnPrev?.addEventListener("click", () => {
    setLive(false);
    fetchPage(state.page - 1);
  });

  btnNext?.addEventListener("click", () => {
    setLive(false);
    fetchPage(state.page + 1);
  });

  btnLiveToggle?.addEventListener("click", () => {
    setLive(!state.live);
    if (!state.live) fetchPage(1);
  });

  readFiltersFromUI();
  setLive(true);
}

function createRow(alert) {
  const tr = document.createElement("tr");
  tr.style.animation = "fadeIn 0.5s ease-out";

  const time = new Date(alert.timestamp).toLocaleTimeString();

  const mitigationCmd = alert.mitigation_command || alert.mitigation || "";
  let mitigationHTML = '<span style="color:#64748b; font-size:11px;">No Action</span>';
  if (mitigationCmd) {
    mitigationHTML = `<div class="mitigation-box"><i class="fa-solid fa-shield-halved"></i> ${mitigationCmd}</div>`;
  }

  let detailsHTML = `<div class="log-details">${alert.description || ""}</div>`;
  if (alert.ml_anomaly_score) {
    detailsHTML += `<div style="margin-top:4px; color:#c084fc; font-weight:700; font-size:11px">
                            <i class="fa-solid fa-brain"></i> AI Score: ${alert.ml_anomaly_score}
                        </div>`;
  }
  detailsHTML += `<div class="log-raw" title="${String(alert.raw_log || "").replaceAll('"', "&quot;")}">${alert.raw_log || ""}</div>`;

  tr.innerHTML = `
        <td class="font-mono">${time}</td>
        <td class="log-name">${alert.alert_name || ""}</td>
        <td><span class="severity-badge severity-${alert.severity}">${alert.severity || ""}</span></td>
        <td class="font-mono">${alert.mitre_attck_id || "-"}</td>
        <td>${detailsHTML}</td>
        <td>${mitigationHTML}</td>
    `;
  return tr;
}

// Helper function
function getColor(sev) {
  if (sev === "CRITICAL") return "#ef4444";
  if (sev === "HIGH") return "#f97316";
  return "#3b82f6";
}

function updateClock() {
  const el = document.getElementById("current-time");
  if (el) {
    setInterval(() => {
      el.innerText = new Date().toLocaleTimeString();
    }, 1000);
  }
}
