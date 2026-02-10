// --- GLOBAL CONFIG ---
const API_STATS = "/api/stats";
const API_ALERTS = "/api/alerts";
const API_ALERTS_SEARCH = "/api/alerts/search";
const API_GRAPH = "/api/graph";
const API_SETTINGS = "/api/settings";
const API_SETTINGS_UPDATE = "/api/settings/update";

document.addEventListener("DOMContentLoaded", () => {
  const path = window.location.pathname;
  updateClock();

  if (path === "/") initDashboard();
  else if (path === "/logs") initLogs();
  else if (path === "/settings") initSettings();
  else if (path === "/graph") initGraphPage();
});

// --- SETTINGS PAGE LOGIC ---
function initSettings() {
  const elStatus = document.getElementById("settings-save-status");

  const elNids = document.getElementById("set-nids-enabled");
  const elHp = document.getElementById("set-honeypot-enabled");

  const elGraphAuto = document.getElementById("set-graph-auto");
  const elGraphRefresh = document.getElementById("set-graph-refresh-ms");
  const elGraphMaxAlerts = document.getElementById("set-graph-max-alerts");
  const elGraphIncludeSources = document.getElementById("set-graph-include-sources");
  const elGraphIncludeCampaigns = document.getElementById("set-graph-include-campaigns");

  function setStatus(msg) {
    if (!elStatus) return;
    elStatus.textContent = msg || "";
  }

  function postPatch(patch) {
    setStatus("Saving...");
    return fetch(API_SETTINGS_UPDATE, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    })
      .then((r) => r.json())
      .then((res) => {
        setStatus(res?.ok ? "Saved." : "Save failed.");
        setTimeout(() => setStatus(""), 1200);
        return res;
      })
      .catch(() => setStatus("Save failed."));
  }

  function bindToggle(el, key) {
    if (!el) return;
    el.addEventListener("change", () => postPatch({ [key]: !!el.checked }));
  }

  function bindNumber(el, key, normalizeFn) {
    if (!el) return;
    el.addEventListener("change", () => {
      let v = parseInt(el.value, 10);
      if (!Number.isFinite(v)) return;
      if (normalizeFn) v = normalizeFn(v);
      el.value = String(v);
      postPatch({ [key]: v });
    });
  }

  fetch(API_SETTINGS, { cache: "no-store" })
    .then((r) => r.json())
    .then((s) => {
      if (elNids) elNids.checked = !!s.NIDS_ENABLED;
      if (elHp) elHp.checked = !!s.HONEYPOT_ENABLED;

      if (elGraphAuto) elGraphAuto.checked = !!s.GRAPH_AUTO_REFRESH;
      if (elGraphRefresh) elGraphRefresh.value = String(s.GRAPH_REFRESH_MS ?? 10000);
      if (elGraphMaxAlerts) elGraphMaxAlerts.value = String(s.GRAPH_MAX_ALERTS ?? 500);
      if (elGraphIncludeSources) elGraphIncludeSources.checked = !!s.GRAPH_INCLUDE_SOURCES;
      if (elGraphIncludeCampaigns) elGraphIncludeCampaigns.checked = !!s.GRAPH_INCLUDE_CAMPAIGNS;

      bindToggle(elNids, "NIDS_ENABLED");
      bindToggle(elHp, "HONEYPOT_ENABLED");

      bindToggle(elGraphAuto, "GRAPH_AUTO_REFRESH");
      bindToggle(elGraphIncludeSources, "GRAPH_INCLUDE_SOURCES");
      bindToggle(elGraphIncludeCampaigns, "GRAPH_INCLUDE_CAMPAIGNS");

      bindNumber(elGraphRefresh, "GRAPH_REFRESH_MS", (v) => Math.max(1000, v));
      bindNumber(elGraphMaxAlerts, "GRAPH_MAX_ALERTS", (v) => Math.max(50, v));
    })
    .catch(() => setStatus("Failed to load settings."));
}

// --- DASHBOARD LOGIC ---
function initDashboard() {
  let severityChart, sourceChart;
  let cy = null;

  let graphTimer = null;
  let graphRefreshMs = 10000;
  let graphAuto = true;
  let lastGraphSig = "";

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

  function ensureGraph() {
    const el = document.getElementById("contextGraph");
    if (!el) return null;
    if (cy) return cy;
    if (typeof cytoscape === "undefined") return null;

    cy = cytoscape({
      container: el,
      elements: [],
      minZoom: 0.35,
      maxZoom: 2.0,
      style: [
        // Base node
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-size": 10,
            color: "#e2e8f0",
            "text-outline-color": C.bg,
            "text-outline-width": 2,
            "text-wrap": "wrap",
            "text-max-width": 180,
            "background-color": C.muted,
            "border-width": 1,
            "border-color": hexToRgba(C.muted, 0.6),
            "shadow-blur": 10,
            "shadow-opacity": 0.25,
            "shadow-offset-x": 0,
            "shadow-offset-y": 6,
            width: "mapData(count, 1, 20, 20, 56)",
            height: "mapData(count, 1, 20, 20, 56)",
          },
        },

        // Primary entity nodes (use gradients for “SIEM-like” neon)
        {
          selector: 'node[type="ip"]',
          style: {
            shape: "ellipse",
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${C.red} ${C.orange}`,
            "border-color": hexToRgba(C.red, 0.8),
            "shadow-color": hexToRgba(C.red, 0.55),
          },
        },
        {
          selector: 'node[type="mitre"]',
          style: {
            shape: "round-rectangle",
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${C.orange} ${C.accentBlue}`,
            "border-color": hexToRgba(C.orange, 0.8),
            "shadow-color": hexToRgba(C.orange, 0.45),
          },
        },
        {
          selector: 'node[type="alert"]',
          style: {
            shape: "round-rectangle",
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${C.blue} ${C.purple}`,
            "border-color": hexToRgba(C.blue, 0.7),
            "shadow-color": hexToRgba(C.blue, 0.45),
          },
        },
        {
          selector: 'node[type="source"]',
          style: {
            shape: "hexagon",
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${C.accentBlue} ${C.blue}`,
            "border-color": hexToRgba(C.accentBlue, 0.7),
          },
        },
        {
          selector: 'node[type="campaign"]',
          style: {
            shape: "diamond",
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${C.purple} ${C.red}`,
            "border-color": hexToRgba(C.purple, 0.8),
            "shadow-color": hexToRgba(C.purple, 0.55),
          },
        },

        // Service nodes (group anchors)
        {
          selector: 'node[type="service"]',
          style: {
            shape: "round-rectangle",
            width: 110,
            height: 36,
            "font-size": 11,
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${hexToRgba(C.muted, 0.25)} ${hexToRgba(C.muted, 0.05)}`,
            "border-color": hexToRgba(C.muted, 0.5),
            "shadow-blur": 14,
            "shadow-opacity": 0.15,
            "shadow-color": hexToRgba(C.accentBlue, 0.35),
          },
        },

        // Event nodes hidden by default
        {
          selector: 'node[type="event"]',
          style: {
            display: "none",
            shape: "round-rectangle",
            width: 120,
            height: 26,
            label: "", // keep clean
            "font-size": 9,
            "text-max-width": 220,
            "background-color": hexToRgba(C.muted, 0.35),
            "border-color": hexToRgba(C.muted, 0.6),
            "shadow-blur": 0,
          },
        },
        { selector: 'node[type="event"].revealed', style: { display: "element" } },
        { selector: 'node[type="event"]:selected', style: { label: "data(label)" } },

        // Event type styling (no new colors; just mix existing palette)
        {
          selector: 'node[type="event"][event_type="ssh_failed"]',
          style: {
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${C.blue} ${C.red}`,
            "border-color": hexToRgba(C.blue, 0.7),
            "shadow-blur": 14,
            "shadow-opacity": 0.18,
            "shadow-color": hexToRgba(C.blue, 0.5),
          },
        },
        {
          selector: 'node[type="event"][event_type="ssh_success"]',
          style: {
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${C.accentBlue} ${C.blue}`,
            "border-color": hexToRgba(C.accentBlue, 0.7),
          },
        },
        {
          selector: 'node[type="event"][event_type^="web"]',
          style: {
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${C.orange} ${C.blue}`,
            "border-color": hexToRgba(C.orange, 0.7),
          },
        },
        {
          selector: 'node[type="event"][event_type="sudo"]',
          style: {
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${C.red} ${C.orange}`,
            "border-color": hexToRgba(C.red, 0.75),
          },
        },
        {
          selector: 'node[type="event"][event_type^="net"]',
          style: {
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${C.accentBlue} ${C.orange}`,
            "border-color": hexToRgba(C.accentBlue, 0.6),
          },
        },
        {
          selector: 'node[type="event"][event_type^="auth"]',
          style: {
            "background-fill": "linear-gradient",
            "background-gradient-stop-colors": `${C.purple} ${C.blue}`,
            "border-color": hexToRgba(C.purple, 0.65),
          },
        },

        // Base edge style: smoother & cleaner
        {
          selector: "edge",
          style: {
            width: "mapData(count, 1, 10, 1.1, 4)",
            "line-color": hexToRgba(C.muted, 0.28),
            "target-arrow-color": hexToRgba(C.muted, 0.35),
            "target-arrow-shape": "vee",
            "curve-style": "bezier",
            "control-point-step-size": 42,
            "line-cap": "round",
            label: "",
          },
        },
        {
          selector: "edge:selected",
          style: {
            label: "data(label)",
            "font-size": 9,
            color: "#cbd5e1",
            "text-background-color": C.bg,
            "text-background-opacity": 0.85,
            "text-background-padding": 2,
          },
        },

        // Edge by etype
        { selector: 'edge[etype="src_ip"]', style: { "line-color": hexToRgba(C.accentBlue, 0.32), "target-arrow-color": hexToRgba(C.accentBlue, 0.35) } },
        { selector: 'edge[etype="ip_mitre"]', style: { "line-color": hexToRgba(C.orange, 0.30), "target-arrow-color": hexToRgba(C.orange, 0.33) } },
        { selector: 'edge[etype="ip_alert"]', style: { "line-color": hexToRgba(C.blue, 0.30), "target-arrow-color": hexToRgba(C.blue, 0.33) } },
        { selector: 'edge[etype^="camp_"]', style: { "line-style": "dashed", "line-color": hexToRgba(C.purple, 0.33), "target-arrow-color": hexToRgba(C.purple, 0.36) } },

        // Hide event edges until revealed
        { selector: 'edge[etype="camp_event"]', style: { display: "none" } },
        { selector: 'edge[etype="camp_event"].revealed', style: { display: "element" } },

        { selector: 'edge[etype="svc_event"]', style: { display: "none", "line-style": "dotted", "target-arrow-shape": "none" } },
        { selector: 'edge[etype="svc_event"].revealed', style: { display: "element" } },

        { selector: "node:selected", style: { "border-width": 2, "border-color": "#eab308" } },
      ],
      layout: {
        name: "cose",
        animate: true,
        nodeRepulsion: 9000,
        idealEdgeLength: 90,
        edgeElasticity: 0.1,
        gravity: 0.15,
        numIter: 250,
      },
    });

    return cy;
  }

  function updateGraphOnce() {
    const g = ensureGraph();
    if (!g) return;

    fetch(API_GRAPH, { cache: "no-store" })
      .then((res) => res.json())
      .then((payload) => {
        const sig = JSON.stringify(payload || {});
        if (sig === lastGraphSig) return;
        lastGraphSig = sig;

        const elements = [...(payload.nodes || []), ...(payload.edges || [])];
        g.elements().remove();
        g.add(elements);
        g.layout(g.options().layout).run();
      })
      .catch(() => {});
  }

  function startGraphAutoRefresh() {
    if (graphTimer) clearInterval(graphTimer);
    if (!graphAuto) return;
    graphTimer = setInterval(updateGraphOnce, graphRefreshMs);
  }

  function loadGraphSettings() {
    fetch(API_SETTINGS, { cache: "no-store" })
      .then((r) => r.json())
      .then((s) => {
        graphAuto = !!s.GRAPH_AUTO_REFRESH;
        graphRefreshMs = Math.max(1000, parseInt(s.GRAPH_REFRESH_MS ?? 10000, 10));
        startGraphAutoRefresh();
      })
      .catch(() => startGraphAutoRefresh());
  }

  function updateDashboard() {
    fetch(API_STATS)
      .then((res) => res.json())
      .then((data) => {
        document.getElementById("val-critical").innerText = data.critical;
        document.getElementById("val-high").innerText = data.high;
        document.getElementById("val-ai").innerText = data.anomalies;
        document.getElementById("val-total").innerText = data.total;

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
              </tr>`;
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

  // Stats refresh stays frequent; graph refresh is separate
  setInterval(updateDashboard, 3000);
  updateDashboard();

  loadGraphSettings();

  cy.on('tap', 'node', function(evt){
    var node = evt.target;
    cy.elements().removeClass('faded');
    var neighborhood = node.neighborhood().add(node);
    cy.elements().not(neighborhood).addClass('faded');
  });

  cy.on('tap', function(evt){
    if( evt.target === cy ){
      cy.elements().removeClass('faded');
    }
  });
  updateGraphOnce();
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

  const src = alert.source_type || "HIDS_LOG";
  let detailsHTML = `<div class="log-details">${alert.description || ""}</div>`;
  detailsHTML += `<div class="muted" style="margin-top:4px; font-size:11px;">Source: ${src}</div>`;

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

function initGraphPage() {
  const el = document.getElementById("contextGraphFull");
  if (!el) return;
  if (typeof cytoscape === "undefined") return;

  const tooltip = document.getElementById("graph-tooltip");
  const btnRefresh = document.getElementById("btn-graph-refresh");
  const btnFit = document.getElementById("btn-graph-fit");

  let cy = cytoscape({
    container: el,
    elements: [],
    minZoom: 0.25,
    maxZoom: 2.5,
    style: [
      // Nodes
      {
        selector: "node",
        style: {
          label: "data(label)",
          "font-size": 11,
          "font-weight": "bold",
          color: "#e2e8f0",
          "text-valign": "bottom",
          "text-halign": "center",
          "text-margin-y": 6,            
          "text-background-color": "#020617", 
          "text-background-opacity": 0.8,
          "text-background-padding": 3,
          "text-background-shape": "roundrectangle",
          "border-width": 2,
          "border-color": "#ffffff",
          "border-opacity": 0.2,
          "background-color": "#64748b",
          width: "mapData(count, 1, 20, 25, 60)",
          height: "mapData(count, 1, 20, 25, 60)",
        },
      },
      { selector: 'node[type="ip"]', style: { "background-color": "#ef4444", shape: "ellipse" } },
      { selector: 'node[type="mitre"]', style: { "background-color": "#f97316", shape: "round-rectangle" } },
      { selector: 'node[type="alert"]', style: { "background-color": "#3b82f6", shape: "round-rectangle" } },
      { selector: 'node[type="source"]', style: { "background-color": "#22c55e", shape: "hexagon" } },
      { selector: 'node[type="campaign"]', style: { "background-color": "#a855f7", shape: "diamond" } },

      {
        selector: '.faded',
        style: {
          'opacity': 0.1,
          'text-opacity': 0
        }
      },

      // Event nodes hidden by default (to avoid clutter)
      { selector: 'node[type="event"]', style: { display: "none", "background-color": "#94a3b8", shape: "round-rectangle" } },
      { selector: 'node[type="event"].revealed', style: { display: "element" } },

      // Edges (default: clean, no labels)
      {
        selector: "edge",
        style: {
          width: 1.5,
          "line-color": "rgba(148, 163, 184, 0.55)",
          "target-arrow-color": "rgba(148, 163, 184, 0.65)",
          "target-arrow-shape": "vee",
          "curve-style": "bezier",
          "control-point-step-size": 48,
          "line-cap": "round",
          "opacity": 0.5,
          label: "",
        },
      },

      // Show edge label only when selected
      {
        selector: "edge:selected",
        style: {
          label: "data(label)",
          "font-size": 9,
          color: "#cbd5e1",
          "text-background-color": "#0b1220",
          "text-background-opacity": 0.9,
          "text-background-padding": 2,
        },
      },

      // Edge coloring by type
      { selector: 'edge[etype="src_ip"]', style: { "line-color": "rgba(34,197,94,0.35)", "target-arrow-color": "rgba(34,197,94,0.35)" } },
      { selector: 'edge[etype="ip_mitre"]', style: { "line-color": "rgba(249,115,22,0.35)", "target-arrow-color": "rgba(249,115,22,0.35)" } },
      { selector: 'edge[etype="ip_alert"]', style: { "line-color": "rgba(59,130,246,0.35)", "target-arrow-color": "rgba(59,130,246,0.35)" } },
      { selector: 'edge[etype^="camp_"]', style: { "line-style": "dashed", "line-color": "rgba(168,85,247,0.35)", "target-arrow-color": "rgba(168,85,247,0.35)" } },

      // Hide campaign->event edges until revealed
      { selector: 'edge[etype="camp_event"]', style: { display: "none" } },
      { selector: 'edge[etype="camp_event"].revealed', style: { display: "element" } },

      { selector: "node:selected", style: { "border-width": 2, "border-color": "#eab308" } },
    ],
    layout: {
      name: "cose",
      animate: true,
      animationDuration: 1000,
      nodeRepulsion: function(node){ return 200000; }, 
      idealEdgeLength: function(edge){ return 150; },
      edgeElasticity: function(edge){ return 32; },
      gravity: 0.1,
      numIter: 1000,
      padding: 50,
      clustering: true,
    },
  });

  function hideTooltip() {
    if (!tooltip) return;
    tooltip.style.display = "none";
  }

  function showTooltip(text, x, y) {
    if (!tooltip) return;
    tooltip.textContent = text || "";
    tooltip.style.left = `${x + 12}px`;
    tooltip.style.top = `${y + 12}px`;
    tooltip.style.display = "block";
  }

  function clearReveal() {
    cy.nodes('node[type="event"]').removeClass("revealed");
    cy.edges('edge[etype="camp_event"]').removeClass("revealed");
    cy.edges('edge[etype="svc_event"]').removeClass("revealed");
  }

  function revealCampaignEvents(campNode) {
    clearReveal();

    const evEdges = campNode.connectedEdges('edge[etype="camp_event"]');
    evEdges.addClass("revealed");

    const evNodes = evEdges.connectedNodes('node[type="event"]');
    evNodes.addClass("revealed");

    // Also reveal service->event edges for those events (grouping effect)
    evNodes.connectedEdges('edge[etype="svc_event"]').addClass("revealed");
  }

  cy.on("unselect", "node", () => {
    clearReveal();
    hideTooltip();
  });

  cy.on("select", 'node[type="campaign"]', (e) => {
    revealCampaignEvents(e.target);
  });

  cy.on("mouseover", "node", (e) => {
    const n = e.target;
    const raw = n.data("raw");
    const label = n.data("label") || n.id();

    const svc = n.data("service");
    const et = n.data("event_type");

    const head = svc || et ? `[${svc || "?"}/${et || "?"}] ` : "";
    const txt = raw ? head + raw : head + label;

    const rp = n.renderedPosition();
    showTooltip(txt, rp.x, rp.y);
  });
  cy.on("mouseout", "node", hideTooltip);

  let timer = null;
  let graphAuto = true;
  let graphRefreshMs = 10000;
  let lastSig = "";

  function schedule() {
    if (timer) clearInterval(timer);
    if (!graphAuto) return;
    timer = setInterval(fetchAndRender, graphRefreshMs);
  }

  function fetchSettings() {
    return fetch("/api/settings", { cache: "no-store" })
      .then((r) => r.json())
      .then((s) => {
        graphAuto = !!s.GRAPH_AUTO_REFRESH;
        graphRefreshMs = Math.max(1000, parseInt(s.GRAPH_REFRESH_MS ?? 10000, 10));
        schedule();
      })
      .catch(() => schedule());
  }

  function autoRevealTopCampaign() {
    const camps = cy.nodes('node[type="campaign"]');
    if (!camps || camps.length === 0) return;

    const top = camps.sort((a, b) => (b.data("count") || 0) - (a.data("count") || 0)).first();
    if (!top || top.empty()) return;

    top.select();                 // triggers revealCampaignEvents
    revealCampaignEvents(top);    // ensure reveal even if select event doesn't fire
    cy.fit(top.closedNeighborhood(), 60);
  }

  function fetchAndRender() {
    return fetch("/api/graph", { cache: "no-store" })
      .then((r) => r.json())
      .then((payload) => {
        const sig = JSON.stringify(payload || {});
        if (sig === lastSig) return;
        lastSig = sig;

        const elements = [...(payload.nodes || []), ...(payload.edges || [])];
        cy.elements().remove();
        cy.add(elements);

        clearReveal();
        cy.layout(cy.options().layout).run();
        autoRevealTopCampaign();
        if (cy.nodes('node[type="campaign"]').length === 0) {
          cy.fit(undefined, 30);
        }
      })
      .catch(() => {});
  }

  btnRefresh?.addEventListener("click", () => fetchAndRender());
  btnFit?.addEventListener("click", () => cy.fit(undefined, 30));

  fetchSettings().then(fetchAndRender);
}

const rootStyle = getComputedStyle(document.documentElement);
const C = {
  bg: rootStyle.getPropertyValue("--bg-body").trim() || "#0f172a",
  border: rootStyle.getPropertyValue("--border").trim() || "#334155",
  muted: rootStyle.getPropertyValue("--text-muted").trim() || "#94a3b8",
  red: rootStyle.getPropertyValue("--color-crit").trim() || "#ef4444",
  orange: rootStyle.getPropertyValue("--color-high").trim() || "#f97316",
  blue: rootStyle.getPropertyValue("--color-blue").trim() || "#3b82f6",
  purple: rootStyle.getPropertyValue("--color-ai").trim() || "#a855f7",
  accentBlue: rootStyle.getPropertyValue("--accent-blue").trim() || "#38bdf8",
};

function hexToRgba(hex, a) {
  const h = (hex || "").replace("#", "").trim();
  if (h.length !== 6) return `rgba(148,163,184,${a})`;
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${a})`;
}
