// --- GLOBAL CONFIG ---
const API_STATS = "/api/stats";
const API_ALERTS = "/api/alerts";
const API_ALERTS_SEARCH = "/api/alerts/search";
const API_DETECTION_COVERAGE = "/api/detection-coverage";
const API_GRAPH = "/api/graph";
const API_SETTINGS = "/api/settings";
const API_SETTINGS_UPDATE = "/api/settings/update";
const API_DETECTION_RULES = "/api/detection-rules";
const API_ASSETS = "/api/assets";
const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content || "";
const CURRENT_ROLE = document.querySelector('meta[name="current-role"]')?.content || "";

document.addEventListener("DOMContentLoaded", () => {
  const path = window.location.pathname;
  updateClock();

  if (path === "/") initDashboard();
  else if (path === "/logs") initLogs();
  else if (path === "/settings") initSettings();
  else if (path === "/assets") initAssets();
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
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF_TOKEN },
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
      if (elGraphRefresh) elGraphRefresh.value = String(s.GRAPH_REFRESH_MS ?? 15000);
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

  const ruleStatus = document.getElementById("rule-lifecycle-status");
  const ruleBody = document.getElementById("rule-lifecycle-body");

  function loadRules() {
    fetch(API_DETECTION_RULES, { cache: "no-store" })
      .then((r) => r.json())
      .then((data) => {
        const rules = data.rules || [];
        ruleStatus.textContent = `${rules.length} rules loaded`;
        ruleBody.innerHTML = rules.map((rule) => `
          <tr title="${escapeAttr(rule.skip_reason || "")}">
            <td><span class="font-mono">${escapeHTML(rule.rule_id)}</span><br>${escapeHTML(rule.title)}</td>
            <td>${escapeHTML(rule.rule_source.toUpperCase())}</td>
            <td>${escapeHTML(rule.validation_status)}</td>
            <td>${escapeHTML(rule.last_loaded_at || "-")}</td>
            <td>${rule.hit_count} · ${rule.never_hit ? "NEVER HIT" : "HIT"}</td>
            <td>${rule.enabled ? "ENABLED" : "DISABLED"}</td>
            <td>${rule.rule_source === "sigma" && rule.supported
              ? `<button class="btn btn-ghost sigma-rule-toggle" data-rule-id="${escapeAttr(rule.rule_id)}" data-enabled="${!rule.enabled}">${rule.enabled ? "Disable" : "Enable"}</button>`
              : "-"}</td>
          </tr>`).join("");
      })
      .catch(() => { ruleStatus.textContent = "Failed to load rules."; });
  }

  ruleBody?.addEventListener("click", (event) => {
    const button = event.target.closest(".sigma-rule-toggle");
    if (!button) return;
    button.disabled = true;
    fetch(`${API_DETECTION_RULES}/${encodeURIComponent(button.dataset.ruleId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF_TOKEN },
      body: JSON.stringify({ enabled: button.dataset.enabled === "true" }),
    })
      .then(async (r) => {
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || "Update failed");
        loadRules();
      })
      .catch((error) => { ruleStatus.textContent = error.message; button.disabled = false; });
  });
  loadRules();
}

// --- ASSET INVENTORY ---
function initAssets() {
  const tableBody = document.getElementById("asset-table-body");
  if (!tableBody) return;

  const status = document.getElementById("asset-status");
  const filters = document.getElementById("asset-filters");
  const filterQ = document.getElementById("asset-filter-q");
  const filterEnvironment = document.getElementById("asset-filter-environment");
  const filterCriticality = document.getElementById("asset-filter-criticality");
  const filterEnabled = document.getElementById("asset-filter-enabled");
  const dialog = document.getElementById("asset-dialog");
  const form = document.getElementById("asset-form");
  const formError = document.getElementById("asset-form-error");
  const saveButton = document.getElementById("asset-save");
  const fields = {
    id: document.getElementById("asset-id"),
    hostname: document.getElementById("asset-hostname"),
    ips: document.getElementById("asset-ips"),
    os: document.getElementById("asset-os"),
    owner: document.getElementById("asset-owner"),
    department: document.getElementById("asset-department"),
    environment: document.getElementById("asset-environment"),
    criticality: document.getElementById("asset-criticality"),
    tags: document.getElementById("asset-tags"),
    enabled: document.getElementById("asset-enabled"),
  };
  let assets = new Map();
  filterQ.value = new URLSearchParams(window.location.search).get("q")?.slice(0, 200) || "";

  const splitList = (value) => value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean);

  function queryString() {
    const query = new URLSearchParams();
    if (filterQ.value.trim()) query.set("q", filterQ.value.trim());
    if (filterEnvironment.value) query.set("environment", filterEnvironment.value);
    if (filterCriticality.value) query.set("criticality", filterCriticality.value);
    if (filterEnabled.value) query.set("enabled", filterEnabled.value);
    return query.toString();
  }

  function render(items) {
    assets = new Map(items.map((asset) => [asset.asset_id, asset]));
    status.textContent = `${items.length} asset${items.length === 1 ? "" : "s"}`;
    if (!items.length) {
      tableBody.innerHTML = '<tr><td colspan="7" class="muted">No assets match the current filters.</td></tr>';
      return;
    }
    tableBody.innerHTML = items.map((asset) => `
      <tr>
        <td><strong>${escapeHTML(asset.hostname)}</strong><div class="asset-secondary font-mono">${escapeHTML(asset.asset_id)}</div></td>
        <td>${asset.ip_addresses.length ? asset.ip_addresses.map(escapeHTML).join("<br>") : '<span class="muted">None</span>'}</td>
        <td><span class="severity-badge severity-${escapeAttr(asset.criticality)}">${escapeHTML(asset.criticality)}</span><div class="asset-secondary">${escapeHTML(asset.environment.toUpperCase())} · ${escapeHTML(asset.os || "Unknown OS")}</div></td>
        <td>${escapeHTML(asset.owner || "Unassigned")}<div class="asset-secondary">${escapeHTML(asset.department || "No department")}</div></td>
        <td>${asset.tags.length ? asset.tags.map((tag) => `<span class="ai-tag">${escapeHTML(tag)}</span>`).join(" ") : '<span class="muted">None</span>'}</td>
        <td>${asset.enabled ? "ENABLED" : "DISABLED"}</td>
        <td><div class="asset-table-actions">
          <button class="btn btn-ghost asset-edit" type="button" data-asset-id="${escapeAttr(asset.asset_id)}">Edit</button>
          <button class="btn btn-ghost asset-delete" type="button" data-asset-id="${escapeAttr(asset.asset_id)}">Delete</button>
        </div></td>
      </tr>`).join("");
  }

  async function loadAssets() {
    status.textContent = "Loading assets...";
    try {
      const response = await fetch(`${API_ASSETS}?${queryString()}`, { cache: "no-store" });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Failed to load assets");
      render(data.assets || []);
    } catch (error) {
      status.textContent = error.message || "Failed to load assets.";
    }
  }

  function openForm(asset) {
    form.reset();
    formError.textContent = "";
    fields.id.value = asset?.asset_id || "";
    fields.hostname.value = asset?.hostname || "";
    fields.ips.value = (asset?.ip_addresses || []).join("\n");
    fields.os.value = asset?.os || "";
    fields.owner.value = asset?.owner || "";
    fields.department.value = asset?.department || "";
    fields.environment.value = asset?.environment || "dev";
    fields.criticality.value = asset?.criticality || "MEDIUM";
    fields.tags.value = (asset?.tags || []).join(", ");
    fields.enabled.checked = asset?.enabled ?? true;
    document.getElementById("asset-dialog-title").textContent = asset ? "Edit asset" : "Add asset";
    dialog.showModal();
    fields.hostname.focus();
  }

  document.getElementById("asset-add").addEventListener("click", () => openForm(null));
  document.getElementById("asset-dialog-close").addEventListener("click", () => dialog.close());
  document.getElementById("asset-cancel").addEventListener("click", () => dialog.close());

  filters.addEventListener("submit", (event) => {
    event.preventDefault();
    loadAssets();
  });
  document.getElementById("asset-filter-clear").addEventListener("click", () => {
    filters.reset();
    loadAssets();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    formError.textContent = "";
    saveButton.disabled = true;
    const assetId = fields.id.value;
    const body = {
      hostname: fields.hostname.value,
      ip_addresses: splitList(fields.ips.value),
      os: fields.os.value,
      owner: fields.owner.value,
      department: fields.department.value,
      environment: fields.environment.value,
      criticality: fields.criticality.value,
      tags: splitList(fields.tags.value),
      enabled: fields.enabled.checked,
    };
    try {
      const response = await fetch(assetId ? `${API_ASSETS}/${encodeURIComponent(assetId)}` : API_ASSETS, {
        method: assetId ? "PATCH" : "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF_TOKEN },
        body: JSON.stringify(body),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Asset save failed");
      dialog.close();
      await loadAssets();
    } catch (error) {
      formError.textContent = error.message || "Asset save failed";
    } finally {
      saveButton.disabled = false;
    }
  });

  tableBody.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-asset-id]");
    if (!button) return;
    const asset = assets.get(button.dataset.assetId);
    if (!asset) return;
    if (button.classList.contains("asset-edit")) {
      openForm(asset);
      return;
    }
    if (!window.confirm(`Delete asset ${asset.hostname}?`)) return;
    button.disabled = true;
    try {
      const response = await fetch(`${API_ASSETS}/${encodeURIComponent(asset.asset_id)}`, {
        method: "DELETE",
        headers: { "X-CSRF-Token": CSRF_TOKEN },
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Asset delete failed");
      }
      await loadAssets();
    } catch (error) {
      status.textContent = error.message || "Asset delete failed";
      button.disabled = false;
    }
  });

  loadAssets();
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
      labels: ["CRITICAL", "HIGH", "MEDIUM", "LOW / INFO"],
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
                <td style="font-weight:bold">${escapeHTML(alert.alert_name || "")}</td>
                <td class="font-mono">${escapeHTML(alert.rule_id || "-")}</td>
                <td><span style="color:${getColor(alert.severity)}">${escapeHTML(alert.severity || "")}</span></td>
                <td>${escapeHTML(alert.ip_address || "N/A")}</td>
                <td>${renderAssetReference(alert.asset_id)}</td>
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

    fetch(API_DETECTION_COVERAGE)
      .then((res) => res.json())
      .then((data) => {
        const summary = data.summary || {};
        document.getElementById("coverage-summary").innerText =
          `${summary.rules_hit || 0}/${summary.rules_total || 0} rules hit · ` +
          `${summary.mitre_techniques_hit || 0}/${summary.mitre_techniques_total || 0} MITRE techniques`;
        document.getElementById("coverage-table-body").innerHTML = (data.rules || [])
          .map((rule) => `
            <tr>
              <td class="font-mono">${escapeHTML(rule.rule_id)}</td>
              <td>${escapeHTML(rule.title)}</td>
              <td>${escapeHTML(rule.rule_source.toUpperCase())}</td>
              <td class="font-mono">${escapeHTML(rule.mitre_technique)}</td>
              <td>${rule.hit_count}</td>
              <td style="color:${rule.triggered ? "#22c55e" : "#ef4444"}">
                ${rule.triggered ? "HIT" : "NEVER HIT"}
              </td>
            </tr>`)
          .join("");
      });
  }

  // Stats refresh stays frequent; graph refresh is separate
  setInterval(updateDashboard, 3000);
  updateDashboard();

  loadGraphSettings();

  const g = ensureGraph();
  if (g) {
    g.on("tap", "node", function (evt) {
      const node = evt.target;
      g.elements().removeClass("faded");
      const neighborhood = node.neighborhood().add(node);
      g.elements().not(neighborhood).addClass("faded");
    });

    g.on("tap", function (evt) {
      if (evt.target === g) {
        g.elements().removeClass("faded");
      }
    });
  }

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
  const inpIncidentStatus = document.getElementById("filter-incident-status");
  const inpAiDisposition = document.getElementById("filter-ai-disposition");
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
    incidentStatus: "",
    aiDisposition: "",
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
    state.incidentStatus = (inpIncidentStatus?.value || "").trim();
    state.aiDisposition = (inpAiDisposition?.value || "").trim();
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
    if (state.incidentStatus) params.set("incident_status", state.incidentStatus);
    if (state.aiDisposition) params.set("ai_disposition", state.aiDisposition);
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
    if (inpIncidentStatus) inpIncidentStatus.value = "";
    if (inpAiDisposition) inpAiDisposition.value = "";
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

  tableBody.addEventListener("focusin", () => setLive(false));

  readFiltersFromUI();
  setLive(true);
}

function createRow(alert) {
  const tr = document.createElement("tr");
  tr.style.animation = "fadeIn 0.5s ease-out";

  const time = new Date(alert.timestamp).toLocaleTimeString();

  const responseActions = alert.response_actions || [];
  const responseAction = responseActions[responseActions.length - 1];
  let responseHTML = '<span style="color:#64748b; font-size:11px;">No Action</span>';
  if (responseAction) {
    responseHTML = `<div class="mitigation-box"><i class="fa-solid fa-shield-halved"></i> ` +
      `${escapeHTML(responseAction.action_type)} ${escapeHTML(responseAction.target)} ` +
      `[${escapeHTML(responseAction.status)} · ${escapeHTML(responseAction.mode)}]` +
      `${responseAction.result || responseAction.error ? `<br><small>${escapeHTML(responseAction.result || responseAction.error)}</small>` : ""}</div>`;
  }

  const src = alert.source_type || "HIDS_LOG";
  let detailsHTML = `<div class="log-details">${escapeHTML(alert.description || "")}</div>`;
  detailsHTML += `<div class="muted" style="margin-top:4px; font-size:11px;">Source: ${escapeHTML(src)}</div>`;
  if (alert.rule_id) {
    detailsHTML += `<div class="muted" style="margin-top:4px; font-size:11px;">Rule: ${escapeHTML(alert.rule_id)}</div>`;
  }
  if (alert.assigned_to) {
    detailsHTML += `<div class="muted" style="margin-top:4px; font-size:11px;">Assigned to: ${escapeHTML(alert.assigned_to)}</div>`;
  }
  if (alert.asset_id) {
    detailsHTML += `<div class="muted" style="margin-top:4px; font-size:11px;">Asset: ${renderAssetReference(alert.asset_id)}</div>`;
  }

  if (alert.ml_anomaly_score) {
    detailsHTML += `<div style="margin-top:4px; color:#c084fc; font-weight:700; font-size:11px">
                            <i class="fa-solid fa-brain"></i> AI Score: ${escapeHTML(alert.ml_anomaly_score)}
                        </div>`;
  }
  detailsHTML += renderThreatIntelligence(alert);
  detailsHTML += renderAIAnalysis(alert);
  detailsHTML += `<div class="log-raw" title="${escapeAttr(alert.raw_log || "")}">${escapeHTML(alert.raw_log || "")}</div>`;
  detailsHTML += renderIncidentPanel(alert);

  tr.innerHTML = `
        <td class="font-mono">${time}</td>
        <td class="log-name">${escapeHTML(alert.alert_name || "")}</td>
        <td><span class="severity-badge severity-${escapeHTML(alert.severity || "")}">${escapeHTML(alert.severity || "")}</span></td>
        <td class="font-mono">${escapeHTML(alert.mitre_attck_id || "-")}</td>
        <td>${detailsHTML}</td>
        <td>${responseHTML}</td>
    `;
  bindIncidentActions(tr, alert);
  return tr;
}

function renderThreatIntelligence(alert) {
  const intel = alert.threat_intel || {};
  const legacyGeoIP = alert.geoip ? {
    ...(alert.geoip_lookup || {}),
    provider: "ipwhois",
    status: alert.geoip_lookup?.status || "ok",
    ioc_type: "ip",
    ioc: alert.ip_address,
  } : null;
  const entries = ["ipwhois", "abuseipdb", "virustotal", "stix"]
    .map((provider) => intel[provider] || (provider === "ipwhois" ? legacyGeoIP : null))
    .filter(Boolean);
  if (!entries.length) return "";

  const observed = [...new Map(entries.map((entry) => [
    `${entry.ioc_type}:${entry.ioc}`,
    `<span><strong>${escapeHTML((entry.ioc_type || "ioc").toUpperCase())}</strong> ${escapeHTML(entry.ioc || "N/A")}</span>`,
  ])).values()].join("");
  const cards = entries.map((entry) => renderThreatIntelProvider(entry, alert)).join("");
  return `
    <section class="threat-intel-panel" aria-label="Threat Intelligence">
      <div class="threat-intel-title"><i class="fa-solid fa-shield-virus"></i> Threat Intelligence</div>
      <div class="threat-intel-observed"><strong>Observed IOC</strong>${observed}</div>
      <div class="threat-intel-note">Third-party intelligence only · system severity unchanged</div>
      <div class="threat-intel-grid">${cards}</div>
    </section>`;
}

function renderThreatIntelProvider(entry, alert) {
  const provider = entry.provider || "unknown";
  const label = { ipwhois: "GeoIP", abuseipdb: "AbuseIPDB", virustotal: "VirusTotal", stix: "STIX/TAXII" }[provider] || provider;
  const status = entry.status || "unavailable";
  let body = "";
  if (status === "pending") {
    body = '<span class="ti-state ti-pending"><i class="fa-solid fa-spinner fa-spin"></i> Lookup pending</span>';
  } else if (status === "unavailable") {
    body = '<span class="ti-state"><i class="fa-solid fa-plug-circle-xmark"></i> Provider unavailable</span>';
  } else if (status === "error" || status === "timeout") {
    body = `<span class="ti-state ti-error"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHTML(entry.error?.message || "Lookup failed")}</span>`;
  } else if (status === "not_found") {
    body = '<span class="ti-state"><i class="fa-solid fa-circle-question"></i> No matching intelligence</span>';
  } else if (provider === "ipwhois") {
    const geo = alert.geoip || {};
    const place = geo.is_private
      ? "Private/local address"
      : [geo.city, geo.country].filter(Boolean).join(", ") || "Unknown location";
    const network = [geo.asn ? `AS${String(geo.asn).replace(/^AS/i, "")}` : null, geo.organization]
      .filter(Boolean).join(" · ");
    body = `<strong>${escapeHTML(place)}</strong>${network ? `<span>${escapeHTML(network)}</span>` : ""}`;
  } else if (provider === "abuseipdb") {
    body = `<strong>${escapeHTML(entry.abuse_confidence ?? 0)}% abuse confidence</strong>` +
      `<span>${escapeHTML(entry.total_reports ?? 0)} reports${entry.usage_type ? ` · ${escapeHTML(entry.usage_type)}` : ""}</span>`;
  } else if (provider === "virustotal") {
    const total = ["malicious", "suspicious", "harmless", "undetected"]
      .reduce((sum, key) => sum + Number(entry[key] || 0), 0);
    body = `<strong>${escapeHTML(entry.malicious ?? 0)} malicious · ${escapeHTML(entry.suspicious ?? 0)} suspicious</strong>` +
      `<span>${escapeHTML(total)} engines reported</span>`;
  } else if (provider === "stix") {
    const sources = Array.isArray(entry.sources) ? entry.sources : [];
    const labels = Array.isArray(entry.labels) ? entry.labels : [];
    body = `<strong>${escapeHTML(entry.match_count ?? 1)} active feed match${Number(entry.match_count) === 1 ? "" : "es"}</strong>` +
      `<span>Source: ${escapeHTML(sources.join(", ") || "unknown")}</span>` +
      (entry.confidence == null ? "" : `<span>${escapeHTML(entry.confidence)}% confidence</span>`) +
      (labels.length ? `<span>${escapeHTML(labels.join(", "))}</span>` : "");
  }
  const meta = [
    Number.isFinite(Number(entry.duration_ms)) ? `${escapeHTML(entry.duration_ms)} ms` : null,
    entry.cached === true ? "Cache hit" : entry.cached === false ? "Live lookup" : null,
  ].filter(Boolean).join(" · ");
  return `<article class="threat-intel-card ti-${escapeAttr(status)}">
    <div class="threat-intel-provider"><strong>${escapeHTML(label)}</strong><span>${escapeHTML(provider)}</span></div>
    <div class="threat-intel-body">${body}</div>
    ${meta ? `<div class="threat-intel-meta">${meta}</div>` : ""}
  </article>`;
}

function renderIncidentPanel(alert) {
  if (!alert.incident_id) return "";
  const canMutate = ["analyst", "admin"].includes(CURRENT_ROLE);

  const statuses = ["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"];
  const statusButtons = canMutate ? statuses.map((status) => `
    <button class="btn btn-ghost incident-status-btn" type="button" data-status="${status}"
      ${status === alert.incident_status ? "disabled" : ""}>${status}</button>`).join("") : "";
  const notes = (alert.analyst_notes || []).slice(-5).reverse().map((note) => `
    <li><strong>${escapeHTML(note.author || "analyst")}</strong>: ${escapeHTML(note.text || "")}</li>`).join("");
  const timelineEvents = [
    { event_type: "CREATED", timestamp: alert.created_at || alert.timestamp },
    ...(alert.timeline || []),
  ];
  const timeline = timelineEvents.slice(-8).reverse().map((event) => `
    <li>${escapeHTML(event.timestamp || "")} · ${escapeHTML(event.event_type || "UPDATED")}` +
      `${event.action_type ? ` · ${escapeHTML(event.action_type)} ${escapeHTML(event.target || "")} [${escapeHTML(event.status || "")}]` : ""}</li>`).join("");
  const responseActionOptions = [
    "BLOCK_IP", "UNBLOCK_IP", "DISABLE_USER", "KILL_PROCESS", "QUARANTINE_FILE", "NOTIFY_ANALYST",
  ].map((type) => `<option value="${type}">${type}</option>`).join("");
  const pendingAction = [...(alert.response_actions || [])].reverse().find(
    (action) => ["PROPOSED", "REQUIRES_APPROVAL"].includes(action.status),
  );
  const simulatedAction = [...(alert.response_actions || [])].reverse().find(
    (action) => action.status === "SIMULATED",
  );
  const responseWorkflow = !canMutate ? "" : pendingAction
    ? `<button class="btn btn-primary incident-approve-btn" type="button" data-action-id="${escapeAttr(pendingAction.action_id)}">Approve action</button>`
    : simulatedAction
      ? `<button class="btn btn-ghost incident-rollback-btn" type="button" data-action-id="${escapeAttr(simulatedAction.action_id)}">Roll back simulation</button>`
      : "";

  return `
    <section class="incident-panel" aria-label="Incident ${escapeAttr(alert.incident_id)}">
      <div class="incident-heading">
        <strong>${escapeHTML(alert.incident_id)}</strong>
        <span class="incident-status">${escapeHTML(alert.incident_status || "NEW")}</span>
      </div>
      ${canMutate ? `<div class="incident-actions">${statusButtons}</div>
      <div class="incident-form-row">
        <input class="styled-input incident-assignee" maxlength="100" aria-label="Assignee"
          value="${escapeAttr(alert.assigned_to || "")}" placeholder="Assignee">
        <button class="btn btn-primary incident-assign-btn" type="button">Assign</button>
      </div>
      <div class="incident-form-row">
        <textarea class="styled-input incident-note" maxlength="2000" aria-label="Analyst note"
          placeholder="Add analyst note"></textarea>
        <button class="btn btn-primary incident-note-btn" type="button">Add note</button>
      </div>
      <div class="incident-form-row">
        <select class="styled-input incident-action-type" aria-label="Response action">${responseActionOptions}</select>
        <input class="styled-input incident-action-target" maxlength="500" aria-label="Response target"
          value="${escapeAttr(alert.ip_address || alert.incident_id)}" placeholder="Target">
        <button class="btn btn-primary incident-response-btn" type="button">Request action</button>
      </div>` : ""}
      ${responseWorkflow ? `<div class="incident-actions">${responseWorkflow}</div>` : ""}
      ${notes ? `<div class="incident-history"><strong>Notes</strong><ul>${notes}</ul></div>` : ""}
      ${timeline ? `<div class="incident-history"><strong>Timeline</strong><ul>${timeline}</ul></div>` : ""}
      <div class="incident-error" role="alert"></div>
    </section>`;
}

function bindIncidentActions(row, alert) {
  if (!alert.incident_id) return;
  const url = `/api/alerts/${encodeURIComponent(alert.alert_id)}`;
  row.querySelectorAll(".incident-status-btn").forEach((button) => {
    button.addEventListener("click", () => mutateIncident(
      row, button, `${url}/status`, "PATCH", { status: button.dataset.status },
    ));
  });
  row.querySelector(".incident-assign-btn")?.addEventListener("click", (event) => mutateIncident(
    row,
    event.currentTarget,
    `${url}/assignee`,
    "PATCH",
    { assigned_to: row.querySelector(".incident-assignee").value },
  ));
  row.querySelector(".incident-note-btn")?.addEventListener("click", (event) => mutateIncident(
    row,
    event.currentTarget,
    `${url}/notes`,
    "POST",
    { note: row.querySelector(".incident-note").value },
  ));
  row.querySelector(".incident-response-btn")?.addEventListener("click", (event) => mutateIncident(
    row,
    event.currentTarget,
    `${url}/response-actions`,
    "POST",
    {
      action_type: row.querySelector(".incident-action-type").value,
      target: row.querySelector(".incident-action-target").value,
    },
  ));
  row.querySelector(".incident-approve-btn")?.addEventListener("click", (event) => mutateIncident(
    row,
    event.currentTarget,
    `${url}/response-actions/${encodeURIComponent(event.currentTarget.dataset.actionId)}/approve`,
    "POST",
    { analyst: "analyst" },
  ));
  row.querySelector(".incident-rollback-btn")?.addEventListener("click", (event) => mutateIncident(
    row,
    event.currentTarget,
    `${url}/response-actions/${encodeURIComponent(event.currentTarget.dataset.actionId)}/rollback`,
    "POST",
    { analyst: "analyst" },
  ));
}

async function mutateIncident(row, button, url, method, body) {
  const error = row.querySelector(".incident-error");
  error.textContent = "";
  button.disabled = true;
  try {
    const response = await fetch(url, {
      method,
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF_TOKEN },
      body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status})`);
    row.replaceWith(createRow(result));
  } catch (requestError) {
    error.textContent = requestError.message || "Incident update failed";
    button.disabled = false;
  }
}

function renderAIAnalysis(alert) {
  const ai = alert.ai_analysis;
  if (!ai) {
    return ["HIGH", "CRITICAL"].includes(alert.severity)
      ? '<div class="ai-pending"><i class="fa-solid fa-clock"></i> AI analysis pending...</div>'
      : "";
  }
  if (ai.skipped) {
    return `<div class="ai-pending"><i class="fa-solid fa-forward"></i> AI analysis skipped: ${escapeHTML(ai.skipped)}</div>`;
  }
  if (ai.error) {
    return `<div class="incident-error"><i class="fa-solid fa-triangle-exclamation"></i> AI analysis failed: ${escapeHTML(ai.error)}</div>`;
  }

  const playbook = Array.isArray(ai.recommended_playbook)
    ? ai.recommended_playbook.map((step) => `<li>${escapeHTML(step)}</li>`).join("")
    : "";
  const iocs = Array.isArray(ai.ioc_tags)
    ? ai.ioc_tags.map((tag) => `<span class="ai-tag">${escapeHTML(tag)}</span>`).join("")
    : "";
  const aiRecommendation = alert.ai_recommended_severity || alert.severity || "UNKNOWN";
  const aiDecision = alert.ai_disposition === "FALSE_POSITIVE_SUSPECTED"
    ? "False positive suspected"
    : ai.escalate_to_human
      ? "Human review required"
      : "No AI escalation";

  return `
    <div class="ai-analysis">
      <div class="ai-title"><i class="fa-solid fa-brain"></i> AI Analyst</div>
      <div class="ai-severity-row">
        <span>System severity <strong>${escapeHTML(alert.severity || "UNKNOWN")}</strong></span>
        <span>AI recommendation <strong>${escapeHTML(aiRecommendation)}</strong></span>
        <span>Decision <strong>${escapeHTML(aiDecision)}</strong></span>
      </div>
      <div class="ai-metrics">
        <span>Threat <strong>${escapeHTML(ai.threat_confidence ?? 0)}%</strong></span>
        <span>FP <strong>${escapeHTML(ai.fp_confidence ?? 0)}%</strong></span>
        <span>Human review <strong>${ai.escalate_to_human ? "Required" : "Not required"}</strong></span>
      </div>
      <div class="ai-field"><strong>Tactic:</strong> ${escapeHTML(ai.mitre_tactic || "N/A")}</div>
      <div class="ai-field"><strong>Technique:</strong> ${escapeHTML(ai.mitre_technique || "N/A")}</div>
      <div class="ai-field"><strong>Summary:</strong> ${escapeHTML(ai.threat_summary || "No summary")}</div>
      ${playbook ? `<ol class="ai-playbook">${playbook}</ol>` : ""}
      ${iocs ? `<div class="ai-iocs"><strong>IOCs:</strong> ${iocs}</div>` : ""}
      <div class="ai-provider">${escapeHTML(ai.provider || "unknown")} / ${escapeHTML(ai.model || "unknown")}</div>
    </div>`;
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function escapeAttr(value) {
  return escapeHTML(value).replaceAll("\n", " ");
}

function renderAssetReference(assetId) {
  if (!assetId) return "-";
  const label = escapeHTML(assetId);
  if (CURRENT_ROLE !== "admin") return label;
  return `<a href="/assets?q=${encodeURIComponent(assetId)}">${label}</a>`;
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

window.hasFitGraph = false;
function initGraphPage() {
  const el = document.getElementById("contextGraphFull");
  if (!el) return;
  if (typeof ForceGraph === "undefined") { setTimeout(initGraphPage, 200); return; }

  const tooltip    = document.getElementById("graph-tooltip");
  const btnRefresh = document.getElementById("btn-graph-refresh");
  const btnFit     = document.getElementById("btn-graph-fit");

  // ── Colour palette ─────────────────────────────────────────────────────────
  const NODE_CORE = { ip:"#ef4444", mitre:"#f97316", alert:"#3b82f6", source:"#22c55e", campaign:"#a855f7", event:"#475569" };
  const NODE_GLOW = { ip:"#f87171", mitre:"#fb923c", alert:"#60a5fa", source:"#4ade80", campaign:"#c084fc", event:"#64748b" };
  const LINK_CLR  = { src_ip:"rgba(34,197,94,0.6)", ip_mitre:"rgba(249,115,22,0.6)", ip_alert:"rgba(59,130,246,0.6)", svc_event:"rgba(148,163,184,0.35)", camp_event:"rgba(168,85,247,0.45)" };
  const PART_CLR  = { src_ip:"rgba(74,222,128,1)", ip_mitre:"rgba(251,146,60,1)", ip_alert:"rgba(96,165,250,1)" };

  // ── State ──────────────────────────────────────────────────────────────────
  // _src/_tgt: internal field names to prevent force-graph mutation corruption
  let rawNodes     = [];
  let rawEdgeStore = [];   // { _id, _src, _tgt, etype, count }
  let revealedCamp = null;
  let lastSig      = "";
  let graphAuto    = true;
  let graphRefreshMs = 10000;
  let timer        = null;
  let didFit       = false;

  function toRgb(hex) {
    const h = hex.replace("#","");
    return [parseInt(h.slice(0,2),16), parseInt(h.slice(2,4),16), parseInt(h.slice(4,6),16)];
  }

  // ── Node painter ───────────────────────────────────────────────────────────
  function paintNode(node, ctx, gs) {
    const t   = node.type || "event";
    const col = NODE_CORE[t] || "#64748b";
    const glw = NODE_GLOW[t] || "#94a3b8";
    const [cr,cg,cb] = toRgb(col);
    const [gr,gg,gb] = toRgb(glw);
    const sel = !!node.__selected;
    const r   = Math.max(5, Math.min(20, 5 + Math.sqrt(node.count||1) * 2.2));

    // Outer glow
    const gR  = r*(sel?5:3.5);
    const grd = ctx.createRadialGradient(node.x,node.y,0,node.x,node.y,gR);
    grd.addColorStop(0,  `rgba(${gr},${gg},${gb},${sel?.5:.28})`);
    grd.addColorStop(.5, `rgba(${gr},${gg},${gb},${sel?.12:.05})`);
    grd.addColorStop(1,  `rgba(${gr},${gg},${gb},0)`);
    ctx.beginPath(); ctx.arc(node.x,node.y,gR,0,Math.PI*2);
    ctx.fillStyle=grd; ctx.fill();

    // Shape
    ctx.save(); ctx.beginPath();
    if (t==="campaign") {
      const s=r*1.5; ctx.translate(node.x,node.y); ctx.rotate(Math.PI/4);
      ctx.roundRect(-s/2,-s/2,s,s,s*.15);
    } else if (t==="mitre"||t==="alert") {
      const w=r*2.6,h=r*1.45; ctx.roundRect(node.x-w/2,node.y-h/2,w,h,h/2);
    } else if (t==="source") {
      for(let i=0;i<6;i++){const a=(Math.PI/3)*i-Math.PI/6;i===0?ctx.moveTo(node.x+r*1.15*Math.cos(a),node.y+r*1.15*Math.sin(a)):ctx.lineTo(node.x+r*1.15*Math.cos(a),node.y+r*1.15*Math.sin(a));}
      ctx.closePath();
    } else {
      ctx.arc(node.x,node.y,r,0,Math.PI*2);
    }
    const fill=ctx.createRadialGradient(node.x-r*.25,node.y-r*.25,r*.05,node.x,node.y,r*1.15);
    fill.addColorStop(0,"rgba(255,255,255,.30)");
    fill.addColorStop(.45,`rgba(${cr},${cg},${cb},1)`);
    fill.addColorStop(1,`rgba(${cr},${cg},${cb},.65)`);
    ctx.fillStyle=fill; ctx.fill();
    ctx.strokeStyle=`rgba(255,255,255,${sel?.55:.15})`; ctx.lineWidth=(sel?2:.8)/gs; ctx.stroke();
    ctx.restore();

    // Selection ring
    if (sel) { ctx.beginPath(); ctx.arc(node.x,node.y,r+4/gs,0,Math.PI*2); ctx.strokeStyle="#fbbf24"; ctx.lineWidth=1.8/gs; ctx.stroke(); }

    // Label
    if (gs>.5||sel||t==="ip"||t==="campaign") {
      const raw=node.label||node.id||"";
      const txt=raw.length>28?raw.slice(0,27)+"…":raw;
      const fs=Math.max(9,11/gs);
      ctx.font=`500 ${fs}px "Inter",sans-serif`; ctx.textAlign="center"; ctx.textBaseline="top";
      const tw=ctx.measureText(txt).width, ty=node.y+r+5/gs, pad=3.5/gs;
      ctx.fillStyle="rgba(2,6,23,.80)"; ctx.beginPath();
      ctx.roundRect(node.x-tw/2-pad,ty-pad*.4,tw+pad*2,fs+pad*1.2,3/gs); ctx.fill();
      ctx.fillStyle=sel?"#fef9c3":"rgba(226,232,240,.90)"; ctx.fillText(txt,node.x,ty);
    }
  }

  function paintPointer(node,color,ctx) {
    const r=Math.max(5,Math.min(20,5+Math.sqrt(node.count||1)*2.2))*2;
    ctx.beginPath(); ctx.arc(node.x,node.y,r,0,Math.PI*2); ctx.fillStyle=color; ctx.fill();
  }

  // ── ForceGraph ─────────────────────────────────────────────────────────────
  const Graph = ForceGraph()(el)
    .backgroundColor("transparent")
    .nodeId("id")
    .nodeLabel(()=>"")
    .linkSource("source")
    .linkTarget("target")
    .linkWidth(l => Math.max(0.8, (l.count||1)*0.35))
    .linkColor(l => LINK_CLR[l.etype] || "rgba(148,163,184,0.40)")
    .linkLineDash(l => l.etype==="camp_event" ? [4,4] : null)
    .linkDirectionalParticles(l => ["src_ip","ip_mitre","ip_alert"].includes(l.etype) ? 4 : 0)
    .linkDirectionalParticleSpeed(0.005)
    .linkDirectionalParticleWidth(2.5)
    .linkDirectionalParticleColor(l => PART_CLR[l.etype]||"rgba(192,132,252,1)")
    .nodeCanvasObject(paintNode)
    .nodeCanvasObjectMode(()=>"replace")
    .nodePointerAreaPaint(paintPointer)
    .onEngineStop(() => { if(!didFit){ Graph.zoomToFit(700,70); didFit=true; } })
    .onNodeClick(node => {
      rawNodes.forEach(n => { n.__selected=(n.id===node.id); });
      if (node.type==="campaign") {
        revealedCamp = revealedCamp===node.id ? null : node.id;
        rebuildGraph();
      } else { Graph.refresh(); }
    })
    .onBackgroundClick(() => {
      rawNodes.forEach(n => { n.__selected=false; });
      if (revealedCamp!==null) { revealedCamp=null; rebuildGraph(); }
      else Graph.refresh();
    })
    .onNodeHover(node => {
      el.style.cursor=node?"pointer":"default";
      if (!tooltip) return;
      if (!node) { tooltip.style.display="none"; return; }
      tooltip.textContent=node.raw||node.label||node.id||"";
      tooltip.style.display="block";
    });

  // ── Tune forces: stronger repulsion + collision to prevent clumping ────────
  // IMPORTANT: use .d3Force(name) to MODIFY existing forces, never replace with null
  Graph.d3Force("charge").strength(-600).distanceMax(600);  // stronger push-apart
  Graph.d3Force("link").distance(l => {
    // Longer distance for hub→event connections to spread them out
    if (l.etype==="svc_event"||l.etype==="camp_event") return 180;
    return 120;
  }).strength(0.3);
  Graph.d3Force("center").strength(0.015);  // weaker gravity → more spread


  // ── Tooltip ────────────────────────────────────────────────────────────────
  el.addEventListener("mousemove", e => {
    if (!tooltip||tooltip.style.display==="none") return;
    const rc=el.getBoundingClientRect();
    tooltip.style.left=`${e.clientX-rc.left+15}px`;
    tooltip.style.top=`${e.clientY-rc.top+15}px`;
  });
  el.addEventListener("mouseleave",()=>{ if(tooltip)tooltip.style.display="none"; });

  // ── Responsive ─────────────────────────────────────────────────────────────
  const ro=new ResizeObserver(()=>Graph.width(el.offsetWidth).height(el.offsetHeight));
  ro.observe(el); Graph.width(el.offsetWidth).height(el.offsetHeight);

  // ── Parse API → rawNodes + rawEdgeStore (string IDs, safe field names) ─────
  function parsePayload(payload) {
    rawNodes = (payload.nodes||[]).map(n => ({
      ...n.data,
      id:         String(n.data.id),
      count:      n.data.count||1,
      __selected: false,
    }));
    rawEdgeStore = (payload.edges||[]).map(e => ({
      _id:   String(e.data.id),
      _src:  String(e.data.source),  // _src/_tgt: force-graph can't mutate these
      _tgt:  String(e.data.target),
      etype: e.data.etype||"",
      count: e.data.count||1,
    }));
    console.log(`[Graph] ${rawNodes.length} nodes, ${rawEdgeStore.length} edges`);
  }

  // ── Auto-reveal: pick campaign with most connections ───────────────────────
  function autoRevealTopCampaign() {
    if (revealedCamp!==null) return;
    const camps=rawNodes.filter(n=>n.type==="campaign");
    if (!camps.length) return;
    const best=camps.reduce((a,c) => {
      const s=rawEdgeStore.filter(e=>e._src===c.id||e._tgt===c.id).length;
      return s>(a.score||0) ? {id:c.id,score:s} : a;
    }, {score:-1});
    revealedCamp=best.id;
  }

  // ── Build visible graph ────────────────────────────────────────────────────
  // svc_event edges always shown (structural backbone).
  // camp_event edges only for the revealed campaign.
  // Event nodes visible if they have a svc_event link, OR a camp_event to the revealed campaign.
  function rebuildGraph() {
    const vis=new Set();

    // 1. All non-event nodes always visible
    rawNodes.forEach(n => { if(n.type!=="event") vis.add(n.id); });

    // 2. Event nodes: add if has svc_event connection (always)
    rawNodes.forEach(n => {
      if (n.type!=="event") return;
      if (rawEdgeStore.some(e=>e.etype==="svc_event"&&(e._src===n.id||e._tgt===n.id)))
        vis.add(n.id);
    });

    // 3. Event nodes: also add if linked to revealed campaign via camp_event
    if (revealedCamp!==null) {
      rawNodes.forEach(n => {
        if (n.type!=="event"||vis.has(n.id)) return;
        if (rawEdgeStore.some(e=>
          e.etype==="camp_event" &&
          (e._src===revealedCamp||e._tgt===revealedCamp) &&
          (e._src===n.id||e._tgt===n.id)
        )) vis.add(n.id);
      });
    }

    const nodes=rawNodes.filter(n=>vis.has(n.id)).map(n=>({...n}));

    const links=rawEdgeStore
      .filter(e => {
        if (!vis.has(e._src)||!vis.has(e._tgt)) return false;
        if (e.etype==="camp_event")
          return revealedCamp!==null&&(e._src===revealedCamp||e._tgt===revealedCamp);
        return true;  // svc_event + all others
      })
      .map(e => ({
        id:     e._id,
        source: e._src,  // fresh string each rebuild → force-graph mutates copy, not rawEdgeStore
        target: e._tgt,
        etype:  e.etype,
        count:  e.count,
      }));

    console.log(`[Graph] render: ${nodes.length} nodes, ${links.length} links`);
    Graph.graphData({ nodes, links });
  }

  // ── Fetch ──────────────────────────────────────────────────────────────────
  function stableSig(payload) {
    return [...(payload.nodes||[]).map(n=>String(n.data?.id)),
            ...(payload.edges||[]).map(e=>String(e.data?.id))].sort().join("|");
  }

  function fetchAndRender() {
    return fetch("/api/graph",{cache:"no-store"}).then(r=>r.json()).then(payload=>{
      const sig=stableSig(payload);
      if(sig===lastSig) return;
      lastSig=sig; didFit=false;
      parsePayload(payload);
      autoRevealTopCampaign();
      rebuildGraph();
    }).catch(e=>console.error("Graph fetch error:",e));
  }

  // ── Auto-refresh ───────────────────────────────────────────────────────────
  function schedule() {
    if(timer) clearInterval(timer);
    if(graphAuto) timer=setInterval(fetchAndRender,graphRefreshMs);
  }
  function fetchSettings() {
    return fetch("/api/settings",{cache:"no-store"}).then(r=>r.json()).then(s=>{
      graphAuto=!!s.GRAPH_AUTO_REFRESH;
      graphRefreshMs=Math.max(3000,parseInt(s.GRAPH_REFRESH_MS??10000,10));
      schedule();
    }).catch(()=>schedule());
  }

  // ── Buttons ────────────────────────────────────────────────────────────────
  btnRefresh?.addEventListener("click",()=>{ lastSig=""; revealedCamp=null; didFit=false; fetchAndRender(); });
  btnFit?.addEventListener("click",()=>Graph.zoomToFit(500,60));

  fetchSettings().then(fetchAndRender);
}
