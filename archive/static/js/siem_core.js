document.addEventListener('DOMContentLoaded', () => {
    const tableBody = document.getElementById('alerts-table-body');
    const dot = document.getElementById('connection-dot');
    const statusText = document.getElementById('connection-text');

    const navLinks = Array.from(document.querySelectorAll('.sidebar nav a[data-nav]'));

    const MAX_ROWS = 50;
    const POLL_MS = 2000;

    let knownKeys = new Set();
    let lastSeenMs = 0;

    function setOnline() {
        dot.classList.add('active');
        statusText.innerText = "SYSTEM ONLINE";
        statusText.style.color = "#4ade80";
    }

    function setOffline() {
        dot.classList.remove('active');
        statusText.innerText = "DISCONNECTED";
        statusText.style.color = "#f43f5e";
    }

    function parseTsMs(ts) {
        const ms = Date.parse(ts);
        return Number.isFinite(ms) ? ms : 0;
    }

    function alertKey(alert) {
        // Best-effort stable key without backend IDs
        return [
            alert.timestamp ?? '',
            alert.alert_name ?? '',
            alert.mitre_attck_id ?? '',
            alert.ip_address ?? '',
            alert.raw_log ?? '',
            alert.description ?? ''
        ].join('|');
    }

    function updateStats(alerts) {
        const critical = alerts.filter(a => a.severity === 'CRITICAL').length;
        const high = alerts.filter(a => a.severity === 'HIGH').length;
        const total = alerts.length;
        const anomalies = alerts.filter(a =>
            a.ml_anomaly_score !== undefined || a.stat_anomaly_score !== undefined
        ).length;

        document.getElementById('cnt-critical').innerText = critical;
        document.getElementById('cnt-high').innerText = high;
        document.getElementById('cnt-anomaly').innerText = anomalies;
        document.getElementById('cnt-total').innerText = total;
    }

    function buildRow(alert) {
        const row = document.createElement('tr');
        row.classList.add('new-row');

        const time = new Date(alert.timestamp).toLocaleTimeString();
        const mitre = alert.mitre_attck_id || 'N/A';
        const ip = alert.ip_address || 'N/A';

        const mitigation = alert.mitigation_command
            ? `<span class="mitigation-code"><i class="fa-solid fa-terminal"></i> ${alert.mitigation_command}</span>`
            : `<span class="muted">No action req.</span>`;

        let details = alert.description || '';
        if (alert.ml_anomaly_score !== undefined && alert.ml_anomaly_score !== null) {
            const s = Number(alert.ml_anomaly_score);
            if (Number.isFinite(s)) {
                details += ` <span style="color: var(--accent-purple); font-weight:bold;">[ML Score: ${s.toFixed(2)}]</span>`;
            }
        }

        row.innerHTML = `
            <td style="font-family: 'JetBrains Mono'; color: var(--text-secondary);">${time}</td>
            <td style="font-weight: 600;">${alert.alert_name || 'Unknown'}</td>
            <td><span class="severity-badge severity-${alert.severity}">${alert.severity}</span></td>
            <td>
                <div style="font-size:12px; color:var(--text-secondary);">IP: ${ip}</div>
                <div style="font-size:11px; color:var(--text-secondary); opacity:0.7;">MITRE: ${mitre}</div>
            </td>
            <td style="max-width: 300px;">${details}</td>
            <td>${mitigation}</td>
        `;
        return row;
    }

    function trimRows() {
        while (tableBody.children.length > MAX_ROWS) {
            tableBody.removeChild(tableBody.firstChild); // remove oldest (top)
        }
    }

    function initialRender(sortedAsc) {
        tableBody.innerHTML = '';
        knownKeys.clear();
        lastSeenMs = 0;

        const tail = sortedAsc.slice(Math.max(0, sortedAsc.length - MAX_ROWS));
        tail.forEach(a => {
            const key = alertKey(a);
            knownKeys.add(key);
            lastSeenMs = Math.max(lastSeenMs, parseTsMs(a.timestamp));
            tableBody.appendChild(buildRow(a));
        });
    }

    function appendNew(sortedAsc) {
        // Append only alerts newer than lastSeenMs OR not seen by key
        const newOnes = sortedAsc.filter(a => {
            const ms = parseTsMs(a.timestamp);
            const key = alertKey(a);
            return ms > lastSeenMs || !knownKeys.has(key);
        });

        if (newOnes.length === 0) return;

        newOnes.forEach(a => {
            const key = alertKey(a);
            knownKeys.add(key);
            lastSeenMs = Math.max(lastSeenMs, parseTsMs(a.timestamp));
            tableBody.appendChild(buildRow(a)); // append at bottom (stable reading)
        });

        trimRows();
    }

    function fetchAlerts() {
        fetch('/api/alerts', { cache: 'no-store' })
            .then(r => r.json())
            .then(data => {
                setOnline();
                updateStats(data);

                // Sort ascending so we can append at bottom (no jumping/reset)
                const sortedAsc = [...data].sort((a, b) => parseTsMs(a.timestamp) - parseTsMs(b.timestamp));

                if (tableBody.children.length === 0) {
                    initialRender(sortedAsc);
                } else {
                    appendNew(sortedAsc);
                }
            })
            .catch(err => {
                console.error('Connection Lost', err);
                setOffline();
            });
    }

    // Sidebar navigation: smooth scroll + active state
    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            const href = link.getAttribute('href') || '';
            if (!href.startsWith('#')) return;

            e.preventDefault();
            const target = document.querySelector(href);
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
            navLinks.forEach(a => a.classList.remove('active'));
            link.classList.add('active');
        });
    });

    fetchAlerts();
    setInterval(fetchAlerts, POLL_MS);
});