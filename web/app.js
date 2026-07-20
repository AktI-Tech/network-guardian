(() => {
  const $ = (id) => document.getElementById(id);
  let connections = [];
  let destinations = [];
  let alerts = [];

  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
      btn.classList.add("active");
      $("panel-" + btn.dataset.tab).classList.add("active");
    });
  });

  $("filter").addEventListener("input", renderConnections);
  $("llm-only").addEventListener("change", renderConnections);

  function badge(cat) {
    const c = (cat || "unknown").toLowerCase();
    return `<span class="badge ${c}">${c}</span>`;
  }

  function renderConnections() {
    const q = ($("filter").value || "").toLowerCase();
    const llmOnly = $("llm-only").checked;
    const body = $("conn-body");
    const rows = connections.filter((c) => {
      const cat = (c.category || "").toLowerCase();
      if (llmOnly && cat !== "llm") return false;
      if (!q) return true;
      const blob = [
        c.process_name,
        c.pid,
        c.remote_addr,
        c.remote_port,
        c.category,
        c.destination_label,
        c.state,
      ]
        .join(" ")
        .toLowerCase();
      return blob.includes(q);
    });

    body.innerHTML = rows
      .map(
        (c) => `<tr>
      <td>${esc(c.process_name || "—")}</td>
      <td>${c.pid ?? "—"}</td>
      <td>${esc(c.remote_addr)}</td>
      <td>${c.remote_port}</td>
      <td>${badge(c.category)}</td>
      <td>${esc(c.destination_label || "—")}</td>
      <td>${esc(c.state)}</td>
    </tr>`
      )
      .join("");

    const llm = connections.filter((c) => (c.category || "").toLowerCase() === "llm").length;
    $("c-llm").textContent = String(llm);
  }

  function renderDestinations() {
    $("dest-body").innerHTML = destinations
      .map(
        (d) => `<tr>
      <td>${esc(d.host_or_ip)}</td>
      <td>${badge(d.category)}</td>
      <td>${esc(d.label || "—")}</td>
      <td>${d.hit_count}</td>
      <td>${esc(shortTime(d.last_seen))}</td>
    </tr>`
      )
      .join("");
  }

  function renderAlerts() {
    $("alert-body").innerHTML = alerts
      .map(
        (a) => `<tr>
      <td><span class="badge ${esc(a.severity)}">${esc(a.severity)}</span></td>
      <td>${esc(a.threat_type)}</td>
      <td title="${esc(a.description)}">${esc(truncate(a.description, 80))}</td>
      <td>${esc(a.ip_address || "—")}</td>
      <td>${esc(shortTime(a.timestamp))}</td>
    </tr>`
      )
      .join("");
  }

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function truncate(s, n) {
    s = String(s || "");
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  function shortTime(iso) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      return d.toLocaleString();
    } catch {
      return iso;
    }
  }

  function formatUptime(secs) {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    const s = secs % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  async function refresh() {
    try {
      const [status, conn, dest, al] = await Promise.all([
        fetch("/api/status").then((r) => r.json()),
        fetch("/api/connections").then((r) => r.json()),
        fetch("/api/destinations").then((r) => r.json()),
        fetch("/api/alerts").then((r) => r.json()),
      ]);

      connections = conn.connections || [];
      destinations = dest.destinations || [];
      alerts = al.alerts || [];

      $("c-conn").textContent = String(status.connection_count ?? connections.length);
      $("c-alerts").textContent = String(status.alert_count ?? alerts.length);
      $("c-up").textContent = formatUptime(status.uptime_secs || 0);
      $("status-pill").textContent = "live · " + (status.listening || "127.0.0.1");
      $("status-pill").classList.add("live");
      $("footer-meta").textContent = `v${status.version || "?"} · sample ${status.sample_interval_secs || "?"}s`;

      renderConnections();
      renderDestinations();
      renderAlerts();
    } catch (e) {
      $("status-pill").textContent = "offline";
      $("status-pill").classList.remove("live");
    }
  }

  refresh();
  setInterval(refresh, 2000);
})();
