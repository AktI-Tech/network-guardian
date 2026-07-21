(() => {
  const $ = (id) => document.getElementById(id);
  let connections = [];
  let destinations = [];
  let alerts = [];
  let stackEnv = null;
  let rulesCfg = null;
  let regionSnap = null;

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
  $("stack-only").addEventListener("change", renderConnections);

  function badge(cat) {
    const c = (cat || "unknown").toLowerCase();
    return `<span class="badge ${c}">${c}</span>`;
  }

  function stackBadge(hint) {
    if (!hint) return "—";
    return `<span class="badge stack ${esc(hint)}">${esc(hint)}</span>`;
  }

  function renderEnv(status, env, region) {
    const pills = [];
    const wsl = env ? env.wsl_detected : status.wsl_detected;
    const docker = env ? env.docker_detected : status.docker_detected;
    if (wsl) {
      const n = env && env.wsl_distros ? env.wsl_distros.length : 0;
      pills.push(`<span class="env-pill on">WSL${n ? " · " + n : ""}</span>`);
    } else pills.push('<span class="env-pill">WSL off</span>');
    if (docker) {
      const n = env && env.docker_containers ? env.docker_containers.length : 0;
      const eng = env && env.docker_engine_ok === false ? " (engine?)" : "";
      pills.push(`<span class="env-pill on">Docker${n ? " · " + n : ""}${eng}</span>`);
    } else pills.push('<span class="env-pill">Docker off</span>');
    if (region && region.enabled) {
      const st = (region.status || "watch").toLowerCase();
      const exp = region.local_exposure && region.local_exposure.level
        ? region.local_exposure.level
        : "none";
      pills.push(
        `<span class="env-pill on" title="Regional radar">NP · ${esc(st)} · ${esc(exp)}</span>`
      );
    } else if (region && region.enabled === false) {
      pills.push('<span class="env-pill">Region off</span>');
    }
    $("env-pills").innerHTML = pills.join("");
  }

  function renderRegion() {
    const r = regionSnap;
    if (!r) {
      $("region-status").textContent = "unavailable";
      $("region-summary").textContent = "Could not load /api/region";
      return;
    }
    const st = (r.status || "watch").toLowerCase();
    $("region-status").className = "region-status " + st;
    $("region-status").textContent = st;
    $("region-meta").textContent = `${r.region_code || "NP"} · ${r.scope || "south_asia"}${
      r.is_sample ? " · sample pack" : ""
    } · loaded ${esc(shortTime(r.loaded_at))}`;
    $("region-summary").textContent = r.summary || "";
    $("region-disclaimer").textContent = r.disclaimer || "";

    const exp = r.local_exposure || {};
    $("region-exposure").textContent = (exp.level || "—").toUpperCase();
    $("region-live").textContent = String(exp.matched_live ?? 0);
    $("region-dest").textContent = String(exp.matched_destinations ?? 0);
    $("region-watch").textContent = exp.watchlist_active ? "yes" : "no";

    const industries = r.industries || [];
    $("region-industries").innerHTML = industries.length
      ? industries
          .map(
            (i) => `<div class="heat-row">
        <div class="heat-label"><span>${esc(i.name)}</span><span>${i.score}</span></div>
        <div class="heat-bar"><div class="heat-fill" style="width:${Math.min(
          100,
          Number(i.score) || 0
        )}%"></div></div>
        <div class="muted" style="font-size:0.78rem;margin-top:0.25rem">${esc(i.rationale || "")}</div>
      </div>`
          )
          .join("")
      : '<p class="muted">No industry data</p>';

    const campaigns = r.campaigns || [];
    $("region-campaigns").innerHTML = campaigns.length
      ? campaigns
          .map(
            (c) => `<div class="campaign-card">
        <h4>${esc(c.title)} <span class="badge ${esc(c.severity || "")}">${esc(
              c.severity || ""
            )}</span></h4>
        <p>${esc(c.summary || "")}</p>
        <p style="margin-top:0.35rem">${esc((c.countries || []).join(", "))} · ${esc(
              (c.sectors || []).join(", ")
            )} · ${esc(c.confidence || "")}
        ${
          c.source_url
            ? ` · <a href="${esc(c.source_url)}" target="_blank" rel="noopener">source</a>`
            : ""
        }</p>
      </div>`
          )
          .join("")
      : '<p class="muted">No campaigns in pack</p>';

    const matches = (exp.matches || []).slice(0, 50);
    $("region-matches").innerHTML = matches.length
      ? matches
          .map(
            (m) => `<tr>
        <td>${esc(m.ioc_type)}</td>
        <td>${esc(m.value)}</td>
        <td>${esc(m.matched_as)}</td>
        <td>${esc(m.process_name || "—")}</td>
        <td title="${esc(m.notes || "")}">${esc(truncate(m.notes || "—", 48))}</td>
      </tr>`
          )
          .join("")
      : `<tr><td colspan="5" class="muted">No IoC overlap with this PC</td></tr>`;

    $("region-notes").textContent = (exp.notes || []).join(" · ");
    const sources = r.sources || [];
    $("region-sources").textContent = sources.length
      ? "Sources: " + sources.map((s) => s.name).join(" · ")
      : "";
  }

  function renderStack() {
    const env = stackEnv || {};
    const distros = env.wsl_distros || [];
    const containers = env.docker_containers || [];
    const ifaces = (env.interfaces || []).filter((i) => i.kind && i.kind !== "host");

    $("wsl-count").textContent = distros.length ? `(${distros.length})` : "";
    $("docker-count").textContent = containers.length
      ? `(${containers.length})`
      : env.docker_detected
        ? env.docker_engine_ok
          ? "(0)"
          : "(engine unreachable)"
        : "";

    $("wsl-body").innerHTML = distros.length
      ? distros
          .map(
            (d) => `<tr>
        <td>${d.is_default ? "★" : ""}</td>
        <td>${esc(d.name)}</td>
        <td>${esc(d.state)}</td>
        <td>${esc(d.version)}</td>
      </tr>`
          )
          .join("")
      : `<tr><td colspan="4" class="muted">${env.wsl_detected ? "No distros listed" : "WSL not detected"}</td></tr>`;

    $("docker-body").innerHTML = containers.length
      ? containers
          .map(
            (c) => `<tr>
        <td>${esc(c.name)}</td>
        <td title="${esc(c.image)}">${esc(truncate(c.image, 36))}</td>
        <td>${esc(c.status)}</td>
        <td title="${esc(c.ports)}">${esc(truncate(c.ports || "—", 40))}</td>
      </tr>`
          )
          .join("")
      : `<tr><td colspan="4" class="muted">${
          env.docker_detected
            ? env.docker_engine_ok
              ? "No containers"
              : "Docker CLI/engine not responding"
            : "Docker not detected"
        }</td></tr>`;

    $("iface-body").innerHTML = ifaces.length
      ? ifaces
          .map(
            (i) => `<tr>
        <td>${stackBadge(i.kind)}</td>
        <td>${esc(i.name)}</td>
        <td>${esc((i.ips || []).join(", ") || "—")}</td>
      </tr>`
          )
          .join("")
      : `<tr><td colspan="3" class="muted">No WSL/Docker/Hyper-V adapters tagged</td></tr>`;

    const notes = env.notes || [];
    $("stack-notes").textContent = notes.length
      ? "Notes: " + notes.join(" · ")
      : "";
  }

  function renderConnections() {
    const q = ($("filter").value || "").toLowerCase();
    const llmOnly = $("llm-only").checked;
    const stackOnly = $("stack-only").checked;
    const body = $("conn-body");
    const rows = connections.filter((c) => {
      const cat = (c.category || "").toLowerCase();
      if (llmOnly && cat !== "llm") return false;
      if (stackOnly && !c.stack_hint) return false;
      if (!q) return true;
      const blob = [
        c.process_name,
        c.pid,
        c.remote_addr,
        c.resolved_host,
        c.remote_port,
        c.category,
        c.destination_label,
        c.stack_hint,
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
      <td title="${esc(c.resolved_host || "")}">${esc(truncate(c.resolved_host || "—", 36))}</td>
      <td>${c.remote_port}</td>
      <td>${badge(c.category)}</td>
      <td>${stackBadge(c.stack_hint)}</td>
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
      return new Date(iso).toLocaleString();
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

  function renderRules() {
    const r = rulesCfg;
    if (!r) {
      $("rules-summary").textContent = "Policy not loaded";
      return;
    }
    const s = r.settings || {};
    $("rules-summary").textContent =
      `v${r.version ?? "?"} · first_seen_unknown=${s.alert_first_seen_unknown} · llm_traffic=${s.alert_llm_traffic} · fanout≥${s.high_fanout_threshold ?? "—"} · ports=${(r.suspicious_ports || []).length}`;
    $("rules-allow").innerHTML =
      (r.process_allowlist || []).map((p) => `<li>${esc(p)}</li>`).join("") ||
      "<li class='muted'>(none)</li>";
    $("rules-watch").innerHTML =
      (r.process_watchlist || []).map((p) => `<li>${esc(p)}</li>`).join("") ||
      "<li class='muted'>(none)</li>";
    $("rules-ports").textContent = (r.suspicious_ports || []).join(", ") || "(none)";
  }

  async function refresh() {
    try {
      const [status, conn, dest, al, env, rules, region] = await Promise.all([
        fetch("/api/status").then((r) => r.json()),
        fetch("/api/connections").then((r) => r.json()),
        fetch("/api/destinations").then((r) => r.json()),
        fetch("/api/alerts").then((r) => r.json()),
        fetch("/api/environment").then((r) => r.json()).catch(() => null),
        fetch("/api/rules").then((r) => r.json()).catch(() => null),
        fetch("/api/region").then((r) => r.json()).catch(() => null),
      ]);

      connections = conn.connections || [];
      destinations = dest.destinations || [];
      alerts = al.alerts || [];
      stackEnv = env;
      rulesCfg = rules;
      regionSnap = region;

      $("c-conn").textContent = String(status.connection_count ?? connections.length);
      $("c-alerts").textContent = String(status.alert_count ?? alerts.length);
      $("c-up").textContent = formatUptime(status.uptime_secs || 0);
      $("status-pill").textContent = "live · " + (status.listening || "127.0.0.1");
      $("status-pill").classList.add("live");
      $("footer-meta").textContent = `v${status.version || "?"} · sample ${status.sample_interval_secs || "?"}s`;
      renderEnv(status, env, region);

      renderConnections();
      renderStack();
      renderDestinations();
      renderAlerts();
      renderRegion();
      renderRules();
    } catch (e) {
      $("status-pill").textContent = "offline";
      $("status-pill").classList.remove("live");
    }
  }

  refresh();
  // Prefer SSE ticks when available; fall back to polling.
  let pollTimer = setInterval(refresh, 5000);
  try {
    const es = new EventSource("/api/events");
    es.onmessage = () => {
      refresh();
    };
    es.onerror = () => {
      /* keep poll timer as backup */
    };
    es.onopen = () => {
      clearInterval(pollTimer);
      pollTimer = setInterval(refresh, 15000);
    };
  } catch (_) {
    /* EventSource unavailable — polling only */
  }
})();
