(() => {
  // Full API base URL must appear as a literal string (CI pages-hint greps for it).
  const GITHUB_REPO_URL = "https://api.github.com/repos/AktI-Tech/network-guardian";
  const GITHUB_RAW_CARGO =
    "https://raw.githubusercontent.com/AktI-Tech/network-guardian/main/Cargo.toml";
  const GITHUB_COMMITS_PAGE =
    "https://github.com/AktI-Tech/network-guardian/commits/main";

  const FEATURES = [
    {
      title: "Process → destination",
      body: "Active TCP map with process name, PID, remote host/IP, category, and stack hints (WSL / Docker / local LLM).",
    },
    {
      title: "Local dashboard",
      body: "Embedded web UI on 127.0.0.1:8787 with filters, LLM-only view, alerts, and SSE live ticks.",
    },
    {
      title: "Destination intelligence",
      body: "Catalog + reverse DNS + AI client process boost (e.g. grok.exe → llm even on shared CDNs).",
    },
    {
      title: "YAML policy rules",
      body: "rules/default.yml controls first-seen unknown, LLM breadcrumbs, and suspicious ports.",
    },
    {
      title: "MCP for IDE agents",
      body: "network_guardian mcp exposes read-only tools: security_summary, connections, alerts, classify, builder_stack.",
    },
    {
      title: "Hybrid IDS hooks",
      body: "Optional Npcap packet path and Suricata eve.json ingest into the same alert store.",
    },
    {
      title: "Privacy by design",
      body: "Loopback-only API, local SQLite, no cloud phone-home. Elevated rights only when capture needs it.",
    },
    {
      title: "Builder stack panel",
      body: "WSL distro list, Docker containers and published ports, tagged Hyper-V/WSL/Docker adapters — CLI stack + MCP builder_stack.",
    },
  ];

  const $ = (id) => document.getElementById(id);

  function renderFeatures() {
    const grid = $("feature-grid");
    if (!grid) return;
    grid.innerHTML = FEATURES.map(
      (f) => `<article class="feature"><h3>${esc(f.title)}</h3><p>${esc(f.body)}</p></article>`
    ).join("");
  }

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function fmtDate(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    } catch {
      return iso;
    }
  }

  function relativeTime(iso) {
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return "—";
    const sec = Math.round((Date.now() - t) / 1000);
    if (sec < 60) return `${sec}s ago`;
    if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
    if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
    if (sec < 86400 * 30) return `${Math.floor(sec / 86400)}d ago`;
    return fmtDate(iso);
  }

  async function fetchJson(url) {
    const res = await fetch(url, {
      headers: { Accept: "application/vnd.github+json" },
    });
    if (!res.ok) throw new Error(`${url} → ${res.status}`);
    return res.json();
  }

  async function fetchText(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${url} → ${res.status}`);
    return res.text();
  }

  function parseCargoVersion(toml) {
    const m = toml.match(/^\s*version\s*=\s*"([^"]+)"/m);
    return m ? m[1] : null;
  }

  async function loadLive() {
    const badges = $("live-badges");
    try {
      const [repo, commits, releases, cargoToml] = await Promise.all([
        fetchJson(GITHUB_REPO_URL),
        fetchJson(`${GITHUB_REPO_URL}/commits?per_page=12`),
        fetchJson(`${GITHUB_REPO_URL}/releases?per_page=10`),
        fetchText(GITHUB_RAW_CARGO).catch(() => ""),
      ]);

      const version =
        parseCargoVersion(cargoToml) ||
        (releases[0] && releases[0].tag_name) ||
        "dev";

      $("stat-version").textContent = version.startsWith("v") ? version : `v${version}`;
      $("stat-stars").textContent = String(repo.stargazers_count ?? 0);
      $("stat-issues").textContent = String(repo.open_issues_count ?? 0);
      $("stat-push").textContent = relativeTime(repo.pushed_at);

      badges.innerHTML = [
        `<span class="pill on">live · main</span>`,
        `<span class="pill llm">v${version.replace(/^v/, "")}</span>`,
        `<span class="pill">${repo.language || "Rust"}</span>`,
        `<span class="pill">${repo.license?.spdx_id || "MIT"}</span>`,
        repo.archived ? `<span class="pill">archived</span>` : "",
      ]
        .filter(Boolean)
        .join("");

      $("footer-meta").textContent = `Updated ${relativeTime(repo.pushed_at)} · data from GitHub API`;

      const commitList = $("commit-list");
      if (Array.isArray(commits) && commits.length) {
        commitList.innerHTML = commits
          .map((c) => {
            const sha = (c.sha || "").slice(0, 7);
            const msg = (c.commit?.message || "").split("\n")[0];
            const when = c.commit?.author?.date;
            const url = c.html_url;
            return `<li>
              <span class="when">${esc(fmtDate(when))} · <code>${esc(sha)}</code></span>
              <a href="${esc(url)}" target="_blank" rel="noopener">${esc(msg)}</a>
            </li>`;
          })
          .join("");
      } else {
        commitList.innerHTML = `<li class="muted">No commits returned (API rate limit or network).</li>`;
      }

      const releaseList = $("release-list");
      if (Array.isArray(releases) && releases.length) {
        releaseList.innerHTML = releases
          .map((r) => {
            const body = (r.body || "")
              .trim()
              .split("\n")
              .slice(0, 4)
              .join(" ")
              .slice(0, 240);
            return `<li>
              <span class="when">${esc(fmtDate(r.published_at || r.created_at))} · ${esc(r.tag_name)}</span>
              <a href="${esc(r.html_url)}" target="_blank" rel="noopener">${esc(r.name || r.tag_name)}</a>
              <div class="msg">${esc(body || "No release notes.")}</div>
            </li>`;
          })
          .join("");
      } else {
        releaseList.innerHTML = `<li class="muted">No GitHub Releases yet — showing commit history instead. Tag releases to populate this tab.</li>`;
      }
    } catch (e) {
      console.error(e);
      badges.innerHTML = `<span class="pill">Live data unavailable (API / network). Static description still valid.</span>`;
      $("stat-version").textContent = "0.3.x";
      $("commit-list").innerHTML = `<li class="muted">Could not load commits. See <a href="${GITHUB_COMMITS_PAGE}">GitHub history</a>.</li>`;
      $("release-list").innerHTML = `<li class="muted">Could not load releases.</li>`;
    }
  }

  function setupTabs() {
    document.querySelectorAll(".tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
        document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        const panel = document.getElementById("panel-" + btn.dataset.panel);
        if (panel) panel.classList.add("active");
      });
    });
  }

  renderFeatures();
  setupTabs();
  loadLive();
})();
