# NetworkGuardian

**Protecting the builders.**

Local-first workstation security monitor for people who ship software with **Windows + WSL2 + Docker + local LLMs**. See **which process talks to which destination**, get a simple localhost dashboard, and grow into hybrid IDS / MCP / mobile later.

| | |
|---|---|
| **Org** | [AktI-Tech](https://github.com/AktI-Tech) (company GitHub — PRs merged there) |
| **License** | MIT |
| **Default surface** | `http://127.0.0.1:8787/` dashboard + background sampler |
| **Privacy** | Loopback API only, local SQLite, no cloud phone-home |

> Status: **active development**. Early packet-capture CLI exists; the product focus is now **process → destination** visibility and a local web UI. Marketing claims of “production-ready Snort replacement” do **not** apply yet.

## Quick start

### Requirements

- Rust 1.75+ ([rustup](https://rustup.rs/))
- Windows 10/11 (primary) or Linux
- Optional: [Npcap](https://nmap.org/npcap/) + SDK for live packet capture

### Build & run

```bash
git clone https://github.com/AktI-Tech/network-guardian.git
cd network-guardian
cargo build --release

# Default: localhost dashboard + connection sampler
cargo run --release
# → open http://127.0.0.1:8787/
```

### Useful commands

```bash
network_guardian serve --bind 127.0.0.1:8787 --interval 2
network_guardian serve --tray         # Windows: system tray (Open Dashboard / Quit)
network_guardian autostart enable     # Windows: start at logon (serve --tray)
network_guardian autostart status
network_guardian connections          # one-shot process → dest table
network_guardian stack                # WSL + Docker (containers, networks, host-port exposure)
network_guardian rules                # show YAML policy (v3 allow/deny/CIDR/custom)
network_guardian region               # Nepal/South Asia radar + local IoC exposure
network_guardian region packs         # list local curated packs (R5, no network)
network_guardian region refresh       # force opt-in live feed pull (HTTP GET only)
network_guardian mcp                  # MCP stdio server for IDE agents
network_guardian stats
network_guardian recent 20
network_guardian monitor              # packet path (optional feature)
network_guardian help

# Optional Suricata hybrid ingest
network_guardian serve --eve C:\path\to\eve.json
```

Packet capture (optional):

```bash
cargo build --release --features packet-capture
# Windows: run elevated, Npcap installed
cargo run --release --features packet-capture -- monitor
```

### MCP (IDE agents)

```json
{
  "mcpServers": {
    "network-guardian": {
      "command": "network_guardian",
      "args": ["mcp"]
    }
  }
}
```

Tools (read-only): `security_summary`, `list_active_connections`, `list_alerts`, `destination_category`, `builder_stack`, `list_rules`, `regional_threat_summary`.

## What works today

- **Process ↔ socket sampling** (active TCP only — filters TIME_WAIT noise)
- **Destination categories**: `llm`, `registry`, `cloud`, `lan`, `localhost`, `unknown`
- **AI client process boost** (e.g. `grok.exe` → llm even on CDN IPs)
- **Builder stack**: WSL distros, Docker containers/networks, tagged adapters
- **Docker host-port exposure**: parse published ports (`0.0.0.0` / LAN / localhost), compose project labels, engine version
- **Reverse DNS** (cached) so CDN IPs can map to known hosts / labels
- **Stack hints**: `wsl`, `docker`, `llm-local` from process names + env probe
- **YAML rules v3** (`rules/default.yml`): first-seen, process allow/watch, destination allow/deny, CIDR, custom match rules, fan-out, ports
- **Regional radar** (Nepal / South Asia): sample pack + **curated local packs (R5)** under `intel/packs/` + **opt-in live feeds** (pull-only HTTP, disk cache) + local IoC exposure
- **Windows tray + autostart**: `serve --tray`, `autostart enable|disable|status` (HKCU Run)
- **MCP stdio server** for coding agents
- **SSE** live ticks (`/api/events`) + dashboard
- **Suricata EVE** optional ingest (`--eve`)
- **SQLite** store: connections, destinations, processes, alerts
- **Local web dashboard** with WSL/Docker pills
- Optional **Npcap** packet path with corrected Ethernet/IP parse

## Guardian Ops (agents + budgets)

Long multi-role sessions (security · marketing/imagen · coding/hobbies) sit **beside** the binary, not inside a second app:

- Sensors + MCP + dashboard = local nervous system (`serve`, `mcp`, `:8787`)
- Session playbooks + token floors = `ops/` (see [`ops/README.md`](ops/README.md))
- Default split keeps **≥10% tokens for coding/hobbies**; security agents stay **read-only** via MCP

## Roadmap (short)

| Phase | Focus |
|-------|--------|
| Now | Dashboard + rules v3 + MCP + Docker exposure + feeds + curated packs (R5) + ops playbooks |
| Next | Headless tray polish, pack auto-update channel (optional), Ops tab / budget MCP |
| Later | Mobile companion, Microsoft new-device / ARM64 clients |

## Project layout

```text
src/
  main.rs              CLI entry (serve is default)
  mcp.rs               MCP stdio server
  sensors/             Host connection sampler
  destinations.rs      LLM / registry / cloud catalog
  rules.rs             YAML-backed policy engine
  suricata.rs          Optional EVE JSON ingest
  api.rs               Loopback HTTP API + SSE
  packet_capture.rs    Optional pcap path
  threat_database.rs   SQLite
rules/default.yml      Default policy rules
intel/region.yml       Regional radar + packs + feed config
intel/packs/           Curated local threat packs (R5, no network)
intel/sessions/        Optional local agent digests (gitignored)
ops/                   Multi-role budgets + agent preambles (playbook)
web/                   Dashboard assets (embedded at build)
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Open PRs against **AktI-Tech/network-guardian**; maintainers review and merge.

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

## Security

Local elevation may be required for some sensors. Report issues privately when appropriate — see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
