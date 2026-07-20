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
network_guardian connections          # one-shot process → dest table
network_guardian stats
network_guardian recent 20
network_guardian monitor              # packet path (optional feature)
network_guardian help
```

Packet capture (optional):

```bash
cargo build --release --features packet-capture
# Windows: run elevated, Npcap installed
cargo run --release --features packet-capture -- monitor
```

## What works today

- **Process ↔ socket sampling** (TCP with remote peers) via host APIs
- **Destination categories**: `llm`, `registry`, `cloud`, `lan`, `localhost`, `unknown`
- **SQLite** store: connections, destinations, processes, alerts
- **Rule MVP**: first-seen unknown destinations; suspicious ports
- **Local web dashboard** (embedded static UI)
- **CLI** for stats / export / cleanup
- Optional **Npcap** packet path with corrected Ethernet/IP parse

## Roadmap (short)

| Phase | Focus |
|-------|--------|
| Now | Local working model on your PC |
| Next | WSL/Docker visibility, richer rules, optional Suricata EVE ingest |
| Later | **MCP plugin / IDE extensions**, mobile companion (Google Play), Microsoft new-device / ARM64 clients |

Deep design: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

## Project layout

```
src/
  main.rs              CLI entry (serve is default)
  sensors/             Host connection sampler
  destinations.rs      LLM / registry / cloud catalog
  rules.rs             First-seen + port policy
  api.rs               Loopback HTTP API
  packet_capture.rs    Optional pcap path
  threat_database.rs   SQLite
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
