# Architecture

**Motto:** Protecting the builders  
**Org:** AktI-Tech / network-guardian

## Overview

```
Browser (localhost)  →  ng-api (axum, 127.0.0.1)  →  SQLite
                              ↑
                     connection sampler + rules
                              ↑
                     host OS sockets (netstat2 + sysinfo)
                              ↑
              optional: Npcap packet path / future Suricata EVE
```

Future clients (same API): **MCP plugins**, **IDE extensions**, **mobile companion**, **Microsoft Store UI**, ARM/Copilot+ devices.

## Components

| Piece | Role |
|-------|------|
| `serve` | Default mode: sampler loop + HTTP dashboard |
| `sensors::connections` | TCP process → remote map |
| `destinations` | Category labels (LLM, registry, cloud, LAN…) |
| `rules` | First-seen unknown, suspicious ports |
| `threat_database` | SQLite: threats, connections, destinations, processes |
| `packet_capture` | Optional feature; Ethernet/IP aware parse |
| `monitor` | Legacy/supplementary packet pipeline |

## Privacy

- Bind check: only loopback addresses accepted for `serve`.
- No remote admin surface in MVP.
- MCP (planned) will default to read-only tools over the same API.

## Elevation

- Host socket tables generally work for the current user; some fields need elevation for other users' processes.
- Raw capture needs Npcap + Admin on Windows.

## Packaging roadmap

1. Local binary + dashboard (now)  
2. MCP server package  
3. Mobile / Store thin clients  
4. Microsoft new-device (ARM64) CI matrix  
