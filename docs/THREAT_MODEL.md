# Threat model (personal builder PC)

## Assets

- Source code, `.env` / secrets, SSH keys, cloud tokens  
- Local model weights and agent configs  
- Corporate or client data on the laptop  

## Actors

- Malware / malicious packages on the host  
- Compromised SaaS / supply chain  
- LAN attackers (rogue APs, MITM)  
- Curious access to a mis-bound dashboard  

## Controls (current direction)

| Control | Status |
|---------|--------|
| Process → destination visibility | MVP |
| First-seen / suspicious port alerts | MVP |
| Loopback-only API | MVP |
| Local SQLite only | MVP |
| Packet IDS / Suricata | Planned optional |
| MCP security context for agents | Planned |
| Block/prevent connections | Out of scope for early versions |

## Non-goals (MVP)

- Replacing Windows Defender / corporate EDR  
- Full Snort rule parity  
- Inspecting LLM prompt contents by default  
- Cloud multi-tenant SaaS  

## Assumptions

- Operator trusts the machine enough to run a local security tool  
- Browser access to `127.0.0.1` is limited to the logged-in user session  
