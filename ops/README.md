# Guardian Ops

Personal multi-role playbook: **NetworkGuardian** is the local nervous system (sensors, dashboard, MCP); **long Grok sessions** are the brain (security digest, marketing imagen, coding/hobbies) with **token budgets**.

Budgets in [`budget.yml`](budget.yml) are **discipline + display**, not enforced by the binary.

## Quick start

1. Run the monitor:

   ```bash
   cargo run --release
   # open http://127.0.0.1:8787/
   ```

2. Optional: point an IDE agent at MCP:

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

3. Open a long session and **timebox by role** (see budget file). Paste a preamble when switching roles.

| Role | Preamble | Notes |
|------|----------|--------|
| Security | [`PREAMBLE_SECURITY.md`](PREAMBLE_SECURITY.md) | MCP read-only; you approve rule changes |
| Marketing / imagen | [`PREAMBLE_MARKETING.md`](PREAMBLE_MARKETING.md) | Batch 3–5 assets, then stop |
| Coding / hobbies | (your task brief) | **≥10% of planned tokens** — hard floor |

## Healthy day (~2.5h)

| Block | ~Minutes | Role |
|-------|----------|------|
| 1 | 30–45 | Security — summary, alerts, stack, region; short digest |
| 2 | 60–90 | Marketing / imagen — fixed brief, small batch |
| 3 | 30–60 | Coding / hobbies — one clear done definition |
| 4 | 5–10 | Closeout — remaining budget, open alerts, tomorrow |

## Lean day (low balance)

1. Optional 10m security skim, or skip.
2. One marketing asset **or** one code/hobby task — if you open a session, protect the coding floor.
3. Stop early; do not burn residual tokens on open-ended chat.

## Operating rules

1. **Floor first** — coding/hobbies ≥10% of *planned* session tokens before marketing expands.
2. **One role per block** — avoid infinite mixed chats.
3. **One write surface per role** — security → `rules/` / packs (human applies); marketing → assets; code → git branches.
4. **No silent PC control** — NG observes and alerts; enforcement stays human-approved YAML.

## Session digests (optional)

Write free-form notes under `intel/sessions/` (gitignored except `.gitkeep`). Example name: `2026-07-24-security.md`.

## Product hooks (shipped)

- MCP tool `budget_policy` — read-only budgets + tool list
- Dashboard **Ops** tab + loopback `GET /api/ops` — budgets, MCP tools, last digest

See main [README](../README.md) roadmap.
