# Contributing to NetworkGuardian

Thanks for helping **protect the builders**.

## Where to send work

- **Canonical repo:** https://github.com/AktI-Tech/network-guardian  
- **Maintainer merge:** AktI-Tech account (company) — open a PR; do not push directly to `main`  
- Preferred integration branch for active work: `features` (or PR into `main` if that is what CI protects)

## Development

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
cargo run -- serve
```

Default dashboard: `http://127.0.0.1:8787/` (loopback only by design).

### Scope guidelines

- Prefer small PRs aligned with the roadmap (schema, sensors, API, UI, rules).
- Privileged / Windows-specific code stays in clear modules (`sensors/`, optional features).
- No cloud telemetry by default.
- Do not log secrets (API keys in URLs, tokens, env dumps).
- MCP, mobile, and Store packaging should consume the **local API**, not fork the agent.

## PR checklist

- [ ] `cargo test` passes  
- [ ] `cargo fmt` / clippy clean  
- [ ] Docs updated if commands or privacy behavior change  
- [ ] No non-loopback bind defaults  

## Code of collaboration

Be respectful. This is a personal/company open-source security tool — assume good intent, prefer clarity over hype.
