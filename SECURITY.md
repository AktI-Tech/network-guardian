# Security Policy

## Supported versions

NetworkGuardian is under active development. Treat pre-1.0 releases as experimental on trusted personal machines only.

## Privacy defaults

- HTTP API binds to **127.0.0.1** only by default; non-loopback binds are refused.
- Data stays in local SQLite (`threats.db` by default).
- No automatic phone-home or telemetry in the default build.

## Reporting a vulnerability

If you find a vulnerability (e.g. remote binding, path traversal on export, privilege issues):

1. Prefer **private disclosure** to the AktI-Tech maintainers (company contact associated with the GitHub org).
2. Do not open a public issue with exploit details until a fix is available.
3. Include: affected version/commit, OS, steps to reproduce, impact.

## Elevated privileges

Process/socket enumeration and packet capture may require Administrator (Windows) or root/capabilities (Linux). Run only software you trust with those rights. The dashboard itself should remain local.

## Scope notes

NetworkGuardian is **visibility and local alerting**, not a replacement for OS antimalware, EDR, or enterprise DLP.
