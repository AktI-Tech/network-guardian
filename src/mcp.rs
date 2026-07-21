//! Minimal MCP (Model Context Protocol) stdio server — read-only security tools.
//!
//! Configure IDE clients with:
//!   command: network_guardian
//!   args: ["mcp"]
//!
//! Tools never return raw packet payloads or secrets.

use crate::models::DestinationCategory;
use crate::sensors::connections;
use crate::sensors::environment;
use crate::threat_database::ThreatDatabase;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::sync::Arc;

const SERVER_NAME: &str = "network-guardian";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL_VERSION: &str = "2024-11-05";

pub fn run(db: Arc<ThreatDatabase>) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let lines = stdin.lock().lines();

    eprintln!("NetworkGuardian MCP server on stdio (read-only). Protecting the builders.");

    for line in lines {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                write_msg(
                    &mut stdout,
                    &json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": { "code": -32700, "message": format!("parse error: {e}") }
                    }),
                )?;
                continue;
            }
        };

        // Notifications have no id and no response.
        if msg.get("id").is_none() {
            continue;
        }

        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");

        let response = match method {
            "initialize" => ok(
                id,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION
                    }
                }),
            ),
            "ping" => ok(id, json!({})),
            "tools/list" => ok(id, json!({ "tools": tool_defs() })),
            "tools/call" => {
                let name = msg
                    .pointer("/params/name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let args = msg
                    .pointer("/params/arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                match call_tool(name, &args, &db) {
                    Ok(result) => ok(id, result),
                    Err(e) => err(id, -32000, e),
                }
            }
            "notifications/initialized" => continue,
            other => err(id, -32601, format!("method not found: {other}")),
        };

        write_msg(&mut stdout, &response)?;
    }

    Ok(())
}

fn tool_defs() -> Value {
    json!([
        {
            "name": "security_summary",
            "description": "One-shot workstation security posture: connection count, alerts, WSL/Docker, motto.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "list_active_connections",
            "description": "List active process→destination TCP connections (no payloads).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 },
                    "llm_only": { "type": "boolean", "default": false }
                }
            }
        },
        {
            "name": "list_alerts",
            "description": "Recent local policy/security alerts.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "maximum": 200, "default": 20 }
                }
            }
        },
        {
            "name": "destination_category",
            "description": "Classify a host or IP (llm/registry/cloud/lan/localhost/unknown).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "host_or_ip": { "type": "string" }
                },
                "required": ["host_or_ip"]
            }
        },
        {
            "name": "builder_stack",
            "description": "WSL distros, Docker containers, and tagged network adapters on this workstation.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
            "name": "list_rules",
            "description": "Show active YAML policy: allowlist, watchlist, fan-out threshold, ports.",
            "inputSchema": { "type": "object", "properties": {} }
        }
    ])
}

fn call_tool(name: &str, args: &Value, db: &ThreatDatabase) -> Result<Value, String> {
    match name {
        "security_summary" => {
            let samples = connections::sample_connections().unwrap_or_default();
            let env = environment::probe_cached();
            let stats = db.get_statistics().map_err(|e| e.to_string())?;
            let llm = samples
                .iter()
                .filter(|s| s.category == DestinationCategory::Llm)
                .count();
            Ok(tool_text(json!({
                "motto": "Protecting the builders",
                "version": SERVER_VERSION,
                "active_connections": samples.len(),
                "llm_connections": llm,
                "alerts_total": stats.total,
                "alerts_high_or_critical": stats.high + stats.critical,
                "wsl_detected": env.wsl_detected,
                "docker_detected": env.docker_detected,
                "docker_engine_ok": env.docker_engine_ok,
                "wsl_distro_count": env.wsl_distros.len(),
                "docker_container_count": env.docker_containers.len(),
            })))
        }
        "builder_stack" => {
            let env = environment::probe_cached();
            Ok(tool_text(serde_json::to_value(env).unwrap_or(json!({}))))
        }
        "list_rules" => {
            let cfg = crate::rules::RuleConfig::load(None);
            Ok(tool_text(serde_json::to_value(cfg).unwrap_or(json!({}))))
        }
        "list_active_connections" => {
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
            let llm_only = args
                .get("llm_only")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let mut samples = connections::sample_connections()?;
            if llm_only {
                samples.retain(|s| s.category == DestinationCategory::Llm);
            }
            samples.truncate(limit);
            let rows: Vec<Value> = samples
                .iter()
                .map(|s| {
                    json!({
                        "process": s.process_name,
                        "pid": s.pid,
                        "remote": s.remote_addr,
                        "port": s.remote_port,
                        "category": s.category.as_str(),
                        "label": s.destination_label,
                        "host": s.resolved_host,
                        "stack": s.stack_hint,
                        "state": s.state,
                    })
                })
                .collect();
            Ok(tool_text(
                json!({ "count": rows.len(), "connections": rows }),
            ))
        }
        "list_alerts" => {
            let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as u32;
            let records = db
                .get_recent_threat_records(limit)
                .map_err(|e| e.to_string())?;
            Ok(tool_text(
                json!({ "count": records.len(), "alerts": records }),
            ))
        }
        "destination_category" => {
            let host = args
                .get("host_or_ip")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "host_or_ip required".to_string())?;
            let c = crate::destinations::classify_host(host);
            Ok(tool_text(json!({
                "host_or_ip": c.host_or_ip,
                "category": c.category.as_str(),
                "label": c.label,
                "resolved_host": c.resolved_host,
            })))
        }
        other => Err(format!("unknown tool: {other}")),
    }
}

fn tool_text(value: Value) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
        }],
        "isError": false
    })
}

fn ok(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() }
    })
}

fn write_msg(out: &mut impl Write, msg: &Value) -> io::Result<()> {
    let line = serde_json::to_string(msg)?;
    writeln!(out, "{line}")?;
    out.flush()
}
