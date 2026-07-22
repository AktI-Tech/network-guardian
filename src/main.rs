#![allow(dead_code)] // stubs (daemon/ui) and future detectors kept intentionally

mod api;
#[cfg(windows)]
mod autostart;
mod daemon;
mod destinations;
mod feeds;
mod mcp;
mod models;
mod network_monitor;
mod notifications;
mod packet_capture;
mod region;
mod rules;
mod sensors;
mod suricata;
mod threat_database;
mod threat_detection;
#[cfg(windows)]
mod tray;
mod ui;
mod utils;

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::api::AppState;
use crate::models::ThreatAlert;
use crate::rules::{RuleConfig, RuleEngine};
use crate::sensors::connections;
use crate::suricata::EveTail;
use crate::threat_database::{ThreatDatabase, ThreatRecord};
use crate::threat_detection::ThreatDetector;
use tokio::sync::{broadcast, mpsc};

const DB_PATH: &str = "threats.db";
const DEFAULT_RECENT_LIMIT: u32 = 10;
const DEFAULT_CLEANUP_DAYS: i32 = 30;
const DEFAULT_BIND: &str = "127.0.0.1:8787";
const DEFAULT_SAMPLE_SECS: u64 = 2;

enum Command {
    Monitor,
    Serve {
        bind: String,
        sample_secs: u64,
        eve: Option<PathBuf>,
        tray: bool,
    },
    Mcp,
    Connections,
    Stack,
    Rules,
    Region,
    RegionRefresh,
    Autostart {
        action: AutostartAction,
    },
    Stats,
    Recent(u32),
    Severity(String),
    ExportJson(String, u32),
    Cleanup(i32),
    Help,
}

enum AutostartAction {
    Enable,
    Disable,
    Status,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let command = match parse_command(env::args().skip(1).collect()) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("❌ {}", err);
            print_usage();
            process::exit(1);
        }
    };

    if matches!(command, Command::Help) {
        print_usage();
        return;
    }

    let db = match ThreatDatabase::new(DB_PATH) {
        Ok(db) => Arc::new(db),
        Err(e) => {
            eprintln!("❌ Failed to initialize database '{}': {}", DB_PATH, e);
            process::exit(1);
        }
    };

    match command {
        Command::Monitor => run_monitor(db).await,
        Command::Serve {
            bind,
            sample_secs,
            eve,
            tray,
        } => run_serve(db, bind, sample_secs, eve, tray).await,
        Command::Mcp => {
            if let Err(e) = mcp::run(db) {
                eprintln!("❌ MCP server error: {}", e);
                process::exit(1);
            }
        }
        Command::Connections => print_connections_once(),
        Command::Stack => print_stack(),
        Command::Rules => print_rules(),
        Command::Region => print_region(Some(&db)),
        Command::RegionRefresh => print_region_refresh(Some(&db)),
        Command::Autostart { action } => run_autostart(action),
        Command::Stats => print_stats(&db),
        Command::Recent(limit) => print_recent(&db, limit),
        Command::Severity(level) => print_by_severity(&db, &level),
        Command::ExportJson(path, limit) => export_json(&db, &path, limit),
        Command::Cleanup(days) => cleanup_old_threats(&db, days),
        Command::Help => {}
    }
}

fn parse_command(args: Vec<String>) -> Result<Command, String> {
    if args.is_empty() {
        return Ok(Command::Serve {
            bind: DEFAULT_BIND.to_string(),
            sample_secs: DEFAULT_SAMPLE_SECS,
            eve: None,
            tray: false,
        });
    }

    match args[0].as_str() {
        "monitor" => Ok(Command::Monitor),
        "mcp" => Ok(Command::Mcp),
        "stack" => Ok(Command::Stack),
        "rules" => Ok(Command::Rules),
        "region" => match args.get(1).map(|s| s.as_str()) {
            Some("refresh") | Some("--refresh") => Ok(Command::RegionRefresh),
            None | Some("show") | Some("status") => Ok(Command::Region),
            Some(other) => Err(format!(
                "unknown region action '{other}' (use region | region refresh)"
            )),
        },
        "autostart" => {
            let action = args.get(1).map(|s| s.as_str()).unwrap_or("status");
            match action {
                "enable" | "on" => Ok(Command::Autostart {
                    action: AutostartAction::Enable,
                }),
                "disable" | "off" => Ok(Command::Autostart {
                    action: AutostartAction::Disable,
                }),
                "status" => Ok(Command::Autostart {
                    action: AutostartAction::Status,
                }),
                other => Err(format!(
                    "unknown autostart action '{other}' (use enable|disable|status)"
                )),
            }
        }
        "serve" => {
            let mut bind = DEFAULT_BIND.to_string();
            let mut sample_secs = DEFAULT_SAMPLE_SECS;
            let mut eve = None;
            let mut tray = false;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--bind" => {
                        i += 1;
                        bind = args
                            .get(i)
                            .cloned()
                            .ok_or_else(|| "--bind requires host:port".to_string())?;
                    }
                    "--interval" => {
                        i += 1;
                        sample_secs = args
                            .get(i)
                            .ok_or_else(|| "--interval requires seconds".to_string())?
                            .parse()
                            .map_err(|_| "invalid --interval".to_string())?;
                    }
                    "--eve" => {
                        i += 1;
                        let p = args
                            .get(i)
                            .cloned()
                            .ok_or_else(|| "--eve requires path to eve.json".to_string())?;
                        eve = Some(PathBuf::from(p));
                    }
                    "--tray" => {
                        tray = true;
                    }
                    other => return Err(format!("unknown serve option '{}'", other)),
                }
                i += 1;
            }
            Ok(Command::Serve {
                bind,
                sample_secs,
                eve,
                tray,
            })
        }
        "connections" => Ok(Command::Connections),
        "stats" => Ok(Command::Stats),
        "recent" => Ok(Command::Recent(parse_u32_arg(
            args.get(1),
            DEFAULT_RECENT_LIMIT,
            "limit",
        )?)),
        "severity" => {
            let value = args
                .get(1)
                .ok_or_else(|| "severity requires a level: low|medium|high|critical".to_string())?;
            Ok(Command::Severity(normalize_severity(value)?))
        }
        "export-json" => {
            let path = args
                .get(1)
                .cloned()
                .unwrap_or_else(|| "threat_report.json".to_string());
            let limit = parse_u32_arg(args.get(2), 100, "limit")?;
            Ok(Command::ExportJson(path, limit))
        }
        "cleanup" => Ok(Command::Cleanup(parse_i32_arg(
            args.get(1),
            DEFAULT_CLEANUP_DAYS,
            "days",
        )?)),
        "help" | "--help" | "-h" => Ok(Command::Help),
        other => Err(format!("unknown command '{}'", other)),
    }
}

fn parse_u32_arg(value: Option<&String>, default: u32, label: &str) -> Result<u32, String> {
    match value {
        Some(value) => value
            .parse::<u32>()
            .map_err(|_| format!("invalid {} '{}'", label, value)),
        None => Ok(default),
    }
}

fn parse_i32_arg(value: Option<&String>, default: i32, label: &str) -> Result<i32, String> {
    match value {
        Some(value) => value
            .parse::<i32>()
            .map_err(|_| format!("invalid {} '{}'", label, value)),
        None => Ok(default),
    }
}

fn normalize_severity(value: &str) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Ok("Low".to_string()),
        "medium" => Ok("Medium".to_string()),
        "high" => Ok("High".to_string()),
        "critical" => Ok("Critical".to_string()),
        _ => Err(format!("unsupported severity '{}'", value)),
    }
}

async fn run_serve(
    db: Arc<ThreatDatabase>,
    bind: String,
    sample_secs: u64,
    eve: Option<PathBuf>,
    tray: bool,
) {
    println!("🛡️  NetworkGuardian");
    println!("   Protecting the builders\n");
    println!("✅ Database: {}", DB_PATH);

    let rules = Arc::new(RuleConfig::load(None));
    println!("📜 Rules loaded:");
    for line in rules.summary_lines() {
        println!("   · {}", line);
    }

    let env = crate::sensors::environment::probe();
    if env.wsl_detected {
        println!("🐧 WSL detected");
    }
    if env.docker_detected {
        println!("🐳 Docker detected");
    }
    for note in &env.notes {
        println!("   · {}", note);
    }

    let addr: SocketAddr = bind.parse().unwrap_or_else(|_| {
        eprintln!("Invalid bind address '{}', using {}", bind, DEFAULT_BIND);
        DEFAULT_BIND.parse().unwrap()
    });

    if !addr.ip().is_loopback() {
        eprintln!("⚠️  Refusing non-loopback bind for privacy. Use 127.0.0.1.");
        eprintln!("   Requested: {}", addr);
        process::exit(1);
    }

    // Clamp once so dashboard status matches actual sampler cadence.
    let sample_secs = sample_secs.max(1);
    let (event_tx, _) = broadcast::channel::<String>(128);

    let state = AppState {
        db: Arc::clone(&db),
        started: Instant::now(),
        bind: addr.to_string(),
        sample_interval_secs: sample_secs,
        events: event_tx.clone(),
        rules: Arc::clone(&rules),
    };

    let sampler_db = Arc::clone(&db);
    let sampler_tx = event_tx.clone();
    let sampler_rules = Arc::clone(&rules);
    let sampler = tokio::spawn(async move {
        run_connection_sampler(sampler_db, sample_secs, sampler_tx, sampler_rules).await;
    });

    let eve_handle = if let Some(path) = eve {
        println!("🦈 Suricata EVE: {}", path.display());
        let eve_db = Arc::clone(&db);
        let eve_tx = event_tx.clone();
        Some(tokio::spawn(async move {
            run_eve_ingest(eve_db, path, eve_tx).await;
        }))
    } else {
        None
    };

    #[cfg(windows)]
    let tray_rx = if tray {
        let dashboard_url = format!("http://{}/", addr);
        Some(tray::spawn(dashboard_url))
    } else {
        None
    };
    #[cfg(not(windows))]
    let _tray_rx = if tray {
        eprintln!("⚠️  --tray is only supported on Windows; continuing without tray");
        None::<()>
    } else {
        None
    };

    let server = api::serve(state, addr);

    #[cfg(windows)]
    {
        tokio::select! {
            result = server => {
                if let Err(e) = result {
                    eprintln!("❌ Server error: {}", e);
                }
            }
            _ = sampler => {
                eprintln!("Sampler task ended unexpectedly");
            }
            _ = async {
                if let Some(h) = eve_handle {
                    let _ = h.await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                eprintln!("EVE ingest task ended");
            }
            _ = async {
                if let Some(rx) = tray_rx {
                    loop {
                        match rx.try_recv() {
                            Ok(tray::TrayCommand::Quit) => break,
                            Err(std::sync::mpsc::TryRecvError::Empty) => {
                                tokio::time::sleep(Duration::from_millis(200)).await;
                            }
                            Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                        }
                    }
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                println!("\nTray quit — shutting down…");
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down…");
            }
        }
    }
    #[cfg(not(windows))]
    {
        tokio::select! {
            result = server => {
                if let Err(e) = result {
                    eprintln!("❌ Server error: {}", e);
                }
            }
            _ = sampler => {
                eprintln!("Sampler task ended unexpectedly");
            }
            _ = async {
                if let Some(h) = eve_handle {
                    let _ = h.await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                eprintln!("EVE ingest task ended");
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down…");
            }
        }
    }
}

fn run_autostart(action: AutostartAction) {
    #[cfg(windows)]
    {
        match action {
            AutostartAction::Enable => match autostart::enable() {
                Ok(cmd) => {
                    println!("✅ Autostart enabled (HKCU Run)");
                    println!("   {cmd}");
                    println!("   Signs in with: serve --tray");
                }
                Err(e) => {
                    eprintln!("❌ Failed to enable autostart: {e}");
                    process::exit(1);
                }
            },
            AutostartAction::Disable => match autostart::disable() {
                Ok(()) => println!("✅ Autostart disabled"),
                Err(e) => {
                    eprintln!("❌ Failed to disable autostart: {e}");
                    process::exit(1);
                }
            },
            AutostartAction::Status => match autostart::status() {
                Ok(Some(cmd)) => {
                    println!("Autostart: ON");
                    println!("   {cmd}");
                }
                Ok(None) => println!("Autostart: OFF"),
                Err(e) => {
                    eprintln!("❌ Failed to read autostart: {e}");
                    process::exit(1);
                }
            },
        }
    }
    #[cfg(not(windows))]
    {
        let _ = action;
        eprintln!("autostart is only supported on Windows");
        process::exit(1);
    }
}

async fn run_connection_sampler(
    db: Arc<ThreatDatabase>,
    sample_secs: u64,
    events: broadcast::Sender<String>,
    rules: Arc<RuleConfig>,
) {
    let mut engine = RuleEngine::from_config((*rules).clone());
    let interval = Duration::from_secs(sample_secs.max(1));
    println!(
        "🔍 Connection sampler every {}s (process → destination)\n",
        interval.as_secs()
    );

    loop {
        match connections::sample_connections() {
            Ok(samples) => {
                if let Err(e) = db.upsert_connection_samples(&samples) {
                    eprintln!("❌ Failed to store connections: {}", e);
                }
                let alerts = engine.evaluate(&samples);
                for alert in alerts {
                    handle_threat(&db, &alert);
                    let _ = events.send(
                        serde_json::json!({
                            "type": "alert",
                            "description": alert.description,
                            "severity": format!("{:?}", alert.severity),
                        })
                        .to_string(),
                    );
                }
                let _ = events.send(
                    serde_json::json!({
                        "type": "tick",
                        "connections": samples.len(),
                    })
                    .to_string(),
                );
            }
            Err(e) => eprintln!("❌ Connection sample failed: {}", e),
        }
        tokio::time::sleep(interval).await;
    }
}

async fn run_eve_ingest(db: Arc<ThreatDatabase>, path: PathBuf, events: broadcast::Sender<String>) {
    let mut tail = EveTail::new(path);
    let interval = Duration::from_secs(2);
    loop {
        match tail.poll_new_alerts() {
            Ok(alerts) => {
                for alert in alerts {
                    handle_threat(&db, &alert);
                    let _ = events.send(
                        serde_json::json!({
                            "type": "alert",
                            "source": "suricata",
                            "description": alert.description,
                            "severity": format!("{:?}", alert.severity),
                        })
                        .to_string(),
                    );
                }
            }
            Err(e) => {
                // File may not exist yet — retry quietly every few cycles
                eprintln!("EVE: {} ({})", e, tail.path().display());
                tokio::time::sleep(Duration::from_secs(10)).await;
                continue;
            }
        }
        tokio::time::sleep(interval).await;
    }
}

fn print_region(db: Option<&ThreatDatabase>) {
    print_region_inner(db, false);
}

fn print_region_refresh(db: Option<&ThreatDatabase>) {
    println!("🔄 Forcing regional feed refresh (pull-only; no local data uploaded)…");
    crate::region::refresh_feeds();
    print_region_inner(db, true);
}

fn print_region_inner(db: Option<&ThreatDatabase>, force_feeds: bool) {
    let rules = RuleConfig::load(None);
    let snap = crate::region::snapshot_with_local_opts(db, &rules.process_watchlist, force_feeds);
    println!("🌏 Regional threat radar");
    println!("   Region: {}  Scope: {}", snap.region_code, snap.scope);
    println!(
        "   Status: {}  Enabled: {}",
        snap.status.to_uppercase(),
        snap.enabled
    );
    println!(
        "   Sample pack: {}  Live feeds: {}",
        snap.is_sample, snap.feeds_enabled
    );
    println!("\n{}", snap.summary);
    println!("\nDisclaimer: {}", snap.disclaimer);
    if !snap.feed_pulls.is_empty() {
        println!("\nFeed pulls:");
        for p in &snap.feed_pulls {
            let flag = if p.ok { "ok" } else { "ERR" };
            let cache = if p.from_cache { " cache" } else { "" };
            println!(
                "   [{flag}{cache}] {}  iocs={}  {}",
                p.name, p.ioc_count, p.message
            );
            if !p.url.is_empty() {
                println!("            {}", p.url);
            }
        }
    }
    if !snap.industries.is_empty() {
        println!("\nIndustry heat:");
        for i in &snap.industries {
            println!("   [{:>3}] {:<20} {}", i.score, i.name, i.rationale);
        }
    }
    if !snap.campaigns.is_empty() {
        println!("\nCampaigns:");
        for c in &snap.campaigns {
            println!(
                "   • {} [{}] countries={:?} sectors={:?}",
                c.title, c.severity, c.countries, c.sectors
            );
            println!("     {}", c.summary);
        }
    }
    println!("\nIoCs loaded: {}", snap.iocs.len());
    let exp = &snap.local_exposure;
    println!("\nLocal exposure: {}", exp.level.to_uppercase());
    println!(
        "   live_ioc_hits={}  dest_hits={}  watchlist_active={}",
        exp.matched_live, exp.matched_destinations, exp.watchlist_active
    );
    for n in &exp.notes {
        println!("   · {}", n);
    }
    if !exp.matches.is_empty() {
        println!("\nMatches:");
        for m in exp.matches.iter().take(20) {
            println!(
                "   {} {} via {} proc={:?}",
                m.ioc_type, m.value, m.matched_as, m.process_name
            );
        }
    }
}

fn print_rules() {
    let cfg = RuleConfig::load(None);
    println!("📜 NetworkGuardian policy rules");
    for line in cfg.summary_lines() {
        println!("   {}", line);
    }
    println!("\nSettings:");
    println!(
        "   first_seen_unknown: {}",
        cfg.settings.alert_first_seen_unknown
    );
    println!("   llm_traffic:        {}", cfg.settings.alert_llm_traffic);
    println!(
        "   high_fanout:        {}",
        cfg.settings.high_fanout_threshold
    );
    println!(
        "   denylist:           {}",
        cfg.settings.alert_destination_denylist
    );
    println!("   cidr_match:         {}", cfg.settings.alert_cidr_match);
    println!(
        "\nSuspicious ports ({}): {:?}",
        cfg.suspicious_ports.len(),
        cfg.suspicious_ports
    );
    println!("\nProcess allowlist ({}):", cfg.process_allowlist.len());
    for p in &cfg.process_allowlist {
        println!("   - {}", p);
    }
    println!("\nProcess watchlist ({}):", cfg.process_watchlist.len());
    for p in &cfg.process_watchlist {
        println!("   - {}", p);
    }
    if !cfg.destination_allowlist.is_empty() {
        println!(
            "\nDestination allowlist ({}):",
            cfg.destination_allowlist.len()
        );
        for d in &cfg.destination_allowlist {
            println!("   - {}", d);
        }
    }
    if !cfg.destination_denylist.is_empty() {
        println!(
            "\nDestination denylist ({}):",
            cfg.destination_denylist.len()
        );
        for d in &cfg.destination_denylist {
            println!("   - {}", d);
        }
    }
    if !cfg.cidr_rules.is_empty() {
        println!("\nCIDR rules ({}):", cfg.cidr_rules.len());
        for r in &cfg.cidr_rules {
            println!(
                "   - {} action={} severity={} {}",
                r.cidr, r.action, r.severity, r.note
            );
        }
    }
    if !cfg.custom_rules.is_empty() {
        println!("\nCustom rules ({}):", cfg.custom_rules.len());
        for r in &cfg.custom_rules {
            println!(
                "   - [{}] action={} severity={} first_seen_only={}",
                r.id, r.action, r.severity, r.first_seen_only
            );
            if !r.message.is_empty() {
                println!("     {}", r.message);
            }
        }
    }
    if !cfg.llm_process_filter.is_empty() {
        println!("\nLLM process filter:");
        for p in &cfg.llm_process_filter {
            println!("   - {}", p);
        }
    }
    println!("\nEdit rules/default.yml and restart serve to apply.");
}

fn print_stack() {
    let env = crate::sensors::environment::probe();
    println!("🛡️  Builder stack");
    println!("   Probed: {}", env.probed_at);
    println!(
        "   WSL: {}    Docker: {} (engine ok: {})",
        env.wsl_detected, env.docker_detected, env.docker_engine_ok
    );
    if let Some(ref v) = env.docker_version {
        print!("   Engine: {v}");
        if let Some(ref ctx) = env.docker_context {
            print!("  context={ctx}");
        }
        println!();
    }
    if env.docker_engine_ok {
        println!(
            "   Containers: {} running / {} stopped",
            env.docker_running, env.docker_stopped
        );
    }
    if !env.notes.is_empty() {
        println!("\nNotes:");
        for n in &env.notes {
            println!("   · {}", n);
        }
    }
    if !env.wsl_distros.is_empty() {
        println!("\nWSL distros:");
        for d in &env.wsl_distros {
            let def = if d.is_default { "*" } else { " " };
            println!("  {} {:<24} {:<12} v{}", def, d.name, d.state, d.version);
        }
    }
    if !env.docker_host_exposure.is_empty() {
        println!("\n⚠️  Host port exposure (beyond loopback):");
        for e in &env.docker_host_exposure {
            let proj = e
                .compose_project
                .as_deref()
                .map(|p| format!("  compose={p}"))
                .unwrap_or_default();
            println!(
                "  [{:<14}] {:>15}:{:<6} → container {}/{}  ({}){}",
                truncate(&e.container, 14),
                e.host_ip,
                e.host_port,
                e.container_port,
                e.protocol,
                e.exposure,
                proj
            );
        }
    }
    if !env.docker_containers.is_empty() {
        println!("\nDocker containers:");
        for c in &env.docker_containers {
            let proj = c
                .compose_project
                .as_deref()
                .map(|p| format!("  [{p}]"))
                .unwrap_or_default();
            println!(
                "  {:<14} {:<20} {:<28} {}{}",
                truncate(&c.id, 12),
                truncate(&c.name, 20),
                truncate(&c.image, 28),
                c.status,
                proj
            );
            if !c.ports.is_empty() {
                println!(
                    "               ports: {}  (exposure: {})",
                    c.ports, c.max_exposure
                );
            }
        }
    } else if env.docker_detected {
        println!("\nDocker containers: (none listed)");
    }
    if !env.docker_networks.is_empty() {
        println!("\nDocker networks:");
        for n in &env.docker_networks {
            println!(
                "  {:<14} {:<24} driver={:<10} scope={}",
                truncate(&n.id, 12),
                truncate(&n.name, 24),
                n.driver,
                n.scope
            );
        }
    }
    if !env.interfaces.is_empty() {
        println!("\nNetwork adapters (tagged):");
        for i in env
            .interfaces
            .iter()
            .filter(|i| i.kind != "host" || !i.ips.is_empty())
        {
            if i.kind == "host" && i.ips.is_empty() {
                continue;
            }
            // Show non-host always; host only if has IPs (cap noise)
            if i.kind == "host" {
                continue;
            }
            println!(
                "  [{:<7}] {}  {}",
                i.kind,
                i.name,
                if i.ips.is_empty() {
                    "—".into()
                } else {
                    i.ips.join(", ")
                }
            );
        }
    }
}

fn print_connections_once() {
    match connections::sample_connections() {
        Ok(samples) => {
            if samples.is_empty() {
                println!("No outbound TCP connections with remote peers found.");
                return;
            }
            println!(
                "{:<20} {:>6}  {:<22} {:<28} {:>5}  {:<10} {:<8} STATE",
                "PROCESS", "PID", "REMOTE", "HOST", "PORT", "CATEGORY", "STACK"
            );
            println!("{}", "-".repeat(120));
            for s in samples {
                println!(
                    "{:<20} {:>6}  {:<22} {:<28} {:>5}  {:<10} {:<8} {}",
                    truncate(s.process_name.as_deref().unwrap_or("?"), 20),
                    s.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                    truncate(&s.remote_addr, 22),
                    truncate(s.resolved_host.as_deref().unwrap_or("-"), 28),
                    s.remote_port,
                    s.category.as_str(),
                    s.stack_hint.as_deref().unwrap_or("-"),
                    s.state
                );
            }
        }
        Err(e) => {
            eprintln!("❌ {}", e);
            process::exit(1);
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!(
            "{}…",
            s.chars().take(max.saturating_sub(1)).collect::<String>()
        )
    }
}

async fn run_monitor(db: Arc<ThreatDatabase>) {
    println!("🛡️  Network Guardian — packet monitor");
    println!("══════════════════\n");
    println!("✅ Threat database initialized at '{}'", DB_PATH);

    match packet_capture::PacketSniffer::list_devices() {
        Ok(devices) => {
            println!("\n📡 Available Network Devices:");
            for device in devices {
                println!("   - {}", device);
            }
        }
        Err(e) => eprintln!("❌ Failed to list devices: {}", e),
    }

    println!("\n🚀 Initializing packet capture...\n");
    let sniffer = match packet_capture::PacketSniffer::new() {
        Ok(sniffer) => sniffer,
        Err(e) => {
            eprintln!("❌ Failed to initialize sniffer: {}", e);
            eprintln!("   Windows: run as Administrator with Npcap + --features packet-capture");
            return;
        }
    };

    let (packet_tx, mut packet_rx) = mpsc::channel::<packet_capture::PacketInfo>(1000);
    let (threat_tx, mut threat_rx) = mpsc::channel::<ThreatAlert>(100);

    let sniffer_handle = tokio::spawn(async move {
        if let Err(e) = sniffer.start_capture_and_send(packet_tx).await {
            eprintln!("❌ Packet capture error: {}", e);
        }
    });

    let threat_handle = tokio::spawn(async move {
        let mut detector = ThreatDetector::new();
        println!("🔍 Threat detection engine started\n");

        while let Some(packet) = packet_rx.recv().await {
            if let Some(threat) = detector.analyze_packet(&packet) {
                println!("🚨 {}", threat.description);
                if threat_tx.send(threat).await.is_err() {
                    eprintln!("Threat logger channel closed");
                    break;
                }
            }
        }
    });

    let process_threats = async {
        while let Some(threat) = threat_rx.recv().await {
            handle_threat(&db, &threat);
        }
    };

    tokio::select! {
        result = sniffer_handle => eprintln!("Packet capture task ended: {:?}", result),
        result = threat_handle => eprintln!("Threat detection task ended: {:?}", result),
        _ = process_threats => eprintln!("Threat processing loop ended"),
    }
}

fn handle_threat(db: &ThreatDatabase, threat: &ThreatAlert) {
    match db.log_threat(threat) {
        Ok(id) => {
            println!(
                "💾 Logged threat #{} [{:?}/{:?}]",
                id, threat.threat_type, threat.severity
            );
            if let Some(ip) = threat.ip {
                println!("   Source IP: {}", ip);
            }
        }
        Err(e) => eprintln!("❌ Database error: {}", e),
    }

    if threat.should_notify() {
        if let Err(e) = notifications::NotificationManager::notify_threat(threat) {
            eprintln!("❌ Notification error: {}", e);
        }
    }
}

fn print_stats(db: &ThreatDatabase) {
    match db.get_statistics() {
        Ok(stats) => {
            println!("📊 Threat Statistics");
            println!("   Total: {}", stats.total);
            println!("   Critical: {}", stats.critical);
            println!("   High: {}", stats.high);
            println!("   Medium: {}", stats.medium);
            println!("   Low: {}", stats.low);

            match db.get_threat_count_by_type() {
                Ok(counts) if !counts.is_empty() => {
                    println!("\n📈 Threat Types");
                    for (threat_type, count) in counts {
                        println!("   {:<20} {}", threat_type, count);
                    }
                }
                Ok(_) => {}
                Err(e) => eprintln!("❌ Failed to load threat type counts: {}", e),
            }

            if let Ok(n) = db.count_connections() {
                println!("\n🔗 Live connection rows: {}", n);
            }
        }
        Err(e) => eprintln!("❌ Failed to load statistics: {}", e),
    }
}

fn print_recent(db: &ThreatDatabase, limit: u32) {
    match db.get_recent_threat_records(limit) {
        Ok(records) => {
            if records.is_empty() {
                println!("No threat records found.");
                return;
            }

            println!("🕒 Recent Threats (last {})", records.len());
            for record in records {
                print_record(&record);
            }
        }
        Err(e) => eprintln!("❌ Failed to load recent threats: {}", e),
    }
}

fn print_by_severity(db: &ThreatDatabase, level: &str) {
    match db.get_threats_by_severity(level) {
        Ok(records) => {
            if records.is_empty() {
                println!("No {} threats found.", level);
                return;
            }

            println!("🚨 {} Threats", level);
            for (id, threat_type, description, ip_address) in records {
                let ip_display = ip_address.unwrap_or_else(|| "n/a".to_string());
                println!(
                    "[#{}] {:<18} {} ({})",
                    id, threat_type, description, ip_display
                );
            }
        }
        Err(e) => eprintln!("❌ Failed to load threats for severity {}: {}", level, e),
    }
}

fn export_json(db: &ThreatDatabase, path: &str, limit: u32) {
    match db.get_recent_threat_records(limit) {
        Ok(records) => {
            let payload = serde_json::json!({
                "generated_at": chrono::Local::now().to_rfc3339(),
                "record_count": records.len(),
                "records": records.iter().map(|record| {
                    serde_json::json!({
                        "id": record.id,
                        "threat_type": record.threat_type,
                        "severity": record.severity,
                        "ip_address": record.ip_address,
                        "description": record.description,
                        "timestamp": record.timestamp,
                        "created_at": record.created_at,
                    })
                }).collect::<Vec<_>>(),
            });

            match std::fs::write(
                path,
                serde_json::to_string_pretty(&payload).unwrap_or_default(),
            ) {
                Ok(_) => println!("✅ Exported {} threat records to {}", records.len(), path),
                Err(e) => eprintln!("❌ Failed to write {}: {}", path, e),
            }
        }
        Err(e) => eprintln!("❌ Failed to load records for export: {}", e),
    }
}

fn cleanup_old_threats(db: &ThreatDatabase, days: i32) {
    match db.cleanup_old_threats(days) {
        Ok(deleted) => println!(
            "🧹 Deleted {} threat records older than {} days",
            deleted, days
        ),
        Err(e) => eprintln!("❌ Cleanup failed: {}", e),
    }
}

fn print_record(record: &ThreatRecord) {
    let ip_display = record.ip_address.as_deref().unwrap_or("n/a");
    println!(
        "[#{}] {:<8} {:<18} {}",
        record.id, record.severity, record.threat_type, record.timestamp
    );
    println!("   IP: {}", ip_display);
    println!("   {}", record.description);
}

fn print_usage() {
    println!("NetworkGuardian — Protecting the builders");
    println!();
    println!("Commands:");
    println!("  serve [--bind 127.0.0.1:8787] [--interval 2] [--eve path] [--tray]");
    println!("                              Start dashboard + sampler (default); --tray = system tray (Windows)");
    println!("  autostart enable|disable|status");
    println!("                              Windows logon autostart (HKCU Run → serve --tray)");
    println!("  mcp                         MCP stdio server (read-only tools for IDE agents)");
    println!("  connections                 One-shot process → destination table");
    println!("  stack                       WSL distros, Docker containers, adapter tags");
    println!("  rules                       Show loaded YAML policy (v3: allow/deny/CIDR/custom)");
    println!("  region [refresh]            Nepal/South Asia radar; refresh = force feed pull");
    println!("  monitor                     Live packet monitor (needs --features packet-capture)");
    println!("  stats                       Show threat + connection summary");
    println!("  recent [limit]              Show recent alerts");
    println!("  severity <level>            Filter by severity: low|medium|high|critical");
    println!("  export-json [path] [limit]  Export recent alerts to JSON");
    println!("  cleanup [days]              Delete threat records older than N days");
    println!("  help                        Show this help");
    println!();
    println!("Dashboard: http://127.0.0.1:8787/  (loopback only)");
    println!("Rules:     rules/default.yml (or embedded defaults)");
}

#[cfg(test)]
mod truncate_tests {
    use super::truncate;

    #[test]
    fn truncate_multibyte_utf8_does_not_panic() {
        let s = "进程名αβγδ";
        let t = truncate(s, 4);
        assert!(t.ends_with('…'));
        assert!(t.chars().count() <= 4);
    }
}
