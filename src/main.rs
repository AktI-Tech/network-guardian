#![allow(dead_code)] // stubs (daemon/ui) and future detectors kept intentionally

mod api;
mod daemon;
mod destinations;
mod models;
mod network_monitor;
mod notifications;
mod packet_capture;
mod rules;
mod sensors;
mod threat_database;
mod threat_detection;
mod ui;
mod utils;

use std::env;
use std::net::SocketAddr;
use std::process;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::api::AppState;
use crate::models::ThreatAlert;
use crate::rules::RuleEngine;
use crate::sensors::connections;
use crate::threat_database::{ThreatDatabase, ThreatRecord};
use crate::threat_detection::ThreatDetector;
use tokio::sync::mpsc;

const DB_PATH: &str = "threats.db";
const DEFAULT_RECENT_LIMIT: u32 = 10;
const DEFAULT_CLEANUP_DAYS: i32 = 30;
const DEFAULT_BIND: &str = "127.0.0.1:8787";
const DEFAULT_SAMPLE_SECS: u64 = 2;

enum Command {
    Monitor,
    Serve { bind: String, sample_secs: u64 },
    Connections,
    Stats,
    Recent(u32),
    Severity(String),
    ExportJson(String, u32),
    Cleanup(i32),
    Help,
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
        Command::Serve { bind, sample_secs } => run_serve(db, bind, sample_secs).await,
        Command::Connections => print_connections_once(),
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
        });
    }

    match args[0].as_str() {
        "monitor" => Ok(Command::Monitor),
        "serve" => {
            let mut bind = DEFAULT_BIND.to_string();
            let mut sample_secs = DEFAULT_SAMPLE_SECS;
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
                    other => return Err(format!("unknown serve option '{}'", other)),
                }
                i += 1;
            }
            Ok(Command::Serve { bind, sample_secs })
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

async fn run_serve(db: Arc<ThreatDatabase>, bind: String, sample_secs: u64) {
    println!("🛡️  NetworkGuardian");
    println!("   Protecting the builders\n");
    println!("✅ Database: {}", DB_PATH);

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

    let state = AppState {
        db: Arc::clone(&db),
        started: Instant::now(),
        bind: addr.to_string(),
        sample_interval_secs: sample_secs,
    };

    let sampler_db = Arc::clone(&db);
    let sampler = tokio::spawn(async move {
        run_connection_sampler(sampler_db, sample_secs).await;
    });

    let server = api::serve(state, addr);

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                eprintln!("❌ Server error: {}", e);
            }
        }
        _ = sampler => {
            eprintln!("Sampler task ended unexpectedly");
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down…");
        }
    }
}

async fn run_connection_sampler(db: Arc<ThreatDatabase>, sample_secs: u64) {
    let mut engine = RuleEngine::new();
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
                }
            }
            Err(e) => eprintln!("❌ Connection sample failed: {}", e),
        }
        tokio::time::sleep(interval).await;
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
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
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
    println!("  serve [--bind 127.0.0.1:8787] [--interval 2]");
    println!("                              Start dashboard + connection sampler (default)");
    println!("  connections                 One-shot process → destination table");
    println!("  monitor                     Live packet monitor (needs --features packet-capture)");
    println!("  stats                       Show threat + connection summary");
    println!("  recent [limit]              Show recent alerts");
    println!("  severity <level>            Filter by severity: low|medium|high|critical");
    println!("  export-json [path] [limit]  Export recent alerts to JSON");
    println!("  cleanup [days]              Delete threat records older than N days");
    println!("  help                        Show this help");
    println!();
    println!("Dashboard: http://127.0.0.1:8787/  (loopback only)");
}
