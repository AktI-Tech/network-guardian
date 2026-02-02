mod network_monitor;
mod threat_detection;
mod ui;
mod daemon;
mod models;
mod utils;
#[cfg(feature = "packet-capture")]
mod packet_capture;
mod threat_database;
mod notifications;

use std::sync::Arc;
use tokio::sync::mpsc;
use crate::models::ThreatAlert;
use crate::packet_capture::PacketInfo;
use crate::threat_database::ThreatDatabase;
use crate::threat_detection::ThreatDetector;

#[tokio::main]
async fn main() {
    env_logger::init();
    
    println!("🛡️  Network Guardian v1.0 - Phase 2 (Packet Capture & Monitoring)");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    // Initialize threat database
    let db = match ThreatDatabase::new("threats.db") {
        Ok(db) => {
            println!("✅ Threat database initialized");
            Arc::new(db)
        }
        Err(e) => {
            eprintln!("❌ Failed to initialize database: {}", e);
            return;
        }
    };
    
    #[cfg(feature = "packet-capture")]
    {
        // List available network devices
        println!("\n📡 Available Network Devices:");
        match packet_capture::PacketSniffer::list_devices() {
            Ok(devices) => {
                for device in devices {
                    println!("   - {}", device);
                }
            }
            Err(e) => eprintln!("   Error listing devices: {}", e),
        }
        
        // Initialize packet sniffer
        println!("\n🚀 Initializing Packet Capture...\n");
        let sniffer = match packet_capture::PacketSniffer::new() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("❌ Failed to initialize sniffer: {}", e);
                eprintln!("   Make sure you have network packet capture permissions");
                eprintln!("   Windows: Run as Administrator");
                eprintln!("   Linux: Use sudo or install libpcap-dev");
                return;
            }
        };
        
        // Create message channels for data flow
        let (packet_tx, mut packet_rx) = mpsc::channel::<PacketInfo>(1000);
        let (threat_tx, mut threat_rx) = mpsc::channel::<ThreatAlert>(100);
        
        // Task 1: Packet capture sends packets through channel
        let sniffer_handle = tokio::spawn(async move {
            println!("📦 Starting Packet Capture (Press Ctrl+C to stop)...\n");
            if let Err(e) = sniffer.start_capture_and_send(packet_tx).await {
                eprintln!("❌ Packet capture error: {}", e);
            }
        });
        
        // Task 2: Threat detection receives packets and generates alerts
        let threat_handle = tokio::spawn(async move {
            let mut detector = ThreatDetector::new();
            println!("🔍 Threat detection engine started\n");
            
            while let Some(packet) = packet_rx.recv().await {
                // Analyze each packet for threats
                if let Some(threat) = detector.analyze_packet(&packet) {
                    println!("🚨 THREAT DETECTED: {}", threat.description);
                    if threat_tx.send(threat).await.is_err() {
                        eprintln!("Logger channel closed");
                        break;
                    }
                }
            }
        });
        
        // Main task: Database logging and notifications (synchronous on main thread)
        println!("💾 Threat logger started\n");
        
        let process_threats = async {
            while let Some(threat) = threat_rx.recv().await {
                // Log to database
                match db.log_threat(&threat) {
                    Ok(id) => {
                        println!("✅ Threat #{} logged to database", id);
                        println!("   Type: {:?}", threat.threat_type);
                        println!("   Severity: {:?}", threat.severity);
                        if let Some(ip) = threat.ip {
                            println!("   IP: {}", ip);
                        }
                    }
                    Err(e) => eprintln!("❌ Database error: {}", e),
                }
                
                // Send notification if high severity
                if threat.should_notify() {
                    match notifications::NotificationManager::notify_threat(&threat) {
                        Ok(_) => println!("📢 Notification sent"),
                        Err(e) => eprintln!("❌ Notification error: {}", e),
                    }
                }
            }
        };
        
        // Wait for sniffer and threat detection tasks
        tokio::select! {
            result = sniffer_handle => {
                eprintln!("Sniffer task ended: {:?}", result);
            }
            result = threat_handle => {
                eprintln!("Threat detection ended: {:?}", result);
            }
            _ = process_threats => {
                eprintln!("Logger ended");
            }
        }
    }
    
    #[cfg(not(feature = "packet-capture"))]
    {
        println!("ℹ️  Packet capture is disabled.");
        println!("    Build with: cargo build --features packet-capture");
        println!("    Requires: Npcap on Windows or libpcap-dev on Linux\n");
        println!("✅ System ready. Database initialized and monitoring capability available.");
    }
}
