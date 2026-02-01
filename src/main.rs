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

#[tokio::main]
async fn main() {
    env_logger::init();
    
    println!("🛡️  Network Guardian v1.0 - Phase 2 (Packet Capture & Monitoring)");
    println!("═══════════════════════════════════════════════════════════════\n");
    
    // Initialize threat database
    let _db = match threat_database::ThreatDatabase::new("threats.db") {
        Ok(db) => {
            println!("✅ Threat database initialized");
            db
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
        
        // Start network monitor
        let monitor = network_monitor::NetworkMonitor::new();
        
        // Start monitoring in background
        let monitor_handle = tokio::spawn(async move {
            if let Err(e) = monitor.run().await {
                eprintln!("Monitor error: {}", e);
            }
        });
        
        // Start packet capture
        println!("\n📦 Starting Packet Capture (Press Ctrl+C to stop)...\n");
        if let Err(e) = sniffer.start_capture().await {
            eprintln!("❌ Packet capture error: {}", e);
        }
        
        monitor_handle.abort();
    }
    
    #[cfg(not(feature = "packet-capture"))]
    {
        println!("ℹ️  Packet capture is disabled.");
        println!("    Build with: cargo build --features packet-capture");
        println!("    Requires: Npcap on Windows or libpcap-dev on Linux\n");
        println!("✅ System ready. Database initialized and monitoring capability available.");
    }
}
