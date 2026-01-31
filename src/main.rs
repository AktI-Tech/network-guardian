mod network_monitor;
mod threat_detection;
mod ui;
mod daemon;
mod models;
mod utils;

#[tokio::main]
async fn main() {
    env_logger::init();
    
    println!("🛡️  Network Guardian - Starting...");
    
    // Initialize network monitor
    let monitor = network_monitor::NetworkMonitor::new();
    
    // Start monitoring in background
    let monitor_handle = tokio::spawn(async move {
        if let Err(e) = monitor.run().await {
            eprintln!("Monitor error: {}", e);
        }
    });
    
    // Start GUI
    println!("Launching GUI...");
    ui::launch_dashboard().await;
    
    monitor_handle.abort();
}
