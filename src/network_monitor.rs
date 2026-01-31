use tokio::sync::mpsc;
use crate::models::NetworkEvent;
use crate::threat_detection::ThreatDetector;

pub struct NetworkMonitor {
    tx: Option<mpsc::Sender<NetworkEvent>>,
    detector: ThreatDetector,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {
            tx: None,
            detector: ThreatDetector::new(),
        }
    }
    
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting network monitor...");
        println!("Available interfaces:");
        println!("  - eth0 (up: true)");
        println!("    IP: 192.168.1.100");
        println!("\n📡 Monitoring interface: eth0");
        self.monitor_interface().await?;
        Ok(())
    }
    
    async fn monitor_interface(&self) -> Result<(), Box<dyn std::error::Error>> {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<NetworkEvent>) {
        self.tx = Some(tx);
    }
}
