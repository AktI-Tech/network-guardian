use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    ArpSpoofing,
    DnsSpoofing,
    MitmAttack,
    RogueAccessPoint,
    TrafficAnomaly,
    ConnectionIssue,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub ip: Option<IpAddr>,
    pub description: String,
    pub timestamp: DateTime<Local>,
}

impl ThreatAlert {
    pub fn is_critical(&self) -> bool {
        self.severity == ThreatSeverity::Critical
    }
    
    pub fn should_notify(&self) -> bool {
        matches!(self.severity, 
            ThreatSeverity::Critical | ThreatSeverity::High
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub event_type: String,
    pub data: serde_json::Value,
    pub timestamp: DateTime<Local>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub is_connected: bool,
    pub interface_name: String,
    pub ip_address: Option<String>,
    pub gateway: Option<String>,
    pub latency_ms: f64,
    pub packet_loss_percent: f64,
    pub active_threats: Vec<ThreatAlert>,
    pub last_update: DateTime<Local>,
}

impl Default for NetworkStatus {
    fn default() -> Self {
        Self {
            is_connected: false,
            interface_name: String::new(),
            ip_address: None,
            gateway: None,
            latency_ms: 0.0,
            packet_loss_percent: 0.0,
            active_threats: Vec::new(),
            last_update: Local::now(),
        }
    }
}
