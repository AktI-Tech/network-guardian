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
    /// Rule-engine or first-seen style host alert
    Policy,
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
        matches!(
            self.severity,
            ThreatSeverity::Critical | ThreatSeverity::High
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DestinationCategory {
    Llm,
    Registry,
    Cloud,
    Lan,
    Localhost,
    Unknown,
}

impl DestinationCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            DestinationCategory::Llm => "llm",
            DestinationCategory::Registry => "registry",
            DestinationCategory::Cloud => "cloud",
            DestinationCategory::Lan => "lan",
            DestinationCategory::Localhost => "localhost",
            DestinationCategory::Unknown => "unknown",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "llm" => DestinationCategory::Llm,
            "registry" => DestinationCategory::Registry,
            "cloud" => DestinationCategory::Cloud,
            "lan" => DestinationCategory::Lan,
            "localhost" => DestinationCategory::Localhost,
            _ => DestinationCategory::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSample {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub category: DestinationCategory,
    pub destination_label: Option<String>,
    /// Reverse-DNS or catalog hostname when available.
    pub resolved_host: Option<String>,
    /// Builder stack hint: wsl | docker | llm-local
    pub stack_hint: Option<String>,
    pub first_seen: DateTime<Local>,
    pub last_seen: DateTime<Local>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WslDistro {
    pub name: String,
    pub state: String,
    pub version: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerPublishedPort {
    /// Original fragment from `docker ps` Ports column.
    pub raw: String,
    pub host_ip: Option<String>,
    pub host_port: Option<String>,
    pub container_port: Option<String>,
    pub protocol: Option<String>,
    /// localhost | lan | all-interfaces | unpublished
    pub exposure: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerContainer {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub ports: String,
    pub running: bool,
    /// `com.docker.compose.project` when present.
    pub compose_project: Option<String>,
    pub published: Vec<DockerPublishedPort>,
    /// Worst exposure among published ports (localhost < lan < all-interfaces).
    pub max_exposure: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerNetwork {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub scope: String,
}

/// Host-published mapping that is not loopback-only (security-relevant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerHostExposure {
    pub container: String,
    pub image: String,
    pub host_ip: String,
    pub host_port: String,
    pub container_port: String,
    pub protocol: String,
    /// lan | all-interfaces
    pub exposure: String,
    pub compose_project: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackInterface {
    pub name: String,
    /// host | wsl | docker | hyper-v | vpn | other
    pub kind: String,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuilderEnvironment {
    pub wsl_detected: bool,
    pub docker_detected: bool,
    pub docker_engine_ok: bool,
    /// Docker Engine server version when reachable.
    pub docker_version: Option<String>,
    pub docker_context: Option<String>,
    pub docker_running: usize,
    pub docker_stopped: usize,
    pub wsl_distros: Vec<WslDistro>,
    pub docker_containers: Vec<DockerContainer>,
    pub docker_networks: Vec<DockerNetwork>,
    /// Non-loopback host port publishes (builders often forget these).
    pub docker_host_exposure: Vec<DockerHostExposure>,
    pub interfaces: Vec<StackInterface>,
    pub notes: Vec<String>,
    pub probed_at: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub motto: String,
    pub version: String,
    pub listening: String,
    pub sample_interval_secs: u64,
    pub connection_count: usize,
    pub alert_count: i64,
    pub uptime_secs: u64,
    pub wsl_detected: bool,
    pub docker_detected: bool,
}
