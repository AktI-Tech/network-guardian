//! Host-context rule engine with optional YAML config (`rules/default.yml`).

use crate::models::{
    ConnectionSample, DestinationCategory, ThreatAlert, ThreatSeverity, ThreatType,
};
use chrono::Local;
use serde::Deserialize;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;

const EMBEDDED_DEFAULT_RULES: &str = include_str!("../rules/default.yml");

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub settings: RuleSettings,
    #[serde(default = "default_suspicious_ports")]
    pub suspicious_ports: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleSettings {
    #[serde(default = "default_true")]
    pub alert_first_seen_unknown: bool,
    #[serde(default = "default_true")]
    pub alert_llm_traffic: bool,
}

impl Default for RuleSettings {
    fn default() -> Self {
        Self {
            alert_first_seen_unknown: true,
            alert_llm_traffic: true,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_version() -> u32 {
    1
}

fn default_suspicious_ports() -> Vec<u16> {
    vec![21, 23, 69, 135, 139, 445, 3389, 4444, 5555, 6667, 31337]
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            version: 1,
            settings: RuleSettings::default(),
            suspicious_ports: default_suspicious_ports(),
        }
    }
}

impl RuleConfig {
    /// Load rules: optional path, else `rules/default.yml` on disk, else embedded default.
    pub fn load(path: Option<&Path>) -> Self {
        if let Some(p) = path {
            if let Ok(text) = std::fs::read_to_string(p) {
                if let Ok(cfg) = serde_yaml::from_str::<RuleConfig>(&text) {
                    return cfg;
                }
            }
        }
        if let Ok(text) = std::fs::read_to_string("rules/default.yml") {
            if let Ok(cfg) = serde_yaml::from_str::<RuleConfig>(&text) {
                return cfg;
            }
        }
        serde_yaml::from_str(EMBEDDED_DEFAULT_RULES).unwrap_or_default()
    }
}

pub struct RuleEngine {
    seen_destinations: HashSet<String>,
    config: RuleConfig,
    seeded: bool,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleEngine {
    pub fn new() -> Self {
        Self::from_config(RuleConfig::load(None))
    }

    pub fn from_config(config: RuleConfig) -> Self {
        Self {
            seen_destinations: HashSet::new(),
            config,
            seeded: false,
        }
    }

    pub fn config(&self) -> &RuleConfig {
        &self.config
    }

    /// First sample only seeds the set so restart doesn't page you with every existing flow.
    pub fn evaluate(&mut self, samples: &[ConnectionSample]) -> Vec<ThreatAlert> {
        let mut alerts = Vec::new();

        if !self.seeded {
            for s in samples {
                self.seen_destinations.insert(dest_key(s));
            }
            self.seeded = true;
            return alerts;
        }

        for s in samples {
            let key = dest_key(s);
            let is_new = self.seen_destinations.insert(key.clone());

            if is_new
                && self.config.settings.alert_first_seen_unknown
                && s.category == DestinationCategory::Unknown
                && !is_local_category(&s.category)
            {
                alerts.push(ThreatAlert {
                    threat_type: ThreatType::Policy,
                    severity: ThreatSeverity::Medium,
                    ip: s.remote_addr.parse::<IpAddr>().ok(),
                    description: format!(
                        "First-seen destination {} {} from {} (pid {})",
                        s.remote_addr,
                        s.remote_port,
                        s.process_name.as_deref().unwrap_or("unknown"),
                        s.pid.unwrap_or(0)
                    ),
                    timestamp: Local::now(),
                });
            }

            if is_new
                && self.config.settings.alert_llm_traffic
                && s.category == DestinationCategory::Llm
            {
                let label = s
                    .destination_label
                    .as_deref()
                    .or(s.resolved_host.as_deref())
                    .unwrap_or(&s.remote_addr);
                alerts.push(ThreatAlert {
                    threat_type: ThreatType::Policy,
                    severity: ThreatSeverity::Low,
                    ip: s.remote_addr.parse::<IpAddr>().ok(),
                    description: format!(
                        "LLM destination first seen: {} ({}:{}) via {} (pid {})",
                        label,
                        s.remote_addr,
                        s.remote_port,
                        s.process_name.as_deref().unwrap_or("unknown"),
                        s.pid.unwrap_or(0)
                    ),
                    timestamp: Local::now(),
                });
            }

            if self.is_suspicious_port(s.remote_port)
                && s.category != DestinationCategory::Lan
                && s.category != DestinationCategory::Localhost
            {
                let port_key = format!(
                    "susport|{}|{}|{}",
                    s.pid.unwrap_or(0),
                    s.remote_addr,
                    s.remote_port
                );
                if self.seen_destinations.insert(port_key) {
                    alerts.push(ThreatAlert {
                        threat_type: ThreatType::TrafficAnomaly,
                        severity: ThreatSeverity::High,
                        ip: s.remote_addr.parse::<IpAddr>().ok(),
                        description: format!(
                            "Suspicious port {} accessed by {} → {}",
                            s.remote_port,
                            s.process_name.as_deref().unwrap_or("unknown"),
                            s.remote_addr
                        ),
                        timestamp: Local::now(),
                    });
                }
            }
        }

        alerts
    }

    fn is_suspicious_port(&self, port: u16) -> bool {
        self.config.suspicious_ports.contains(&port)
    }
}

fn dest_key(s: &ConnectionSample) -> String {
    format!(
        "{}|{}|{}",
        s.process_name.as_deref().unwrap_or("?"),
        s.remote_addr,
        s.remote_port
    )
}

fn is_local_category(c: &DestinationCategory) -> bool {
    matches!(c, DestinationCategory::Lan | DestinationCategory::Localhost)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(remote: &str, port: u16, cat: DestinationCategory, proc: &str) -> ConnectionSample {
        ConnectionSample {
            protocol: "TCP".into(),
            local_addr: "10.0.0.2".into(),
            local_port: 50000,
            remote_addr: remote.into(),
            remote_port: port,
            state: "ESTABLISHED".into(),
            pid: Some(1234),
            process_name: Some(proc.into()),
            process_path: None,
            category: cat,
            destination_label: None,
            resolved_host: None,
            stack_hint: None,
            first_seen: Local::now(),
            last_seen: Local::now(),
        }
    }

    #[test]
    fn loads_embedded_default() {
        let cfg: RuleConfig = serde_yaml::from_str(EMBEDDED_DEFAULT_RULES).unwrap();
        assert!(cfg.settings.alert_first_seen_unknown);
        assert!(cfg.suspicious_ports.contains(&445));
    }

    #[test]
    fn first_pass_seeds_without_alerts() {
        let mut eng = RuleEngine::new();
        let s = vec![sample(
            "1.2.3.4",
            443,
            DestinationCategory::Unknown,
            "python.exe",
        )];
        assert!(eng.evaluate(&s).is_empty());
    }

    #[test]
    fn second_pass_alerts_new_unknown() {
        let mut eng = RuleEngine::new();
        let s1 = vec![sample(
            "1.2.3.4",
            443,
            DestinationCategory::Unknown,
            "python.exe",
        )];
        eng.evaluate(&s1);
        let s2 = vec![
            sample("1.2.3.4", 443, DestinationCategory::Unknown, "python.exe"),
            sample("5.6.7.8", 443, DestinationCategory::Unknown, "python.exe"),
        ];
        let a = eng.evaluate(&s2);
        assert_eq!(a.len(), 1);
        assert!(a[0].description.contains("5.6.7.8"));
    }

    #[test]
    fn first_seen_llm_alerts_low() {
        let mut eng = RuleEngine::new();
        let s1 = vec![sample(
            "1.2.3.4",
            443,
            DestinationCategory::Llm,
            "chrome.exe",
        )];
        assert!(eng.evaluate(&s1).is_empty());
        let s2 = vec![
            sample("1.2.3.4", 443, DestinationCategory::Llm, "chrome.exe"),
            sample("9.9.9.9", 443, DestinationCategory::Llm, "chrome.exe"),
        ];
        let a = eng.evaluate(&s2);
        assert_eq!(a.len(), 1);
        assert!(a[0].description.contains("LLM destination"));
        assert_eq!(a[0].severity, ThreatSeverity::Low);
    }

    #[test]
    fn can_disable_unknown_via_config() {
        let mut cfg = RuleConfig::default();
        cfg.settings.alert_first_seen_unknown = false;
        let mut eng = RuleEngine::from_config(cfg);
        eng.evaluate(&[sample(
            "1.2.3.4",
            443,
            DestinationCategory::Unknown,
            "python.exe",
        )]);
        let a = eng.evaluate(&[sample(
            "9.9.9.9",
            443,
            DestinationCategory::Unknown,
            "python.exe",
        )]);
        assert!(a.is_empty());
    }
}
