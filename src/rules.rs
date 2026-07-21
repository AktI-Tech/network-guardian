//! Host-context rule engine with YAML policy (`rules/default.yml`).

use crate::models::{
    ConnectionSample, DestinationCategory, ThreatAlert, ThreatSeverity, ThreatType,
};
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

const EMBEDDED_DEFAULT_RULES: &str = include_str!("../rules/default.yml");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub settings: RuleSettings,
    #[serde(default = "default_suspicious_ports")]
    pub suspicious_ports: Vec<u16>,
    /// Process name substrings — suppress first-seen unknown.
    #[serde(default)]
    pub process_allowlist: Vec<String>,
    /// Process name substrings — elevate first-seen unknown to High.
    #[serde(default)]
    pub process_watchlist: Vec<String>,
    /// If non-empty, LLM first-seen only for matching processes.
    #[serde(default)]
    pub llm_process_filter: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSettings {
    #[serde(default = "default_true")]
    pub alert_first_seen_unknown: bool,
    #[serde(default = "default_true")]
    pub alert_llm_traffic: bool,
    /// Unique remotes per process name in one sample; 0 disables.
    #[serde(default = "default_fanout")]
    pub high_fanout_threshold: u32,
}

impl Default for RuleSettings {
    fn default() -> Self {
        Self {
            alert_first_seen_unknown: true,
            alert_llm_traffic: true,
            high_fanout_threshold: 25,
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_version() -> u32 {
    2
}

fn default_fanout() -> u32 {
    25
}

fn default_suspicious_ports() -> Vec<u16> {
    vec![21, 23, 69, 135, 139, 445, 3389, 4444, 5555, 6667, 31337]
}

fn default_allowlist() -> Vec<String> {
    vec![
        "svchost".into(),
        "SearchHost".into(),
        "System".into(),
        "Idle".into(),
    ]
}

fn default_watchlist() -> Vec<String> {
    vec![
        "python".into(),
        "node".into(),
        "powershell".into(),
        "pwsh".into(),
        "cmd.exe".into(),
        "curl".into(),
        "wsl".into(),
    ]
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            version: 2,
            settings: RuleSettings::default(),
            suspicious_ports: default_suspicious_ports(),
            process_allowlist: default_allowlist(),
            process_watchlist: default_watchlist(),
            llm_process_filter: Vec::new(),
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

    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!("version={}", self.version),
            format!(
                "first_seen_unknown={} llm_traffic={} fanout={}",
                self.settings.alert_first_seen_unknown,
                self.settings.alert_llm_traffic,
                self.settings.high_fanout_threshold
            ),
            format!(
                "suspicious_ports={} allowlist={} watchlist={}",
                self.suspicious_ports.len(),
                self.process_allowlist.len(),
                self.process_watchlist.len()
            ),
        ]
    }
}

pub struct RuleEngine {
    seen_destinations: HashSet<String>,
    fanout_alerted: HashSet<String>,
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
            fanout_alerted: HashSet::new(),
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
            let proc = s.process_name.as_deref().unwrap_or("unknown");
            let key = dest_key(s);
            let is_new = self.seen_destinations.insert(key.clone());

            if is_new
                && self.config.settings.alert_first_seen_unknown
                && s.category == DestinationCategory::Unknown
                && !is_local_category(&s.category)
                && !name_matches(proc, &self.config.process_allowlist)
            {
                let watched = name_matches(proc, &self.config.process_watchlist);
                let severity = if watched {
                    ThreatSeverity::High
                } else {
                    ThreatSeverity::Medium
                };
                let watch_tag = if watched { " [watchlist]" } else { "" };
                alerts.push(ThreatAlert {
                    threat_type: ThreatType::Policy,
                    severity,
                    ip: s.remote_addr.parse::<IpAddr>().ok(),
                    description: format!(
                        "First-seen destination {} {} from {} (pid {}){}",
                        s.remote_addr,
                        s.remote_port,
                        proc,
                        s.pid.unwrap_or(0),
                        watch_tag
                    ),
                    timestamp: Local::now(),
                });
            }

            if is_new
                && self.config.settings.alert_llm_traffic
                && s.category == DestinationCategory::Llm
                && llm_process_allowed(proc, &self.config.llm_process_filter)
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
                        proc,
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
                            s.remote_port, proc, s.remote_addr
                        ),
                        timestamp: Local::now(),
                    });
                }
            }
        }

        // High fan-out: many unique remotes for one process in this sample
        let threshold = self.config.settings.high_fanout_threshold;
        if threshold > 0 {
            let mut by_proc: HashMap<String, HashSet<String>> = HashMap::new();
            for s in samples {
                if is_local_category(&s.category) {
                    continue;
                }
                let proc = s
                    .process_name
                    .clone()
                    .unwrap_or_else(|| format!("pid:{}", s.pid.unwrap_or(0)));
                if name_matches(&proc, &self.config.process_allowlist) {
                    continue;
                }
                by_proc
                    .entry(proc)
                    .or_default()
                    .insert(s.remote_addr.clone());
            }
            for (proc, remotes) in by_proc {
                let n = remotes.len() as u32;
                if n >= threshold && self.fanout_alerted.insert(proc.clone()) {
                    alerts.push(ThreatAlert {
                        threat_type: ThreatType::TrafficAnomaly,
                        severity: ThreatSeverity::Medium,
                        ip: None,
                        description: format!(
                            "High fan-out: {} has {} unique remote hosts in one sample (threshold {})",
                            proc, n, threshold
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

fn name_matches(process_name: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let n = process_name.to_ascii_lowercase();
    patterns
        .iter()
        .any(|p| !p.is_empty() && n.contains(&p.to_ascii_lowercase()))
}

fn llm_process_allowed(process_name: &str, filter: &[String]) -> bool {
    filter.is_empty() || name_matches(process_name, filter)
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
        assert!(!cfg.process_watchlist.is_empty());
        assert!(!cfg.process_allowlist.is_empty());
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
        let mut eng = RuleEngine::from_config(RuleConfig {
            process_allowlist: vec![],
            process_watchlist: vec![],
            ..RuleConfig::default()
        });
        eng.evaluate(&[sample(
            "1.2.3.4",
            443,
            DestinationCategory::Unknown,
            "app.exe",
        )]);
        let a = eng.evaluate(&[
            sample("1.2.3.4", 443, DestinationCategory::Unknown, "app.exe"),
            sample("5.6.7.8", 443, DestinationCategory::Unknown, "app.exe"),
        ]);
        assert_eq!(a.len(), 1);
        assert!(a[0].description.contains("5.6.7.8"));
        assert_eq!(a[0].severity, ThreatSeverity::Medium);
    }

    #[test]
    fn watchlist_elevates_severity() {
        let mut eng = RuleEngine::from_config(RuleConfig {
            process_allowlist: vec![],
            process_watchlist: vec!["python".into()],
            ..RuleConfig::default()
        });
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
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].severity, ThreatSeverity::High);
        assert!(a[0].description.contains("watchlist"));
    }

    #[test]
    fn allowlist_suppresses_first_seen() {
        let mut eng = RuleEngine::from_config(RuleConfig {
            process_allowlist: vec!["chrome".into()],
            process_watchlist: vec![],
            ..RuleConfig::default()
        });
        eng.evaluate(&[sample(
            "1.2.3.4",
            443,
            DestinationCategory::Unknown,
            "chrome.exe",
        )]);
        let a = eng.evaluate(&[sample(
            "9.9.9.9",
            443,
            DestinationCategory::Unknown,
            "chrome.exe",
        )]);
        assert!(a.is_empty());
    }

    #[test]
    fn first_seen_llm_alerts_low() {
        let mut eng = RuleEngine::from_config(RuleConfig {
            process_allowlist: vec![],
            ..RuleConfig::default()
        });
        eng.evaluate(&[sample(
            "1.2.3.4",
            443,
            DestinationCategory::Llm,
            "chrome.exe",
        )]);
        let a = eng.evaluate(&[
            sample("1.2.3.4", 443, DestinationCategory::Llm, "chrome.exe"),
            sample("9.9.9.9", 443, DestinationCategory::Llm, "chrome.exe"),
        ]);
        assert_eq!(a.len(), 1);
        assert!(a[0].description.contains("LLM destination"));
        assert_eq!(a[0].severity, ThreatSeverity::Low);
    }

    #[test]
    fn high_fanout_alerts_once() {
        let mut cfg = RuleConfig::default();
        cfg.settings.high_fanout_threshold = 3;
        cfg.process_allowlist = vec![];
        let mut eng = RuleEngine::from_config(cfg);
        // seed
        eng.evaluate(&[sample(
            "1.1.1.1",
            443,
            DestinationCategory::Unknown,
            "node.exe",
        )]);
        let many: Vec<_> = (0..5)
            .map(|i| {
                sample(
                    &format!("1.2.3.{i}"),
                    443,
                    DestinationCategory::Unknown,
                    "node.exe",
                )
            })
            .collect();
        let a = eng.evaluate(&many);
        let fanout: Vec<_> = a
            .iter()
            .filter(|x| x.description.contains("fan-out"))
            .collect();
        assert_eq!(fanout.len(), 1);
        // second sample should not re-alert fanout
        let a2 = eng.evaluate(&many);
        assert!(!a2.iter().any(|x| x.description.contains("fan-out")));
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
        assert!(a.iter().all(|x| !x.description.contains("First-seen")));
    }
}
