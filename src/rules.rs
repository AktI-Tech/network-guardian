//! Host-context rule engine with YAML policy (`rules/default.yml`).
//!
//! Version 3 adds destination allow/deny lists, CIDR rules, and custom match rules.

use crate::models::{
    ConnectionSample, DestinationCategory, ThreatAlert, ThreatSeverity, ThreatType,
};
use chrono::Local;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

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
    /// Host/IP substrings or `.suffix` — suppress first-seen / custom noise.
    #[serde(default)]
    pub destination_allowlist: Vec<String>,
    /// Host/IP substrings — always alert (once per dest key).
    #[serde(default)]
    pub destination_denylist: Vec<String>,
    /// CIDR allow/alert rules.
    #[serde(default)]
    pub cidr_rules: Vec<CidrRule>,
    /// Explicit match → allow | alert rules (evaluated before built-ins when matching).
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,
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
    #[serde(default = "default_true")]
    pub alert_destination_denylist: bool,
    #[serde(default = "default_true")]
    pub alert_cidr_match: bool,
}

impl Default for RuleSettings {
    fn default() -> Self {
        Self {
            alert_first_seen_unknown: true,
            alert_llm_traffic: true,
            high_fanout_threshold: 25,
            alert_destination_denylist: true,
            alert_cidr_match: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CidrRule {
    pub cidr: String,
    /// allow | alert
    #[serde(default = "default_alert_action")]
    pub action: String,
    #[serde(default = "default_high")]
    pub severity: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    pub id: String,
    /// YAML key is `match:`.
    #[serde(default, rename = "match")]
    pub match_fields: CustomMatch,
    /// allow | alert
    #[serde(default = "default_alert_action")]
    pub action: String,
    #[serde(default = "default_medium")]
    pub severity: String,
    #[serde(default)]
    pub message: String,
    /// When true, only fire on first-seen dest key for this process/flow.
    #[serde(default = "default_true")]
    pub first_seen_only: bool,
}

/// Flattened match after load (handles `match` vs `match_fields` YAML keys).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CustomMatch {
    #[serde(default)]
    pub process: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub remote_host: Option<String>,
    #[serde(default)]
    pub remote_ip: Option<String>,
    #[serde(default)]
    pub remote_port: Option<u16>,
    /// If true, require unresolved public IP (no reverse DNS host).
    #[serde(default)]
    pub raw_ip_only: bool,
}

fn default_true() -> bool {
    true
}
fn default_version() -> u32 {
    3
}
fn default_fanout() -> u32 {
    25
}
fn default_alert_action() -> String {
    "alert".into()
}
fn default_high() -> String {
    "high".into()
}
fn default_medium() -> String {
    "medium".into()
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
            version: 3,
            settings: RuleSettings::default(),
            suspicious_ports: default_suspicious_ports(),
            process_allowlist: default_allowlist(),
            process_watchlist: default_watchlist(),
            llm_process_filter: Vec::new(),
            destination_allowlist: Vec::new(),
            destination_denylist: Vec::new(),
            cidr_rules: Vec::new(),
            custom_rules: Vec::new(),
        }
    }
}

impl RuleConfig {
    /// Load rules: optional path, else `rules/default.yml` on disk, else embedded default.
    pub fn load(path: Option<&Path>) -> Self {
        let mut cfg = if let Some(p) = path {
            load_yaml(p).unwrap_or_else(|_| Self::embedded_or_default())
        } else if let Ok(cfg) = load_yaml(Path::new("rules/default.yml")) {
            cfg
        } else {
            Self::embedded_or_default()
        };
        cfg.normalize();
        cfg
    }

    fn embedded_or_default() -> Self {
        serde_yaml::from_str(EMBEDDED_DEFAULT_RULES).unwrap_or_default()
    }

    fn normalize(&mut self) {
        // Placeholder for future migrations (v2 → v3 field renames).
        let _ = self.version;
    }

    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!("version={}", self.version),
            format!(
                "first_seen_unknown={} llm_traffic={} fanout={} denylist={} cidr={}",
                self.settings.alert_first_seen_unknown,
                self.settings.alert_llm_traffic,
                self.settings.high_fanout_threshold,
                self.settings.alert_destination_denylist,
                self.settings.alert_cidr_match
            ),
            format!(
                "ports={} proc_allow={} proc_watch={} dest_allow={} dest_deny={} cidrs={} custom={}",
                self.suspicious_ports.len(),
                self.process_allowlist.len(),
                self.process_watchlist.len(),
                self.destination_allowlist.len(),
                self.destination_denylist.len(),
                self.cidr_rules.len(),
                self.custom_rules.len()
            ),
        ]
    }
}

fn load_yaml(path: &Path) -> Result<RuleConfig, ()> {
    let text = std::fs::read_to_string(path).map_err(|_| ())?;
    serde_yaml::from_str(&text).map_err(|_| ())
}

pub struct RuleEngine {
    seen_destinations: HashSet<String>,
    fanout_alerted: HashSet<String>,
    config: RuleConfig,
    seeded: bool,
    parsed_cidrs: Vec<(IpNet, CidrRule)>,
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

    pub fn from_config(mut config: RuleConfig) -> Self {
        config.normalize();
        let parsed_cidrs = config
            .cidr_rules
            .iter()
            .filter_map(|r| IpNet::from_str(r.cidr.trim()).ok().map(|n| (n, r.clone())))
            .collect();
        Self {
            seen_destinations: HashSet::new(),
            fanout_alerted: HashSet::new(),
            config,
            seeded: false,
            parsed_cidrs,
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

            // Destination allowlist / CIDR allow / custom allow → skip built-ins for this flow
            if dest_allowed(s, &self.config, &self.parsed_cidrs)
                || custom_allows(s, &self.config.custom_rules)
            {
                continue;
            }

            // Denylist (substring host/IP)
            if self.config.settings.alert_destination_denylist
                && dest_matches_list(s, &self.config.destination_denylist)
            {
                let dkey = format!("deny|{key}");
                if self.seen_destinations.insert(dkey) {
                    alerts.push(ThreatAlert {
                        threat_type: ThreatType::Policy,
                        severity: ThreatSeverity::High,
                        ip: s.remote_addr.parse::<IpAddr>().ok(),
                        description: format!(
                            "Denylisted destination {} ({}) via {} (pid {})",
                            display_dest(s),
                            s.remote_addr,
                            proc,
                            s.pid.unwrap_or(0)
                        ),
                        timestamp: Local::now(),
                    });
                }
            }

            // CIDR alert rules
            if self.config.settings.alert_cidr_match {
                if let Some((net, rule)) = self.matching_cidr(s) {
                    if rule.action.eq_ignore_ascii_case("alert") {
                        let dkey = format!("cidr|{}|{}", net, key);
                        if self.seen_destinations.insert(dkey) {
                            let note = if rule.note.is_empty() {
                                String::new()
                            } else {
                                format!(" — {}", rule.note)
                            };
                            alerts.push(ThreatAlert {
                                threat_type: ThreatType::Policy,
                                severity: parse_severity(&rule.severity),
                                ip: s.remote_addr.parse::<IpAddr>().ok(),
                                description: format!(
                                    "CIDR match {} → {} via {} (pid {}){}",
                                    net,
                                    s.remote_addr,
                                    proc,
                                    s.pid.unwrap_or(0),
                                    note
                                ),
                                timestamp: Local::now(),
                            });
                        }
                    }
                }
            }

            // Custom alert rules
            for rule in &self.config.custom_rules {
                if !rule.action.eq_ignore_ascii_case("alert") {
                    continue;
                }
                if !custom_matches(s, &rule.match_fields) {
                    continue;
                }
                if rule.first_seen_only && !is_new {
                    continue;
                }
                let ckey = format!("custom|{}|{}", rule.id, key);
                if !self.seen_destinations.insert(ckey) {
                    continue;
                }
                let msg = if rule.message.is_empty() {
                    format!("Custom rule {} matched", rule.id)
                } else {
                    rule.message.clone()
                };
                alerts.push(ThreatAlert {
                    threat_type: ThreatType::Policy,
                    severity: parse_severity(&rule.severity),
                    ip: s.remote_addr.parse::<IpAddr>().ok(),
                    description: format!(
                        "{} — {} → {}:{} (pid {})",
                        msg,
                        proc,
                        s.remote_addr,
                        s.remote_port,
                        s.pid.unwrap_or(0)
                    ),
                    timestamp: Local::now(),
                });
            }

            if is_new
                && self.config.settings.alert_first_seen_unknown
                && s.category == DestinationCategory::Unknown
                && !is_local_category(&s.category)
                && !name_matches(proc, &self.config.process_allowlist)
                && !dest_matches_list(s, &self.config.destination_allowlist)
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
                if dest_allowed(s, &self.config, &self.parsed_cidrs) {
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

    fn matching_cidr(&self, s: &ConnectionSample) -> Option<(IpNet, CidrRule)> {
        let ip: IpAddr = s.remote_addr.parse().ok()?;
        self.parsed_cidrs
            .iter()
            .find(|(net, _)| net.contains(&ip))
            .map(|(n, r)| (*n, r.clone()))
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

fn display_dest(s: &ConnectionSample) -> String {
    s.resolved_host
        .clone()
        .or_else(|| s.destination_label.clone())
        .unwrap_or_else(|| s.remote_addr.clone())
}

/// Substring or leading-dot suffix match against remote IP / resolved host / label.
fn dest_matches_list(s: &ConnectionSample, list: &[String]) -> bool {
    if list.is_empty() {
        return false;
    }
    let candidates = [
        s.remote_addr.to_ascii_lowercase(),
        s.resolved_host
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase(),
        s.destination_label
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase(),
    ];
    for pat in list {
        let p = pat.trim().to_ascii_lowercase();
        if p.is_empty() {
            continue;
        }
        for c in &candidates {
            if c.is_empty() {
                continue;
            }
            if p.starts_with('.') {
                // suffix: ".microsoft.com"
                if c == p.trim_start_matches('.') || c.ends_with(&p) {
                    return true;
                }
            } else if c.contains(&p) || c == &p {
                return true;
            }
        }
    }
    false
}

fn dest_allowed(
    s: &ConnectionSample,
    cfg: &RuleConfig,
    parsed_cidrs: &[(IpNet, CidrRule)],
) -> bool {
    if dest_matches_list(s, &cfg.destination_allowlist) {
        return true;
    }
    if let Ok(ip) = s.remote_addr.parse::<IpAddr>() {
        for (net, rule) in parsed_cidrs {
            if net.contains(&ip) && rule.action.eq_ignore_ascii_case("allow") {
                return true;
            }
        }
    }
    false
}

fn custom_allows(s: &ConnectionSample, rules: &[CustomRule]) -> bool {
    rules
        .iter()
        .any(|r| r.action.eq_ignore_ascii_case("allow") && custom_matches(s, &r.match_fields))
}

fn custom_matches(s: &ConnectionSample, m: &CustomMatch) -> bool {
    if let Some(ref p) = m.process {
        let proc = s.process_name.as_deref().unwrap_or("");
        if !name_matches(proc, std::slice::from_ref(p)) {
            return false;
        }
    }
    if let Some(ref cat) = m.category {
        let c = format!("{:?}", s.category).to_ascii_lowercase();
        // DestinationCategory Debug is like "Unknown" — also accept snake
        let want = cat.to_ascii_lowercase();
        let cat_str = match s.category {
            DestinationCategory::Llm => "llm",
            DestinationCategory::Registry => "registry",
            DestinationCategory::Cloud => "cloud",
            DestinationCategory::Lan => "lan",
            DestinationCategory::Localhost => "localhost",
            DestinationCategory::Unknown => "unknown",
        };
        if cat_str != want.as_str() && !c.contains(&want) {
            return false;
        }
    }
    if let Some(ref host) = m.remote_host {
        let h = host.to_ascii_lowercase();
        let resolved = s
            .resolved_host
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let label = s
            .destination_label
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        if !(resolved.contains(&h)
            || label.contains(&h)
            || s.remote_addr.to_ascii_lowercase().contains(&h))
        {
            return false;
        }
    }
    if let Some(ref ip) = m.remote_ip {
        if !s.remote_addr.eq_ignore_ascii_case(ip.trim()) {
            return false;
        }
    }
    if let Some(port) = m.remote_port {
        if s.remote_port != port {
            return false;
        }
    }
    if m.raw_ip_only {
        let has_host = s
            .resolved_host
            .as_deref()
            .map(|h| !h.is_empty())
            .unwrap_or(false);
        if has_host || is_local_category(&s.category) {
            return false;
        }
        // must look like an IP
        if s.remote_addr.parse::<IpAddr>().is_err() {
            return false;
        }
    }
    // If match is completely empty, do not match everything
    m.process.is_some()
        || m.category.is_some()
        || m.remote_host.is_some()
        || m.remote_ip.is_some()
        || m.remote_port.is_some()
        || m.raw_ip_only
}

fn parse_severity(s: &str) -> ThreatSeverity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => ThreatSeverity::Critical,
        "high" => ThreatSeverity::High,
        "low" => ThreatSeverity::Low,
        _ => ThreatSeverity::Medium,
    }
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

    fn sample_host(
        remote: &str,
        host: &str,
        port: u16,
        cat: DestinationCategory,
        proc: &str,
    ) -> ConnectionSample {
        let mut s = sample(remote, port, cat, proc);
        s.resolved_host = Some(host.into());
        s
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
    fn destination_allowlist_suppresses() {
        let mut eng = RuleEngine::from_config(RuleConfig {
            process_allowlist: vec![],
            destination_allowlist: vec![".example.com".into()],
            ..RuleConfig::default()
        });
        eng.evaluate(&[sample_host(
            "1.2.3.4",
            "cdn.example.com",
            443,
            DestinationCategory::Unknown,
            "app.exe",
        )]);
        let a = eng.evaluate(&[sample_host(
            "5.6.7.8",
            "api.example.com",
            443,
            DestinationCategory::Unknown,
            "app.exe",
        )]);
        assert!(a.iter().all(|x| !x.description.contains("First-seen")));
    }

    #[test]
    fn destination_denylist_alerts() {
        let mut eng = RuleEngine::from_config(RuleConfig {
            process_allowlist: vec![],
            destination_denylist: vec!["evil.example".into()],
            settings: RuleSettings {
                alert_first_seen_unknown: false,
                ..RuleSettings::default()
            },
            ..RuleConfig::default()
        });
        eng.evaluate(&[sample(
            "1.2.3.4",
            443,
            DestinationCategory::Unknown,
            "app.exe",
        )]);
        let a = eng.evaluate(&[sample_host(
            "9.9.9.9",
            "evil.example",
            443,
            DestinationCategory::Unknown,
            "app.exe",
        )]);
        assert!(a.iter().any(|x| x.description.contains("Denylisted")));
    }

    #[test]
    fn cidr_alert_rule() {
        let mut eng = RuleEngine::from_config(RuleConfig {
            process_allowlist: vec![],
            settings: RuleSettings {
                alert_first_seen_unknown: false,
                ..RuleSettings::default()
            },
            cidr_rules: vec![CidrRule {
                cidr: "10.20.30.0/24".into(),
                action: "alert".into(),
                severity: "high".into(),
                note: "lab range".into(),
            }],
            ..RuleConfig::default()
        });
        eng.evaluate(&[sample(
            "1.1.1.1",
            443,
            DestinationCategory::Unknown,
            "app.exe",
        )]);
        let a = eng.evaluate(&[sample(
            "10.20.30.5",
            443,
            DestinationCategory::Unknown,
            "app.exe",
        )]);
        assert!(a.iter().any(|x| x.description.contains("CIDR match")));
    }

    #[test]
    fn custom_rule_raw_ip() {
        let mut eng = RuleEngine::from_config(RuleConfig {
            process_allowlist: vec![],
            settings: RuleSettings {
                alert_first_seen_unknown: false,
                ..RuleSettings::default()
            },
            custom_rules: vec![CustomRule {
                id: "py-raw".into(),
                match_fields: CustomMatch {
                    process: Some("python".into()),
                    raw_ip_only: true,
                    ..Default::default()
                },
                action: "alert".into(),
                severity: "high".into(),
                message: "Python to raw IP".into(),
                first_seen_only: true,
            }],
            ..RuleConfig::default()
        });
        eng.evaluate(&[sample(
            "1.1.1.1",
            443,
            DestinationCategory::Unknown,
            "python.exe",
        )]);
        let a = eng.evaluate(&[sample(
            "8.8.4.4",
            443,
            DestinationCategory::Unknown,
            "python.exe",
        )]);
        assert!(a.iter().any(|x| x.description.contains("Python to raw IP")));
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

    #[test]
    fn yaml_custom_match_key() {
        let y = r#"
version: 3
custom_rules:
  - id: test
    match:
      process: curl
      remote_ip: "1.2.3.4"
    action: alert
    severity: high
    message: hit
"#;
        let mut cfg: RuleConfig = serde_yaml::from_str(y).unwrap();
        cfg.normalize();
        assert_eq!(
            cfg.custom_rules[0].match_fields.process.as_deref(),
            Some("curl")
        );
    }
}
