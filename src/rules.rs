//! Minimal host-context rule engine (first-seen destinations, policy alerts).

use crate::models::{
    ConnectionSample, DestinationCategory, ThreatAlert, ThreatSeverity, ThreatType,
};
use chrono::Local;
use std::collections::HashSet;
use std::net::IpAddr;

pub struct RuleEngine {
    seen_destinations: HashSet<String>,
    /// When true, first connection to an unknown public host raises Medium Policy alert.
    alert_first_seen_unknown: bool,
    /// Alert when process talks to LLM category (informational Low by default).
    alert_llm_traffic: bool,
    seeded: bool,
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            seen_destinations: HashSet::new(),
            alert_first_seen_unknown: true,
            alert_llm_traffic: true,
            seeded: false,
        }
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
                && self.alert_first_seen_unknown
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

            // First-seen LLM destinations get a low-severity breadcrumb (not covered by
            // first-seen-unknown, which only fires for DestinationCategory::Unknown).
            if is_new && self.alert_llm_traffic && s.category == DestinationCategory::Llm {
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

            // Suspicious remote ports with process context
            if is_suspicious_port(s.remote_port)
                && s.category != DestinationCategory::Lan
                && s.category != DestinationCategory::Localhost
            {
                // Dedup via a pseudo-key so we don't re-alert every sample forever
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

fn is_suspicious_port(port: u16) -> bool {
    matches!(
        port,
        21 | 23 | 69 | 135 | 139 | 445 | 3389 | 4444 | 5555 | 6667 | 31337
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DestinationCategory;

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
    fn first_pass_seeds_without_alerts() {
        let mut eng = RuleEngine::new();
        let s = vec![sample(
            "1.2.3.4",
            443,
            DestinationCategory::Unknown,
            "python.exe",
        )];
        let a = eng.evaluate(&s);
        assert!(a.is_empty());
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
        assert!(eng.evaluate(&s1).is_empty()); // seed
        let s2 = vec![
            sample("1.2.3.4", 443, DestinationCategory::Llm, "chrome.exe"),
            sample("9.9.9.9", 443, DestinationCategory::Llm, "chrome.exe"),
        ];
        let a = eng.evaluate(&s2);
        assert_eq!(a.len(), 1);
        assert!(a[0].description.contains("LLM destination"));
        assert_eq!(a[0].severity, ThreatSeverity::Low);
    }
}
