use crate::models::{ThreatAlert, ThreatType, ThreatSeverity};
use std::collections::HashMap;
use std::net::IpAddr;

pub struct ThreatDetector {
    arp_table: HashMap<IpAddr, String>, // IP -> MAC mapping
    baseline_traffic: TrafficBaseline,
    dns_cache: DnsCache,
}

struct TrafficBaseline {
    packets_per_second: f64,
    bytes_per_second: f64,
    sample_count: usize,
}

struct DnsCache {
    responses: HashMap<String, Vec<IpAddr>>,
}

impl ThreatDetector {
    pub fn new() -> Self {
        Self {
            arp_table: HashMap::new(),
            baseline_traffic: TrafficBaseline {
                packets_per_second: 0.0,
                bytes_per_second: 0.0,
                sample_count: 0,
            },
            dns_cache: DnsCache {
                responses: HashMap::new(),
            },
        }
    }
    
    /// Detect ARP spoofing by monitoring IP-MAC mappings
    pub fn detect_arp_spoofing(&mut self, ip: IpAddr, mac: String) -> Option<ThreatAlert> {
        if let Some(known_mac) = self.arp_table.get(&ip) {
            if known_mac != &mac {
                return Some(ThreatAlert {
                    threat_type: ThreatType::ArpSpoofing,
                    severity: ThreatSeverity::High,
                    ip: Some(ip),
                    description: format!(
                        "ARP spoofing detected! IP {} changed from MAC {} to {}",
                        ip, known_mac, mac
                    ),
                    timestamp: chrono::Local::now(),
                });
            }
        } else {
            self.arp_table.insert(ip, mac);
        }
        
        None
    }
    
    /// Detect DNS spoofing by validating responses
    pub fn detect_dns_spoofing(
        &mut self,
        domain: &str,
        ip: IpAddr,
    ) -> Option<ThreatAlert> {
        let entry = self.dns_cache.responses.entry(domain.to_string()).or_default();
        
        if !entry.is_empty() && !entry.contains(&ip) {
            // Different IP for same domain - potential spoofing
            return Some(ThreatAlert {
                threat_type: ThreatType::DnsSpoofing,
                severity: ThreatSeverity::High,
                ip: Some(ip),
                description: format!(
                    "DNS anomaly detected for {}. Expected {:?}, got {}",
                    domain, entry, ip
                ),
                timestamp: chrono::Local::now(),
            });
        }
        
        if !entry.contains(&ip) {
            entry.push(ip);
        }
        
        None
    }
    
    /// Detect MITM attacks by monitoring SSL/TLS certificate mismatches
    pub fn detect_mitm(&self, host: &str, cert_issuer: &str) -> Option<ThreatAlert> {
        // Simplified check - in production, validate against certificate pinning/TOFU
        if cert_issuer.contains("FAKE") || cert_issuer.contains("UNKNOWN") {
            return Some(ThreatAlert {
                threat_type: ThreatType::MitmAttack,
                severity: ThreatSeverity::Critical,
                ip: None,
                description: format!(
                    "Potential MITM attack detected on {}. Suspicious certificate: {}",
                    host, cert_issuer
                ),
                timestamp: chrono::Local::now(),
            });
        }
        
        None
    }
    
    /// Detect rogue wireless access points
    pub fn detect_rogue_ap(&self, ssid: &str, mac: &str, signal_strength: i32) -> Option<ThreatAlert> {
        // Check for known malicious SSIDs or suspicious characteristics
        if ssid.contains("FREE_WIFI") || ssid.contains("GUEST_NETWORK") || ssid.is_empty() {
            if signal_strength > -30 { // Suspiciously strong signal
                return Some(ThreatAlert {
                    threat_type: ThreatType::RogueAccessPoint,
                    severity: ThreatSeverity::High,
                    ip: None,
                    description: format!(
                        "Suspicious access point detected: SSID='{}', MAC={}, Signal={}dBm",
                        ssid, mac, signal_strength
                    ),
                    timestamp: chrono::Local::now(),
                });
            }
        }
        
        None
    }
    
    /// Detect traffic anomalies using baseline analysis
    pub fn detect_traffic_anomaly(
        &mut self,
        current_pps: f64,
        current_bps: f64,
    ) -> Option<ThreatAlert> {
        self.baseline_traffic.packets_per_second =
            (self.baseline_traffic.packets_per_second * self.baseline_traffic.sample_count as f64
                + current_pps)
                / (self.baseline_traffic.sample_count as f64 + 1.0);
        self.baseline_traffic.bytes_per_second =
            (self.baseline_traffic.bytes_per_second * self.baseline_traffic.sample_count as f64
                + current_bps)
                / (self.baseline_traffic.sample_count as f64 + 1.0);
        self.baseline_traffic.sample_count += 1;
        
        // Detect if traffic is 5x baseline (potential DDoS or data exfiltration)
        if self.baseline_traffic.sample_count > 10 {
            if current_pps > self.baseline_traffic.packets_per_second * 5.0
                || current_bps > self.baseline_traffic.bytes_per_second * 5.0
            {
                return Some(ThreatAlert {
                    threat_type: ThreatType::TrafficAnomaly,
                    severity: ThreatSeverity::Medium,
                    ip: None,
                    description: format!(
                        "Traffic anomaly detected! Current: {:.0} pps, {:.0} bps. Baseline: {:.0} pps, {:.0} bps",
                        current_pps, current_bps,
                        self.baseline_traffic.packets_per_second,
                        self.baseline_traffic.bytes_per_second
                    ),
                    timestamp: chrono::Local::now(),
                });
            }
        }
        
        None
    }
    
    /// Detect connection quality issues
    pub fn detect_connection_issues(
        &self,
        latency_ms: f64,
        packet_loss_percent: f64,
    ) -> Option<ThreatAlert> {
        if latency_ms > 500.0 || packet_loss_percent > 10.0 {
            let severity = if packet_loss_percent > 50.0 {
                ThreatSeverity::High
            } else {
                ThreatSeverity::Medium
            };
            
            return Some(ThreatAlert {
                threat_type: ThreatType::ConnectionIssue,
                severity,
                ip: None,
                description: format!(
                    "Connection quality degraded. Latency: {}ms, Packet Loss: {:.1}%",
                    latency_ms, packet_loss_percent
                ),
                timestamp: chrono::Local::now(),
            });
        }
        
        None
    }
}
