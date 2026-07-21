use crate::models::{ThreatAlert, ThreatSeverity, ThreatType};
use crate::packet_capture::PacketInfo;
use std::collections::HashMap;
use std::net::IpAddr;

pub struct ThreatDetector {
    arp_table: HashMap<IpAddr, String>,
    baseline_traffic: TrafficBaseline,
    dns_cache: DnsCache,
    suspicious_port_connections: HashMap<u16, usize>,
    packet_count: usize,
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
            suspicious_port_connections: HashMap::new(),
            packet_count: 0,
        }
    }

    /// Analyze a packet for threats — main entry for capture path.
    /// Does not emit volume-spam every N packets; host sampler handles first-seen.
    pub fn analyze_packet(&mut self, packet: &PacketInfo) -> Option<ThreatAlert> {
        self.packet_count += 1;

        if let Some(dst_port) = packet.dst_port {
            if self.is_suspicious_port(dst_port) {
                let count = self
                    .suspicious_port_connections
                    .entry(dst_port)
                    .or_insert(0);
                *count += 1;

                if *count == 4 {
                    return Some(ThreatAlert {
                        threat_type: ThreatType::TrafficAnomaly,
                        severity: ThreatSeverity::High,
                        ip: packet.dst_ip,
                        description: format!(
                            "Suspicious port access detected: {:?} → port {} ({} times)",
                            packet.src_ip, dst_port, count
                        ),
                        timestamp: chrono::Local::now(),
                    });
                }
            }
        }

        if packet.length > 65000 {
            return Some(ThreatAlert {
                threat_type: ThreatType::TrafficAnomaly,
                severity: ThreatSeverity::Medium,
                ip: packet.src_ip,
                description: format!("Abnormally large packet detected: {} bytes", packet.length),
                timestamp: chrono::Local::now(),
            });
        }

        None
    }

    fn is_suspicious_port(&self, port: u16) -> bool {
        matches!(
            port,
            21 | 23 | 69 | 135 | 139 | 445 | 3389 | 4444 | 5555 | 8888 | 9999 | 9050
        )
    }

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

    pub fn detect_dns_spoofing(&mut self, domain: &str, ip: IpAddr) -> Option<ThreatAlert> {
        let entry = self
            .dns_cache
            .responses
            .entry(domain.to_string())
            .or_default();

        if !entry.is_empty() && !entry.contains(&ip) {
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

    pub fn detect_mitm(&self, host: &str, cert_issuer: &str) -> Option<ThreatAlert> {
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

    pub fn detect_rogue_ap(
        &self,
        ssid: &str,
        mac: &str,
        signal_strength: i32,
    ) -> Option<ThreatAlert> {
        if (ssid.contains("FREE_WIFI") || ssid.contains("GUEST_NETWORK") || ssid.is_empty())
            && signal_strength > -30
        {
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

        None
    }

    pub fn detect_traffic_anomaly(
        &mut self,
        current_pps: f64,
        current_bps: f64,
    ) -> Option<ThreatAlert> {
        self.baseline_traffic.packets_per_second = (self.baseline_traffic.packets_per_second
            * self.baseline_traffic.sample_count as f64
            + current_pps)
            / (self.baseline_traffic.sample_count as f64 + 1.0);
        self.baseline_traffic.bytes_per_second = (self.baseline_traffic.bytes_per_second
            * self.baseline_traffic.sample_count as f64
            + current_bps)
            / (self.baseline_traffic.sample_count as f64 + 1.0);
        self.baseline_traffic.sample_count += 1;

        if self.baseline_traffic.sample_count > 10
            && (current_pps > self.baseline_traffic.packets_per_second * 5.0
                || current_bps > self.baseline_traffic.bytes_per_second * 5.0)
        {
            return Some(ThreatAlert {
                threat_type: ThreatType::TrafficAnomaly,
                severity: ThreatSeverity::Medium,
                ip: None,
                description: format!(
                    "Traffic anomaly detected! Current: {:.0} pps, {:.0} bps. Baseline: {:.0} pps, {:.0} bps",
                    current_pps,
                    current_bps,
                    self.baseline_traffic.packets_per_second,
                    self.baseline_traffic.bytes_per_second
                ),
                timestamp: chrono::Local::now(),
            });
        }

        None
    }

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

impl Default for ThreatDetector {
    fn default() -> Self {
        Self::new()
    }
}
