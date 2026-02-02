use std::net::IpAddr;
use chrono::Local;

#[cfg(feature = "packet-capture")]
use pcap::Device;

/// Packet sniffer for real-time network monitoring
pub struct PacketSniffer {
    #[cfg(feature = "packet-capture")]
    device: Option<Device>,
    #[cfg(not(feature = "packet-capture"))]
    mock_mode: bool,
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src_ip: Option<IpAddr>,
    pub dst_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub length: u32,
    pub timestamp: chrono::DateTime<chrono::Local>,
}

impl PacketSniffer {
    pub fn new() -> Result<Self, String> {
        #[cfg(feature = "packet-capture")]
        {
            let devices = Device::list()
                .map_err(|e| format!("Failed to list devices: {}", e))?;
            
            // Prefer Intel Wireless, then any non-monitor device
            let device = devices.iter()
                .find(|d| {
                    d.desc.as_ref().map(|s| s.contains("Intel") && s.contains("Wireless")).unwrap_or(false)
                })
                .or_else(|| {
                    devices.iter().find(|d| {
                        !d.desc.as_ref().map(|s| s.contains("Monitor")).unwrap_or(false)
                    })
                })
                .or_else(|| devices.iter().next())
                .cloned()
                .ok_or_else(|| "No suitable devices found".to_string())?;
            
            println!("📡 Using device: {}", device.name);
            println!("   Description: {}", device.desc.as_deref().unwrap_or("N/A"));
            
            Ok(Self {
                device: Some(device),
            })
        }
        
        #[cfg(not(feature = "packet-capture"))]
        {
            println!("📡 Running in MOCK mode (Npcap SDK not available)");
            Ok(Self { mock_mode: true })
        }
    }
    
    /// Start packet sniffing and send through channel
    pub async fn start_capture_and_send(
        &self,
        tx: tokio::sync::mpsc::Sender<PacketInfo>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(feature = "packet-capture")]
        {
            if let Some(device) = &self.device {
                let mut cap = pcap::Capture::from_device(device.clone())?
                    .promisc(true)
                    .snaplen(65535)
                    .timeout(1000)  // 1 second timeout
                    .open()?;
                
                println!("✅ Packet capture started on {}", device.name);
                println!("   Listening for network traffic...\n");
                println!("   (Promiscuous mode enabled, timeout=1s)\n");
                
                // Don't filter - capture all packets initially for testing
                // cap.filter("ip", true)?;
                
                let mut packet_count = 0;
                let mut timeouts = 0;
                loop {
                    match cap.next_packet() {
                        Ok(packet) => {
                            packet_count += 1;
                            timeouts = 0;  // Reset timeout counter
                            if let Some(packet_info) = Self::parse_packet(packet.data) {
                                let port_info = if let (Some(src), Some(dst)) = (packet_info.src_port, packet_info.dst_port) {
                                    format!("{}:{} -> {}:{}", 
                                        packet_info.src_ip.unwrap_or_else(|| "N/A".parse().unwrap()),
                                        src,
                                        packet_info.dst_ip.unwrap_or_else(|| "N/A".parse().unwrap()),
                                        dst
                                    )
                                } else {
                                    format!("{} -> {} ({})",
                                        packet_info.src_ip.unwrap_or_else(|| "N/A".parse().unwrap()),
                                        packet_info.dst_ip.unwrap_or_else(|| "N/A".parse().unwrap()),
                                        packet_info.protocol
                                    )
                                };
                                println!("📦 Packet #{}: {} ({}bytes)", packet_count, port_info, packet_info.length);
                                
                                // Send packet through channel for threat detection
                                if tx.send(packet_info).await.is_err() {
                                    eprintln!("Detection channel closed");
                                    break;
                                }
                            } else {
                                // Silently skip unparseable packets
                            }
                            
                            if packet_count % 100 == 0 {
                                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                            }
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("timeout") {
                                // Timeout is normal (no packets during 1 second)
                                timeouts += 1;
                                if timeouts % 10 == 0 {
                                    println!("   [Waiting for packets... {}s]", timeouts);
                                }
                                continue;
                            } else {
                                eprintln!("❌ Capture error: {}", e);
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        #[cfg(not(feature = "packet-capture"))]
        {
            println!("✅ Mock packet capture started");
            println!("   Simulating network traffic...\n");
            
            let mock_packets = vec![
                ("192.168.1.100", "8.8.8.8", 54321, 53, "DNS", "UDP"),
                ("192.168.1.101", "172.217.16.142", 55432, 443, "HTTPS", "TCP"),
                ("192.168.1.102", "93.184.216.34", 49152, 80, "HTTP", "TCP"),
            ];
            
            let mut packet_count = 0;
            loop {
                packet_count += 1;
                let mock = &mock_packets[(packet_count - 1) % mock_packets.len()];
                
                println!("📦 Packet #{}: {} -> {}:{} ({})",
                    packet_count,
                    mock.0,
                    mock.1,
                    mock.3,
                    mock.5
                );
                
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }
        
        Ok(())
    }
    
    /// Parse packet data to extract protocol information
    #[cfg(feature = "packet-capture")]
    fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
        if data.len() < 20 {
            return None;
        }
        
        let version = data[0] >> 4;
        
        // Handle both IPv4 and IPv6
        match version {
            4 => {
                // IPv4
                let src_ip = IpAddr::from([data[12], data[13], data[14], data[15]]);
                let dst_ip = IpAddr::from([data[16], data[17], data[18], data[19]]);
                let protocol_num = data[9];
                let (protocol, src_port, dst_port) = Self::parse_ports_ipv4(protocol_num, data);
                
                Some(PacketInfo {
                    src_ip: Some(src_ip),
                    dst_ip: Some(dst_ip),
                    src_port,
                    dst_port,
                    protocol,
                    length: data.len() as u32,
                    timestamp: Local::now(),
                })
            }
            6 => {
                // IPv6
                if data.len() < 40 {
                    return None;
                }
                // Extract source and destination IPv6 addresses
                let src_ip = IpAddr::from([
                    data[8], data[9], data[10], data[11],
                    data[12], data[13], data[14], data[15],
                    data[16], data[17], data[18], data[19],
                    data[20], data[21], data[22], data[23],
                ]);
                let dst_ip = IpAddr::from([
                    data[24], data[25], data[26], data[27],
                    data[28], data[29], data[30], data[31],
                    data[32], data[33], data[34], data[35],
                    data[36], data[37], data[38], data[39],
                ]);
                
                let next_header = data[6];
                let (protocol, src_port, dst_port) = Self::parse_ports_ipv6(next_header, data);
                
                Some(PacketInfo {
                    src_ip: Some(src_ip),
                    dst_ip: Some(dst_ip),
                    src_port,
                    dst_port,
                    protocol,
                    length: data.len() as u32,
                    timestamp: Local::now(),
                })
            }
            _ => None,
        }
    }
    
    #[cfg(feature = "packet-capture")]
    fn parse_ports_ipv4(protocol_num: u8, data: &[u8]) -> (String, Option<u16>, Option<u16>) {
        let protocol = match protocol_num {
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            1 => "ICMP".to_string(),
            _ => format!("OTHER({})", protocol_num),
        };
        
        let (src_port, dst_port) = if data.len() >= 24 && (protocol_num == 6 || protocol_num == 17) {
            let src = u16::from_be_bytes([data[20], data[21]]);
            let dst = u16::from_be_bytes([data[22], data[23]]);
            (Some(src), Some(dst))
        } else {
            (None, None)
        };
        
        (protocol, src_port, dst_port)
    }
    
    #[cfg(feature = "packet-capture")]
    fn parse_ports_ipv6(next_header: u8, data: &[u8]) -> (String, Option<u16>, Option<u16>) {
        let protocol = match next_header {
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            58 => "ICMPv6".to_string(),
            _ => format!("OTHER({})", next_header),
        };
        
        // For IPv6, ports are at the same relative offset as IPv4 (after fixed header)
        let (src_port, dst_port) = if data.len() >= 48 && (next_header == 6 || next_header == 17) {
            let src = u16::from_be_bytes([data[40], data[41]]);
            let dst = u16::from_be_bytes([data[42], data[43]]);
            (Some(src), Some(dst))
        } else {
            (None, None)
        };
        
        (protocol, src_port, dst_port)
    }
    
    /// Get available network devices
    #[cfg(feature = "packet-capture")]
    pub fn list_devices() -> Result<Vec<String>, String> {
        let devices = pcap::Device::list()
            .map_err(|e| format!("Failed to list devices: {}", e))?;
        
        Ok(devices.iter().map(|d| format!("{} - {}", d.name, d.desc.as_deref().unwrap_or("N/A"))).collect())
    }
    
    #[cfg(not(feature = "packet-capture"))]
    pub fn list_devices() -> Result<Vec<String>, String> {
        Ok(vec!["[MOCK] eth0 - Mock Ethernet Device".to_string()])
    }
}

impl Default for PacketSniffer {
    fn default() -> Self {
        #[cfg(feature = "packet-capture")]
        {
            Self { device: None }
        }
        #[cfg(not(feature = "packet-capture"))]
        {
            Self { mock_mode: false }
        }
    }
}
