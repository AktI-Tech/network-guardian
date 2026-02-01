use std::net::IpAddr;
use std::str::FromStr;
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
            let device = Device::lookup()
                .map_err(|e| format!("Failed to get device: {}", e))?
                .ok_or_else(|| "No devices found".to_string())?;
            
            println!("📡 Using device: {}", device.name);
            println!("   Description: {}", device.desc.as_deref().unwrap_or("N/A"));
            
            Ok(Self {
                device: Some(device),
            })
        }
        
        #[cfg(not(feature = "packet-capture"))]
        {
            println!("📡 Running in MOCK mode (Npcap SDK not available)");
            println!("   To enable real packet capture:");
            println!("   1. Install Npcap SDK from: https://github.com/nmap/npcap/releases");
            println!("   2. Build with: cargo build --features packet-capture");
            Ok(Self { mock_mode: true })
        }
    }
    
    /// Start packet sniffing
    pub async fn start_capture(&self) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(feature = "packet-capture")]
        {
            if let Some(device) = &self.device {
                let mut cap = pcap::Capture::from_device(device.clone())?
                    .promisc(true)
                    .snaplen(65535)
                    .open()?;
                
                println!("✅ Packet capture started on {}", device.name);
                println!("   Listening for network traffic...\n");
                
                // Set filter to capture IP packets
                cap.filter("ip", true)?;
                
                let mut packet_count = 0;
                let mut capture = cap;
            
            loop {
                match capture.next_packet() {
                    Ok(packet) => {
                        packet_count += 1;
                        if let Some(packet_info) = Self::parse_packet(packet.data) {
                            println!("📦 Packet #{}: {} -> {} ({})",
                                packet_count,
                                packet_info.src_ip.unwrap_or_else(|| "N/A".parse().unwrap()),
                                packet_info.dst_ip.unwrap_or_else(|| "N/A".parse().unwrap()),
                                packet_info.protocol
                            );
                        }
                        
                        // Every 100 packets, yield to prevent blocking
                        if packet_count % 100 == 0 {
                            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                        }
                    }
                    Err(e) => {
                        eprintln!("Capture error: {}", e);
                        break;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Parse packet data to extract protocol information
    fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
        if data.len() < 20 {
            return None;
        }
        
        // Check IP version (first nibble of first byte)
        let version = data[0] >> 4;
        if version != 4 {
            return None; // Only IPv4 for now
        }
        
        // Extract source and destination IPs (bytes 12-15 and 16-19)
        let src_ip = IpAddr::from([data[12], data[13], data[14], data[15]]);
        let dst_ip = IpAddr::from([data[16], data[17], data[18], data[19]]);
        
        // Get protocol (byte 9)
        let protocol_num = data[9];
        let protocol = match protocol_num {
            6 => "TCP".to_string(),
            17 => "UDP".to_string(),
            1 => "ICMP".to_string(),
            _ => format!("OTHER({})", protocol_num),
        };
        
        // Extract ports for TCP/UDP (if present)
        let (src_port, dst_port) = if data.len() >= 24 && (protocol_num == 6 || protocol_num == 17) {
            let src = u16::from_be_bytes([data[20], data[21]]);
            let dst = u16::from_be_bytes([data[22], data[23]]);
            (Some(src), Some(dst))
        } else {
            (None, None)
        };
        
        Some(PacketInfo {
            src_ip: Some(src_ip),
            dst_ip: Some(dst_ip),
            src_port,
            dst_port,
            protocol,
            length: data.len() as u32,
            timestamp: chrono::Local::now(),
        })
    }
    
    /// Get available network devices
    pub fn list_devices() -> Result<Vec<String>, String> {
        let devices = pcap::Device::list()
            .map_err(|e| format!("Failed to list devices: {}", e))?;
        
        Ok(devices.iter().map(|d| format!("{} - {}", d.name, d.desc.as_deref().unwrap_or("N/A"))).collect())
    }
}

impl Default for PacketSniffer {
    fn default() -> Self {
        Self { device: None }
    }
}
