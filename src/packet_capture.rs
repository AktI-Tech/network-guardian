use chrono::Local;
use std::net::IpAddr;

#[cfg(feature = "packet-capture")]
use pcap::Device;

/// Packet sniffer for real-time network monitoring
#[derive(Default)]
pub struct PacketSniffer {
    #[cfg(feature = "packet-capture")]
    device: Option<Device>,
    #[cfg(not(feature = "packet-capture"))]
    #[allow(dead_code)]
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
            let devices = Device::list().map_err(|e| format!("Failed to list devices: {}", e))?;

            let device = devices
                .iter()
                .find(|d| {
                    d.desc
                        .as_ref()
                        .map(|s| s.contains("Intel") && s.contains("Wireless"))
                        .unwrap_or(false)
                })
                .or_else(|| {
                    devices.iter().find(|d| {
                        !d.desc
                            .as_ref()
                            .map(|s| s.contains("Monitor"))
                            .unwrap_or(false)
                    })
                })
                .or_else(|| devices.iter().next())
                .cloned()
                .ok_or_else(|| "No suitable devices found".to_string())?;

            println!("📡 Using device: {}", device.name);
            println!(
                "   Description: {}",
                device.desc.as_deref().unwrap_or("N/A")
            );

            Ok(Self {
                device: Some(device),
            })
        }

        #[cfg(not(feature = "packet-capture"))]
        {
            println!("📡 Running in MOCK mode (packet-capture feature not enabled)");
            Ok(Self { mock_mode: true })
        }
    }

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
                    .timeout(1000)
                    .open()?;

                println!("✅ Packet capture started on {}", device.name);
                println!("   Listening for network traffic...\n");

                let mut packet_count = 0u64;
                let mut timeouts = 0u64;
                loop {
                    match cap.next_packet() {
                        Ok(packet) => {
                            packet_count += 1;
                            timeouts = 0;
                            if let Some(packet_info) = parse_packet(packet.data) {
                                if packet_count % 50 == 0 {
                                    println!(
                                        "📦 Packet #{}: {:?} → {:?} {} ({} B)",
                                        packet_count,
                                        packet_info.src_ip,
                                        packet_info.dst_ip,
                                        packet_info.protocol,
                                        packet_info.length
                                    );
                                }
                                if tx.send(packet_info).await.is_err() {
                                    eprintln!("Detection channel closed");
                                    break;
                                }
                            }
                            if packet_count % 100 == 0 {
                                tokio::task::yield_now().await;
                            }
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("timeout") {
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
            let _ = &self.mock_mode;
            println!("✅ Mock packet capture started");
            let mock_packets = [
                ("192.168.1.100", "8.8.8.8", 54321u16, 53u16, "UDP"),
                ("192.168.1.101", "1.1.1.1", 55432, 443, "TCP"),
            ];
            let mut packet_count = 0usize;
            loop {
                packet_count += 1;
                let m = &mock_packets[(packet_count - 1) % mock_packets.len()];
                let info = PacketInfo {
                    src_ip: m.0.parse().ok(),
                    dst_ip: m.1.parse().ok(),
                    src_port: Some(m.2),
                    dst_port: Some(m.3),
                    protocol: m.4.to_string(),
                    length: 64,
                    timestamp: Local::now(),
                };
                if tx.send(info).await.is_err() {
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            }
        }

        Ok(())
    }

    #[cfg(feature = "packet-capture")]
    pub fn list_devices() -> Result<Vec<String>, String> {
        let devices = pcap::Device::list().map_err(|e| format!("Failed to list devices: {}", e))?;
        Ok(devices
            .iter()
            .map(|d| format!("{} - {}", d.name, d.desc.as_deref().unwrap_or("N/A")))
            .collect())
    }

    #[cfg(not(feature = "packet-capture"))]
    pub fn list_devices() -> Result<Vec<String>, String> {
        Ok(vec!["[MOCK] eth0 - Mock Ethernet Device".to_string()])
    }
}

/// Parse a captured frame. Supports Ethernet (optional VLAN) and raw IP.
pub fn parse_packet(data: &[u8]) -> Option<PacketInfo> {
    let (l3_offset, ethertype) = locate_l3(data)?;
    match ethertype {
        0x0800 => parse_ipv4(&data[l3_offset..], data.len() as u32),
        0x86dd => parse_ipv6(&data[l3_offset..], data.len() as u32),
        _ => None,
    }
}

fn locate_l3(data: &[u8]) -> Option<(usize, u16)> {
    // Prefer Ethernet framing first. Checking "raw IP" via the high nibble of data[0]
    // before Ethernet mis-parses normal frames when the first MAC octet looks like
    // IPv4 version 4 (0x40–0x4F) or IPv6 version 6 (0x60–0x6F).
    if data.len() >= 14 {
        let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
        let mut offset = 14usize;

        // 802.1Q VLAN tag
        if ethertype == 0x8100 {
            if data.len() < 18 {
                return None;
            }
            ethertype = u16::from_be_bytes([data[16], data[17]]);
            offset = 18;
        }

        if ethertype == 0x0800 || ethertype == 0x86dd {
            return Some((offset, ethertype));
        }
    }

    // Raw IPv4/IPv6 only when the frame is not clearly Ethernet IP
    // (Linux cooked capture, some VPN/tunnel paths).
    if !data.is_empty() {
        let version = data[0] >> 4;
        if version == 4 && data.len() >= 20 {
            return Some((0, 0x0800));
        }
        if version == 6 && data.len() >= 40 {
            return Some((0, 0x86dd));
        }
    }

    None
}

fn parse_ipv4(data: &[u8], frame_len: u32) -> Option<PacketInfo> {
    if data.len() < 20 {
        return None;
    }
    if data[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((data[0] & 0x0f) as usize) * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }

    let protocol_num = data[9];
    let src_ip = IpAddr::from([data[12], data[13], data[14], data[15]]);
    let dst_ip = IpAddr::from([data[16], data[17], data[18], data[19]]);
    let (protocol, src_port, dst_port) = parse_l4(protocol_num, &data[ihl..]);

    Some(PacketInfo {
        src_ip: Some(src_ip),
        dst_ip: Some(dst_ip),
        src_port,
        dst_port,
        protocol,
        length: frame_len,
        timestamp: Local::now(),
    })
}

fn parse_ipv6(data: &[u8], frame_len: u32) -> Option<PacketInfo> {
    if data.len() < 40 {
        return None;
    }
    if data[0] >> 4 != 6 {
        return None;
    }

    let next_header = data[6];
    let src_ip = IpAddr::from([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
        data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);
    let dst_ip = IpAddr::from([
        data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31], data[32],
        data[33], data[34], data[35], data[36], data[37], data[38], data[39],
    ]);
    // Note: extension headers not fully walked in MVP
    let (protocol, src_port, dst_port) = parse_l4(next_header, &data[40..]);

    Some(PacketInfo {
        src_ip: Some(src_ip),
        dst_ip: Some(dst_ip),
        src_port,
        dst_port,
        protocol,
        length: frame_len,
        timestamp: Local::now(),
    })
}

fn parse_l4(protocol_num: u8, l4: &[u8]) -> (String, Option<u16>, Option<u16>) {
    let protocol = match protocol_num {
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        1 => "ICMP".to_string(),
        58 => "ICMPv6".to_string(),
        n => format!("OTHER({n})"),
    };

    let (src_port, dst_port) = if l4.len() >= 4 && (protocol_num == 6 || protocol_num == 17) {
        let src = u16::from_be_bytes([l4[0], l4[1]]);
        let dst = u16::from_be_bytes([l4[2], l4[3]]);
        (Some(src), Some(dst))
    } else {
        (None, None)
    };

    (protocol, src_port, dst_port)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Minimal Ethernet + IPv4 + TCP (20+20+20)
    fn ethernet_ipv4_tcp() -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 20];
        // Ethertype IPv4
        frame[12] = 0x08;
        frame[13] = 0x00;
        let ip = &mut frame[14..];
        ip[0] = 0x45; // v4, IHL=5
        ip[9] = 6; // TCP
                   // src 10.0.0.1
        ip[12] = 10;
        ip[13] = 0;
        ip[14] = 0;
        ip[15] = 1;
        // dst 8.8.8.8
        ip[16] = 8;
        ip[17] = 8;
        ip[18] = 8;
        ip[19] = 8;
        let tcp = &mut frame[34..];
        // src port 12345, dst 443
        tcp[0] = 0x30;
        tcp[1] = 0x39;
        tcp[2] = 0x01;
        tcp[3] = 0xbb;
        frame
    }

    #[test]
    fn parses_ethernet_ipv4_tcp() {
        let frame = ethernet_ipv4_tcp();
        let info = parse_packet(&frame).expect("parse");
        assert_eq!(info.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(info.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert_eq!(info.src_port, Some(12345));
        assert_eq!(info.dst_port, Some(443));
        assert_eq!(info.protocol, "TCP");
    }

    #[test]
    fn parses_raw_ipv4() {
        let mut ip = vec![0u8; 20 + 8];
        ip[0] = 0x45;
        ip[9] = 17; // UDP
        ip[12] = 192;
        ip[13] = 168;
        ip[14] = 1;
        ip[15] = 10;
        ip[16] = 1;
        ip[17] = 1;
        ip[18] = 1;
        ip[19] = 1;
        ip[20] = 0x00;
        ip[21] = 0x35; // 53
        ip[22] = 0x00;
        ip[23] = 0x35;
        let info = parse_packet(&ip).expect("parse raw");
        assert_eq!(info.dst_port, Some(53));
        assert_eq!(info.protocol, "UDP");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_packet(&[0u8; 10]).is_none());
    }

    #[test]
    fn ethernet_not_misread_as_raw_ip_when_mac_looks_like_v4() {
        // Dest MAC starts with 0x45 (version nibble 4) — must still use Ethernet offset.
        let mut frame = ethernet_ipv4_tcp();
        frame[0] = 0x45;
        let info = parse_packet(&frame).expect("parse");
        assert_eq!(info.src_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(info.dst_port, Some(443));
    }
}
