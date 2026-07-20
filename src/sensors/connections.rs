//! Process ↔ socket enumeration (host outbound map).

use crate::destinations::classify_ip;
use crate::models::{ConnectionSample, DestinationCategory};
use chrono::Local;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use std::collections::HashMap;
use std::net::IpAddr;
use sysinfo::{Pid, ProcessesToUpdate, System};

/// Snapshot open TCP/UDP sockets with owning process info when available.
pub fn sample_connections() -> Result<Vec<ConnectionSample>, String> {
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let sockets =
        get_sockets_info(af, proto).map_err(|e| format!("socket enumeration failed: {e}"))?;

    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);

    let mut out = Vec::with_capacity(sockets.len());
    let now = Local::now();

    for si in sockets {
        let pids: Vec<u32> = si.associated_pids.clone();
        let (protocol, local_addr, local_port, remote_addr, remote_port, state) =
            match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => {
                    // Focus on connections that have a remote peer (outbound / established-ish).
                    let remote = tcp.remote_addr;
                    let remote_port = tcp.remote_port;
                    if is_unspecified(&remote) || remote_port == 0 {
                        continue;
                    }
                    (
                        "TCP".to_string(),
                        tcp.local_addr.to_string(),
                        tcp.local_port,
                        remote.to_string(),
                        remote_port,
                        tcp_state_str(tcp.state).to_string(),
                    )
                }
                ProtocolSocketInfo::Udp(_udp) => {
                    // UDP often has no remote peer; skip for MVP outbound map.
                    continue;
                }
            };

        let pid = pids.first().copied();
        let (process_name, process_path) = pid
            .map(|p| resolve_process(&system, p))
            .unwrap_or((None, None));

        let remote_ip: Option<IpAddr> = remote_addr.parse().ok();
        let classified =
            remote_ip
                .map(classify_ip)
                .unwrap_or(crate::destinations::ClassifiedDestination {
                    host_or_ip: remote_addr.clone(),
                    category: DestinationCategory::Unknown,
                    label: None,
                });

        out.push(ConnectionSample {
            protocol,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            pid,
            process_name,
            process_path,
            category: classified.category,
            destination_label: classified.label,
            first_seen: now,
            last_seen: now,
        });
    }

    // Stable-ish order for UI
    out.sort_by(|a, b| {
        a.process_name
            .cmp(&b.process_name)
            .then(a.remote_addr.cmp(&b.remote_addr))
            .then(a.remote_port.cmp(&b.remote_port))
    });

    Ok(out)
}

fn resolve_process(system: &System, pid: u32) -> (Option<String>, Option<String>) {
    let Some(proc_) = system.process(Pid::from_u32(pid)) else {
        return (None, None);
    };
    let name = proc_.name().to_string_lossy().to_string();
    let path = proc_.exe().map(|p| p.to_string_lossy().to_string());
    (Some(name), path)
}

fn is_unspecified(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_unspecified(),
        IpAddr::V6(v) => v.is_unspecified(),
    }
}

fn tcp_state_str(state: TcpState) -> &'static str {
    match state {
        TcpState::Closed => "CLOSED",
        TcpState::Listen => "LISTEN",
        TcpState::SynSent => "SYN_SENT",
        TcpState::SynReceived => "SYN_RECEIVED",
        TcpState::Established => "ESTABLISHED",
        TcpState::FinWait1 => "FIN_WAIT1",
        TcpState::FinWait2 => "FIN_WAIT2",
        TcpState::CloseWait => "CLOSE_WAIT",
        TcpState::Closing => "CLOSING",
        TcpState::LastAck => "LAST_ACK",
        TcpState::TimeWait => "TIME_WAIT",
        TcpState::DeleteTcb => "DELETE_TCB",
        _ => "UNKNOWN",
    }
}

/// Deduplicate connection keys for first-seen tracking.
pub fn connection_key(c: &ConnectionSample) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}",
        c.protocol,
        c.pid.unwrap_or(0),
        c.local_port,
        c.remote_addr,
        c.remote_port,
        c.process_name.as_deref().unwrap_or("?")
    )
}

/// Group sample counts by process name for overview widgets.
pub fn top_processes(samples: &[ConnectionSample], limit: usize) -> Vec<(String, usize)> {
    let mut map: HashMap<String, usize> = HashMap::new();
    for s in samples {
        let name = s
            .process_name
            .clone()
            .unwrap_or_else(|| format!("pid:{}", s.pid.unwrap_or(0)));
        *map.entry(name).or_default() += 1;
    }
    let mut v: Vec<_> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(limit);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_does_not_panic() {
        // May return empty under restricted CI, but should not error on Windows/Linux desktop.
        let result = sample_connections();
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    }
}
