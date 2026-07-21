//! Process ↔ socket enumeration (host outbound map).

use crate::destinations::{apply_process_boost, classify_ip_with_context};
use crate::models::{ConnectionSample, DestinationCategory};
use crate::sensors::environment::stack_hint_for_process;
use chrono::Local;
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use std::collections::HashMap;
use std::net::IpAddr;
use sysinfo::{Pid, ProcessesToUpdate, System};

/// Snapshot open TCP sockets with owning process info when available.
/// Filters out TIME_WAIT/CLOSED noise; focuses on active outbound-ish flows.
pub fn sample_connections() -> Result<Vec<ConnectionSample>, String> {
    sample_connections_opts(SampleOpts::default())
}

#[derive(Debug, Clone)]
pub struct SampleOpts {
    /// When true, reverse-DNS unknown public IPs (cached).
    pub reverse_dns: bool,
    /// Max reverse-DNS lookups per sample (keeps interval responsive).
    pub max_dns_lookups: usize,
    /// Include TIME_WAIT / CLOSED / LISTEN rows.
    pub include_idle: bool,
}

impl Default for SampleOpts {
    fn default() -> Self {
        Self {
            reverse_dns: true,
            max_dns_lookups: 24,
            include_idle: false,
        }
    }
}

pub fn sample_connections_opts(opts: SampleOpts) -> Result<Vec<ConnectionSample>, String> {
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let sockets =
        get_sockets_info(af, proto).map_err(|e| format!("socket enumeration failed: {e}"))?;

    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::All, true);

    let mut out = Vec::with_capacity(sockets.len());
    let now = Local::now();
    let mut dns_used = 0usize;

    for si in sockets {
        let pids: Vec<u32> = si.associated_pids.clone();
        let (protocol, local_addr, local_port, remote_addr, remote_port, state) =
            match si.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => {
                    let remote = tcp.remote_addr;
                    let remote_port = tcp.remote_port;
                    if is_unspecified(&remote) || remote_port == 0 {
                        continue;
                    }
                    let state = tcp_state_str(tcp.state).to_string();
                    if !opts.include_idle && !is_active_state(&state) {
                        continue;
                    }
                    (
                        "TCP".to_string(),
                        tcp.local_addr.to_string(),
                        tcp.local_port,
                        remote.to_string(),
                        remote_port,
                        state,
                    )
                }
                ProtocolSocketInfo::Udp(_udp) => continue,
            };

        let pid = pids.first().copied().filter(|&p| p != 0);
        let (process_name, process_path) = match pid {
            Some(p) => resolve_process(&system, p),
            None => (None, None),
        };

        // Skip system Idle TIME_WAIT leftovers if any slipped through
        if process_name.as_deref() == Some("Idle") && pid.is_none() {
            continue;
        }

        let stack_hint = stack_hint_for_process(process_name.as_deref(), process_path.as_deref());

        let remote_ip: Option<IpAddr> = remote_addr.parse().ok();
        let do_dns = opts.reverse_dns
            && dns_used < opts.max_dns_lookups
            && remote_ip
                .map(|ip| !ip.is_loopback() && !is_private_quick(ip))
                .unwrap_or(false);

        let mut classified = remote_ip
            .map(|ip| {
                if do_dns {
                    dns_used += 1;
                }
                classify_ip_with_context(ip, Some(remote_port), do_dns)
            })
            .unwrap_or(crate::destinations::ClassifiedDestination {
                host_or_ip: remote_addr.clone(),
                category: DestinationCategory::Unknown,
                label: None,
                resolved_host: None,
            });

        classified =
            apply_process_boost(classified, process_name.as_deref(), stack_hint.as_deref());

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
            resolved_host: classified.resolved_host,
            stack_hint,
            first_seen: now,
            last_seen: now,
        });
    }

    out.sort_by(|a, b| {
        a.process_name
            .cmp(&b.process_name)
            .then(a.remote_addr.cmp(&b.remote_addr))
            .then(a.remote_port.cmp(&b.remote_port))
    });

    Ok(out)
}

fn is_active_state(state: &str) -> bool {
    matches!(
        state,
        "ESTABLISHED" | "SYN_SENT" | "SYN_RECEIVED" | "CLOSE_WAIT" | "FIN_WAIT1" | "FIN_WAIT2"
    )
}

fn is_private_quick(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
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
        // Skip reverse DNS in unit tests (can be slow / network-dependent).
        let result = sample_connections_opts(SampleOpts {
            reverse_dns: false,
            max_dns_lookups: 0,
            include_idle: false,
        });
        assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    }

    #[test]
    fn active_state_filter() {
        assert!(is_active_state("ESTABLISHED"));
        assert!(!is_active_state("TIME_WAIT"));
        assert!(!is_active_state("LISTEN"));
    }
}
