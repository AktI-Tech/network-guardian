//! Builder stack probes: WSL distros, Docker containers/networks, host-port exposure, adapter tags.

use crate::models::{
    BuilderEnvironment, DockerContainer, DockerHostExposure, DockerNetwork, DockerPublishedPort,
    StackInterface, WslDistro,
};
use chrono::Local;
use parking_lot::Mutex;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use sysinfo::Networks;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

static CACHE: OnceLock<Mutex<Option<(Instant, BuilderEnvironment)>>> = OnceLock::new();
const CACHE_TTL: Duration = Duration::from_secs(20);
const CMD_TIMEOUT_HINT: &str = "probe timed out or failed";

fn cache() -> &'static Mutex<Option<(Instant, BuilderEnvironment)>> {
    CACHE.get_or_init(|| Mutex::new(None))
}

/// Cached probe so the sampler / API do not shell out every request.
pub fn probe_cached() -> BuilderEnvironment {
    let mut guard = cache().lock();
    if let Some((at, env)) = guard.as_ref() {
        if at.elapsed() < CACHE_TTL {
            return env.clone();
        }
    }
    let env = probe();
    *guard = Some((Instant::now(), env.clone()));
    env
}

/// Force a fresh probe (CLI `stack` command).
pub fn probe() -> BuilderEnvironment {
    let mut notes = Vec::new();
    let mut wsl_distros = list_wsl_distros(&mut notes);
    let wsl_detected = !wsl_distros.is_empty() || detect_wsl_install(&mut notes);

    let docker = probe_docker(&mut notes);
    let interfaces = list_stack_interfaces();

    // If install found but distro list empty, keep detected true via install path.
    if wsl_detected && wsl_distros.is_empty() {
        notes.push("WSL installed but no distros listed (or list parse failed)".into());
    }

    // Enrich notes with interface summary
    let wsl_ifaces = interfaces.iter().filter(|i| i.kind == "wsl").count();
    let docker_ifaces = interfaces.iter().filter(|i| i.kind == "docker").count();
    if wsl_ifaces > 0 {
        notes.push(format!("{wsl_ifaces} WSL-related adapter(s)"));
    }
    if docker_ifaces > 0 {
        notes.push(format!("{docker_ifaces} Docker-related adapter(s)"));
    }

    // Ensure default flag only once
    if let Some(first) = wsl_distros.iter_mut().find(|d| d.is_default) {
        let _ = first;
    }

    if !docker.host_exposure.is_empty() {
        notes.push(format!(
            "{} host-published port(s) beyond loopback (see Stack → Host exposure)",
            docker.host_exposure.len()
        ));
    }

    BuilderEnvironment {
        wsl_detected,
        docker_detected: docker.detected,
        docker_engine_ok: docker.engine_ok,
        docker_version: docker.version,
        docker_context: docker.context,
        docker_running: docker.running,
        docker_stopped: docker.stopped,
        wsl_distros,
        docker_containers: docker.containers,
        docker_networks: docker.networks,
        docker_host_exposure: docker.host_exposure,
        interfaces,
        notes,
        probed_at: Local::now().to_rfc3339(),
    }
}

struct DockerProbe {
    detected: bool,
    engine_ok: bool,
    version: Option<String>,
    context: Option<String>,
    running: usize,
    stopped: usize,
    containers: Vec<DockerContainer>,
    networks: Vec<DockerNetwork>,
    host_exposure: Vec<DockerHostExposure>,
}

fn detect_wsl_install(notes: &mut Vec<String>) -> bool {
    #[cfg(windows)]
    {
        for p in [
            r"C:\Windows\System32\wsl.exe",
            r"C:\Windows\Sysnative\wsl.exe",
        ] {
            if Path::new(p).exists() {
                notes.push(format!("Found {p}"));
                return true;
            }
        }
        if which_on_path("wsl.exe") || which_on_path("wsl") {
            notes.push("Found wsl on PATH".into());
            return true;
        }
        false
    }
    #[cfg(not(windows))]
    {
        if Path::new("/proc/sys/fs/binfmt_misc/WSLInterop").exists()
            || std::fs::read_to_string("/proc/version")
                .map(|v| v.to_ascii_lowercase().contains("microsoft"))
                .unwrap_or(false)
        {
            notes.push("Linux appears to be WSL".into());
            true
        } else {
            false
        }
    }
}

fn list_wsl_distros(notes: &mut Vec<String>) -> Vec<WslDistro> {
    #[cfg(windows)]
    {
        let output = match run_hidden("wsl.exe", &["-l", "-v"]) {
            Ok(o) => o,
            Err(e) => {
                notes.push(format!("wsl -l -v: {e}"));
                return Vec::new();
            }
        };
        if !output.status.success() && output.stdout.is_empty() {
            notes.push(format!(
                "wsl -l -v exit {}",
                output.status.code().unwrap_or(-1)
            ));
            return Vec::new();
        }
        let text = decode_command_output(&output.stdout);
        parse_wsl_list(&text)
    }
    #[cfg(not(windows))]
    {
        let _ = notes;
        Vec::new()
    }
}

/// Parse `wsl -l -v` table (UTF-8 or decoded UTF-16).
pub fn parse_wsl_list(text: &str) -> Vec<WslDistro> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("name") && lower.contains("state") {
            continue; // header
        }
        // Format: * Ubuntu    Running    2
        // or:   docker-desktop    Stopped    2
        let is_default = line.starts_with('*');
        let rest = line.trim_start_matches('*').trim();
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        // Last token is often version (1/2); second-to-last may be state multi-word?
        // States: Running, Stopped, Installing, Uninstalling
        let (name, state, version) = if parts.len() >= 3 {
            let version = parts[parts.len() - 1].to_string();
            let state = parts[parts.len() - 2].to_string();
            let name = parts[..parts.len() - 2].join(" ");
            (name, state, version)
        } else {
            (parts[0].to_string(), parts[1].to_string(), "?".into())
        };
        // Skip junk rows
        if name.eq_ignore_ascii_case("name") {
            continue;
        }
        out.push(WslDistro {
            name,
            state,
            version,
            is_default,
        });
    }
    out
}

fn probe_docker(notes: &mut Vec<String>) -> DockerProbe {
    let install = detect_docker_install(notes);
    match list_docker_containers(notes) {
        Ok(containers) => {
            let running = containers.iter().filter(|c| c.running).count();
            let stopped = containers.len().saturating_sub(running);
            let host_exposure = host_exposure_from_containers(&containers);
            let networks = list_docker_networks().unwrap_or_default();
            let version = docker_server_version(notes);
            let context = docker_context_name(notes);
            if let Some(ref v) = version {
                notes.push(format!("Docker Engine {v}"));
            }
            if !networks.is_empty() {
                notes.push(format!("{} docker network(s)", networks.len()));
            }
            notes.push(format!(
                "{running} running / {stopped} stopped container(s)"
            ));
            DockerProbe {
                detected: true,
                engine_ok: true,
                version,
                context,
                running,
                stopped,
                containers,
                networks,
                host_exposure,
            }
        }
        Err(e) => {
            if install {
                notes.push(format!("Docker installed but engine query failed: {e}"));
                DockerProbe {
                    detected: true,
                    engine_ok: false,
                    version: None,
                    context: None,
                    running: 0,
                    stopped: 0,
                    containers: Vec::new(),
                    networks: Vec::new(),
                    host_exposure: Vec::new(),
                }
            } else {
                DockerProbe {
                    detected: false,
                    engine_ok: false,
                    version: None,
                    context: None,
                    running: 0,
                    stopped: 0,
                    containers: Vec::new(),
                    networks: Vec::new(),
                    host_exposure: Vec::new(),
                }
            }
        }
    }
}

fn docker_server_version(notes: &mut Vec<String>) -> Option<String> {
    let output = match run_hidden("docker", &["version", "--format", "{{.Server.Version}}"]) {
        Ok(o) => o,
        Err(e) => {
            notes.push(format!("docker version: {e}"));
            return None;
        }
    };
    if !output.status.success() {
        return None;
    }
    let v = decode_command_output(&output.stdout).trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn docker_context_name(notes: &mut Vec<String>) -> Option<String> {
    let output = match run_hidden("docker", &["context", "show"]) {
        Ok(o) => o,
        Err(e) => {
            notes.push(format!("docker context: {e}"));
            return None;
        }
    };
    if !output.status.success() {
        return None;
    }
    let v = decode_command_output(&output.stdout).trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn list_docker_networks() -> Result<Vec<DockerNetwork>, String> {
    let output = run_hidden(
        "docker",
        &[
            "network",
            "ls",
            "--format",
            "{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}",
        ],
    )?;
    if !output.status.success() {
        let err = decode_command_output(&output.stderr);
        return Err(if err.is_empty() {
            format!("exit {}", output.status.code().unwrap_or(-1))
        } else {
            err.lines().next().unwrap_or(CMD_TIMEOUT_HINT).to_string()
        });
    }
    Ok(parse_docker_networks(&decode_command_output(
        &output.stdout,
    )))
}

/// Parse `docker network ls` tab-separated rows.
pub fn parse_docker_networks(text: &str) -> Vec<DockerNetwork> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        if parts.len() < 4 {
            continue;
        }
        out.push(DockerNetwork {
            id: parts[0].chars().take(12).collect(),
            name: parts[1].to_string(),
            driver: parts[2].to_string(),
            scope: parts[3].to_string(),
        });
    }
    out
}

fn host_exposure_from_containers(containers: &[DockerContainer]) -> Vec<DockerHostExposure> {
    let mut out = Vec::new();
    for c in containers {
        for p in &c.published {
            if p.exposure != "all-interfaces" && p.exposure != "lan" {
                continue;
            }
            out.push(DockerHostExposure {
                container: c.name.clone(),
                image: c.image.clone(),
                host_ip: p.host_ip.clone().unwrap_or_else(|| "*".into()),
                host_port: p.host_port.clone().unwrap_or_else(|| "?".into()),
                container_port: p.container_port.clone().unwrap_or_else(|| "?".into()),
                protocol: p.protocol.clone().unwrap_or_else(|| "tcp".into()),
                exposure: p.exposure.clone(),
                compose_project: c.compose_project.clone(),
            });
        }
    }
    out.sort_by(|a, b| {
        exposure_rank(&b.exposure)
            .cmp(&exposure_rank(&a.exposure))
            .then(a.container.cmp(&b.container))
            .then(a.host_port.cmp(&b.host_port))
    });
    out
}

fn exposure_rank(e: &str) -> u8 {
    match e {
        "all-interfaces" => 3,
        "lan" => 2,
        "localhost" => 1,
        _ => 0,
    }
}

/// Classify a host bind address for exposure severity.
pub fn classify_host_bind(host_ip: &str) -> &'static str {
    let h = host_ip.trim().trim_matches(|c| c == '[' || c == ']');
    if h.is_empty() || h == "0.0.0.0" || h == "*" || h == "::" || h == "::0" {
        "all-interfaces"
    } else if h == "127.0.0.1" || h == "::1" || h.eq_ignore_ascii_case("localhost") {
        "localhost"
    } else {
        "lan"
    }
}

/// Parse the `docker ps` Ports column into structured published ports.
pub fn parse_published_ports(ports: &str) -> Vec<DockerPublishedPort> {
    let mut out = Vec::new();
    if ports.trim().is_empty() {
        return out;
    }
    for frag in ports.split(',') {
        let raw = frag.trim();
        if raw.is_empty() {
            continue;
        }
        // Published: [host_ip:]host_port->container_port[/proto]
        // Unmapped expose: 80/tcp
        if let Some((left, right)) = raw.split_once("->") {
            let (container_port, protocol) = split_port_proto(right.trim());
            let left = left.trim();
            // IPv6 all-interfaces: :::8080  or  [::]:8080
            let (host_ip, host_port) = if let Some(rest) = left.strip_prefix(":::") {
                (Some("::".to_string()), Some(rest.to_string()))
            } else if left.starts_with('[') {
                // [::]:8080 or [fe80::1]:8080
                if let Some(end) = left.find(']') {
                    let ip = left[1..end].to_string();
                    let rest = left[end + 1..].trim_start_matches(':');
                    (Some(ip), Some(rest.to_string()))
                } else {
                    (None, Some(left.to_string()))
                }
            } else if let Some((ip, port)) = left.rsplit_once(':') {
                // 0.0.0.0:8080 or 127.0.0.1:5432 — last colon splits IP from port
                // (IPv4 only here; IPv6 handled above)
                if ip.contains('.') || ip == "*" || ip == "localhost" {
                    (Some(ip.to_string()), Some(port.to_string()))
                } else if ip.is_empty() {
                    (Some("0.0.0.0".into()), Some(port.to_string()))
                } else {
                    // bare host port without IP (Docker sometimes omits 0.0.0.0)
                    (Some("0.0.0.0".into()), Some(left.to_string()))
                }
            } else {
                // host_port only → all interfaces
                (Some("0.0.0.0".into()), Some(left.to_string()))
            };
            let exposure = host_ip
                .as_deref()
                .map(classify_host_bind)
                .unwrap_or("all-interfaces")
                .to_string();
            out.push(DockerPublishedPort {
                raw: raw.to_string(),
                host_ip,
                host_port,
                container_port,
                protocol,
                exposure,
            });
        } else {
            let (container_port, protocol) = split_port_proto(raw);
            out.push(DockerPublishedPort {
                raw: raw.to_string(),
                host_ip: None,
                host_port: None,
                container_port,
                protocol,
                exposure: "unpublished".into(),
            });
        }
    }
    out
}

fn split_port_proto(s: &str) -> (Option<String>, Option<String>) {
    if let Some((port, proto)) = s.split_once('/') {
        (Some(port.to_string()), Some(proto.to_string()))
    } else {
        (Some(s.to_string()), None)
    }
}

fn max_exposure_of(published: &[DockerPublishedPort]) -> String {
    published
        .iter()
        .map(|p| p.exposure.as_str())
        .max_by_key(|e| exposure_rank(e))
        .unwrap_or("unpublished")
        .to_string()
}

fn status_is_running(status: &str) -> bool {
    let s = status.trim().to_ascii_lowercase();
    s.starts_with("up ") || s == "up" || s.starts_with("running")
}

fn detect_docker_install(notes: &mut Vec<String>) -> bool {
    #[cfg(windows)]
    {
        for p in [
            r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
            r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
        ] {
            if Path::new(p).exists() {
                notes.push(format!("Found {p}"));
                return true;
            }
        }
        if which_on_path("docker.exe") || which_on_path("docker") {
            notes.push("Found docker on PATH".into());
            return true;
        }
        false
    }
    #[cfg(not(windows))]
    {
        if Path::new("/var/run/docker.sock").exists() {
            notes.push("Found /var/run/docker.sock".into());
            return true;
        }
        which_on_path("docker")
    }
}

fn list_docker_containers(notes: &mut Vec<String>) -> Result<Vec<DockerContainer>, String> {
    // Prefer 6 fields (compose project label); fall back if template fails on older clients.
    const FMT_WITH_COMPOSE: &str =
        "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Label \"com.docker.compose.project\"}}";
    const FMT_BASIC: &str = "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}";

    let output = match run_hidden("docker", &["ps", "-a", "--format", FMT_WITH_COMPOSE]) {
        Ok(o) if o.status.success() => o,
        Ok(_) | Err(_) => run_hidden("docker", &["ps", "-a", "--format", FMT_BASIC])?,
    };
    if !output.status.success() {
        let err = decode_command_output(&output.stderr);
        return Err(if err.is_empty() {
            format!("exit {}", output.status.code().unwrap_or(-1))
        } else {
            err.lines().next().unwrap_or(CMD_TIMEOUT_HINT).to_string()
        });
    }
    let text = decode_command_output(&output.stdout);
    let containers = parse_docker_ps(&text);
    notes.push(format!("{} container(s) via docker ps", containers.len()));
    Ok(containers)
}

/// Parse `docker ps` tab rows (5 or 6 columns; 6th = compose project).
pub fn parse_docker_ps(text: &str) -> Vec<DockerContainer> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(6, '\t').collect();
        if parts.len() < 4 {
            continue;
        }
        let ports = parts.get(4).unwrap_or(&"").to_string();
        let compose = parts
            .get(5)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        let published = parse_published_ports(&ports);
        let max_exposure = max_exposure_of(&published);
        let status = parts[3].to_string();
        out.push(DockerContainer {
            id: parts[0].chars().take(12).collect(),
            name: parts[1].to_string(),
            image: parts[2].to_string(),
            running: status_is_running(&status),
            status,
            ports,
            compose_project: compose,
            published,
            max_exposure,
        });
    }
    out
}

fn list_stack_interfaces() -> Vec<StackInterface> {
    let mut networks = Networks::new_with_refreshed_list();
    networks.refresh(true);
    let mut out = Vec::new();
    for (name, data) in networks.iter() {
        let name_s = name.to_string();
        let kind = classify_interface(&name_s);
        let ips: Vec<String> = data
            .ip_networks()
            .iter()
            .map(|n| n.addr.to_string())
            .collect();
        out.push(StackInterface {
            name: name_s,
            kind: kind.to_string(),
            ips,
        });
    }
    out.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.name.cmp(&b.name)));
    out
}

pub fn classify_interface(name: &str) -> &'static str {
    let n = name.to_ascii_lowercase();
    if n.contains("wsl") {
        return "wsl";
    }
    // Default Switch / vEthernet often WSL2 or Hyper-V
    if n.contains("vethernet") && (n.contains("wsl") || n.contains("default switch")) {
        return "wsl";
    }
    if n.contains("vethernet") || n.contains("hyper-v") {
        return "hyper-v";
    }
    if n.contains("docker") || n.contains("nbr") || n.contains("br-") || n.contains("veth") {
        return "docker";
    }
    if n.contains("vpn") || n.contains("tun") || n.contains("tap") || n.contains("wg") {
        return "vpn";
    }
    if n.contains("loopback") || n == "lo" || n.contains("pseudo") {
        return "other";
    }
    "host"
}

fn run_hidden(program: &str, args: &[&str]) -> Result<std::process::Output, String> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.output()
        .map_err(|e| format!("failed to run {program}: {e}"))
}

/// WSL on Windows often emits UTF-16LE; detect NULs / BOM before UTF-8.
fn decode_command_output(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let looks_utf16 = bytes.starts_with(&[0xFF, 0xFE])
        || bytes.starts_with(&[0xFE, 0xFF])
        || (bytes.len() >= 4 && bytes.iter().filter(|&&b| b == 0).count() * 2 >= bytes.len());

    let s = if looks_utf16 {
        let (le, data) = if bytes.starts_with(&[0xFF, 0xFE]) {
            (true, &bytes[2..])
        } else if bytes.starts_with(&[0xFE, 0xFF]) {
            (false, &bytes[2..])
        } else {
            (true, bytes)
        };
        if data.len() < 2 {
            return String::new();
        }
        let aligned = &data[..data.len() - (data.len() % 2)];
        let u16s: Vec<u16> = aligned
            .chunks_exact(2)
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16_lossy(&u16s)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    // Safety: strip any residual NULs that break table parsing
    s.replace('\u{0}', "")
}

fn which_on_path(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return true;
        }
        #[cfg(windows)]
        {
            let with_exe = dir.join(format!("{name}.exe"));
            if with_exe.is_file() {
                return true;
            }
        }
    }
    false
}

/// Infer stack hint from process name / path (per connection).
pub fn stack_hint_for_process(name: Option<&str>, path: Option<&str>) -> Option<String> {
    let blob = format!(
        "{} {}",
        name.unwrap_or("").to_ascii_lowercase(),
        path.unwrap_or("").to_ascii_lowercase()
    );
    if blob.contains("wsl")
        || blob.contains("vmmemwsl")
        || blob.contains("wslservice")
        || blob.contains("wslrelay")
    {
        return Some("wsl".into());
    }
    if blob.contains("docker")
        || blob.contains("vpnkit")
        || blob.contains("com.docker")
        || blob.contains("docker-proxy")
    {
        return Some("docker".into());
    }
    if blob.contains("ollama")
        || blob.contains("lm studio")
        || blob.contains("lmstudio")
        || blob.contains("llama.cpp")
        || blob.contains("vllm")
    {
        return Some("llm-local".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stack_hint_wsl() {
        assert_eq!(
            stack_hint_for_process(Some("wsl.exe"), None).as_deref(),
            Some("wsl")
        );
    }

    #[test]
    fn stack_hint_docker() {
        assert_eq!(
            stack_hint_for_process(Some("Docker Desktop.exe"), None).as_deref(),
            Some("docker")
        );
    }

    #[test]
    fn stack_hint_ollama() {
        assert_eq!(
            stack_hint_for_process(Some("ollama.exe"), None).as_deref(),
            Some("llm-local")
        );
    }

    #[test]
    fn parse_wsl_list_sample() {
        let sample = "  NAME            STATE           VERSION\n* Ubuntu-22.04    Running         2\n  docker-desktop  Stopped         2\n";
        let d = parse_wsl_list(sample);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].name, "Ubuntu-22.04");
        assert!(d[0].is_default);
        assert_eq!(d[0].state, "Running");
        assert_eq!(d[1].name, "docker-desktop");
        assert!(!d[1].is_default);
    }

    #[test]
    fn decode_utf16le_wsl_style() {
        // "Ubuntu" as UTF-16LE
        let bytes: Vec<u8> = "Ubuntu"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(decode_command_output(&bytes), "Ubuntu");
    }

    #[test]
    fn parse_docker_ps_sample() {
        let sample = "abc123def456\tnginx\tnginx:latest\tUp 2 hours\t0.0.0.0:8080->80/tcp\tweb\n";
        let c = parse_docker_ps(sample);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].name, "nginx");
        assert!(c[0].ports.contains("8080"));
        assert!(c[0].running);
        assert_eq!(c[0].compose_project.as_deref(), Some("web"));
        assert_eq!(c[0].max_exposure, "all-interfaces");
        assert_eq!(c[0].published.len(), 1);
        assert_eq!(c[0].published[0].host_port.as_deref(), Some("8080"));
    }

    #[test]
    fn parse_published_localhost_and_lan() {
        let ports = "127.0.0.1:5432->5432/tcp, 10.0.0.5:9000->9000/tcp, 80/tcp";
        let p = parse_published_ports(ports);
        assert_eq!(p.len(), 3);
        assert_eq!(p[0].exposure, "localhost");
        assert_eq!(p[1].exposure, "lan");
        assert_eq!(p[2].exposure, "unpublished");
    }

    #[test]
    fn parse_published_ipv6_all() {
        let p = parse_published_ports(":::3000->3000/tcp");
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].exposure, "all-interfaces");
        assert_eq!(p[0].host_port.as_deref(), Some("3000"));
    }

    #[test]
    fn classify_host_bind_kinds() {
        assert_eq!(classify_host_bind("0.0.0.0"), "all-interfaces");
        assert_eq!(classify_host_bind("::"), "all-interfaces");
        assert_eq!(classify_host_bind("127.0.0.1"), "localhost");
        assert_eq!(classify_host_bind("10.0.0.1"), "lan");
    }

    #[test]
    fn parse_docker_networks_sample() {
        let sample = "abc\tbridge\tbridge\tlocal\ndef\thost\thost\tlocal\n";
        let n = parse_docker_networks(sample);
        assert_eq!(n.len(), 2);
        assert_eq!(n[0].name, "bridge");
        assert_eq!(n[1].driver, "host");
    }

    #[test]
    fn host_exposure_skips_localhost() {
        let sample = "id1\tdb\tpostgres\tUp\t127.0.0.1:5432->5432/tcp\t\nid2\tapi\tapp\tUp\t0.0.0.0:8080->80/tcp\tmyapp\n";
        let c = parse_docker_ps(sample);
        let exp = host_exposure_from_containers(&c);
        assert_eq!(exp.len(), 1);
        assert_eq!(exp[0].container, "api");
        assert_eq!(exp[0].exposure, "all-interfaces");
        assert_eq!(exp[0].compose_project.as_deref(), Some("myapp"));
    }

    #[test]
    fn classify_iface_kinds() {
        assert_eq!(classify_interface("vEthernet (WSL)"), "wsl");
        assert_eq!(classify_interface("docker0"), "docker");
        assert_eq!(classify_interface("Ethernet"), "host");
        assert_eq!(classify_interface("WireGuard Tunnel"), "vpn");
    }

    #[test]
    fn probe_does_not_panic() {
        let e = probe();
        let _ = e.wsl_detected | e.docker_detected;
        assert!(!e.probed_at.is_empty());
        // New fields always present
        let _ = e.docker_running + e.docker_stopped + e.docker_networks.len();
    }
}
