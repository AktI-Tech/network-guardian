//! Builder stack probes: WSL distros, Docker containers, adapter tags.

use crate::models::{BuilderEnvironment, DockerContainer, StackInterface, WslDistro};
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

    let (docker_detected, docker_engine_ok, docker_containers) = probe_docker(&mut notes);
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

    BuilderEnvironment {
        wsl_detected,
        docker_detected,
        docker_engine_ok,
        wsl_distros,
        docker_containers,
        interfaces,
        notes,
        probed_at: Local::now().to_rfc3339(),
    }
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

fn probe_docker(notes: &mut Vec<String>) -> (bool, bool, Vec<DockerContainer>) {
    let install = detect_docker_install(notes);
    match list_docker_containers(notes) {
        Ok(containers) => (true, true, containers),
        Err(e) => {
            if install {
                notes.push(format!("Docker installed but engine query failed: {e}"));
                (true, false, Vec::new())
            } else {
                (false, false, Vec::new())
            }
        }
    }
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
    let output = run_hidden(
        "docker",
        &[
            "ps",
            "-a",
            "--format",
            "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}",
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
    let text = decode_command_output(&output.stdout);
    let containers = parse_docker_ps(&text);
    notes.push(format!("{} container(s) via docker ps", containers.len()));
    Ok(containers)
}

pub fn parse_docker_ps(text: &str) -> Vec<DockerContainer> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(5, '\t').collect();
        if parts.len() < 4 {
            continue;
        }
        out.push(DockerContainer {
            id: parts[0].chars().take(12).collect(),
            name: parts[1].to_string(),
            image: parts[2].to_string(),
            status: parts[3].to_string(),
            ports: parts.get(4).unwrap_or(&"").to_string(),
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
        let sample = "abc123def456\tnginx\tnginx:latest\tUp 2 hours\t0.0.0.0:8080->80/tcp\n";
        let c = parse_docker_ps(sample);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].name, "nginx");
        assert!(c[0].ports.contains("8080"));
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
    }
}
