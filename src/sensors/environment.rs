//! Lightweight WSL2 / Docker presence probes (builder stack).

use crate::models::BuilderEnvironment;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static CACHED: OnceLock<(Instant, BuilderEnvironment)> = OnceLock::new();
const CACHE_TTL: Duration = Duration::from_secs(30);

/// Cached probe so the sampler / API do not shell out every request.
pub fn probe_cached() -> BuilderEnvironment {
    if let Some((at, env)) = CACHED.get() {
        if at.elapsed() < CACHE_TTL {
            return env.clone();
        }
    }
    let env = probe();
    let _ = CACHED.set((Instant::now(), env.clone()));
    // If already set and stale, still return fresh env this call
    env
}

pub fn probe() -> BuilderEnvironment {
    let mut notes = Vec::new();
    let wsl_detected = detect_wsl(&mut notes);
    let docker_detected = detect_docker(&mut notes);

    BuilderEnvironment {
        wsl_detected,
        docker_detected,
        notes,
    }
}

fn detect_wsl(notes: &mut Vec<String>) -> bool {
    #[cfg(windows)]
    {
        let candidates = [
            r"C:\Windows\System32\wsl.exe",
            r"C:\Windows\Sysnative\wsl.exe",
        ];
        for p in candidates {
            if Path::new(p).exists() {
                notes.push(format!("Found {p}"));
                return true;
            }
        }
        // Fallback: PATH lookup
        if which_on_path("wsl.exe") || which_on_path("wsl") {
            notes.push("Found wsl on PATH".into());
            return true;
        }
        false
    }
    #[cfg(not(windows))]
    {
        // Running inside Linux (possibly WSL)
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

fn detect_docker(notes: &mut Vec<String>) -> bool {
    #[cfg(windows)]
    {
        let pipes = [
            r"\\.\pipe\docker_engine",
            r"\\.\pipe\dockerDesktopLinuxEngine",
            r"\\.\pipe\dockerDesktopWindowsEngine",
        ];
        for p in pipes {
            // Opening named pipes as paths is awkward; existence via \\.\pipe\ listing is hard.
            // Heuristic: docker CLI present or common install dirs.
            let _ = p;
        }
        let install_hints = [
            r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
            r"C:\Program Files\Docker\Docker\resources\bin\docker.exe",
        ];
        for p in install_hints {
            if Path::new(p).exists() {
                notes.push(format!("Found {p}"));
                return true;
            }
        }
        if which_on_path("docker.exe") || which_on_path("docker") {
            notes.push("Found docker on PATH".into());
            return true;
        }
        // Process names are checked on connections via stack_hint; env flag is install/path based.
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
    fn probe_does_not_panic() {
        let e = probe();
        // Just ensure struct is usable
        let _ = e.wsl_detected | e.docker_detected;
    }
}
