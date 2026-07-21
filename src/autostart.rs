//! Windows HKCU Run-key autostart for NetworkGuardian serve --tray.

#![cfg(windows)]

use std::env;
use std::path::PathBuf;
use winreg::enums::*;
use winreg::RegKey;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const VALUE_NAME: &str = "NetworkGuardian";

/// Command line written to the Run key.
pub fn serve_tray_command() -> Result<String, String> {
    let exe = env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let exe = dunce_simplify(exe);
    // Quote path for spaces; always use serve --tray so dashboard+sampler start headless-friendly.
    Ok(format!("\"{}\" serve --tray", exe.display()))
}

fn dunce_simplify(p: PathBuf) -> PathBuf {
    // Strip \\?\ prefix if present for cleaner registry values
    let s = p.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        p
    }
}

pub fn enable() -> Result<String, String> {
    let cmd = serve_tray_command()?;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(RUN_KEY)
        .map_err(|e| format!("open Run key: {e}"))?;
    key.set_value(VALUE_NAME, &cmd)
        .map_err(|e| format!("set value: {e}"))?;
    Ok(cmd)
}

pub fn disable() -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .open_subkey_with_flags(RUN_KEY, KEY_WRITE)
        .map_err(|e| format!("open Run key: {e}"))?;
    match key.delete_value(VALUE_NAME) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("delete value: {e}")),
    }
}

pub fn status() -> Result<Option<String>, String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = match hkcu.open_subkey(RUN_KEY) {
        Ok(k) => k,
        Err(_) => return Ok(None),
    };
    match key.get_value::<String, _>(VALUE_NAME) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read value: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_contains_serve_tray() {
        let cmd = serve_tray_command().expect("exe path");
        assert!(cmd.contains("serve"));
        assert!(cmd.contains("--tray"));
        assert!(cmd.starts_with('"'));
    }
}
