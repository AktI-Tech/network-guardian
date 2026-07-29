//! Guardian Ops — multi-role budgets + agent surface (display / playbook only).
//!
//! Loads `ops/budget.yml` from the process CWD. Budgets are **not enforced** by
//! the binary; they guide long Grok sessions and the dashboard Ops tab.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const BUDGET_PATH: &str = "ops/budget.yml";
const SESSIONS_DIR: &str = "intel/sessions";
const EMBEDDED_BUDGET: &str = include_str!("../ops/budget.yml");

/// MCP tools exposed by `network_guardian mcp` (keep in sync with `mcp.rs`).
pub const MCP_TOOLS: &[&str] = &[
    "security_summary",
    "list_active_connections",
    "list_alerts",
    "destination_category",
    "builder_stack",
    "list_rules",
    "regional_threat_summary",
    "budget_policy",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub floors: BudgetFloors,
    #[serde(default)]
    pub roles: BudgetRoles,
    #[serde(default)]
    pub session: BudgetSession,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetFloors {
    #[serde(default = "default_coding_floor")]
    pub coding_hobbies: f64,
}

impl Default for BudgetFloors {
    fn default() -> Self {
        Self {
            coding_hobbies: default_coding_floor(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetRoles {
    #[serde(default = "default_security")]
    pub security_guardian: f64,
    #[serde(default = "default_marketing")]
    pub marketing_imagen: f64,
    #[serde(default = "default_coding")]
    pub coding_hobbies: f64,
    #[serde(default = "default_reserve")]
    pub reserve: f64,
}

impl Default for BudgetRoles {
    fn default() -> Self {
        Self {
            security_guardian: default_security(),
            marketing_imagen: default_marketing(),
            coding_hobbies: default_coding(),
            reserve: default_reserve(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BudgetSession {
    #[serde(default = "default_max_hours")]
    pub max_hours_per_day: f64,
    #[serde(default)]
    pub preferred_windows: Vec<String>,
    #[serde(default)]
    pub blocks_minutes: BudgetBlocks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetBlocks {
    #[serde(default = "default_block_security")]
    pub security_guardian: u32,
    #[serde(default = "default_block_marketing")]
    pub marketing_imagen: u32,
    #[serde(default = "default_block_coding")]
    pub coding_hobbies: u32,
    #[serde(default = "default_block_closeout")]
    pub closeout: u32,
}

impl Default for BudgetBlocks {
    fn default() -> Self {
        Self {
            security_guardian: default_block_security(),
            marketing_imagen: default_block_marketing(),
            coding_hobbies: default_block_coding(),
            closeout: default_block_closeout(),
        }
    }
}

fn default_version() -> u32 {
    1
}
fn default_coding_floor() -> f64 {
    0.10
}
fn default_security() -> f64 {
    0.30
}
fn default_marketing() -> f64 {
    0.45
}
fn default_coding() -> f64 {
    0.15
}
fn default_reserve() -> f64 {
    0.10
}
fn default_max_hours() -> f64 {
    3.0
}
fn default_block_security() -> u32 {
    45
}
fn default_block_marketing() -> u32 {
    90
}
fn default_block_coding() -> u32 {
    45
}
fn default_block_closeout() -> u32 {
    10
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionDigestInfo {
    pub name: String,
    pub path: String,
    pub preview: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpsSnapshot {
    pub motto: String,
    pub enforced: bool,
    pub budget_path: String,
    pub budget_source: String,
    pub budget: BudgetConfig,
    pub mcp_tools: Vec<String>,
    pub mcp_command: String,
    pub preambles: Vec<String>,
    pub sessions_dir: String,
    pub last_digest: Option<SessionDigestInfo>,
    pub notes: String,
}

impl BudgetConfig {
    pub fn load() -> (Self, String) {
        if Path::new(BUDGET_PATH).is_file() {
            match fs::read_to_string(BUDGET_PATH) {
                Ok(text) => match serde_yaml::from_str::<BudgetConfig>(&text) {
                    Ok(cfg) => return (cfg, "file".into()),
                    Err(e) => {
                        log::warn!("ops: failed to parse {BUDGET_PATH}: {e}; using embedded");
                    }
                },
                Err(e) => {
                    log::warn!("ops: failed to read {BUDGET_PATH}: {e}; using embedded");
                }
            }
        }
        match serde_yaml::from_str::<BudgetConfig>(EMBEDDED_BUDGET) {
            Ok(cfg) => (cfg, "embedded".into()),
            Err(_) => (BudgetConfig::default(), "defaults".into()),
        }
    }
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            version: 1,
            floors: BudgetFloors::default(),
            roles: BudgetRoles::default(),
            session: BudgetSession::default(),
            notes: String::new(),
        }
    }
}

/// Latest free-form digest under `intel/sessions/` (newest mtime).
pub fn latest_session_digest() -> Option<SessionDigestInfo> {
    let dir = Path::new(SESSIONS_DIR);
    if !dir.is_dir() {
        return None;
    }
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    let entries = fs::read_dir(dir).ok()?;
    for ent in entries.flatten() {
        let path = ent.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name()?.to_string_lossy();
        if name.starts_with('.') || name == ".gitkeep" {
            continue;
        }
        let meta = ent.metadata().ok()?;
        let mtime = meta.modified().ok()?;
        match &best {
            None => best = Some((mtime, path)),
            Some((t, _)) if mtime > *t => best = Some((mtime, path)),
            _ => {}
        }
    }
    let (_, path) = best?;
    let text = fs::read_to_string(&path).ok()?;
    let bytes = text.len() as u64;
    let preview = preview_text(&text, 480);
    Some(SessionDigestInfo {
        name: path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "digest".into()),
        path: path.display().to_string().replace('\\', "/"),
        preview,
        bytes,
    })
}

fn preview_text(text: &str, max: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max {
        return trimmed.to_string();
    }
    let mut out = String::new();
    for (i, ch) in trimmed.chars().enumerate() {
        if i >= max.saturating_sub(1) {
            break;
        }
        out.push(ch);
    }
    out.push('…');
    out
}

pub fn snapshot() -> OpsSnapshot {
    let (budget, source) = BudgetConfig::load();
    let preambles = [
        "ops/PREAMBLE_SECURITY.md",
        "ops/PREAMBLE_MARKETING.md",
        "ops/README.md",
    ]
    .into_iter()
    .filter(|p| Path::new(p).is_file())
    .map(|s| s.to_string())
    .collect();

    OpsSnapshot {
        motto: "Protecting the builders".into(),
        enforced: false,
        budget_path: BUDGET_PATH.into(),
        budget_source: source,
        budget,
        mcp_tools: MCP_TOOLS.iter().map(|s| (*s).to_string()).collect(),
        mcp_command: "network_guardian mcp".into(),
        preambles,
        sessions_dir: SESSIONS_DIR.into(),
        last_digest: latest_session_digest(),
        notes: "Budgets are playbook discipline only — the binary does not enforce token splits. Security agents stay read-only via MCP.".into(),
    }
}

/// Compact JSON for MCP `budget_policy`.
pub fn budget_policy_json() -> Value {
    let snap = snapshot();
    json!({
        "enforced": snap.enforced,
        "budget_path": snap.budget_path,
        "budget_source": snap.budget_source,
        "budget": snap.budget,
        "mcp_tools": snap.mcp_tools,
        "mcp_command": snap.mcp_command,
        "preambles": snap.preambles,
        "last_digest": snap.last_digest,
        "notes": snap.notes,
        "motto": snap.motto,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_budget_parses() {
        let cfg: BudgetConfig = serde_yaml::from_str(EMBEDDED_BUDGET).expect("parse embedded");
        assert_eq!(cfg.version, 1);
        assert!((cfg.floors.coding_hobbies - 0.10).abs() < f64::EPSILON);
        assert!((cfg.roles.security_guardian - 0.30).abs() < f64::EPSILON);
    }

    #[test]
    fn preview_truncates() {
        let s = "a".repeat(20);
        assert_eq!(preview_text(&s, 10).chars().count(), 10);
        assert!(preview_text(&s, 10).ends_with('…'));
    }

    #[test]
    fn mcp_tools_include_budget_policy() {
        assert!(MCP_TOOLS.contains(&"budget_policy"));
        assert!(MCP_TOOLS.contains(&"security_summary"));
    }
}
