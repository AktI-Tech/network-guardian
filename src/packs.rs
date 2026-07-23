//! Local curated threat packs (R5).
//!
//! Drop JSON packs under `intel/packs/` (same schema as the regional sample pack,
//! plus optional pack metadata). No network — operator / AktI-Tech curated files only.
//! Privacy: never uploads connections; never fetches URLs.

use crate::region::{
    IndustryHeat, RegionalCampaign, RegionalIoc, RegionalSource, SnapshotFile,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_DIR: &str = "intel/packs";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacksConfig {
    /// Load local packs from disk (default true).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Directory relative to process CWD (default `intel/packs`).
    #[serde(default = "default_dir")]
    pub directory: String,
    /// If non-empty, only load these pack ids or file stems.
    #[serde(default)]
    pub prefer: Vec<String>,
    /// Keep sample pack as the base layer (default true).
    #[serde(default = "default_true")]
    pub include_sample: bool,
}

fn default_true() -> bool {
    true
}
fn default_dir() -> String {
    DEFAULT_DIR.into()
}

impl Default for PacksConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            directory: default_dir(),
            prefer: Vec::new(),
            include_sample: true,
        }
    }
}

/// Whether local curated packs are enabled (`NG_REGION_PACKS` overrides config).
pub fn packs_enabled(cfg: &PacksConfig) -> bool {
    if let Ok(v) = std::env::var("NG_REGION_PACKS") {
        return matches!(
            v.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        );
    }
    cfg.enabled
}

/// Metadata for a pack discovered on disk or successfully loaded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadedPack {
    pub id: String,
    pub name: String,
    pub version: String,
    pub curator: String,
    /// sample | curated | custom
    pub kind: String,
    pub path: String,
    pub ioc_count: usize,
    pub campaign_count: usize,
    pub loaded: bool,
    pub message: String,
}

/// Result of scanning + merging local packs into the regional base.
#[derive(Debug, Clone, Default)]
pub struct PackMerge {
    pub packs: Vec<LoadedPack>,
    pub iocs: Vec<RegionalIoc>,
    pub campaigns: Vec<RegionalCampaign>,
    pub industries: Vec<IndustryHeat>,
    pub sources: Vec<RegionalSource>,
    pub status: Option<String>,
    pub summary: Option<String>,
    pub region_code: Option<String>,
    pub scope: Option<String>,
    /// True when at least one curated (non-sample) pack contributed data.
    pub any_curated: bool,
}

/// Optional envelope fields on pack JSON (all optional for back-compat).
#[derive(Debug, Clone, Deserialize)]
struct PackEnvelope {
    #[serde(default)]
    pack_id: String,
    #[serde(default)]
    pack_name: String,
    #[serde(default)]
    pack_version: String,
    #[serde(default)]
    curator: String,
    #[serde(default)]
    kind: String,
    #[serde(flatten)]
    body: SnapshotFile,
}

/// List packs available under the configured directory (does not require enabled).
pub fn list_available(cfg: &PacksConfig) -> Vec<LoadedPack> {
    let dir = Path::new(&cfg.directory);
    if !dir.is_dir() {
        return vec![];
    }
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    for path in paths {
        match load_pack_file(&path) {
            Ok((meta, env)) => {
                let filtered_out = !prefer_allows(&cfg.prefer, &meta.id, &path);
                out.push(LoadedPack {
                    id: meta.id,
                    name: meta.name,
                    version: meta.version,
                    curator: meta.curator,
                    kind: meta.kind,
                    path: path.display().to_string(),
                    ioc_count: env.body.iocs.len(),
                    campaign_count: env.body.campaigns.len(),
                    loaded: !filtered_out,
                    message: if filtered_out {
                        "available (not in packs.prefer)".into()
                    } else {
                        "available".into()
                    },
                });
            }
            Err(e) => {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                out.push(LoadedPack {
                    id: stem,
                    name: path.display().to_string(),
                    version: String::new(),
                    curator: String::new(),
                    kind: "error".into(),
                    path: path.display().to_string(),
                    ioc_count: 0,
                    campaign_count: 0,
                    loaded: false,
                    message: e,
                });
            }
        }
    }
    out
}

/// Load and merge enabled packs (respecting prefer filter).
pub fn load_and_merge(cfg: &PacksConfig) -> PackMerge {
    let mut out = PackMerge::default();
    if !packs_enabled(cfg) {
        out.packs.push(LoadedPack {
            id: "packs".into(),
            name: "Local packs".into(),
            version: String::new(),
            curator: String::new(),
            kind: "disabled".into(),
            path: cfg.directory.clone(),
            ioc_count: 0,
            campaign_count: 0,
            loaded: false,
            message: "Local packs disabled (set packs.enabled: true or NG_REGION_PACKS=1)".into(),
        });
        return out;
    }

    let dir = Path::new(&cfg.directory);
    if !dir.is_dir() {
        out.packs.push(LoadedPack {
            id: "packs".into(),
            name: "Local packs".into(),
            version: String::new(),
            curator: String::new(),
            kind: "missing".into(),
            path: cfg.directory.clone(),
            ioc_count: 0,
            campaign_count: 0,
            loaded: false,
            message: format!("Pack directory not found: {}", cfg.directory),
        });
        return out;
    }

    let available = list_available(cfg);
    let mut to_load: Vec<PathBuf> = available
        .iter()
        .filter(|p| p.kind != "error" && prefer_allows(&cfg.prefer, &p.id, Path::new(&p.path)))
        .map(|p| PathBuf::from(&p.path))
        .collect();

    // Prefer list order when set
    if !cfg.prefer.is_empty() {
        to_load.sort_by_key(|p| {
            let stem = p
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            cfg.prefer
                .iter()
                .position(|x| x.eq_ignore_ascii_case(&stem) || path_matches_prefer(p, x))
                .unwrap_or(usize::MAX)
        });
    }

    for path in to_load {
        match load_pack_file(&path) {
            Ok((meta, env)) => {
                let is_curated = !matches!(
                    meta.kind.to_ascii_lowercase().as_str(),
                    "sample" | "local_sample"
                );
                if is_curated {
                    out.any_curated = true;
                }
                // Last pack wins for status/summary when set
                if !env.body.status.is_empty() {
                    out.status = Some(env.body.status.clone());
                }
                if !env.body.summary.is_empty() {
                    out.summary = Some(env.body.summary.clone());
                }
                if !env.body.region_code.is_empty() {
                    out.region_code = Some(env.body.region_code.clone());
                }
                if !env.body.scope.is_empty() {
                    out.scope = Some(env.body.scope.clone());
                }
                out.iocs.extend(env.body.iocs.iter().cloned());
                out.campaigns.extend(env.body.campaigns.iter().cloned());
                merge_industries(&mut out.industries, &env.body.industries);
                out.sources.extend(env.body.sources.iter().cloned());
                out.sources.push(RegionalSource {
                    name: format!("pack:{}", meta.id),
                    url: path.display().to_string(),
                    kind: meta.kind.clone(),
                    note: format!(
                        "{} v{} by {} ({} IoCs)",
                        meta.name,
                        meta.version,
                        if meta.curator.is_empty() {
                            "unknown"
                        } else {
                            &meta.curator
                        },
                        env.body.iocs.len()
                    ),
                });
                out.packs.push(LoadedPack {
                    id: meta.id,
                    name: meta.name,
                    version: meta.version,
                    curator: meta.curator,
                    kind: meta.kind,
                    path: path.display().to_string(),
                    ioc_count: env.body.iocs.len(),
                    campaign_count: env.body.campaigns.len(),
                    loaded: true,
                    message: "loaded".into(),
                });
            }
            Err(e) => {
                out.packs.push(LoadedPack {
                    id: path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("unknown")
                        .into(),
                    name: path.display().to_string(),
                    version: String::new(),
                    curator: String::new(),
                    kind: "error".into(),
                    path: path.display().to_string(),
                    ioc_count: 0,
                    campaign_count: 0,
                    loaded: false,
                    message: e,
                });
            }
        }
    }

    dedupe_iocs(&mut out.iocs);
    dedupe_campaigns(&mut out.campaigns);
    out
}

struct PackMeta {
    id: String,
    name: String,
    version: String,
    curator: String,
    kind: String,
}

fn load_pack_file(path: &Path) -> Result<(PackMeta, PackEnvelope), String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
    let env: PackEnvelope =
        serde_json::from_str(&text).map_err(|e| format!("parse JSON: {e}"))?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("pack")
        .to_string();
    let id = if env.pack_id.is_empty() {
        stem.clone()
    } else {
        env.pack_id.clone()
    };
    let name = if env.pack_name.is_empty() {
        id.clone()
    } else {
        env.pack_name.clone()
    };
    let version = if env.pack_version.is_empty() {
        "0".into()
    } else {
        env.pack_version.clone()
    };
    let curator = env.curator.clone();
    let kind = if env.kind.is_empty() {
        "curated".into()
    } else {
        env.kind.clone()
    };
    Ok((
        PackMeta {
            id,
            name,
            version,
            curator,
            kind,
        },
        env,
    ))
}

fn prefer_allows(prefer: &[String], id: &str, path: &Path) -> bool {
    if prefer.is_empty() {
        return true;
    }
    prefer.iter().any(|p| {
        p.eq_ignore_ascii_case(id)
            || path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(|s| s.eq_ignore_ascii_case(p))
                .unwrap_or(false)
            || path_matches_prefer(path, p)
    })
}

fn path_matches_prefer(path: &Path, prefer: &str) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case(prefer))
        .unwrap_or(false)
}

fn merge_industries(dst: &mut Vec<IndustryHeat>, src: &[IndustryHeat]) {
    for ind in src {
        if let Some(existing) = dst.iter_mut().find(|e| e.name.eq_ignore_ascii_case(&ind.name)) {
            if ind.score > existing.score {
                existing.score = ind.score;
                existing.rationale = ind.rationale.clone();
            }
        } else {
            dst.push(ind.clone());
        }
    }
}

fn dedupe_iocs(iocs: &mut Vec<RegionalIoc>) {
    let mut seen = HashSet::new();
    iocs.retain(|i| {
        let k = format!(
            "{}|{}",
            i.ioc_type.to_ascii_lowercase(),
            i.value.to_ascii_lowercase()
        );
        seen.insert(k)
    });
}

fn dedupe_campaigns(campaigns: &mut Vec<RegionalCampaign>) {
    let mut seen = HashSet::new();
    campaigns.retain(|c| seen.insert(c.id.to_ascii_lowercase()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn prefer_filter_by_id() {
        assert!(prefer_allows(&[], "any", Path::new("x.json")));
        assert!(prefer_allows(
            &["akti-builders-v1".into()],
            "akti-builders-v1",
            Path::new("intel/packs/other.json")
        ));
        assert!(!prefer_allows(
            &["akti-builders-v1".into()],
            "other",
            Path::new("intel/packs/other.json")
        ));
    }

    #[test]
    fn merge_industries_takes_max_score() {
        let mut dst = vec![IndustryHeat {
            name: "Builders / Tech".into(),
            score: 40,
            rationale: "base".into(),
        }];
        merge_industries(
            &mut dst,
            &[IndustryHeat {
                name: "Builders / Tech".into(),
                score: 70,
                rationale: "curated".into(),
            }],
        );
        assert_eq!(dst.len(), 1);
        assert_eq!(dst[0].score, 70);
        assert_eq!(dst[0].rationale, "curated");
    }

    #[test]
    fn load_pack_file_reads_metadata() {
        let dir = std::env::temp_dir().join("ng_pack_test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test-pack.json");
        let mut f = fs::File::create(&path).unwrap();
        write!(
            f,
            r#"{{
            "pack_id": "test-pack",
            "pack_name": "Test Pack",
            "pack_version": "1.2.3",
            "curator": "AktI-Tech",
            "kind": "curated",
            "schema_version": 1,
            "status": "watch",
            "summary": "unit test pack",
            "iocs": [{{"ioc_type":"ip","value":"203.0.113.10","tags":[],"source":"t","notes":""}}],
            "campaigns": [],
            "industries": [],
            "sources": []
        }}"#
        )
        .unwrap();
        let (meta, env) = load_pack_file(&path).expect("parse");
        assert_eq!(meta.id, "test-pack");
        assert_eq!(meta.version, "1.2.3");
        assert_eq!(env.body.iocs.len(), 1);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn load_and_merge_disabled() {
        let cfg = PacksConfig {
            enabled: false,
            ..Default::default()
        };
        // Ensure env does not force on during test
        std::env::remove_var("NG_REGION_PACKS");
        let m = load_and_merge(&cfg);
        assert!(!m.any_curated);
        assert!(!m.packs.is_empty());
        assert_eq!(m.packs[0].kind, "disabled");
    }
}
