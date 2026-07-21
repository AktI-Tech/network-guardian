//! Opt-in regional OSINT feed pull (R2).
//!
//! Privacy: HTTP GET only. Never uploads connections or process data.
//! Disabled by default. Results cached under `intel/cache/`.

use crate::region::{RegionalCampaign, RegionalIoc, RegionalSource, SnapshotFile};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CACHE_DIR: &str = "intel/cache";
const DEFAULT_UA: &str =
    "NetworkGuardian/0.9 (+https://github.com/AktI-Tech/network-guardian; pull-only; no-upload)";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedsConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Re-fetch after this many minutes (use disk cache while fresh).
    #[serde(default = "default_refresh")]
    pub refresh_minutes: u32,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub sources: Vec<FeedSource>,
}

fn default_refresh() -> u32 {
    360
}
fn default_timeout() -> u64 {
    15
}

impl Default for FeedsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            refresh_minutes: default_refresh(),
            timeout_secs: default_timeout(),
            user_agent: None,
            sources: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSource {
    pub name: String,
    pub url: String,
    /// json_pack | line_iocs
    #[serde(default = "default_format")]
    pub format: String,
    /// For line_iocs: default ioc type (ip | domain).
    #[serde(default = "default_ioc_type")]
    pub ioc_type: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_format() -> String {
    "json_pack".into()
}
fn default_ioc_type() -> String {
    "ip".into()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedPullStatus {
    pub name: String,
    pub url: String,
    pub ok: bool,
    pub from_cache: bool,
    pub ioc_count: usize,
    pub message: String,
    pub fetched_at: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct FeedMerge {
    pub iocs: Vec<RegionalIoc>,
    pub campaigns: Vec<RegionalCampaign>,
    pub sources: Vec<RegionalSource>,
    pub status: Option<String>,
    pub summary: Option<String>,
    pub industries_from_pack: bool,
    pub pulls: Vec<FeedPullStatus>,
    pub any_live: bool,
}

/// Resolve whether feeds are enabled (config + env overrides).
pub fn feeds_enabled(cfg: &FeedsConfig) -> bool {
    if let Ok(v) = std::env::var("NG_REGION_FEEDS") {
        return matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
    }
    cfg.enabled
}

/// Pull enabled feeds (or use cache) and merge into a partial snapshot overlay.
pub fn pull_and_merge(cfg: &FeedsConfig, force: bool) -> FeedMerge {
    let mut out = FeedMerge::default();
    if !feeds_enabled(cfg) {
        out.pulls.push(FeedPullStatus {
            name: "feeds".into(),
            url: String::new(),
            ok: true,
            from_cache: false,
            ioc_count: 0,
            message: "Live feeds disabled (set feeds.enabled: true or NG_REGION_FEEDS=1)".into(),
            fetched_at: None,
        });
        return out;
    }

    let mut sources = cfg.sources.clone();
    // Single-URL override for quick testing / operator packs.
    if let Ok(url) = std::env::var("NG_REGION_FEED_URL") {
        let url = url.trim().to_string();
        if !url.is_empty() {
            sources.insert(
                0,
                FeedSource {
                    name: "NG_REGION_FEED_URL".into(),
                    url,
                    format: "json_pack".into(),
                    ioc_type: "ip".into(),
                    enabled: true,
                },
            );
        }
    }

    if sources.is_empty() {
        out.pulls.push(FeedPullStatus {
            name: "feeds".into(),
            url: String::new(),
            ok: false,
            from_cache: false,
            ioc_count: 0,
            message: "feeds.enabled but no sources configured in intel/region.yml".into(),
            fetched_at: None,
        });
        return out;
    }

    let ua = cfg.user_agent.clone().unwrap_or_else(|| DEFAULT_UA.into());
    let timeout = Duration::from_secs(cfg.timeout_secs.max(3));
    let ttl = Duration::from_secs(u64::from(cfg.refresh_minutes.max(1)) * 60);

    let _ = fs::create_dir_all(CACHE_DIR);

    for src in sources.into_iter().filter(|s| s.enabled) {
        let status = fetch_one(&src, &ua, timeout, ttl, force);
        if status.ok {
            out.any_live = true;
        }
        out.ioc_count_note(&status);
        // Parse body from cache file when ok
        if status.ok {
            if let Some(path) = cache_path_for(&src.url) {
                if let Ok(body) = fs::read_to_string(&path) {
                    merge_body(&src, &body, &mut out);
                }
            }
        }
        out.pulls.push(status);
    }

    dedupe_iocs(&mut out.iocs);
    out
}

impl FeedMerge {
    fn ioc_count_note(&mut self, status: &FeedPullStatus) {
        let _ = status;
    }
}

fn cache_path_for(url: &str) -> Option<PathBuf> {
    let digest = simple_hash(url);
    Some(Path::new(CACHE_DIR).join(format!("{digest}.body")))
}

fn meta_path_for(url: &str) -> Option<PathBuf> {
    let digest = simple_hash(url);
    Some(Path::new(CACHE_DIR).join(format!("{digest}.meta")))
}

fn simple_hash(s: &str) -> String {
    // FNV-1a 64-bit — stable, no extra dep
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn fetch_one(
    src: &FeedSource,
    ua: &str,
    timeout: Duration,
    ttl: Duration,
    force: bool,
) -> FeedPullStatus {
    let cache_path = match cache_path_for(&src.url) {
        Some(p) => p,
        None => {
            return FeedPullStatus {
                name: src.name.clone(),
                url: src.url.clone(),
                ok: false,
                from_cache: false,
                ioc_count: 0,
                message: "invalid cache path".into(),
                fetched_at: None,
            };
        }
    };
    let meta_path = meta_path_for(&src.url);

    if !force {
        if let (Ok(meta), Ok(body)) = (
            meta_path
                .as_ref()
                .map(fs::read_to_string)
                .unwrap_or(Ok(String::new())),
            fs::read_to_string(&cache_path),
        ) {
            if let Some(age) = cache_age_secs(&meta) {
                if age < ttl.as_secs() && !body.is_empty() {
                    let count = count_iocs_in_body(src, &body);
                    return FeedPullStatus {
                        name: src.name.clone(),
                        url: src.url.clone(),
                        ok: true,
                        from_cache: true,
                        ioc_count: count,
                        message: format!("cache hit (age {}s)", age),
                        fetched_at: Some(meta.trim().to_string()),
                    };
                }
            }
        }
    }

    match http_get(&src.url, ua, timeout) {
        Ok(body) => {
            let now = chrono::Local::now().to_rfc3339();
            let _ = fs::write(&cache_path, &body);
            if let Some(mp) = &meta_path {
                let _ = fs::write(mp, &now);
            }
            let count = count_iocs_in_body(src, &body);
            FeedPullStatus {
                name: src.name.clone(),
                url: src.url.clone(),
                ok: true,
                from_cache: false,
                ioc_count: count,
                message: format!("fetched {} bytes", body.len()),
                fetched_at: Some(now),
            }
        }
        Err(e) => {
            // Stale cache fallback
            if let Ok(body) = fs::read_to_string(&cache_path) {
                if !body.is_empty() {
                    let count = count_iocs_in_body(src, &body);
                    let fetched_at = meta_path.as_ref().and_then(|p| fs::read_to_string(p).ok());
                    return FeedPullStatus {
                        name: src.name.clone(),
                        url: src.url.clone(),
                        ok: true,
                        from_cache: true,
                        ioc_count: count,
                        message: format!("fetch failed ({e}); using stale cache"),
                        fetched_at,
                    };
                }
            }
            FeedPullStatus {
                name: src.name.clone(),
                url: src.url.clone(),
                ok: false,
                from_cache: false,
                ioc_count: 0,
                message: format!("fetch failed: {e}"),
                fetched_at: None,
            }
        }
    }
}

fn cache_age_secs(meta: &str) -> Option<u64> {
    let ts = meta.trim();
    if ts.is_empty() {
        return None;
    }
    // Prefer file mtime via parsing RFC3339 roughly: use meta as opaque; compute from SystemTime if parse fails
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(ts) {
        let now = chrono::Local::now();
        let age = now.signed_duration_since(dt.with_timezone(&chrono::Local));
        return Some(age.num_seconds().max(0) as u64);
    }
    None
}

fn http_get(url: &str, ua: &str, timeout: Duration) -> Result<String, String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("URL must be http(s)".into());
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .user_agent(ua)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client.get(url).send().map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    // Cap body size ~4 MiB
    let bytes = resp.bytes().map_err(|e| e.to_string())?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("response too large (>4MiB)".into());
    }
    String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string())
}

fn count_iocs_in_body(src: &FeedSource, body: &str) -> usize {
    match src.format.to_ascii_lowercase().as_str() {
        "line_iocs" | "lines" | "text" => parse_line_iocs(body, &src.ioc_type, &src.name).len(),
        _ => parse_json_pack(body).map(|p| p.iocs.len()).unwrap_or(0),
    }
}

fn merge_body(src: &FeedSource, body: &str, out: &mut FeedMerge) {
    match src.format.to_ascii_lowercase().as_str() {
        "line_iocs" | "lines" | "text" => {
            let iocs = parse_line_iocs(body, &src.ioc_type, &src.name);
            out.iocs.extend(iocs);
            out.sources.push(RegionalSource {
                name: src.name.clone(),
                url: src.url.clone(),
                kind: "line_iocs".into(),
                note: "Pull-only IoC list (no local data uploaded)".into(),
            });
        }
        _ => {
            if let Some(pack) = parse_json_pack(body) {
                if !pack.iocs.is_empty() {
                    out.iocs.extend(pack.iocs);
                }
                if !pack.campaigns.is_empty() {
                    out.campaigns.extend(pack.campaigns);
                }
                if !pack.sources.is_empty() {
                    out.sources.extend(pack.sources);
                }
                if !pack.status.is_empty() {
                    out.status = Some(pack.status);
                }
                if !pack.summary.is_empty() {
                    out.summary = Some(pack.summary);
                }
                if !pack.industries.is_empty() {
                    out.industries_from_pack = true;
                    // industries applied by caller if needed — store via campaigns path only for now
                }
                out.sources.push(RegionalSource {
                    name: format!("{} (live)", src.name),
                    url: src.url.clone(),
                    kind: "json_pack".into(),
                    note: "Live JSON pack merge".into(),
                });
            }
        }
    }
}

/// Parse full or partial JSON pack (same schema as `intel/np_sa_sample.json`).
pub fn parse_json_pack(body: &str) -> Option<SnapshotFile> {
    serde_json::from_str::<SnapshotFile>(body).ok()
}

/// Parse line-oriented IoC list (# comments, blank lines skipped).
pub fn parse_line_iocs(body: &str, default_type: &str, source: &str) -> Vec<RegionalIoc> {
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        // optional "type value" or bare value
        let (ioc_type, value) = if let Some((t, v)) = line.split_once(char::is_whitespace) {
            let t = t.trim().to_ascii_lowercase();
            if matches!(t.as_str(), "ip" | "domain" | "host" | "url" | "cidr") {
                (t, v.trim().to_string())
            } else {
                (default_type.to_ascii_lowercase(), line.to_string())
            }
        } else {
            (default_type.to_ascii_lowercase(), line.to_string())
        };
        if value.is_empty() {
            continue;
        }
        // skip pure CIDR lines for line_iocs unless typed
        out.push(RegionalIoc {
            ioc_type,
            value,
            tags: vec!["feed".into()],
            source: source.into(),
            notes: format!("from feed {source}"),
        });
    }
    out
}

fn dedupe_iocs(iocs: &mut Vec<RegionalIoc>) {
    let mut seen = std::collections::HashSet::new();
    iocs.retain(|i| {
        let k = format!(
            "{}|{}",
            i.ioc_type.to_ascii_lowercase(),
            i.value.to_ascii_lowercase()
        );
        seen.insert(k)
    });
}

/// For tests: write a synthetic cache entry age helper.
#[allow(dead_code)]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lines_skips_comments() {
        let body = "# comment\n185.220.101.1\n\ndomain evil.example\nip 1.2.3.4\n";
        let iocs = parse_line_iocs(body, "ip", "test");
        assert_eq!(iocs.len(), 3);
        assert_eq!(iocs[0].value, "185.220.101.1");
        assert_eq!(iocs[1].ioc_type, "domain");
        assert_eq!(iocs[1].value, "evil.example");
        assert_eq!(iocs[2].ioc_type, "ip");
    }

    #[test]
    fn parse_embedded_style_json() {
        let body = include_str!("../intel/np_sa_sample.json");
        let pack = parse_json_pack(body).expect("sample pack");
        assert!(!pack.iocs.is_empty());
        assert!(!pack.campaigns.is_empty());
    }

    #[test]
    fn feeds_disabled_by_default() {
        // Clear env influence for this process if set
        std::env::remove_var("NG_REGION_FEEDS");
        let cfg = FeedsConfig::default();
        assert!(!feeds_enabled(&cfg));
        let m = pull_and_merge(&cfg, false);
        assert!(!m.any_live);
        assert!(!m.pulls.is_empty());
    }

    #[test]
    fn simple_hash_stable() {
        assert_eq!(simple_hash("https://a"), simple_hash("https://a"));
        assert_ne!(simple_hash("https://a"), simple_hash("https://b"));
    }
}
