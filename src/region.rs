//! Regional threat radar (R1 snapshot + R4 local correlation).
//!
//! Privacy: loads a local sample pack by default. Does not upload connection data.
//! Opt out via intel/region.yml `enabled: false` or NG_REGION_ENABLED=0.

use crate::models::{ConnectionSample, DestinationCategory};
use crate::sensors::connections;
use crate::threat_database::{DestinationRecord, ThreatDatabase};
use chrono::Local;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

const EMBEDDED_SNAPSHOT: &str = include_str!("../intel/np_sa_sample.json");
const EMBEDDED_CONFIG: &str = include_str!("../intel/region.yml");

static CACHED: OnceLock<parking_lot::Mutex<Option<RegionalSnapshot>>> = OnceLock::new();

fn cache() -> &'static parking_lot::Mutex<Option<RegionalSnapshot>> {
    CACHED.get_or_init(|| parking_lot::Mutex::new(None))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_region")]
    pub region_code: String,
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default = "default_ttl")]
    pub cache_ttl_minutes: u32,
}

fn default_true() -> bool {
    true
}
fn default_region() -> String {
    "NP".into()
}
fn default_scope() -> String {
    "south_asia".into()
}
fn default_ttl() -> u32 {
    60
}

impl Default for RegionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            region_code: default_region(),
            scope: default_scope(),
            cache_ttl_minutes: default_ttl(),
        }
    }
}

impl RegionConfig {
    pub fn load() -> Self {
        if let Ok(v) = std::env::var("NG_REGION_ENABLED") {
            let enabled = matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
            let mut c = Self::from_files();
            c.enabled = enabled;
            return c;
        }
        Self::from_files()
    }

    fn from_files() -> Self {
        if let Ok(text) = std::fs::read_to_string("intel/region.yml") {
            if let Ok(c) = serde_yaml::from_str(&text) {
                return c;
            }
        }
        serde_yaml::from_str(EMBEDDED_CONFIG).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegionalStatus {
    Quiet,
    Watch,
    Elevated,
    Critical,
}

impl RegionalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RegionalStatus::Quiet => "quiet",
            RegionalStatus::Watch => "watch",
            RegionalStatus::Elevated => "elevated",
            RegionalStatus::Critical => "critical",
        }
    }

    fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "quiet" => RegionalStatus::Quiet,
            "elevated" => RegionalStatus::Elevated,
            "critical" => RegionalStatus::Critical,
            _ => RegionalStatus::Watch,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndustryHeat {
    pub name: String,
    pub score: u8,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionalCampaign {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub countries: Vec<String>,
    pub sectors: Vec<String>,
    pub summary: String,
    pub source_name: String,
    pub source_url: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionalIoc {
    pub ioc_type: String,
    pub value: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionalSource {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocMatch {
    pub ioc_type: String,
    pub value: String,
    pub matched_as: String,
    pub process_name: Option<String>,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalExposure {
    /// none | possible | match
    pub level: String,
    pub matched_live: usize,
    pub matched_destinations: usize,
    pub watchlist_active: bool,
    pub notes: Vec<String>,
    pub matches: Vec<IocMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotFile {
    #[serde(default)]
    schema_version: u32,
    region_code: String,
    scope: String,
    status: String,
    summary: String,
    generated_at: String,
    industries: Vec<IndustryHeat>,
    campaigns: Vec<RegionalCampaign>,
    iocs: Vec<RegionalIoc>,
    sources: Vec<RegionalSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegionalSnapshot {
    pub enabled: bool,
    pub region_code: String,
    pub scope: String,
    pub status: String,
    pub summary: String,
    pub generated_at: String,
    pub loaded_at: String,
    pub is_sample: bool,
    pub industries: Vec<IndustryHeat>,
    pub campaigns: Vec<RegionalCampaign>,
    pub iocs: Vec<RegionalIoc>,
    pub sources: Vec<RegionalSource>,
    pub local_exposure: LocalExposure,
    pub disclaimer: String,
}

impl RegionalSnapshot {
    pub fn disabled(region: &str, scope: &str) -> Self {
        Self {
            enabled: false,
            region_code: region.into(),
            scope: scope.into(),
            status: RegionalStatus::Quiet.as_str().into(),
            summary: "Regional threat radar is disabled. Set intel/region.yml enabled: true or NG_REGION_ENABLED=1.".into(),
            generated_at: Local::now().to_rfc3339(),
            loaded_at: Local::now().to_rfc3339(),
            is_sample: true,
            industries: vec![],
            campaigns: vec![],
            iocs: vec![],
            sources: vec![],
            local_exposure: LocalExposure {
                level: "none".into(),
                matched_live: 0,
                matched_destinations: 0,
                watchlist_active: false,
                notes: vec!["Regional view opt-out.".into()],
                matches: vec![],
            },
            disclaimer: "Local-only product. No connection data is uploaded.".into(),
        }
    }
}

/// Full snapshot with fresh local correlation.
pub fn snapshot_with_local(db: Option<&ThreatDatabase>, watchlist: &[String]) -> RegionalSnapshot {
    let cfg = RegionConfig::load();
    if !cfg.enabled {
        return RegionalSnapshot::disabled(&cfg.region_code, &cfg.scope);
    }

    let mut base = load_base_snapshot(&cfg);
    let live = connections::sample_connections().unwrap_or_default();
    let dests = db
        .and_then(|d| d.get_destinations(500).ok())
        .unwrap_or_default();
    base.local_exposure = correlate(&base.iocs, &live, &dests, watchlist);
    base
}

fn load_base_snapshot(cfg: &RegionConfig) -> RegionalSnapshot {
    // Prefer disk pack so operators can drop updated JSON without rebuild.
    let file = if Path::new("intel/np_sa_sample.json").exists() {
        std::fs::read_to_string("intel/np_sa_sample.json").ok()
    } else {
        None
    };
    let text = file.as_deref().unwrap_or(EMBEDDED_SNAPSHOT);
    let parsed: SnapshotFile = serde_json::from_str(text).unwrap_or_else(|_| {
        serde_json::from_str(EMBEDDED_SNAPSHOT).expect("embedded snapshot valid")
    });

    let status = RegionalStatus::from_str_lossy(&parsed.status);
    RegionalSnapshot {
        enabled: true,
        region_code: if parsed.region_code.is_empty() {
            cfg.region_code.clone()
        } else {
            parsed.region_code
        },
        scope: if parsed.scope.is_empty() {
            cfg.scope.clone()
        } else {
            parsed.scope
        },
        status: status.as_str().into(),
        summary: parsed.summary,
        generated_at: parsed.generated_at,
        loaded_at: Local::now().to_rfc3339(),
        is_sample: true,
        industries: parsed.industries,
        campaigns: parsed.campaigns,
        iocs: parsed.iocs,
        sources: parsed.sources,
        local_exposure: LocalExposure {
            level: "none".into(),
            matched_live: 0,
            matched_destinations: 0,
            watchlist_active: false,
            notes: vec![],
            matches: vec![],
        },
        disclaimer: "OSINT-style sample for perspective. Not an official CERT feed. Confidence is limited until live feeds (R2) and curated AktI-Tech packs (R5).".into(),
    }
}

/// R4: intersect IoCs with live connections and known destinations.
pub fn correlate(
    iocs: &[RegionalIoc],
    live: &[ConnectionSample],
    dests: &[DestinationRecord],
    watchlist: &[String],
) -> LocalExposure {
    let mut ip_set: HashSet<String> = HashSet::new();
    let mut domain_set: HashSet<String> = HashSet::new();
    let mut ioc_notes: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    for i in iocs {
        let v = i.value.trim().to_ascii_lowercase();
        if v.is_empty() {
            continue;
        }
        ioc_notes.insert(v.clone(), i.notes.clone());
        match i.ioc_type.to_ascii_lowercase().as_str() {
            "ip" => {
                ip_set.insert(v);
            }
            "domain" | "host" | "url" => {
                // strip scheme/path for crude domain compare
                let host = v
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .split('/')
                    .next()
                    .unwrap_or(&v)
                    .to_string();
                domain_set.insert(host);
            }
            _ => {
                ip_set.insert(v.clone());
                domain_set.insert(v);
            }
        }
    }

    let mut matches = Vec::new();

    for c in live {
        let remote = c.remote_addr.trim().to_ascii_lowercase();
        let host = c
            .resolved_host
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        if ip_set.contains(&remote) {
            matches.push(IocMatch {
                ioc_type: "ip".into(),
                value: remote.clone(),
                matched_as: "live_connection".into(),
                process_name: c.process_name.clone(),
                remote_addr: Some(c.remote_addr.clone()),
                remote_port: Some(c.remote_port),
                notes: ioc_notes.get(&remote).cloned().unwrap_or_default(),
            });
        }
        if !host.is_empty()
            && domain_set
                .iter()
                .any(|d| host == *d || host.ends_with(&format!(".{d}")))
        {
            let dmatch = domain_set
                .iter()
                .find(|d| host == **d || host.ends_with(&format!(".{}", d)))
                .cloned()
                .unwrap_or(host.clone());
            matches.push(IocMatch {
                ioc_type: "domain".into(),
                value: dmatch.clone(),
                matched_as: "live_resolved_host".into(),
                process_name: c.process_name.clone(),
                remote_addr: Some(c.remote_addr.clone()),
                remote_port: Some(c.remote_port),
                notes: ioc_notes.get(&dmatch).cloned().unwrap_or_default(),
            });
        }
    }

    for d in dests {
        let host = d.host_or_ip.trim().to_ascii_lowercase();
        if ip_set.contains(&host)
            || domain_set
                .iter()
                .any(|dom| host == *dom || host.ends_with(&format!(".{dom}")))
        {
            let is_ip = ip_set.contains(&host);
            matches.push(IocMatch {
                ioc_type: if is_ip { "ip" } else { "domain" }.into(),
                value: host.clone(),
                matched_as: "destination_history".into(),
                process_name: None,
                remote_addr: Some(d.host_or_ip.clone()),
                remote_port: None,
                notes: format!("category={} hits={}", d.category, d.hit_count),
            });
        }
    }

    // Dedupe matches by value+matched_as+process
    let mut seen = HashSet::new();
    matches.retain(|m| {
        let k = format!(
            "{}|{}|{}|{}",
            m.ioc_type,
            m.value,
            m.matched_as,
            m.process_name.as_deref().unwrap_or("")
        );
        seen.insert(k)
    });

    let live_hits = matches
        .iter()
        .filter(|m| m.matched_as.starts_with("live_"))
        .count();
    let dest_match_count = matches
        .iter()
        .filter(|m| m.matched_as == "destination_history")
        .count();

    let watchlist_active = live.iter().any(|c| {
        let n = c.process_name.as_deref().unwrap_or("");
        name_matches(n, watchlist)
            && !matches!(
                c.category,
                DestinationCategory::Lan | DestinationCategory::Localhost
            )
    });

    let mut notes = Vec::new();
    if live_hits == 0 && dest_match_count == 0 {
        notes.push("No IoC overlap with live connections or known destinations.".into());
    } else {
        if live_hits > 0 {
            notes.push(format!(
                "{live_hits} live connection(s) match regional IoC sample set."
            ));
        }
        if dest_match_count > 0 {
            notes.push(format!(
                "{dest_match_count} historical destination(s) match regional IoCs."
            ));
        }
    }
    if watchlist_active {
        notes.push(
            "Watchlist process has non-LAN outbound activity while regional status is set.".into(),
        );
    }
    notes.push(
        "Sample pack includes demo IoCs (e.g. public DNS/Tor) for correlator testing — interpret carefully."
            .into(),
    );

    let level = if live_hits > 0 {
        "match"
    } else if dest_match_count > 0 || watchlist_active {
        "possible"
    } else {
        "none"
    };

    LocalExposure {
        level: level.into(),
        matched_live: live_hits,
        matched_destinations: dest_match_count,
        watchlist_active,
        notes,
        matches,
    }
}

fn name_matches(process_name: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return false;
    }
    let n = process_name.to_ascii_lowercase();
    patterns
        .iter()
        .any(|p| !p.is_empty() && n.contains(&p.to_ascii_lowercase()))
}

/// Invalidate in-memory cache (for future refresh).
pub fn clear_cache() {
    *cache().lock() = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DestinationCategory;
    use chrono::Local;

    fn conn(remote: &str, host: Option<&str>, proc: &str) -> ConnectionSample {
        ConnectionSample {
            protocol: "TCP".into(),
            local_addr: "10.0.0.2".into(),
            local_port: 50000,
            remote_addr: remote.into(),
            remote_port: 443,
            state: "ESTABLISHED".into(),
            pid: Some(1),
            process_name: Some(proc.into()),
            process_path: None,
            category: DestinationCategory::Unknown,
            destination_label: None,
            resolved_host: host.map(|s| s.into()),
            stack_hint: None,
            first_seen: Local::now(),
            last_seen: Local::now(),
        }
    }

    #[test]
    fn loads_embedded_snapshot() {
        let cfg = RegionConfig::default();
        let s = load_base_snapshot(&cfg);
        assert!(s.enabled);
        assert!(!s.campaigns.is_empty());
        assert!(!s.industries.is_empty());
        assert!(!s.iocs.is_empty());
    }

    #[test]
    fn correlate_live_ip_hit() {
        let iocs = vec![RegionalIoc {
            ioc_type: "ip".into(),
            value: "185.220.101.1".into(),
            tags: vec![],
            source: "t".into(),
            notes: "tor sample".into(),
        }];
        let live = vec![conn("185.220.101.1", None, "curl.exe")];
        let exp = correlate(&iocs, &live, &[], &[]);
        assert_eq!(exp.level, "match");
        assert_eq!(exp.matched_live, 1);
    }

    #[test]
    fn correlate_none() {
        let iocs = vec![RegionalIoc {
            ioc_type: "ip".into(),
            value: "9.9.9.9".into(),
            tags: vec![],
            source: "t".into(),
            notes: String::new(),
        }];
        let live = vec![conn("8.8.8.8", Some("dns.google"), "chrome.exe")];
        let exp = correlate(&iocs, &live, &[], &[]);
        assert_eq!(exp.level, "none");
    }

    #[test]
    fn disabled_via_config_shape() {
        let d = RegionalSnapshot::disabled("NP", "south_asia");
        assert!(!d.enabled);
        assert_eq!(d.local_exposure.level, "none");
    }
}
