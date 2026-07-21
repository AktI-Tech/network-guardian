//! Optional Suricata EVE JSON ingest (hybrid IDS hook).
//!
//! Point at an eve.json (or eve.jsonl) file with `network_guardian serve --eve path`.
//! Each alert event is mapped into the unified threat store.

use crate::models::{ThreatAlert, ThreatSeverity, ThreatType};
use chrono::Local;
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Tail-like reader for newline-delimited EVE JSON.
pub struct EveTail {
    path: PathBuf,
    offset: u64,
}

impl EveTail {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            offset: 0,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read new complete lines since last call; return parsed threat alerts.
    pub fn poll_new_alerts(&mut self) -> Result<Vec<ThreatAlert>, String> {
        let mut file = File::open(&self.path).map_err(|e| format!("open eve: {e}"))?;
        let meta_len = file.metadata().map_err(|e| format!("stat eve: {e}"))?.len();
        if meta_len < self.offset {
            // File rotated/truncated
            self.offset = 0;
        }
        file.seek(SeekFrom::Start(self.offset))
            .map_err(|e| format!("seek eve: {e}"))?;

        let mut reader = BufReader::new(file);
        let mut alerts = Vec::new();
        let mut buf = String::new();
        let mut consumed = self.offset;

        loop {
            buf.clear();
            let n = reader
                .read_line(&mut buf)
                .map_err(|e| format!("read eve: {e}"))?;
            if n == 0 {
                break;
            }
            // Incomplete last line: don't advance offset past it
            if !buf.ends_with('\n') {
                break;
            }
            consumed += n as u64;
            let line = buf.trim();
            if line.is_empty() {
                continue;
            }
            if let Some(alert) = parse_eve_line(line) {
                alerts.push(alert);
            }
        }

        self.offset = consumed;
        Ok(alerts)
    }
}

fn parse_eve_line(line: &str) -> Option<ThreatAlert> {
    let v: Value = serde_json::from_str(line).ok()?;
    let event_type = v.get("event_type")?.as_str()?;
    if event_type != "alert" {
        return None;
    }

    let signature = v
        .pointer("/alert/signature")
        .and_then(|x| x.as_str())
        .unwrap_or("Suricata alert");
    let severity_num = v
        .pointer("/alert/severity")
        .and_then(|x| x.as_u64())
        .unwrap_or(3);
    let severity = match severity_num {
        1 => ThreatSeverity::Critical,
        2 => ThreatSeverity::High,
        3 => ThreatSeverity::Medium,
        _ => ThreatSeverity::Low,
    };

    let src = v
        .get("src_ip")
        .and_then(|x| x.as_str())
        .and_then(|s| s.parse::<IpAddr>().ok());
    let dest = v.get("dest_ip").and_then(|x| x.as_str()).unwrap_or("?");
    let dest_port = v
        .get("dest_port")
        .and_then(|x| x.as_u64())
        .map(|p| p.to_string())
        .unwrap_or_else(|| "-".into());

    Some(ThreatAlert {
        threat_type: ThreatType::TrafficAnomaly,
        severity,
        ip: src,
        description: format!("Suricata: {signature} → {dest}:{dest_port}"),
        timestamp: Local::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn parses_alert_line() {
        let line = r#"{"event_type":"alert","src_ip":"1.2.3.4","dest_ip":"5.6.7.8","dest_port":443,"alert":{"signature":"ET TEST","severity":2}}"#;
        let a = parse_eve_line(line).expect("alert");
        assert!(a.description.contains("ET TEST"));
        assert_eq!(a.severity, ThreatSeverity::High);
    }

    #[test]
    fn ignores_non_alert() {
        let line = r#"{"event_type":"flow","src_ip":"1.2.3.4"}"#;
        assert!(parse_eve_line(line).is_none());
    }

    #[test]
    fn tail_reads_new_lines() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ng-eve-test-{stamp}.json"));
        {
            let mut f = File::create(&path).unwrap();
            writeln!(
                f,
                r#"{{"event_type":"alert","src_ip":"9.9.9.9","dest_ip":"8.8.8.8","dest_port":53,"alert":{{"signature":"DNS","severity":3}}}}"#
            )
            .unwrap();
        }
        let mut tail = EveTail::new(&path);
        let a1 = tail.poll_new_alerts().unwrap();
        assert_eq!(a1.len(), 1);
        let a2 = tail.poll_new_alerts().unwrap();
        assert!(a2.is_empty());
        let _ = std::fs::remove_file(path);
    }
}
