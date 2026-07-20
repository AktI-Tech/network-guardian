use chrono::Local;
use rusqlite::{params, Connection, Result as SqlResult};
use std::sync::Mutex;

use crate::models::{ConnectionSample, DestinationCategory, ThreatAlert};

/// Local SQLite store for threats/alerts and connection snapshots.
/// Connection is mutex-guarded so the sampler and HTTP API can share it.
pub struct ThreatDatabase {
    connection: Mutex<Connection>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ThreatRecord {
    pub id: i64,
    pub threat_type: String,
    pub severity: String,
    pub ip_address: Option<String>,
    pub description: String,
    pub timestamp: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DestinationRecord {
    pub id: i64,
    pub host_or_ip: String,
    pub category: String,
    pub label: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub hit_count: i64,
}

impl ThreatDatabase {
    pub fn new(db_path: &str) -> SqlResult<Self> {
        let connection = Connection::open(db_path)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let db = ThreatDatabase {
            connection: Mutex::new(connection),
        };
        db.initialize_schema()?;
        Ok(db)
    }

    fn with_conn<F, T>(&self, f: F) -> SqlResult<T>
    where
        F: FnOnce(&Connection) -> SqlResult<T>,
    {
        let conn = self.connection.lock().expect("database mutex poisoned");
        f(&conn)
    }

    fn initialize_schema(&self) -> SqlResult<()> {
        self.with_conn(|connection| {
            connection.execute_batch(
                "
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    ip_address TEXT,
                    description TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_timestamp ON threats(timestamp);
                CREATE INDEX IF NOT EXISTS idx_severity ON threats(severity);
                CREATE INDEX IF NOT EXISTS idx_threat_type ON threats(threat_type);

                CREATE TABLE IF NOT EXISTS processes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    path TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(pid, name)
                );

                CREATE TABLE IF NOT EXISTS destinations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_or_ip TEXT NOT NULL UNIQUE,
                    category TEXT NOT NULL,
                    label TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_dest_category ON destinations(category);

                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    protocol TEXT NOT NULL,
                    local_addr TEXT NOT NULL,
                    local_port INTEGER NOT NULL,
                    remote_addr TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    pid INTEGER,
                    process_name TEXT,
                    process_path TEXT,
                    category TEXT NOT NULL,
                    destination_label TEXT,
                    resolved_host TEXT,
                    stack_hint TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(protocol, pid, local_port, remote_addr, remote_port)
                );

                CREATE INDEX IF NOT EXISTS idx_conn_remote ON connections(remote_addr);
                CREATE INDEX IF NOT EXISTS idx_conn_process ON connections(process_name);
                CREATE INDEX IF NOT EXISTS idx_conn_category ON connections(category);

                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                ",
            )?;
            // Migrations for DBs created before v0.2.1
            let _ = connection.execute("ALTER TABLE connections ADD COLUMN resolved_host TEXT", []);
            let _ = connection.execute("ALTER TABLE connections ADD COLUMN stack_hint TEXT", []);
            Ok(())
        })
    }

    pub fn log_threat(&self, threat: &ThreatAlert) -> SqlResult<i64> {
        let threat_type = format!("{:?}", threat.threat_type);
        let severity = format!("{:?}", threat.severity);
        let ip_str = threat.ip.map(|ip| ip.to_string());
        let timestamp = threat.timestamp.to_rfc3339();
        let created_at = Local::now().to_rfc3339();

        self.with_conn(|connection| {
            connection.execute(
                "INSERT INTO threats (threat_type, severity, ip_address, description, timestamp, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    threat_type,
                    severity,
                    ip_str,
                    threat.description,
                    timestamp,
                    created_at,
                ],
            )?;
            Ok(connection.last_insert_rowid())
        })
    }

    pub fn upsert_connection_samples(&self, samples: &[ConnectionSample]) -> SqlResult<usize> {
        let now = Local::now().to_rfc3339();
        self.with_conn(|connection| {
            let mut count = 0usize;
            for s in samples {
                connection.execute(
                    "INSERT INTO destinations (host_or_ip, category, label, first_seen, last_seen, hit_count)
                     VALUES (?, ?, ?, ?, ?, 1)
                     ON CONFLICT(host_or_ip) DO UPDATE SET
                        last_seen=excluded.last_seen,
                        hit_count=hit_count+1,
                        category=excluded.category,
                        label=COALESCE(excluded.label, destinations.label)",
                    params![
                        s.remote_addr,
                        s.category.as_str(),
                        s.destination_label,
                        now,
                        now,
                    ],
                )?;

                if let Some(pid) = s.pid {
                    let name = s.process_name.as_deref().unwrap_or("unknown");
                    connection.execute(
                        "INSERT INTO processes (pid, name, path, first_seen, last_seen)
                         VALUES (?, ?, ?, ?, ?)
                         ON CONFLICT(pid, name) DO UPDATE SET
                            last_seen=excluded.last_seen,
                            path=COALESCE(excluded.path, processes.path)",
                        params![pid as i64, name, s.process_path, now, now],
                    )?;
                }

                connection.execute(
                    "INSERT INTO connections (
                        protocol, local_addr, local_port, remote_addr, remote_port, state,
                        pid, process_name, process_path, category, destination_label,
                        resolved_host, stack_hint, first_seen, last_seen
                     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                     ON CONFLICT(protocol, pid, local_port, remote_addr, remote_port) DO UPDATE SET
                        state=excluded.state,
                        process_name=excluded.process_name,
                        process_path=excluded.process_path,
                        category=excluded.category,
                        destination_label=excluded.destination_label,
                        resolved_host=excluded.resolved_host,
                        stack_hint=excluded.stack_hint,
                        last_seen=excluded.last_seen",
                    params![
                        s.protocol,
                        s.local_addr,
                        s.local_port as i64,
                        s.remote_addr,
                        s.remote_port as i64,
                        s.state,
                        s.pid.map(|p| p as i64),
                        s.process_name,
                        s.process_path,
                        s.category.as_str(),
                        s.destination_label,
                        s.resolved_host,
                        s.stack_hint,
                        now,
                        now,
                    ],
                )?;
                count += 1;
            }

            let cutoff = (Local::now() - chrono::Duration::minutes(2)).to_rfc3339();
            connection.execute(
                "DELETE FROM connections WHERE last_seen < ?",
                params![cutoff],
            )?;

            Ok(count)
        })
    }

    pub fn get_recent_connections(&self, limit: u32) -> SqlResult<Vec<ConnectionSample>> {
        self.with_conn(|connection| {
            let mut stmt = connection.prepare(
                "SELECT protocol, local_addr, local_port, remote_addr, remote_port, state,
                        pid, process_name, process_path, category, destination_label,
                        resolved_host, stack_hint, first_seen, last_seen
                 FROM connections
                 ORDER BY last_seen DESC
                 LIMIT ?",
            )?;

            let rows = stmt
                .query_map(params![limit], |row| {
                    let first_seen_s: String = row.get(13)?;
                    let last_seen_s: String = row.get(14)?;
                    let category_s: String = row.get(9)?;
                    Ok(ConnectionSample {
                        protocol: row.get(0)?,
                        local_addr: row.get(1)?,
                        local_port: row.get::<_, i64>(2)? as u16,
                        remote_addr: row.get(3)?,
                        remote_port: row.get::<_, i64>(4)? as u16,
                        state: row.get(5)?,
                        pid: row.get::<_, Option<i64>>(6)?.map(|p| p as u32),
                        process_name: row.get(7)?,
                        process_path: row.get(8)?,
                        category: DestinationCategory::from_str_lossy(&category_s),
                        destination_label: row.get(10)?,
                        resolved_host: row.get(11)?,
                        stack_hint: row.get(12)?,
                        first_seen: chrono::DateTime::parse_from_rfc3339(&first_seen_s)
                            .map(|d| d.with_timezone(&Local))
                            .unwrap_or_else(|_| Local::now()),
                        last_seen: chrono::DateTime::parse_from_rfc3339(&last_seen_s)
                            .map(|d| d.with_timezone(&Local))
                            .unwrap_or_else(|_| Local::now()),
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            Ok(rows)
        })
    }

    pub fn count_connections(&self) -> SqlResult<i64> {
        self.with_conn(|connection| {
            connection.query_row("SELECT COUNT(*) FROM connections", [], |row| row.get(0))
        })
    }

    pub fn get_destinations(&self, limit: u32) -> SqlResult<Vec<DestinationRecord>> {
        self.with_conn(|connection| {
            let mut stmt = connection.prepare(
                "SELECT id, host_or_ip, category, label, first_seen, last_seen, hit_count
                 FROM destinations
                 ORDER BY last_seen DESC
                 LIMIT ?",
            )?;
            let rows = stmt
                .query_map(params![limit], |row| {
                    Ok(DestinationRecord {
                        id: row.get(0)?,
                        host_or_ip: row.get(1)?,
                        category: row.get(2)?,
                        label: row.get(3)?,
                        first_seen: row.get(4)?,
                        last_seen: row.get(5)?,
                        hit_count: row.get(6)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn get_recent_threats(
        &self,
        limit: u32,
    ) -> SqlResult<Vec<(i64, String, String, Option<String>, String)>> {
        self.with_conn(|connection| {
            let mut stmt = connection.prepare(
                "SELECT id, threat_type, severity, ip_address, description
                 FROM threats
                 ORDER BY timestamp DESC
                 LIMIT ?",
            )?;

            let threats = stmt
                .query_map(params![limit], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;

            Ok(threats)
        })
    }

    pub fn get_recent_threat_records(&self, limit: u32) -> SqlResult<Vec<ThreatRecord>> {
        self.with_conn(|connection| {
            let mut stmt = connection.prepare(
                "SELECT id, threat_type, severity, ip_address, description, timestamp, created_at
                 FROM threats
                 ORDER BY timestamp DESC
                 LIMIT ?",
            )?;

            let threats = stmt
                .query_map(params![limit], |row| {
                    Ok(ThreatRecord {
                        id: row.get(0)?,
                        threat_type: row.get(1)?,
                        severity: row.get(2)?,
                        ip_address: row.get(3)?,
                        description: row.get(4)?,
                        timestamp: row.get(5)?,
                        created_at: row.get(6)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            Ok(threats)
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn get_threats_by_severity(
        &self,
        severity: &str,
    ) -> SqlResult<Vec<(i64, String, String, Option<String>)>> {
        self.with_conn(|connection| {
            let mut stmt = connection.prepare(
                "SELECT id, threat_type, description, ip_address
                 FROM threats
                 WHERE severity = ?
                 ORDER BY timestamp DESC",
            )?;

            let threats = stmt
                .query_map(params![severity], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;

            Ok(threats)
        })
    }

    pub fn get_threat_count_by_type(&self) -> SqlResult<Vec<(String, i32)>> {
        self.with_conn(|connection| {
            let mut stmt = connection.prepare(
                "SELECT threat_type, COUNT(*) as count
                 FROM threats
                 GROUP BY threat_type
                 ORDER BY count DESC",
            )?;

            let counts = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;

            Ok(counts)
        })
    }

    pub fn get_statistics(&self) -> SqlResult<ThreatStatistics> {
        self.with_conn(|connection| {
            let total: i32 =
                connection.query_row("SELECT COUNT(*) FROM threats", [], |row| row.get(0))?;

            let critical: i32 = connection.query_row(
                "SELECT COUNT(*) FROM threats WHERE severity = 'Critical'",
                [],
                |row| row.get(0),
            )?;

            let high: i32 = connection.query_row(
                "SELECT COUNT(*) FROM threats WHERE severity = 'High'",
                [],
                |row| row.get(0),
            )?;

            let medium: i32 = connection.query_row(
                "SELECT COUNT(*) FROM threats WHERE severity = 'Medium'",
                [],
                |row| row.get(0),
            )?;

            let low: i32 = connection.query_row(
                "SELECT COUNT(*) FROM threats WHERE severity = 'Low'",
                [],
                |row| row.get(0),
            )?;

            Ok(ThreatStatistics {
                total,
                critical,
                high,
                medium,
                low,
            })
        })
    }

    pub fn cleanup_old_threats(&self, days_old: i32) -> SqlResult<usize> {
        let cutoff = Local::now() - chrono::Duration::days(days_old as i64);
        let cutoff_str = cutoff.to_rfc3339();

        self.with_conn(|connection| {
            connection.execute(
                "DELETE FROM threats WHERE timestamp < ?",
                params![cutoff_str],
            )
        })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ThreatStatistics {
    pub total: i32,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{DestinationCategory, ThreatSeverity, ThreatType};

    #[test]
    fn test_database_creation() {
        let db = ThreatDatabase::new(":memory:").expect("Failed to create DB");
        let stats = db.get_statistics().expect("Failed to get stats");
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn test_upsert_connections_and_destinations() {
        let db = ThreatDatabase::new(":memory:").expect("db");
        let sample = ConnectionSample {
            protocol: "TCP".into(),
            local_addr: "10.0.0.2".into(),
            local_port: 50000,
            remote_addr: "1.1.1.1".into(),
            remote_port: 443,
            state: "ESTABLISHED".into(),
            pid: Some(42),
            process_name: Some("test.exe".into()),
            process_path: None,
            category: DestinationCategory::Unknown,
            destination_label: None,
            resolved_host: Some("one.one.one.one".into()),
            stack_hint: None,
            first_seen: Local::now(),
            last_seen: Local::now(),
        };
        db.upsert_connection_samples(&[sample]).unwrap();
        assert_eq!(db.count_connections().unwrap(), 1);
        assert_eq!(db.get_destinations(10).unwrap().len(), 1);
    }

    #[test]
    fn test_log_policy_threat() {
        let db = ThreatDatabase::new(":memory:").expect("db");
        let threat = ThreatAlert {
            threat_type: ThreatType::Policy,
            severity: ThreatSeverity::Medium,
            ip: None,
            description: "test".into(),
            timestamp: Local::now(),
        };
        let id = db.log_threat(&threat).unwrap();
        assert!(id > 0);
        assert_eq!(db.get_statistics().unwrap().medium, 1);
    }
}
