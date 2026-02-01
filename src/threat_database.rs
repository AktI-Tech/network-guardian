use rusqlite::{Connection, Result as SqlResult, params};
use chrono::Local;
use crate::models::ThreatAlert;

/// Threat database manager
pub struct ThreatDatabase {
    connection: Connection,
}

impl ThreatDatabase {
    /// Create or open threat database
    pub fn new(db_path: &str) -> SqlResult<Self> {
        let connection = Connection::open(db_path)?;
        let db = ThreatDatabase { connection };
        db.initialize_schema()?;
        Ok(db)
    }
    
    /// Initialize database schema
    fn initialize_schema(&self) -> SqlResult<()> {
        self.connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS threats (
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
            CREATE INDEX IF NOT EXISTS idx_threat_type ON threats(threat_type);",
        )?;
        Ok(())
    }
    
    /// Log a threat alert to database
    pub fn log_threat(&self, threat: &ThreatAlert) -> SqlResult<i64> {
        let threat_type = format!("{:?}", threat.threat_type);
        let severity = format!("{:?}", threat.severity);
        let ip_str = threat.ip.map(|ip| ip.to_string());
        let timestamp = threat.timestamp.to_rfc3339();
        let created_at = Local::now().to_rfc3339();
        
        self.connection.execute(
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
        
        Ok(self.connection.last_insert_rowid())
    }
    
    /// Get recent threats
    pub fn get_recent_threats(&self, limit: u32) -> SqlResult<Vec<(i64, String, String, Option<String>, String)>> {
        let mut stmt = self.connection.prepare(
            "SELECT id, threat_type, severity, ip_address, description 
             FROM threats 
             ORDER BY timestamp DESC 
             LIMIT ?"
        )?;
        
        let threats = stmt.query_map(params![limit], |row| {
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
    }
    
    /// Get threats by severity
    pub fn get_threats_by_severity(&self, severity: &str) -> SqlResult<Vec<(i64, String, String, Option<String>)>> {
        let mut stmt = self.connection.prepare(
            "SELECT id, threat_type, description, ip_address 
             FROM threats 
             WHERE severity = ? 
             ORDER BY timestamp DESC"
        )?;
        
        let threats = stmt.query_map(params![severity], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
        
        Ok(threats)
    }
    
    /// Get threat count by type
    pub fn get_threat_count_by_type(&self) -> SqlResult<Vec<(String, i32)>> {
        let mut stmt = self.connection.prepare(
            "SELECT threat_type, COUNT(*) as count 
             FROM threats 
             GROUP BY threat_type 
             ORDER BY count DESC"
        )?;
        
        let counts = stmt.query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
        
        Ok(counts)
    }
    
    /// Get threat statistics
    pub fn get_statistics(&self) -> SqlResult<ThreaStatistics> {
        let total: i32 = self.connection.query_row(
            "SELECT COUNT(*) FROM threats",
            [],
            |row| row.get(0),
        )?;
        
        let critical: i32 = self.connection.query_row(
            "SELECT COUNT(*) FROM threats WHERE severity = 'Critical'",
            [],
            |row| row.get(0),
        )?;
        
        let high: i32 = self.connection.query_row(
            "SELECT COUNT(*) FROM threats WHERE severity = 'High'",
            [],
            |row| row.get(0),
        )?;
        
        let medium: i32 = self.connection.query_row(
            "SELECT COUNT(*) FROM threats WHERE severity = 'Medium'",
            [],
            |row| row.get(0),
        )?;
        
        let low: i32 = self.connection.query_row(
            "SELECT COUNT(*) FROM threats WHERE severity = 'Low'",
            [],
            |row| row.get(0),
        )?;
        
        Ok(ThreaStatistics {
            total,
            critical,
            high,
            medium,
            low,
        })
    }
    
    /// Clear old threats (older than days_old)
    pub fn cleanup_old_threats(&self, days_old: i32) -> SqlResult<usize> {
        let cutoff = Local::now() - chrono::Duration::days(days_old as i64);
        let cutoff_str = cutoff.to_rfc3339();
        
        self.connection.execute(
            "DELETE FROM threats WHERE timestamp < ?",
            params![cutoff_str],
        )
    }
}

#[derive(Debug, Clone)]
pub struct ThreaStatistics {
    pub total: i32,
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_database_creation() {
        let db = ThreatDatabase::new(":memory:").expect("Failed to create DB");
        let stats = db.get_statistics().expect("Failed to get stats");
        assert_eq!(stats.total, 0);
    }
}
