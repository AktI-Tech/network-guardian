use rusqlite::{Connection, Result};

fn main() -> Result<()> {
    let conn = Connection::open("threats.db")?;
    
    // Get threat count
    let count: i32 = conn.query_row(
        "SELECT COUNT(*) FROM threats",
        [],
        |row| row.get(0),
    )?;
    
    println!("Total threats logged: {}", count);
    
    if count > 0 {
        println!("\n--- Recent Threats (last 5) ---");
        let mut stmt = conn.prepare(
            "SELECT id, threat_type, severity, source_ip, dest_port, timestamp FROM threats ORDER BY timestamp DESC LIMIT 5"
        )?;
        
        let threats = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i32>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        
        for threat in threats {
            let (id, threat_type, severity, source_ip, dest_port, timestamp) = threat?;
            println!("ID: {}, Type: {}, Severity: {}, From: {}, Port: {}, Time: {}", 
                id, threat_type, severity, source_ip, dest_port, timestamp);
        }
    }
    
    Ok(())
}
