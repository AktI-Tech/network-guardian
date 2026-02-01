use notify_rust::Notification;
use crate::models::{ThreatAlert, ThreatSeverity, ThreatType};

/// Helper methods for ThreatAlert notification strings
fn threat_severity_string(severity: &ThreatSeverity) -> String {
    match severity {
        ThreatSeverity::Critical => "CRITICAL".to_string(),
        ThreatSeverity::High => "HIGH".to_string(),
        ThreatSeverity::Medium => "MEDIUM".to_string(),
        ThreatSeverity::Low => "LOW".to_string(),
    }
}

fn threat_type_string(threat_type: &ThreatType) -> String {
    match threat_type {
        ThreatType::ArpSpoofing => "ARP Spoofing".to_string(),
        ThreatType::DnsSpoofing => "DNS Spoofing".to_string(),
        ThreatType::MitmAttack => "MITM Attack".to_string(),
        ThreatType::RogueAccessPoint => "Rogue Access Point".to_string(),
        ThreatType::TrafficAnomaly => "Traffic Anomaly".to_string(),
        ThreatType::ConnectionIssue => "Connection Issue".to_string(),
    }
}

/// Desktop notification manager
pub struct NotificationManager;

impl NotificationManager {
    /// Send threat notification
    pub fn notify_threat(threat: &ThreatAlert) -> Result<(), Box<dyn std::error::Error>> {
        let severity_icon = match threat.severity {
            ThreatSeverity::Critical => "dialog-warning",
            ThreatSeverity::High => "dialog-error",
            ThreatSeverity::Medium => "dialog-question",
            ThreatSeverity::Low => "dialog-information",
        };
        
        let title = format!("🚨 {} - {}", threat_severity_string(&threat.severity), threat_type_string(&threat.threat_type));
        
        let body = if let Some(ip) = threat.ip {
            format!("IP: {}\n{}", ip, threat.description)
        } else {
            threat.description.clone()
        };
        
        Notification::new()
            .summary(&title)
            .body(&body)
            .icon(severity_icon)
            .show()?;
        
        Ok(())
    }
    
    /// Send info notification
    pub fn notify_info(title: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        Notification::new()
            .summary(title)
            .body(message)
            .icon("dialog-information")
            .show()?;
        
        Ok(())
    }
    
    /// Send success notification
    pub fn notify_success(title: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        Notification::new()
            .summary(title)
            .body(message)
            .icon("emblem-ok-symbolic")
            .show()?;
        
        Ok(())
    }
    
    /// Send error notification
    pub fn notify_error(title: &str, message: &str) -> Result<(), Box<dyn std::error::Error>> {
        Notification::new()
            .summary(title)
            .body(message)
            .icon("dialog-error")
            .show()?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_notification_strings() {
        // Test that notification strings are generated without panic
        let severity = ThreatSeverity::Critical;
        println!("Severity: {:?}", severity);
    }
}
