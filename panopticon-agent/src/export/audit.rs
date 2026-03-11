#![allow(dead_code)]
//! Append-only audit log for PII events.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::pii::{PiiCategory, PiiSource};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditAction {
    Detected,
    Redacted,
    Suppressed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp_ns: u64,
    pub category: PiiCategory,
    pub source: PiiSource,
    pub confidence: f32,
    pub action: AuditAction,
    pub service_identity: String,
}

pub struct PiiAuditLog {
    writer: BufWriter<File>,
}

impl PiiAuditLog {
    pub fn new(path: &str) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open PII audit log file: {}", path))?;

        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    pub fn emit(&mut self, entries: &[AuditEntry]) -> Result<()> {
        for entry in entries {
            // TODO: HMAC signing for tamper detection
            serde_json::to_writer(&mut self.writer, entry)
                .context("Failed to serialize audit entry")?;
            self.writer.write_all(b"\n")?;
        }
        self.writer.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_append_only() {
        let dir = std::env::temp_dir();
        let path = dir.join("panopticon_test_audit.jsonl");
        let path_str = path.to_str().unwrap();

        {
            let mut log1 = PiiAuditLog::new(path_str).unwrap();
            log1.emit(&[AuditEntry {
                timestamp_ns: 1000,
                category: PiiCategory::Email,
                source: PiiSource::Regex,
                confidence: 1.0,
                action: AuditAction::Redacted,
                service_identity: "unknown".to_string(),
            }])
            .unwrap();
        }

        {
            let mut log2 = PiiAuditLog::new(path_str).unwrap();
            log2.emit(&[AuditEntry {
                timestamp_ns: 2000,
                category: PiiCategory::Ssn,
                source: PiiSource::Ml,
                confidence: 0.9,
                action: AuditAction::Detected,
                service_identity: "unknown".to_string(),
            }])
            .unwrap();
        }

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        let e1: AuditEntry = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(e1.timestamp_ns, 1000);
        let e2: AuditEntry = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(e2.timestamp_ns, 2000);

        std::fs::remove_file(&path).ok();
    }
}
