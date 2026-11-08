#![allow(dead_code)]
//! Append-only audit log for PII events.

use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::io_gate::{IoGate, RecordFile};
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
    /// The server end, named like the service graph names it.
    pub service_identity: String,
    /// The server end's `ip:port`, always: a name taken from DNS answers
    /// seen in the traffic is only as good as those answers.
    #[serde(default)]
    pub service_addr: String,
}

/// One capture pipeline's writer of the audit log: whole lines, straight
/// to the shared file under the pipeline's gate. Nothing is kept for a
/// later flush: a refused or failed write drops its lines.
#[derive(Clone)]
pub struct PiiAuditLog {
    file: Arc<RecordFile>,
    gate: Arc<IoGate>,
}

impl PiiAuditLog {
    /// Open the audit log file, appending, owner-only (0600) like the JSON
    /// export: findings name services and PII categories.
    pub fn open(path: &str) -> Result<Arc<RecordFile>> {
        RecordFile::create(path, b"", u64::MAX, true).context("PII audit log file")
    }

    /// A writer on its own open gate (tests).
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self::on(Self::open(path)?, IoGate::new()))
    }

    pub fn on(file: Arc<RecordFile>, gate: Arc<IoGate>) -> Self {
        Self { file, gate }
    }

    pub fn emit(&self, entries: &[AuditEntry]) -> Result<()> {
        let mut buf = Vec::with_capacity(entries.len() * 160);
        for entry in entries {
            // TODO: HMAC signing for tamper detection
            serde_json::to_writer(&mut buf, entry).context("Failed to serialize audit entry")?;
            buf.push(b'\n');
        }
        self.file
            .write(&self.gate, &buf)
            .map_err(|e| anyhow::anyhow!("audit log write refused: {e:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn test_audit_log_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join("panopticon_test_audit_mode.jsonl");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let _log = PiiAuditLog::new(path.to_str().unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let _ = std::fs::remove_file(&path);
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_audit_log_append_only() {
        let dir = std::env::temp_dir();
        let path = dir.join("panopticon_test_audit.jsonl");
        let path_str = path.to_str().unwrap();

        {
            let log1 = PiiAuditLog::new(path_str).unwrap();
            log1.emit(&[AuditEntry {
                timestamp_ns: 1000,
                category: PiiCategory::Email,
                source: PiiSource::Regex,
                confidence: 1.0,
                action: AuditAction::Redacted,
                service_identity: "unknown".to_string(),
                service_addr: "unknown".to_string(),
            }])
            .unwrap();
        }

        {
            let log2 = PiiAuditLog::new(path_str).unwrap();
            log2.emit(&[AuditEntry {
                timestamp_ns: 2000,
                category: PiiCategory::Ssn,
                source: PiiSource::Ml,
                confidence: 0.9,
                action: AuditAction::Detected,
                service_identity: "unknown".to_string(),
                service_addr: "unknown".to_string(),
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
