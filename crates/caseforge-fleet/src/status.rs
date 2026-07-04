//! Derive a DFIR investigation's live state from its run directory — the same
//! custody-forward signals the TS workbench reads, mapped to herdr-style status.
//! Pure + deterministic: `now_secs` is passed in (never SystemTime::now here) so
//! state derivation is reproducible and unit-testable.

use std::fs;
use std::path::{Path, PathBuf};

/// herdr-style liveness of an investigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Idle,    // no audit activity (not started, or stalled cold)
    Working, // audit log growing recently
    Blocked, // heartbeat failure / sealed-partial — needs attention
    Done,    // run.manifest.json written (investigation finished)
}

/// Custody verdict for the run, independent of liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    Unknown,
    Incomplete,     // missing the hard custody files
    CustodyInvalid, // present but the seal does not verify
    Complete,       // sealed + verified
}

#[derive(Debug, Clone)]
pub struct Status {
    pub dir: PathBuf,
    pub state: RunState,
    pub custody: Custody,
    pub audit_records: usize,
    pub last_kind: Option<String>,
    pub age_secs: Option<u64>, // seconds since last audit write, if known
}

const WORKING_WINDOW_SECS: u64 = 90;
const BLOCKED_KINDS: [&str; 2] = ["heartbeat_failure", "heartbeat_terminated"];

fn read_json(path: &Path) -> Option<serde_json::Value> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// A run's manifest seal verifies if manifest_verify.json reports overall pass,
/// or the audit chain carries a passing manifest_verify seal. Fail-closed.
fn manifest_verified(dir: &Path, audit_lines: &[serde_json::Value]) -> bool {
    if let Some(v) = read_json(&dir.join("manifest_verify.json")) {
        if v.get("overall").and_then(|b| b.as_bool()) == Some(true)
            || v.get("ok").and_then(|b| b.as_bool()) == Some(true)
        {
            return true;
        }
    }
    audit_lines.iter().any(|e| {
        let tool = e
            .pointer("/payload/tool_name")
            .and_then(|t| t.as_str())
            .unwrap_or("");
        tool.contains("manifest_verify")
            && e.pointer("/payload/output/overall")
                .and_then(|b| b.as_bool())
                == Some(true)
    })
}

fn parse_audit(dir: &Path) -> Vec<serde_json::Value> {
    let text = match fs::read_to_string(dir.join("audit.jsonl")) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect()
}

fn audit_age_secs(dir: &Path, now_secs: u64) -> Option<u64> {
    let meta = fs::metadata(dir.join("audit.jsonl")).ok()?;
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(now_secs.saturating_sub(mtime))
}

/// Derive the full status of a run directory as of `now_secs` (unix seconds).
pub fn derive_status(dir: &Path, now_secs: u64) -> Status {
    let audit = parse_audit(dir);
    let last_kind = audit
        .last()
        .and_then(|e| e.get("kind"))
        .and_then(|k| k.as_str())
        .map(str::to_string);
    let age = audit_age_secs(dir, now_secs);

    let has_manifest = dir.join("run.manifest.json").exists();
    let has_audit = dir.join("audit.jsonl").exists();

    let state = if last_kind
        .as_deref()
        .map(|k| BLOCKED_KINDS.contains(&k))
        .unwrap_or(false)
    {
        RunState::Blocked
    } else if has_manifest {
        RunState::Done
    } else if age.map(|a| a <= WORKING_WINDOW_SECS).unwrap_or(false) {
        RunState::Working
    } else {
        RunState::Idle
    };

    let custody = if !has_manifest || !has_audit {
        Custody::Incomplete
    } else if manifest_verified(dir, &audit) {
        Custody::Complete
    } else {
        Custody::CustodyInvalid
    };

    Status {
        dir: dir.to_path_buf(),
        state,
        custody,
        audit_records: audit.len(),
        last_kind,
        age_secs: age,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic")
    }

    #[test]
    fn sample_run_is_done_and_complete() {
        let s = derive_status(&fixtures().join("sample-run"), 4_000_000_000);
        assert_eq!(s.state, RunState::Done); // run.manifest.json present
        assert_eq!(s.custody, Custody::Complete); // manifest_verify overall:true
        assert!(s.audit_records >= 3);
    }

    #[test]
    fn custody_invalid_run_reads_invalid() {
        let s = derive_status(&fixtures().join("custody-invalid-run"), 4_000_000_000);
        assert_eq!(s.custody, Custody::CustodyInvalid);
    }

    #[test]
    fn missing_dir_is_incomplete_idle() {
        let s = derive_status(&fixtures().join("does-not-exist"), 4_000_000_000);
        assert_eq!(s.state, RunState::Idle);
        assert_eq!(s.custody, Custody::Incomplete);
        assert_eq!(s.audit_records, 0);
    }
}
