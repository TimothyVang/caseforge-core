//! Launch primitive: spawn an investigation as a child process. The fleet points
//! this at `caseforge investigate <evidence> ...`; the resulting run dir is then
//! tracked by status::derive_status. Kept minimal + injectable so it is testable
//! without the real caseforge/verdict binary.

use std::process::{Child, Command, Stdio};

/// Spawn `program` with `args`, detached from our stdio (the fleet renders status
/// from the run dir, not the child's stdout). Returns the live child handle.
pub fn spawn(program: &str, args: &[String]) -> std::io::Result<Child> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// Build the argv for a caseforge investigation of `evidence`.
pub fn investigate_args(evidence: &str, extra: &[String]) -> Vec<String> {
    let mut v = vec!["investigate".to_string(), evidence.to_string()];
    v.extend_from_slice(extra);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_runs_a_process() {
        let mut child = spawn("sh", &["-c".into(), "exit 0".into()]).expect("spawn");
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn investigate_args_shape() {
        let a = investigate_args("/ev/x.E01", &["--privacy".into(), "local-only".into()]);
        assert_eq!(a[0], "investigate");
        assert_eq!(a[1], "/ev/x.E01");
        assert_eq!(a.last().unwrap(), "local-only");
    }
}
