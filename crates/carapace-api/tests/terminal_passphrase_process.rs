#![cfg(unix)]

use std::io::{Seek, Write};
use std::process::{Command, Stdio};

const SENTINEL: &str = "terminal-passphrase-must-not-cross-process-boundaries";
const WRAPPER: &str = r#"
import json, os, sys
report, binary, state_dir = sys.argv[1:]
argv = [binary, "run", "--state-dir", state_dir, "--terminal-passphrase", "--bind", "127.0.0.1:0"]
environment = {"PATH": os.environ.get("PATH", "")}
with open(report, "w", encoding="utf-8") as output:
    json.dump({"argv": argv, "environment": environment}, output, sort_keys=True)
os.setsid()
os.execve(binary, argv, environment)
"#;

fn run_without_terminal() -> (tempfile::TempDir, std::process::Output, u64, String) {
    let directory = tempfile::tempdir().unwrap();
    let state_dir = directory.path().join("state");
    std::fs::create_dir(&state_dir).unwrap();
    let report = directory.path().join("launch.json");
    let stdin_path = directory.path().join("redirected-input");
    let mut stdin_writer = std::fs::File::create(&stdin_path).unwrap();
    stdin_writer.write_all(SENTINEL.as_bytes()).unwrap();
    drop(stdin_writer);
    let mut stdin_reader = std::fs::File::open(&stdin_path).unwrap();

    let output = Command::new("python3")
        .args([
            "-c",
            WRAPPER,
            report.to_str().unwrap(),
            env!("CARGO_BIN_EXE_carapaced"),
            state_dir.to_str().unwrap(),
        ])
        .stdin(Stdio::from(stdin_reader.try_clone().unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("CARAPACE_PASSPHRASE")
        .output()
        .unwrap();
    let input_offset = stdin_reader.stream_position().unwrap();
    let launch = std::fs::read_to_string(report).unwrap();
    (directory, output, input_offset, launch)
}

#[test]
fn terminal_passphrase_without_a_controlling_terminal_fails_before_networking() {
    let (directory, output, input_offset, _) = run_without_terminal();
    assert!(!output.status.success());
    assert_eq!(input_offset, 0, "redirected standard input was read");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires a controlling terminal"));
    let state_dir = directory.path().join("state");
    assert!(!state_dir.join("state.redb").exists());
    assert!(!state_dir.join("api-url").exists());
    assert!(!state_dir.join("api-token").exists());
}

#[test]
fn terminal_passphrase_is_absent_from_process_inputs_and_output() {
    let (_, output, _, launch) = run_without_terminal();
    assert!(
        !launch.contains(SENTINEL),
        "passphrase entered argv or environment"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SENTINEL));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SENTINEL));
}
