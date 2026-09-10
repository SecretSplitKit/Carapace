use std::process::Command;

#[test]
fn help_exits_successfully_without_starting_the_server() {
    let output = Command::new(env!("CARGO_BIN_EXE_carapaced"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("Usage: carapaced"), "{stdout}");
    assert!(stdout.contains("--state-dir"), "{stdout}");
}

#[test]
fn run_help_exits_successfully_without_starting_the_server() {
    let output = Command::new(env!("CARGO_BIN_EXE_carapaced"))
        .args(["run", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .starts_with("Usage: carapaced"));
}

#[test]
fn version_exits_successfully_without_starting_the_server() {
    let output = Command::new(env!("CARGO_BIN_EXE_carapaced"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("carapaced {}", env!("CARGO_PKG_VERSION"))
    );
}
