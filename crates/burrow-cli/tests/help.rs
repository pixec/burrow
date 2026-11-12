use std::process::Command;

#[test]
fn help_hides_secret_env_values() {
    let output = Command::new(env!("CARGO_BIN_EXE_burrow"))
        .args(["ps", "--help"])
        .env("BURROW_API_KEY", "leaked-api-key")
        .output()
        .unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("[env: BURROW_API_KEY]"), "{help}");
    assert!(!help.contains("leaked-api-key"), "{help}");
}
