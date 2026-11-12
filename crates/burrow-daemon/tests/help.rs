use std::process::Command;

#[test]
fn help_hides_secret_env_values() {
    let output = Command::new(env!("CARGO_BIN_EXE_burrowd"))
        .args(["serve", "--help"])
        .env("BURROW_API_KEY", "leaked-api-key")
        .env("BURROW_NODE_TOKEN", "leaked-node-token")
        .output()
        .unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("[env: BURROW_NODE_TOKEN]"), "{help}");
    for secret in ["leaked-api-key", "leaked-node-token"] {
        assert!(!help.contains(secret), "{help}");
    }
}
