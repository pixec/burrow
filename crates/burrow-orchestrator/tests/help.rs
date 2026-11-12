use std::process::Command;

#[test]
fn help_hides_secret_env_values() {
    let output = Command::new(env!("CARGO_BIN_EXE_burrow-orchestrator"))
        .args(["--help"])
        .env("BURROW_API_KEY", "leaked-api-key")
        .env("BURROW_NODE_TOKEN", "leaked-node-token")
        .env(
            "BURROW_DATABASE_URL",
            "postgres://burrow:leaked-password@db/burrow",
        )
        .output()
        .unwrap();
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("[env: BURROW_DATABASE_URL]"), "{help}");
    for secret in ["leaked-api-key", "leaked-node-token", "leaked-password"] {
        assert!(!help.contains(secret), "{help}");
    }
}
