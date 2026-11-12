use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    if let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
    }
    if let Some(refs) = git(&["rev-parse", "--git-path", "refs"]) {
        println!("cargo:rerun-if-changed={refs}");
    }
    let commit = git(&["rev-parse", "--short", "HEAD"]).unwrap_or_default();
    println!("cargo:rustc-env=BURROW_COMMIT={commit}");
}
