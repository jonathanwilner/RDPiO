//! Embeds the git revision into the binary so every log identifies exactly
//! which build produced it — field logs from stale copies of rdpio.exe are
//! otherwise indistinguishable from current ones.

fn main() {
    // Reproducible-build override: when RDPIO_BUILD is set in the environment
    // (e.g. Nix sets it to the flake revision — there is no .git in the
    // sandbox), that value is embedded verbatim and no git call is made.
    if let Some(stamp) = std::env::var("RDPIO_BUILD")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        println!("cargo:rustc-env=RDPIO_BUILD={stamp}");
        return;
    }
    let describe = std::process::Command::new("git")
        .args(["describe", "--always", "--dirty"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=RDPIO_BUILD={describe}");
    // Re-stamp when the checked-out commit moves (HEAD for branch switches,
    // the ref file for new commits on the same branch).
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
}
