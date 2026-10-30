//! Build metadata baked into the binary.
//!
//! Emits `MIUTURN_BUILD_TIME` (UTC, RFC3339) so production startup logs can
//! identify exactly which build is running. Uses the system `date` command
//! (present on macOS dev machines and in the linux CI builder image) to
//! avoid pulling in a date library for build.rs only.

use std::process::Command;

fn main() {
    let build_time = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=MIUTURN_BUILD_TIME={build_time}");
    println!("cargo:rerun-if-changed=build.rs");
}
