//! Build metadata baked into the binary.
//!
//! Emits `MIUTURN_BUILD_TIME` (UTC, RFC3339) so production startup logs can
//! identify exactly which build is running.
//!
//! Computed in pure Rust (std only): calling out to external commands like
//! `date` fails silently on restricted CI builders (observed: `built unknown`
//! in the cnb docker build), so the timestamp is derived directly from the
//! system clock using the civil-from-days algorithm (Howard Hinnant).

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // civil_from_days: convert unix day number to (y, m, d).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = (z - era * 146_097) as i64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let mth = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if mth <= 2 { y + 1 } else { y };

    let ts = format!("{y:04}-{mth:02}-{d:02}T{h:02}:{m:02}:{s:02}Z");
    println!("cargo:rustc-env=MIUTURN_BUILD_TIME={ts}");

    // Commit hash of the built source. Requires .git in the build context
    // (Dockerfile COPYs it); "unknown" means the checkout was shallow or the
    // context lacked .git.
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=MIUTURN_BUILD_GIT={git_hash}");

    println!("cargo:rerun-if-changed=build.rs");
}
