//! Restart state persistence.
//!
//! Serializes live session state (UDP allocations, channel bindings, auth
//! nonces, lifetime counters) to a JSON file so a process restart — docker
//! stop / systemd restart / SIGUSR2 — can resume sessions instead of dropping
//! them. The file is written atomically (`tmp` + `fsync` + `rename`), so a
//! crash mid-write leaves the previous state intact.
//!
//! Restore semantics: the state carries a `config_fingerprint` derived from
//! the settings that give sessions their meaning (listening addresses, relay
//! port range, external IP, realm). A fingerprint mismatch means sessions
//! cannot safely be resumed; the state file is rotated aside and the server
//! starts fresh.
//!
//! Only UDP allocations are persisted. TCP/TLS client connections cannot be
//! re-attached to a new process and are left to ICE-level reconnect.

use crate::config::Config;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Bump when the on-disk shape of [`PersistedState`] changes in a
/// backwards-incompatible way. Loaders reject files with a different version
/// (treated as corrupt → fresh start) instead of guessing.
pub const STATE_VERSION: u32 = 1;

/// Resolved `[persist]` settings.
#[derive(Debug, Clone)]
pub struct PersistSettings {
    pub enabled: bool,
    pub path: PathBuf,
    pub checkpoint_interval_secs: u64,
}

impl From<&crate::config::PersistConfig> for PersistSettings {
    fn from(cfg: &crate::config::PersistConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            path: PathBuf::from(&cfg.path),
            checkpoint_interval_secs: cfg.checkpoint_interval_secs.max(1),
        }
    }
}

/// One persisted UDP allocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedAllocation {
    pub id: [u8; 12],
    /// Client's address as seen by the server (the allocation's 5-tuple source).
    pub client_addr: SocketAddr,
    /// Server side of the client 5-tuple.
    pub server_addr: SocketAddr,
    /// Advertised relay address (`external_ip:relay_port`). The relay port is
    /// re-bound on restore so clients keep sending to the same address.
    pub relayed_addr: SocketAddr,
    /// Authenticated username that created the allocation (NAT-rebind
    /// Refresh fallback lookup).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Unix seconds of the allocation's creation.
    pub created_at_epoch: u64,
    /// Unix seconds of the last refresh; lifetime is measured from here.
    pub refreshed_at_epoch: u64,
    /// Granted lifetime in seconds.
    pub lifetime_secs: u64,
    /// Permitted peer IPs (RFC 5766 §8, port ignored).
    #[serde(default)]
    pub permissions: Vec<std::net::IpAddr>,
    /// Bytes relayed so far (preserved so usage accounting survives restarts).
    #[serde(default)]
    pub bytes_forwarded: u64,
    #[serde(default)]
    pub messages_forwarded: u64,
}

/// One persisted channel binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedChannel {
    pub channel_id: u16,
    pub peer_addr: SocketAddr,
    pub relayed_addr: SocketAddr,
    pub created_at_epoch: u64,
    pub lifetime_secs: u64,
}

/// One persisted STUN nonce (long-term credential auth).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedNonce {
    pub nonce: String,
    pub created_at_epoch: u64,
}

/// Lifetime server counters, preserved so restarts don't reset usage stats.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct PersistedCounters {
    pub total_allocations: u64,
    pub total_bytes_relayed: u64,
    pub total_messages: u64,
}

/// The full on-disk state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedState {    pub version: u32,
    /// Unix seconds when the snapshot was taken.
    pub saved_at_epoch: u64,
    /// Fingerprint of the config the state was created with (see
    /// [`config_fingerprint`]); restore is refused on mismatch.
    pub config_fingerprint: String,
    #[serde(default)]
    pub allocations: Vec<PersistedAllocation>,
    #[serde(default)]
    pub channels: Vec<PersistedChannel>,
    #[serde(default)]
    pub nonces: Vec<PersistedNonce>,
    #[serde(default)]
    pub counters: PersistedCounters,
}

/// Sessions waiting to be re-attached after a restart. Handed from `main`
/// (where the state file is loaded) to the `AllocationTable`, and consumed
/// once the main UDP socket is bound (`run_udp` → `restore_pending`).
#[derive(Debug, Default)]
pub struct PendingRestore {
    pub allocations: Vec<PersistedAllocation>,
    pub channels: Vec<PersistedChannel>,
}

/// Why a state file could not be loaded.
#[derive(Debug)]
pub enum PersistLoadError {
    /// No state file (first start, or persistence just enabled).
    NotFound,
    /// Present but unusable (bad JSON, wrong version, wrong shape).
    Corrupt(String),
}

/// Current unix time in whole seconds (0 if the clock is before the epoch).
pub fn epoch_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Convert an [`Instant`] to unix seconds given the current epoch reading.
/// `now_epoch - elapsed` cannot go negative even for clocks at/before epoch.
pub fn epoch_of_instant(instant: Instant, now_epoch: u64) -> u64 {
    now_epoch.saturating_sub(instant.elapsed().as_secs())
}

/// Reconstruct an [`Instant`] from unix seconds. A snapshot taken `d` seconds
/// ago with timestamp `t` maps to `Instant::now() - (now_epoch - t)`, clamped
/// so future timestamps (clock moved) become "now".
pub fn instant_from_epoch(epoch_secs: u64, now_epoch: u64) -> Instant {
    if epoch_secs >= now_epoch {
        return Instant::now();
    }
    let age = Duration::from_secs(now_epoch - epoch_secs);
    Instant::now().checked_sub(age).unwrap_or_else(Instant::now)
}

/// Stable fingerprint of the config fields that give persisted sessions their
/// meaning. A change here (relay range, external IP, listeners, realm, max
/// allocation duration) invalidates previously saved state: restore is
/// refused and the server starts fresh.
pub fn config_fingerprint(config: &Config) -> String {
    use sha2::{Digest, Sha256};

    let mut listeners: Vec<String> = config
        .server
        .listening
        .iter()
        .map(|l| format!("{}://{}", l.protocol, l.address))
        .collect();
    listeners.sort();

    let canonical = format!(
        "v1|realm={}|external_ip={}|relay_bind_ip={}|ports={}-{}|listeners={}|max_alloc_dur={}",
        config.server.realm,
        config.server.external_ip,
        config.server.relay_bind_ip.as_deref().unwrap_or(""),
        config.server.start_port,
        config.server.end_port,
        listeners.join(","),
        config.server.max_allocation_duration_secs.map(|v| v.to_string()).unwrap_or_default(),
    );

    let digest = Sha256::digest(canonical.as_bytes());
    hex::encode(digest)
}

/// Atomically write `state` to `path`: serialize → write `path.tmp` →
/// `sync_all` → rename over `path` → fsync the parent directory. A crash at
/// any point leaves either the previous file or the new file, never a torn
/// one. Parent directories are created if missing.
pub fn save_state(path: &Path, state: &PersistedState) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let tmp_path = tmp_path_for(path);
    {
        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)?;

    // Best-effort directory fsync so the rename itself survives power loss.
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn tmp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Load and validate a state file. A file that fails validation is reported
/// as [`PersistLoadError::Corrupt`]; the caller decides whether to rotate it
/// aside (see `main`).
pub fn load_state(path: &Path) -> Result<PersistedState, PersistLoadError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(PersistLoadError::NotFound)
        }
        Err(e) => return Err(PersistLoadError::Corrupt(e.to_string())),
    };

    let state: PersistedState = serde_json::from_str(&content)
        .map_err(|e| PersistLoadError::Corrupt(format!("parse failed: {e}")))?;

    if state.version != STATE_VERSION {
        return Err(PersistLoadError::Corrupt(format!(
            "unsupported state version {} (expected {STATE_VERSION})",
            state.version
        )));
    }

    Ok(state)
}

/// Rename a bad state file aside (`<path>.corrupt-<epoch>`) so the next
/// checkpoint starts from a clean slate and the offending file is kept for
/// diagnosis. Best effort.
pub fn rotate_aside(path: &Path, suffix: &str) -> Option<PathBuf> {
    let aside = PathBuf::from(format!(
        "{}.{}-{}",
        path.display(),
        suffix,
        epoch_secs_now()
    ));
    match std::fs::rename(path, &aside) {
        Ok(()) => Some(aside),
        Err(_) => None,
    }
}

impl PersistedState {
    /// Serialized form with `saved_at_epoch` normalized away, for checkpoint
    /// change detection. Without this, the timestamp alone would make every
    /// snapshot look "changed" and an idle server would rewrite (and log) on
    /// every tick.
    pub fn comparison_key(&self) -> serde_json::Result<String> {
        let mut copy = self.clone();
        copy.saved_at_epoch = 0;
        serde_json::to_string(&copy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_state() -> PersistedState {
        PersistedState {
            version: STATE_VERSION,
            saved_at_epoch: 1_760_000_000,
            config_fingerprint: "abc123".to_string(),
            allocations: vec![PersistedAllocation {
                id: [7u8; 12],
                client_addr: SocketAddr::from(([1, 2, 3, 4], 50000)),
                server_addr: SocketAddr::from(([5, 6, 7, 8], 3478)),
                relayed_addr: SocketAddr::from(([5, 6, 7, 8], 49152)),
                username: Some("1760003600:user1".to_string()),
                created_at_epoch: 1_759_999_700,
                refreshed_at_epoch: 1_760_000_000,
                lifetime_secs: 600,
                permissions: vec![
                    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                    IpAddr::V6("2001:db8::1".parse().unwrap()),
                ],
                bytes_forwarded: 123_456,
                messages_forwarded: 789,
            }],
            channels: vec![PersistedChannel {
                channel_id: 0x4000,
                peer_addr: SocketAddr::from(([9, 9, 9, 9], 1234)),
                relayed_addr: SocketAddr::from(([5, 6, 7, 8], 49152)),
                created_at_epoch: 1_760_000_000,
                lifetime_secs: 600,
            }],
            nonces: vec![PersistedNonce {
                nonce: "nonce-1".to_string(),
                created_at_epoch: 1_760_000_000,
            }],
            counters: PersistedCounters {
                total_allocations: 42,
                total_bytes_relayed: 1 << 30,
                total_messages: 100_000,
            },
        }
    }

    /// Unique temp dir per test (no tempfile dependency).
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "miuturn-persist-{}-{}-{}",
            tag,
            std::process::id(),
            epoch_secs_now()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_serde_roundtrip() {
        let state = sample_state();
        let json = serde_json::to_string(&state).unwrap();
        let back: PersistedState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("state.json");
        let state = sample_state();

        save_state(&path, &state).unwrap();
        let loaded = load_state(&path).unwrap();
        assert_eq!(loaded, state);
        // No leftover temp file after a successful save.
        assert!(!tmp_path_for(&path).exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_save_creates_parent_dirs() {
        let dir = temp_dir("parents");
        let path = dir.join("a").join("b").join("state.json");
        save_state(&path, &sample_state()).unwrap();
        assert!(load_state(&path).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_missing_file_is_not_found() {
        let dir = temp_dir("missing");
        let err = load_state(&dir.join("state.json")).unwrap_err();
        assert!(matches!(err, PersistLoadError::NotFound));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_corrupt_json() {
        let dir = temp_dir("corrupt");
        let path = dir.join("state.json");
        std::fs::write(&path, "{not json").unwrap();
        let err = load_state(&path).unwrap_err();
        assert!(matches!(err, PersistLoadError::Corrupt(_)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_load_wrong_version_rejected() {
        let dir = temp_dir("version");
        let path = dir.join("state.json");
        let mut state = sample_state();
        state.version = STATE_VERSION + 1;
        save_state(&path, &state).unwrap();
        let err = load_state(&path).unwrap_err();
        assert!(matches!(err, PersistLoadError::Corrupt(_)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_atomic_save_leaves_previous_file_on_tmp_failure() {
        // Simulate a crash between tmp write and rename: the tmp file exists,
        // the real file keeps its old content and stays loadable.
        let dir = temp_dir("atomic");
        let path = dir.join("state.json");
        let old = sample_state();
        save_state(&path, &old).unwrap();

        let mut newer = sample_state();
        newer.saved_at_epoch += 100;
        // Write only the tmp side of a "new" save.
        std::fs::write(tmp_path_for(&path), serde_json::to_string(&newer).unwrap()).unwrap();

        // The previous full state is still intact and readable.
        assert_eq!(load_state(&path).unwrap(), old);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_rotate_aside_renames_file() {
        let dir = temp_dir("rotate");
        let path = dir.join("state.json");
        save_state(&path, &sample_state()).unwrap();
        let aside = rotate_aside(&path, "corrupt").expect("rename should succeed");
        assert!(aside.exists());
        assert!(!path.exists());
        assert!(aside.to_string_lossy().contains("corrupt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn fingerprint_fixture(start_port: u16) -> Config {
        let mut config = Config::default();
        config.server.realm = "fp-realm".into();
        config.server.external_ip = "1.2.3.4".into();
        config.server.start_port = start_port;
        config.server.end_port = 65535;
        config
    }

    #[test]
    fn test_fingerprint_stable_and_sensitive() {
        // Deterministic for the same config.
        assert_eq!(
            config_fingerprint(&fingerprint_fixture(49152)),
            config_fingerprint(&fingerprint_fixture(49152))
        );
        // Sensitive to relay range…
        assert_ne!(
            config_fingerprint(&fingerprint_fixture(49152)),
            config_fingerprint(&fingerprint_fixture(50000))
        );
        // …and to the realm.
        let mut other = fingerprint_fixture(49152);
        other.server.realm = "other".into();
        assert_ne!(
            config_fingerprint(&fingerprint_fixture(49152)),
            config_fingerprint(&other)
        );
        // Sensitive to the listener set.
        let mut with_listener = fingerprint_fixture(49152);
        with_listener.server.listening.push(crate::config::ListenConfig {
            protocol: "tcp".into(),
            address: "127.0.0.1:3479".into(),
        });
        assert_ne!(
            config_fingerprint(&fingerprint_fixture(49152)),
            config_fingerprint(&with_listener)
        );
    }

    #[test]
    fn test_instant_epoch_roundtrip() {
        let now_epoch = epoch_secs_now();
        let marker = Instant::now();
        std::thread::sleep(Duration::from_millis(20));

        let epoch = epoch_of_instant(marker, now_epoch);
        // The recorded epoch is in the past (sub-second sleeps round to
        // "now", so equality is allowed).
        assert!(epoch <= now_epoch);

        let rebuilt = instant_from_epoch(epoch, epoch_secs_now());
        let original_age = marker.elapsed();
        let rebuilt_age = rebuilt.elapsed();
        // Epoch conversion truncates to whole seconds, so allow up to ~1s of
        // skew between the original instant and the reconstructed one.
        let diff = if rebuilt_age >= original_age {
            (rebuilt_age - original_age).as_millis()
        } else {
            (original_age - rebuilt_age).as_millis()
        };
        assert!(diff <= 1500, "reconstructed instant drifted {diff}ms");

        // Future timestamps clamp to "now".
        let future = instant_from_epoch(now_epoch + 10_000, now_epoch);
        assert!(future.elapsed().as_millis() <= 50);
    }

    #[test]
    fn test_instant_from_epoch_clock_at_epoch() {
        // now_epoch = 0 (clock before epoch): must not panic or underflow.
        let i = instant_from_epoch(1_760_000_000, 0);
        assert!(i.elapsed().as_millis() <= 50);
    }
}
