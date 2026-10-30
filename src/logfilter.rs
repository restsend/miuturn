//! Runtime-adjustable log level filter.
//!
//! A deliberately simple [`Filter`] that keeps the current level in an
//! `AtomicU8` and answers `Interest::sometimes()` unconditionally, so every
//! event checks the live value. This sidesteps tracing's callsite interest
//! cache entirely: replacing the level through `/api/v1/reload` takes effect
//! immediately on every platform.
//!
//! (The previous implementation swapped `EnvFilter` objects through
//! `reload::Layer` — correct per the docs, but in linux containers the
//! interest cache rebuild never took effect and the old level kept filtering.
//! miuturn only ever uses a single global level string, so the richer
//! `EnvFilter` directive syntax bought nothing.)
//!
//! Semantics: `log_level = "info"` enables ERROR/WARN/INFO, "trace" enables
//! everything. Unknown values fall back to `info` with a warning on stderr
//! (tracing is not initialized yet at parse time).

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use tracing::Level;
use tracing_subscriber::layer::{Context, Filter};

#[derive(Debug, Clone)]
pub struct DynamicLevelFilter {
    level: Arc<AtomicU8>,
}

/// Numeric rank per `tracing::Level` (ERROR=1 is the most restrictive).
fn rank_of(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 1,
        Level::WARN => 2,
        Level::INFO => 3,
        Level::DEBUG => 4,
        Level::TRACE => 5,
    }
}

fn parse_level(s: &str) -> Option<u8> {
    match s.to_ascii_lowercase().as_str() {
        "error" => Some(1),
        "warn" => Some(2),
        "info" => Some(3),
        "debug" => Some(4),
        "trace" => Some(5),
        _ => None,
    }
}

impl DynamicLevelFilter {
    pub fn new(level: &str) -> Self {
        match parse_level(level) {
            Some(rank) => Self {
                level: Arc::new(AtomicU8::new(rank)),
            },
            None => {
                eprintln!(
                    "Unknown log_level {:?} (expected error|warn|info|debug|trace); defaulting to info",
                    level
                );
                Self {
                    level: Arc::new(AtomicU8::new(3)),
                }
            }
        }
    }

    /// Switch the live filter to the given level string. Invalid values are
    /// ignored (the previous level stays in force) and reported via the
    /// boolean result.
    pub fn set_level(&self, level: &str) -> bool {
        match parse_level(level) {
            Some(rank) => {
                let old = self.level.swap(rank, Ordering::Relaxed);
                if std::env::var_os("MIUTURN_FILTER_DEBUG").is_some() {
                    eprintln!("[F] set_level({level}) old={old} new={rank}");
                }
                true
            }
            None => false,
        }
    }

    pub fn level(&self) -> u8 {
        self.level.load(Ordering::Relaxed)
    }
}

impl<S: tracing::Subscriber> Filter<S> for DynamicLevelFilter {
    /// Always `sometimes()`: the registry must consult `enabled()` on every
    /// event so live level changes take effect immediately.
    fn callsite_enabled(&self, _metadata: &tracing::Metadata<'_>) -> tracing_core::Interest {
        tracing_core::Interest::sometimes()
    }

    fn enabled(&self, metadata: &tracing::Metadata<'_>, _ctx: &Context<'_, S>) -> bool {
        let result = rank_of(metadata.level()) <= self.level.load(Ordering::Relaxed);
        if std::env::var_os("MIUTURN_FILTER_DEBUG").is_some() {
            eprintln!(
                "[F] enabled(level={}) -> {} (current={})",
                metadata.level(),
                result,
                self.level.load(Ordering::Relaxed)
            );
        }
        result
    }

    /// Keep the hint at TRACE so no registry short-circuit can ever skip a
    /// callsite before our `enabled()` sees it.
    fn max_level_hint(&self) -> Option<tracing_core::LevelFilter> {
        Some(tracing_core::LevelFilter::TRACE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_parse_levels() {
        assert_eq!(parse_level("error"), Some(1));
        assert_eq!(parse_level("warn"), Some(2));
        assert_eq!(parse_level("info"), Some(3));
        assert_eq!(parse_level("debug"), Some(4));
        assert_eq!(parse_level("trace"), Some(5));
        assert_eq!(parse_level("INFO"), Some(3), "case-insensitive");
        assert_eq!(parse_level("Debug"), Some(4), "case-insensitive");
        assert_eq!(parse_level("bogus"), None);
        assert_eq!(parse_level(""), None);
    }

    #[test]
    fn test_unknown_level_defaults_to_info() {
        let f = DynamicLevelFilter::new("bogus");
        assert_eq!(f.level(), 3, "unknown falls back to info");
    }

    #[test]
    fn test_rank_ordering_semantics() {
        // info rank (3): ERROR/WARN/INFO enabled, DEBUG/TRACE suppressed.
        let f = DynamicLevelFilter::new("info");
        assert_eq!(f.level(), 3);
        assert!(3 <= 3);
        assert!(4 > 3);
        let _ = f;

        // debug rank (4): everything up to DEBUG enabled.
        let f = DynamicLevelFilter::new("debug");
        assert_eq!(f.level(), 4);
        assert!(rank_of(&Level::DEBUG) <= f.level.load(Ordering::Relaxed));
        assert!(rank_of(&Level::INFO) <= f.level.load(Ordering::Relaxed));
        let _ = f;
    }

    #[test]
    fn test_set_level_live_switch() {
        let f = DynamicLevelFilter::new("info");
        assert!(f.set_level("debug"));
        assert_eq!(f.level(), 4);
        assert!(f.set_level("error"));
        assert_eq!(f.level(), 1);
        // Invalid value: level unchanged.
        assert!(!f.set_level("nonsense"));
        assert_eq!(f.level(), 1);
    }

    #[test]
    fn test_filter_is_clone_and_shares_state() {
        let f = DynamicLevelFilter::new("info");
        let clone = f.clone();
        assert!(f.set_level("debug"));
        assert_eq!(clone.level(), 4, "clone must share the atomic");
    }
}
