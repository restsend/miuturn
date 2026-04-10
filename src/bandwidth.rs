//! Bandwidth limiting using Token Bucket algorithm
//!
//! Provides per-allocation and per-user bandwidth control for TURN relay.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Token bucket bandwidth limiter
/// Tokens are added at a constant rate (bytes_per_sec)
/// Each packet consumes tokens equal to its size
pub struct BandwidthLimiter {
    /// Maximum tokens (bucket size)
    max_tokens: u64,
    /// Current tokens available
    tokens: AtomicU64,
    /// Tokens added per second
    rate_bytes_per_sec: u64,
    /// Last update timestamp
    last_update: parking_lot::RwLock<Instant>,
}

impl BandwidthLimiter {
    /// Create a new bandwidth limiter
    /// rate_bytes_per_sec: sustained transfer rate in bytes/second
    /// burst_bytes: maximum burst size (bucket capacity)
    pub fn new(rate_bytes_per_sec: u64, burst_bytes: u64) -> Self {
        Self {
            max_tokens: burst_bytes,
            tokens: AtomicU64::new(burst_bytes),
            rate_bytes_per_sec,
            last_update: parking_lot::RwLock::new(Instant::now()),
        }
    }

    /// Check if we can send data of given size and consume tokens if allowed
    /// Returns the number of tokens remaining after consumption
    /// Returns None if bandwidth limit would be exceeded
    pub fn try_consume(&self, size: usize) -> Option<u64> {
        let size = size as u64;
        let now = Instant::now();
        let elapsed = now.duration_since(*self.last_update.read());

        // For very high rates, avoid overflow by using saturating arithmetic
        let tokens_to_add = elapsed
            .as_secs()
            .saturating_mul(self.rate_bytes_per_sec)
            .saturating_add(
                ((elapsed.subsec_nanos() as u128 * self.rate_bytes_per_sec as u128) / 1_000_000_000)
                    as u64,
            );

        // Load current tokens
        let mut current = self.tokens.load(Ordering::Relaxed);

        loop {
            // Calculate available tokens after replenishment
            let available = std::cmp::min(current.saturating_add(tokens_to_add), self.max_tokens);

            if available < size {
                // Not enough bandwidth
                return None;
            }

            let new_tokens = available - size;
            match self.tokens.compare_exchange_weak(
                current,
                new_tokens,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // Successfully consumed tokens - update last_update
                    *self.last_update.write() = now;
                    return Some(new_tokens);
                }
                Err(e) => current = e,
            }
        }
    }

    /// Get current available bandwidth (in bytes)
    pub fn available_tokens(&self) -> u64 {
        let now = Instant::now();
        let elapsed = now.duration_since(*self.last_update.read());
        let tokens_to_add = elapsed.as_secs() * self.rate_bytes_per_sec;
        let current = self.tokens.load(Ordering::Relaxed);
        std::cmp::min(current + tokens_to_add, self.max_tokens)
    }

    /// Reset the limiter to full capacity
    pub fn reset(&self) {
        self.tokens.store(self.max_tokens, Ordering::Relaxed);
    }

    /// Get rate limit
    pub fn rate_bytes_per_sec(&self) -> u64 {
        self.rate_bytes_per_sec
    }

    /// Get max tokens (burst capacity)
    pub fn max_tokens(&self) -> u64 {
        self.max_tokens
    }
}

impl std::fmt::Debug for BandwidthLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BandwidthLimiter")
            .field("max_tokens", &self.max_tokens)
            .field("rate_bytes_per_sec", &self.rate_bytes_per_sec)
            .finish()
    }
}

/// Per-user bandwidth tracking
pub struct UserBandwidthTracker {
    /// Username or identifier
    user_id: String,
    /// Bandwidth limiter for this user
    limiter: Arc<BandwidthLimiter>,
    /// Total bytes relayed for this user
    total_bytes: AtomicU64,
    /// User's bandwidth limit in bytes per second (None = unlimited)
    limit_bytes_per_sec: Option<u64>,
}

impl UserBandwidthTracker {
    pub fn new(user_id: String, limit_bytes_per_sec: Option<u64>) -> Self {
        // For unlimited, use a very large but not max value to avoid overflow
        let rate = limit_bytes_per_sec.unwrap_or(u64::MAX / 2);
        let burst = rate.saturating_mul(10); // 10 second burst
        let limiter = Arc::new(BandwidthLimiter::new(rate, burst));
        Self {
            user_id,
            limiter,
            total_bytes: AtomicU64::new(0),
            limit_bytes_per_sec,
        }
    }

    /// Try to relay data for this user
    /// Returns Some(bytes_remaining) if allowed, None if bandwidth exceeded
    pub fn try_relay(&self, size: usize) -> Option<u64> {
        if self.limit_bytes_per_sec.is_none() {
            // Unlimited
            self.total_bytes.fetch_add(size as u64, Ordering::Relaxed);
            return Some(u64::MAX);
        }
        let result = self.limiter.try_consume(size);
        if result.is_some() {
            self.total_bytes.fetch_add(size as u64, Ordering::Relaxed);
        }
        result
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    pub fn limit_bytes_per_sec(&self) -> Option<u64> {
        self.limit_bytes_per_sec
    }
}

impl std::fmt::Debug for UserBandwidthTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserBandwidthTracker")
            .field("user_id", &self.user_id)
            .field("limit_bytes_per_sec", &self.limit_bytes_per_sec)
            .finish()
    }
}

/// Per-allocation bandwidth tracking
pub struct AllocationBandwidthTracker {
    /// Relayed address
    relayed_addr: String,
    /// Bandwidth limiter
    limiter: Arc<BandwidthLimiter>,
    /// Allocation's bandwidth limit
    limit_bytes_per_sec: Option<u64>,
}

impl AllocationBandwidthTracker {
    pub fn new(limit_bytes_per_sec: Option<u64>) -> Self {
        // For unlimited, use a very large but not max value to avoid overflow
        let rate = limit_bytes_per_sec.unwrap_or(u64::MAX / 2);
        let burst = rate.saturating_mul(10); // 10 second burst
        let limiter = Arc::new(BandwidthLimiter::new(rate, burst));
        Self {
            relayed_addr: String::new(),
            limiter,
            limit_bytes_per_sec,
        }
    }

    pub fn with_relayed_addr(mut self, addr: &str) -> Self {
        self.relayed_addr = addr.to_string();
        self
    }

    /// Try to relay data for this allocation
    pub fn try_relay(&self, size: usize) -> Option<u64> {
        if self.limit_bytes_per_sec.is_none() {
            return Some(u64::MAX);
        }
        self.limiter.try_consume(size)
    }

    pub fn limit_bytes_per_sec(&self) -> Option<u64> {
        self.limit_bytes_per_sec
    }

    pub fn relayed_addr(&self) -> &str {
        &self.relayed_addr
    }
}

impl std::fmt::Debug for AllocationBandwidthTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AllocationBandwidthTracker")
            .field("relayed_addr", &self.relayed_addr)
            .field("limit_bytes_per_sec", &self.limit_bytes_per_sec)
            .finish()
    }
}

/// Global bandwidth manager for tracking all allocations
pub struct BandwidthManager {
    /// Per-allocation trackers
    trackers:
        parking_lot::RwLock<std::collections::HashMap<String, Arc<AllocationBandwidthTracker>>>,
    /// Global bandwidth limiter
    global_limiter: Arc<BandwidthLimiter>,
    /// Total bytes relayed
    total_bytes: AtomicU64,
    /// Global limit in bytes per second
    global_limit: Option<u64>,
}

impl BandwidthManager {
    pub fn new(global_limit_bytes_per_sec: Option<u64>) -> Self {
        // For unlimited, use a very large but not max value to avoid overflow
        let rate = global_limit_bytes_per_sec.unwrap_or(u64::MAX / 2);
        let burst = rate.saturating_mul(10); // 10 second burst
        let limiter = Arc::new(BandwidthLimiter::new(rate, burst));
        Self {
            trackers: parking_lot::RwLock::new(std::collections::HashMap::new()),
            global_limiter: limiter,
            total_bytes: AtomicU64::new(0),
            global_limit: global_limit_bytes_per_sec,
        }
    }

    /// Register a new allocation with bandwidth tracking
    pub fn register_allocation(&self, relayed_addr: &str, limit_bytes_per_sec: Option<u64>) {
        let tracker = Arc::new(
            AllocationBandwidthTracker::new(limit_bytes_per_sec).with_relayed_addr(relayed_addr),
        );
        self.trackers
            .write()
            .insert(relayed_addr.to_string(), tracker);
    }

    /// Unregister an allocation
    pub fn unregister_allocation(&self, relayed_addr: &str) {
        self.trackers.write().remove(relayed_addr);
    }

    /// Try to relay data through an allocation
    /// Returns true if allowed, false if bandwidth limit exceeded
    pub fn try_relay(&self, relayed_addr: &str, size: usize) -> bool {
        // Check global limit first
        if self.global_limit.is_some() && self.global_limiter.try_consume(size).is_none() {
            return false;
        }

        // Check allocation-specific limit
        let trackers = self.trackers.read();
        if let Some(tracker) = trackers.get(relayed_addr) {
            if tracker.try_relay(size).is_some() {
                self.total_bytes.fetch_add(size as u64, Ordering::Relaxed);
                return true;
            }
            return false;
        }

        // No tracker means unlimited
        self.total_bytes.fetch_add(size as u64, Ordering::Relaxed);
        true
    }

    pub fn total_bytes_relayed(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }

    pub fn global_limit(&self) -> Option<u64> {
        self.global_limit
    }

    /// Get number of tracked allocations
    pub fn tracked_count(&self) -> usize {
        self.trackers.read().len()
    }
}

impl Default for BandwidthManager {
    fn default() -> Self {
        Self::new(None)
    }
}

impl std::fmt::Debug for BandwidthManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BandwidthManager")
            .field("global_limit", &self.global_limit)
            .field("tracked_count", &self.tracked_count())
            .field("total_bytes_relayed", &self.total_bytes_relayed())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_bandwidth_limiter_basic() {
        let limiter = BandwidthLimiter::new(1000, 5000); // 1KB/s rate, 5KB burst

        // Should be able to consume 5000 initially (burst)
        let result = limiter.try_consume(3000);
        assert!(result.is_some());

        // Should be able to consume more
        let result = limiter.try_consume(2000);
        assert!(result.is_some());

        // Should fail - burst exhausted
        let result = limiter.try_consume(100);
        assert!(result.is_none());
    }

    #[test]
    fn test_bandwidth_limiter_rate_limiting() {
        let limiter = BandwidthLimiter::new(1000, 1000); // 1KB/s rate, 1KB burst

        // Exhaust burst
        let result = limiter.try_consume(1000);
        assert!(result.is_some());

        // Should fail immediately
        let result = limiter.try_consume(100);
        assert!(result.is_none());

        // Wait for refill
        std::thread::sleep(Duration::from_millis(100));

        // Should allow some data now (0.1KB added)
        let result = limiter.try_consume(100);
        assert!(result.is_some());
    }

    #[test]
    fn test_bandwidth_limiter_reset() {
        let limiter = BandwidthLimiter::new(1000, 1000);

        // Exhaust
        let _ = limiter.try_consume(1000);
        assert!(limiter.try_consume(100).is_none());

        // Reset
        limiter.reset();
        assert!(limiter.try_consume(1000).is_some());
    }

    #[test]
    fn test_bandwidth_limiter_unlimited() {
        // Use very large values instead of u64::MAX to avoid overflow
        let limiter = BandwidthLimiter::new(u64::MAX / 4, u64::MAX / 4);

        // Should always succeed for any reasonable size
        for _ in 0..1000 {
            assert!(limiter.try_consume(1000000).is_some());
        }
    }

    #[test]
    fn test_user_bandwidth_tracker() {
        // Use a small burst to make tests predictable
        // Create tracker with rate=100, burst=100 (1 second burst)
        let tracker = UserBandwidthTracker::new("user1".to_string(), Some(100));

        // Burst is 1000 (rate * 10), so 500 + 500 = 1000 works
        assert!(tracker.try_relay(500).is_some());
        assert!(tracker.try_relay(500).is_some());

        // Now burst is exhausted, should fail
        assert!(tracker.try_relay(100).is_none());

        assert_eq!(tracker.total_bytes(), 1000);
    }

    #[test]
    fn test_user_bandwidth_tracker_unlimited() {
        let tracker = UserBandwidthTracker::new("user1".to_string(), None);

        // Should always succeed with large burst
        for _ in 0..100 {
            assert!(tracker.try_relay(1000000).is_some());
        }

        assert_eq!(tracker.total_bytes(), 100000000);
    }

    #[test]
    fn test_allocation_bandwidth_tracker() {
        // Create tracker with rate=100, burst=100 (1 second burst)
        let tracker =
            AllocationBandwidthTracker::new(Some(100)).with_relayed_addr("10.0.0.1:49152");

        // Burst is 1000 (rate * 10), so 500 + 500 = 1000 works
        assert!(tracker.try_relay(500).is_some());
        assert!(tracker.try_relay(500).is_some());

        // Now burst is exhausted, should fail
        assert!(tracker.try_relay(100).is_none());
    }

    #[test]
    fn test_bandwidth_manager() {
        // Global limit 10KB/s with 100KB burst (rate * 10)
        let manager = BandwidthManager::new(Some(10000));

        // Each allocation has 5KB limit, 50KB burst
        manager.register_allocation("10.0.0.1:49152", Some(5000));
        manager.register_allocation("10.0.0.1:49153", Some(5000));

        // Exhaust global burst (100KB) - consume 100KB total
        // First allocation: 50KB
        assert!(manager.try_relay("10.0.0.1:49152", 50000));
        // Second allocation: 50KB
        assert!(manager.try_relay("10.0.0.1:49153", 50000));

        // Burst exhausted, should fail
        assert!(!manager.try_relay("10.0.0.1:49152", 100));

        assert_eq!(manager.tracked_count(), 2);
        assert_eq!(manager.total_bytes_relayed(), 100000);
    }

    #[test]
    fn test_bandwidth_manager_unregister() {
        let manager = BandwidthManager::new(Some(10000));

        manager.register_allocation("10.0.0.1:49152", Some(5000));
        assert_eq!(manager.tracked_count(), 1);

        manager.unregister_allocation("10.0.0.1:49152");
        assert_eq!(manager.tracked_count(), 0);
    }

    #[test]
    fn test_bandwidth_manager_no_tracker() {
        let manager = BandwidthManager::new(Some(10000));

        // No tracker registered - should be unlimited
        assert!(manager.try_relay("10.0.0.1:49152", 10000));
        assert!(manager.try_relay("10.0.0.1:49152", 10000));
    }

    #[test]
    fn test_bandwidth_manager_global_only() {
        // 5KB/s global with 50KB burst (10x)
        let manager = BandwidthManager::new(Some(5000));

        // Register without specific limit
        manager.register_allocation("10.0.0.1:49152", None);

        // Should be limited by global burst (50KB)
        // Consume 50KB to exhaust burst
        assert!(manager.try_relay("10.0.0.1:49152", 50000));

        // Burst exhausted, should fail
        assert!(!manager.try_relay("10.0.0.1:49152", 100));
    }

    #[test]
    fn test_debug_formats() {
        let limiter = BandwidthLimiter::new(1000, 5000);
        let limiter_debug = format!("{:?}", limiter);
        assert!(limiter_debug.contains("BandwidthLimiter"));

        let tracker = UserBandwidthTracker::new("user1".to_string(), Some(1000));
        let tracker_debug = format!("{:?}", tracker);
        assert!(tracker_debug.contains("UserBandwidthTracker"));

        let manager = BandwidthManager::new(Some(5000));
        let manager_debug = format!("{:?}", manager);
        assert!(manager_debug.contains("BandwidthManager"));
    }
}
