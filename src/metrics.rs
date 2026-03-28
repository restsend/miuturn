//! Prometheus metrics for TURN server
//!
//! Provides comprehensive metrics for monitoring TURN server performance.

use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Prometheus-style metrics collector
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<RwLock<MetricsInner>>,
}

struct MetricsInner {
    // Connection metrics
    total_allocations: u64,
    active_allocations: u64,
    total_bytes_relayed: u64,
    total_messages: u64,

    // Request metrics
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    auth_failures: u64,

    // Channel metrics
    total_channel_binds: u64,
    active_channels: u64,

    // Timing metrics (simplified)
    last_request_duration_ms: u64,

    // Start time
    start_time: Instant,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(MetricsInner {
                total_allocations: 0,
                active_allocations: 0,
                total_bytes_relayed: 0,
                total_messages: 0,
                total_requests: 0,
                successful_requests: 0,
                failed_requests: 0,
                auth_failures: 0,
                total_channel_binds: 0,
                active_channels: 0,
                last_request_duration_ms: 0,
                start_time: Instant::now(),
            })),
        }
    }

    // Allocation metrics
    pub fn record_allocation(&self) {
        let inner = &mut (*self.inner.write());
        inner.total_allocations += 1;
        inner.active_allocations += 1;
    }

    pub fn record_allocation_dropped(&self) {
        let mut inner = self.inner.write();
        if inner.active_allocations > 0 {
            inner.active_allocations -= 1;
        }
    }

    // Data relay metrics
    pub fn record_bytes_relayed(&self, bytes: usize) {
        let mut inner = self.inner.write();
        inner.total_bytes_relayed += bytes as u64;
        inner.total_messages += 1;
    }

    // Request metrics
    pub fn record_request(&self, success: bool, duration: Duration, auth_failed: bool) {
        let mut inner = self.inner.write();
        inner.total_requests += 1;
        if success {
            inner.successful_requests += 1;
        } else {
            inner.failed_requests += 1;
        }
        if auth_failed {
            inner.auth_failures += 1;
        }
        inner.last_request_duration_ms = duration.as_millis() as u64;
    }

    // Channel metrics
    pub fn record_channel_bind(&self) {
        let mut inner = self.inner.write();
        inner.total_channel_binds += 1;
        inner.active_channels += 1;
    }

    pub fn record_channel_unbind(&self) {
        let mut inner = self.inner.write();
        if inner.active_channels > 0 {
            inner.active_channels -= 1;
        }
    }

    /// Get current metrics snapshot
    pub fn snapshot(&self) -> MetricsSnapshot {
        let inner = self.inner.read();
        let uptime = inner.start_time.elapsed();

        MetricsSnapshot {
            total_allocations: inner.total_allocations,
            active_allocations: inner.active_allocations,
            total_bytes_relayed: inner.total_bytes_relayed,
            total_messages: inner.total_messages,
            total_requests: inner.total_requests,
            successful_requests: inner.successful_requests,
            failed_requests: inner.failed_requests,
            auth_failures: inner.auth_failures,
            total_channel_binds: inner.total_channel_binds,
            active_channels: inner.active_channels,
            last_request_duration_ms: inner.last_request_duration_ms,
            uptime_secs: uptime.as_secs(),
        }
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let snap = self.snapshot();
        let mut output = String::new();

        output.push_str("# HELP turn_total_allocations Total number of allocations created\n");
        output.push_str("# TYPE turn_total_allocations counter\n");
        output.push_str(&format!(
            "turn_total_allocations {}\n",
            snap.total_allocations
        ));

        output.push_str("# HELP turn_active_allocations Current number of active allocations\n");
        output.push_str("# TYPE turn_active_allocations gauge\n");
        output.push_str(&format!(
            "turn_active_allocations {}\n",
            snap.active_allocations
        ));

        output.push_str("# HELP turn_total_bytes_relayed Total bytes relayed\n");
        output.push_str("# TYPE turn_total_bytes_relayed counter\n");
        output.push_str(&format!(
            "turn_total_bytes_relayed {}\n",
            snap.total_bytes_relayed
        ));

        output.push_str("# HELP turn_total_messages Total messages relayed\n");
        output.push_str("# TYPE turn_total_messages counter\n");
        output.push_str(&format!("turn_total_messages {}\n", snap.total_messages));

        output.push_str("# HELP turn_total_requests Total TURN requests received\n");
        output.push_str("# TYPE turn_total_requests counter\n");
        output.push_str(&format!("turn_total_requests {}\n", snap.total_requests));

        output.push_str("# HELP turn_successful_requests Successful requests\n");
        output.push_str("# TYPE turn_successful_requests counter\n");
        output.push_str(&format!(
            "turn_successful_requests {}\n",
            snap.successful_requests
        ));

        output.push_str("# HELP turn_failed_requests Failed requests\n");
        output.push_str("# TYPE turn_failed_requests counter\n");
        output.push_str(&format!("turn_failed_requests {}\n", snap.failed_requests));

        output.push_str("# HELP turn_auth_failures Authentication failures\n");
        output.push_str("# TYPE turn_auth_failures counter\n");
        output.push_str(&format!("turn_auth_failures {}\n", snap.auth_failures));

        output.push_str("# HELP turn_total_channel_binds Total channel binds\n");
        output.push_str("# TYPE turn_total_channel_binds counter\n");
        output.push_str(&format!(
            "turn_total_channel_binds {}\n",
            snap.total_channel_binds
        ));

        output.push_str("# HELP turn_active_channels Current active channels\n");
        output.push_str("# TYPE turn_active_channels gauge\n");
        output.push_str(&format!("turn_active_channels {}\n", snap.active_channels));

        output.push_str("# HELP turn_request_duration_ms Last request duration\n");
        output.push_str("# TYPE turn_request_duration_ms gauge\n");
        output.push_str(&format!(
            "turn_request_duration_ms {}\n",
            snap.last_request_duration_ms
        ));

        output.push_str("# HELP turn_uptime_seconds Server uptime\n");
        output.push_str("# TYPE turn_uptime_seconds gauge\n");
        output.push_str(&format!("turn_uptime_seconds {}\n", snap.uptime_secs));

        output
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub total_allocations: u64,
    pub active_allocations: u64,
    pub total_bytes_relayed: u64,
    pub total_messages: u64,
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub auth_failures: u64,
    pub total_channel_binds: u64,
    pub active_channels: u64,
    pub last_request_duration_ms: u64,
    pub uptime_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collection() {
        let metrics = Metrics::new();

        metrics.record_allocation();
        metrics.record_request(true, Duration::from_millis(10), false);
        metrics.record_bytes_relayed(1024);

        let snap = metrics.snapshot();
        assert_eq!(snap.total_allocations, 1);
        assert_eq!(snap.active_allocations, 1);
        assert_eq!(snap.total_requests, 1);
        assert_eq!(snap.successful_requests, 1);
        assert_eq!(snap.total_bytes_relayed, 1024);
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = Metrics::new();
        metrics.record_allocation();

        let output = metrics.export_prometheus();
        assert!(output.contains("turn_total_allocations 1"));
        assert!(output.contains("# TYPE turn_total_allocations counter"));
    }

    #[test]
    fn test_metrics_record_allocation_dropped() {
        let metrics = Metrics::new();
        metrics.record_allocation();
        assert_eq!(metrics.snapshot().active_allocations, 1);

        metrics.record_allocation_dropped();
        assert_eq!(metrics.snapshot().active_allocations, 0);

        // Should not go below zero
        metrics.record_allocation_dropped();
        assert_eq!(metrics.snapshot().active_allocations, 0);
    }

    #[test]
    fn test_metrics_request_tracking() {
        let metrics = Metrics::new();

        metrics.record_request(true, Duration::from_millis(100), false);
        metrics.record_request(false, Duration::from_millis(50), false);
        metrics.record_request(false, Duration::from_millis(50), true); // auth failure

        let snap = metrics.snapshot();
        assert_eq!(snap.total_requests, 3);
        assert_eq!(snap.successful_requests, 1);
        assert_eq!(snap.failed_requests, 2);
        assert_eq!(snap.auth_failures, 1);
    }

    #[test]
    fn test_metrics_channel_tracking() {
        let metrics = Metrics::new();

        metrics.record_channel_bind();
        metrics.record_channel_bind();
        assert_eq!(metrics.snapshot().active_channels, 2);

        metrics.record_channel_unbind();
        assert_eq!(metrics.snapshot().active_channels, 1);

        // Should not go below zero
        metrics.record_channel_unbind();
        metrics.record_channel_unbind();
        assert_eq!(metrics.snapshot().active_channels, 0);
    }

    #[test]
    fn test_metrics_bytes_relayed() {
        let metrics = Metrics::new();

        metrics.record_bytes_relayed(1024);
        metrics.record_bytes_relayed(2048);
        metrics.record_bytes_relayed(512);

        let snap = metrics.snapshot();
        assert_eq!(snap.total_bytes_relayed, 3584);
        assert_eq!(snap.total_messages, 3);
    }

    #[test]
    fn test_prometheus_export_all_metrics() {
        let metrics = Metrics::new();
        metrics.record_allocation();
        metrics.record_request(true, Duration::from_millis(10), false);
        metrics.record_bytes_relayed(100);
        metrics.record_channel_bind();

        let output = metrics.export_prometheus();

        // Check all metric types are present
        assert!(output.contains("# HELP turn_total_allocations"));
        assert!(output.contains("# TYPE turn_total_allocations counter"));
        assert!(output.contains("# HELP turn_active_allocations"));
        assert!(output.contains("# TYPE turn_active_allocations gauge"));
        assert!(output.contains("# HELP turn_total_bytes_relayed"));
        assert!(output.contains("# TYPE turn_total_bytes_relayed counter"));
        assert!(output.contains("# HELP turn_total_messages"));
        assert!(output.contains("# TYPE turn_total_messages counter"));
        assert!(output.contains("# HELP turn_total_requests"));
        assert!(output.contains("# HELP turn_auth_failures"));
        assert!(output.contains("# HELP turn_total_channel_binds"));
        assert!(output.contains("# HELP turn_active_channels"));
        assert!(output.contains("# HELP turn_request_duration_ms"));
        assert!(output.contains("# HELP turn_uptime_seconds"));
    }

    #[test]
    fn test_metrics_clone() {
        let metrics1 = Metrics::new();
        metrics1.record_allocation();

        let metrics2 = metrics1.clone();
        metrics2.record_allocation();

        // Clones share the same underlying data (via Arc)
        // So both should see both allocations
        assert_eq!(metrics1.snapshot().total_allocations, 2);
        assert_eq!(metrics2.snapshot().total_allocations, 2);
    }

    #[test]
    fn test_metrics_default() {
        let metrics = Metrics::default();
        let snap = metrics.snapshot();

        assert_eq!(snap.total_allocations, 0);
        assert_eq!(snap.active_allocations, 0);
        assert_eq!(snap.total_bytes_relayed, 0);
        assert_eq!(snap.total_messages, 0);
        assert_eq!(snap.total_requests, 0);
    }
}
