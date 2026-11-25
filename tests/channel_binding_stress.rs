//! Stress and regression tests for the channel-binding hot path.
//!
//! The peer→client and client→peer relay paths touch a `ChannelBinding` for
//! every media packet. Historically `refresh_binding_for_peer` scanned every
//! channel on the server under a global write lock (O(N) per packet, O(N²)
//! per second), which turned concurrent media into lock convoys. These tests
//! pin both the complexity and the two-index consistency invariants.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use miuturn::ChannelTable;

const CHANNEL_ID: u16 = 0x4000;

/// Unique relayed peer for binding index `i` (10.(i>>16).(i>>8).(i):5000).
fn relayed_addr(i: usize) -> SocketAddr {
    SocketAddr::from((
        Ipv4Addr::new(10, (i >> 16) as u8, (i >> 8) as u8, i as u8),
        40000 + (i & 0xff) as u16,
    ))
}

/// Unique far-side peer for binding index `i` (192.168.(i>>8).(i):6000).
fn peer_addr(i: usize) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(192, 168, (i >> 8) as u8, i as u8), 6000))
}

fn table_with_bindings(n: usize) -> ChannelTable {
    let table = ChannelTable::with_lifetime(Duration::from_secs(600));
    for i in 0..n {
        table
            .bind(CHANNEL_ID, peer_addr(i), relayed_addr(i))
            .expect("bind");
    }
    assert_eq!(table.len(), n);
    assert_eq!(table.by_peer_len(), n);
    table
}

/// Time `iters` peer→client touches spread over the first 256 bindings.
fn time_peer_touches(table: &ChannelTable, iters: usize) -> Duration {
    let mut targets = Vec::with_capacity(256);
    for i in 0..256 {
        targets.push((relayed_addr(i), peer_addr(i)));
    }
    let start = Instant::now();
    for i in 0..iters {
        let (relayed, peer) = targets[i & 255];
        assert!(
            table.refresh_binding_for_peer(&relayed, &peer),
            "binding vanished during the benchmark"
        );
    }
    start.elapsed()
}

/// O(1) regression: the per-packet touch cost must not grow with the number of
/// channels on the server. The old implementation scanned the whole table, so a
/// 20x larger table took ~20x longer; the fixed one is flat.
#[test]
fn refresh_cost_does_not_scale_with_table_size() {
    const ITERS: usize = 100_000;

    // Warm up allocator/caches so the small measurement is not dominated by
    // first-touch faults.
    let warm = table_with_bindings(1_000);
    time_peer_touches(&warm, 10_000);
    drop(warm);

    let small_table = table_with_bindings(1_000);
    let small = time_peer_touches(&small_table, ITERS);
    drop(small_table);

    let large_table = table_with_bindings(20_000);
    let large = time_peer_touches(&large_table, ITERS);
    drop(large_table);

    let small_ns = small.as_secs_f64() * 1e9 / ITERS as f64;
    let large_ns = large.as_secs_f64() * 1e9 / ITERS as f64;
    eprintln!(
        "peer→client touch: 1k bindings = {small_ns:.1} ns/op, \
         20k bindings = {large_ns:.1} ns/op (ratio {:.2})",
        large.as_secs_f64() / small.as_secs_f64().max(f64::MIN_POSITIVE)
    );

    // 2x + 10ms slack: absorbs scheduler noise when both measurements are
    // tiny, but still catches any O(N) scan (which would be ~20x).
    assert!(
        large.as_secs_f64() < small.as_secs_f64() * 2.0 + 0.010,
        "per-packet refresh cost scales with table size \
         (1k: {small:?}, 20k: {large:?}) — the O(N) scan is back"
    );
}

/// Client→peer lookup + touch must stay O(1) as well.
#[test]
fn client_to_peer_touch_does_not_scale_with_table_size() {
    const ITERS: usize = 100_000;

    let small_table = table_with_bindings(1_000);
    let large_table = table_with_bindings(20_000);

    let measure = |table: &ChannelTable| {
        let start = Instant::now();
        for i in 0..ITERS {
            let relayed = relayed_addr(i & 255);
            assert!(table.get_by_channel_touching(relayed, CHANNEL_ID).is_some());
        }
        start.elapsed()
    };

    let small = measure(&small_table);
    let large = measure(&large_table);
    eprintln!("client→peer touch: 1k = {small:?}, 20k = {large:?}");
    assert!(
        large.as_secs_f64() < small.as_secs_f64() * 2.0 + 0.010,
        "client→peer touch scales with table size (1k: {small:?}, 20k: {large:?})"
    );
}

/// Concurrency + churn: 8 threads hammer their own slice of bindings while
/// binding/unbinding entries. Afterwards both indexes must agree exactly.
#[test]
fn concurrent_touch_keeps_indexes_consistent() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 250;
    const OPS: usize = 20_000;

    let table = Arc::new(table_with_bindings(THREADS * PER_THREAD));

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let table = table.clone();
            std::thread::spawn(move || {
                let base = t * PER_THREAD;
                for op in 0..OPS {
                    let i = base + (op * 7) % PER_THREAD;
                    let relayed = relayed_addr(i);
                    let peer = peer_addr(i);
                    match op % 100 {
                        // Mostly the two media hot paths.
                        0..=59 => {
                            assert_eq!(
                                table.get_by_peer_for_relayed_touching(&relayed, &peer),
                                Some(CHANNEL_ID)
                            );
                        }
                        60..=96 => {
                            assert!(table.get_by_channel_touching(relayed, CHANNEL_ID).is_some());
                        }
                        97..=98 => {
                            assert!(table.refresh_binding(relayed, CHANNEL_ID));
                        }
                        // Churn: unbind and immediately re-bind the same pair.
                        _ => {
                            let removed = table.unbind(relayed, CHANNEL_ID);
                            assert!(removed.is_some(), "unbind lost a live binding");
                            table.bind(CHANNEL_ID, peer, relayed).expect("re-bind");
                        }
                    }
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("worker panicked");
    }

    let expected = THREADS * PER_THREAD;
    assert_eq!(table.len(), expected, "channel index lost entries");
    assert_eq!(
        table.by_peer_len(),
        expected,
        "by_peer index diverged from channels (one-sided expiry/teardown)"
    );
    for i in 0..expected {
        assert_eq!(
            table.get_by_peer_for_relayed(&relayed_addr(i), &peer_addr(i)),
            Some(CHANNEL_ID),
            "binding {i} missing from by_peer after churn"
        );
        assert!(
            table.get_by_channel(relayed_addr(i), CHANNEL_ID).is_some(),
            "binding {i} missing from channels after churn"
        );
    }
    assert_eq!(table.cleanup_expired(), 0, "live bindings expired");
    assert_eq!(table.len(), expected);
    assert_eq!(table.by_peer_len(), expected);
}

/// Long-running-call simulation: touches every 20ms for 20 ticks on a 60ms
/// lifetime binding, with a cleanup sweep on every tick. This is the 600s
/// production bug compressed into 400ms.
#[test]
fn touches_survive_repeated_cleanup_sweeps() {
    let table = ChannelTable::with_lifetime(Duration::from_millis(60));
    table
        .bind(CHANNEL_ID, peer_addr(0), relayed_addr(0))
        .unwrap();

    for tick in 0..20 {
        std::thread::sleep(Duration::from_millis(20));
        // Alternate the two directions the way real traffic does.
        if tick % 2 == 0 {
            assert_eq!(
                table.get_by_peer_for_relayed_touching(&relayed_addr(0), &peer_addr(0)),
                Some(CHANNEL_ID)
            );
        } else {
            assert!(
                table
                    .get_by_channel_touching(relayed_addr(0), CHANNEL_ID)
                    .is_some()
            );
        }
        table.cleanup_expired();
        assert_eq!(table.len(), 1, "tick {tick}: channel was reaped");
        assert_eq!(
            table.by_peer_len(),
            1,
            "tick {tick}: by_peer was reaped independently (downlink downgrades to Data Indication)"
        );
    }
}

/// Manual latency run: `cargo test --release --test channel_binding_stress --
/// --ignored --nocapture`. Prints p50/p99/p999 per-packet touch latency at
/// several table sizes with 8 competing threads.
#[test]
#[ignore = "latency benchmark; run explicitly with --ignored --nocapture"]
fn touch_latency_under_concurrency() {
    const THREADS: usize = 8;
    const OPS_PER_THREAD: usize = 200_000;

    for table_size in [1_000usize, 5_000, 20_000] {
        let table = Arc::new(table_with_bindings(table_size));
        let barrier = Arc::new(std::sync::Barrier::new(THREADS));

        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let table = table.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let mut samples = Vec::with_capacity(OPS_PER_THREAD);
                    barrier.wait();
                    for op in 0..OPS_PER_THREAD {
                        let i = (t * 131 + op) % 256;
                        let relayed = relayed_addr(i);
                        let peer = peer_addr(i);
                        let start = Instant::now();
                        if op % 2 == 0 {
                            let _ = table.get_by_peer_for_relayed_touching(&relayed, &peer);
                        } else {
                            let _ = table.get_by_channel_touching(relayed, CHANNEL_ID);
                        }
                        samples.push(start.elapsed().as_nanos() as u64);
                    }
                    samples
                })
            })
            .collect();

        let started = Instant::now();
        let mut all: Vec<u64> = Vec::with_capacity(THREADS * OPS_PER_THREAD);
        for h in handles {
            all.extend(h.join().expect("worker panicked"));
        }
        let wall = started.elapsed();
        all.sort_unstable();

        let pct = |p: f64| all[((all.len() as f64 - 1.0) * p) as usize];
        eprintln!(
            "table={table_size:6} ops={:8} wall={:?} p50={}ns p99={}ns p999={}ns",
            all.len(),
            wall,
            pct(0.50),
            pct(0.99),
            pct(0.999),
        );

        assert_eq!(table.len(), table_size);
        assert_eq!(table.by_peer_len(), table_size);
    }
}
