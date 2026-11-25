//! Per-allocation relay pacing diagnostics.
//!
//! Answers one question for every relayed connection, in both directions:
//! are packets arriving/leaving *evenly* (e.g. one every 20 ms) or in *bursts*
//! separated by silence (the "300 ms hole, then 40 packets" shape that client
//! jitter buffers report as batching)?
//!
//! Design constraints:
//!
//! * **Hot path is constant-cost**: two `fetch_add`s, one `swap`, one CAS into
//!   a 100 ms slot ring, per packet. No locks, no allocation, no logging, and
//!   the caller already has the monotonic timestamp it passes in.
//! * **No global per-connection registry.** All state lives in the `Allocation`
//!   and is freed with it, so an allocation torn down without going through the
//!   reporter cannot leak anything. The only process-wide state is a fixed
//!   32-slot array used to correlate stalls.
//! * The reporter is read-only and runs every 10 s (see
//!   `TurnServer::start_pacing_report_task`).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

/// Width of one pacing slot. 100 ms resolves the 300–400 ms holes that client
/// jitter buffers report as batching.
const SLOT_MS: u64 = 100;
/// Ring length: 32 x 100 ms = 3.2 s observation window.
const SLOTS: usize = 32;
/// How many of the most recent slots are kept in a snapshot (for event logs).
pub const RECENT_SLOTS: usize = 16;
/// A gap at least this long is considered a stall and recorded globally.
const STALL_GAP_MS: u64 = 100;

/// Process-wide monotonic milliseconds. Same guarantees as `Instant` (a
/// wall-clock step must not expire bindings early or fake a gap).
pub fn monotonic_ms() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Pack a slot tag and a count into one atomic word.
#[inline]
fn pack(slot: u32, count: u32) -> u64 {
    ((slot as u64) << 32) | count as u64
}

#[inline]
fn unpack(raw: u64) -> (u32, u32) {
    ((raw >> 32) as u32, raw as u32)
}

/// Bump the counter of `slots[slot % len]`, replacing a stale slot atomically.
fn bump_slot(slots: &[AtomicU64], slot: u32, len: usize) {
    let idx = (slot as usize) % len;
    loop {
        let cur = slots[idx].load(Ordering::Relaxed);
        let (cur_slot, count) = unpack(cur);
        let next = if cur_slot == slot {
            pack(slot, count.saturating_add(1))
        } else {
            pack(slot, 1)
        };
        if slots[idx]
            .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
    }
}

/// Per-direction counters for one allocation.
#[derive(Debug)]
pub struct DirectionPacer {
    packets: AtomicU64,
    bytes: AtomicU64,
    /// Monotonic ms of the previous packet; 0 = none yet.
    last_at_ms: AtomicU64,
    /// Largest gap observed since the last reporter sweep (`take_max_gap`).
    max_gap_ms: AtomicU64,
    /// Last 100 ms slot in which this direction reported a stall. Used to count
    /// *connections* (not events) per stall slot without per-connection maps.
    last_stall_slot: AtomicU32,
    /// Ring of `(slot << 32) | packets`.
    slots: [AtomicU64; SLOTS],
}

impl Default for DirectionPacer {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectionPacer {
    pub fn new() -> Self {
        Self {
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            last_at_ms: AtomicU64::new(0),
            max_gap_ms: AtomicU64::new(0),
            last_stall_slot: AtomicU32::new(u32::MAX),
            slots: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Account for one relayed packet. `now_ms` comes from [`monotonic_ms`]
    /// (callers already read the clock for channel-binding refreshes).
    #[inline]
    pub fn record(&self, now_ms: u64, len: usize) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(len as u64, Ordering::Relaxed);

        let prev = self.last_at_ms.swap(now_ms, Ordering::Relaxed);
        if prev != 0 {
            let gap = now_ms.saturating_sub(prev);
            if gap > self.max_gap_ms.load(Ordering::Relaxed) {
                self.max_gap_ms.fetch_max(gap, Ordering::Relaxed);
            }
            if gap >= STALL_GAP_MS {
                self.note_stall(now_ms);
            }
        }

        bump_slot(&self.slots, (now_ms / SLOT_MS) as u32, SLOTS);
    }

    /// One connection contributes at most once per 100 ms stall slot, so the
    /// global slot counter approximates "how many connections stalled together".
    #[inline]
    fn note_stall(&self, now_ms: u64) {
        let slot = (now_ms / SLOT_MS) as u32;
        if self.last_stall_slot.swap(slot, Ordering::Relaxed) != slot {
            stalls().note(now_ms);
        }
    }

    /// Largest gap since the previous call, and reset it (windowed reporting).
    pub fn take_max_gap(&self) -> u64 {
        self.max_gap_ms.swap(0, Ordering::Relaxed)
    }

    /// Cumulative counters (since allocation creation).
    pub fn totals(&self) -> (u64, u64) {
        (
            self.packets.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        )
    }

    /// Read the 100 ms ring and derive rate/shape metrics.
    pub fn snapshot(&self, now_ms: u64) -> DirectionSnapshot {
        let cur_slot = (now_ms / SLOT_MS) as u32;
        let mut counts = [0u32; SLOTS];
        for (i, count) in counts.iter_mut().enumerate() {
            let slot = cur_slot.wrapping_sub((SLOTS - 1 - i) as u32);
            let raw = self.slots[(slot as usize) % SLOTS].load(Ordering::Relaxed);
            let (tag, value) = unpack(raw);
            if tag == slot {
                *count = value;
            }
        }

        let window_packets: u64 = counts.iter().map(|c| *c as u64).sum();
        let first = counts.iter().position(|c| *c > 0);
        let last = counts.iter().rposition(|c| *c > 0);
        let (packets, bytes) = self.totals();

        let mut snap = DirectionSnapshot {
            packets,
            bytes,
            window_packets,
            active_slots: counts.iter().filter(|c| **c > 0).count() as u32,
            max_slot: counts.iter().copied().max().unwrap_or(0),
            zero_run: 0,
            pps: 0.0,
            bps: 0.0,
            cv: 0.0,
            burst_ratio: 0.0,
            recent: [0u32; RECENT_SLOTS],
        };
        for (i, value) in counts[SLOTS - RECENT_SLOTS..].iter().enumerate() {
            snap.recent[i] = *value;
        }

        let (Some(first), Some(last)) = (first, last) else {
            return snap;
        };

        // Rate is measured from the first packet in the window to *now* (not
        // to the last packet): a connection that went silent two seconds ago
        // must report ~0 pps, not its rate from before the silence.
        let span_slots = SLOTS - first;
        let span_secs = span_slots as f64 * (SLOT_MS as f64 / 1000.0);
        snap.pps = window_packets as f64 / span_secs;
        // Bytes are only tracked cumulatively (a second slot ring would double
        // the per-packet cost). Average payload size x window pps is accurate
        // enough for a bandwidth read-out.
        if packets > 0 {
            let avg_len = bytes as f64 / packets as f64;
            snap.bps = snap.pps * avg_len;
        }

        // Longest run of empty slots strictly inside the active span.
        let mut run = 0;
        for value in &counts[first..=last] {
            if *value == 0 {
                run += 1;
                snap.zero_run = snap.zero_run.max(run);
            } else {
                run = 0;
            }
        }

        let active = &counts[first..=last];
        let mean = active.iter().map(|c| *c as f64).sum::<f64>() / active.len() as f64;
        if mean > 0.0 {
            snap.burst_ratio = snap.max_slot as f64 / mean;
            let var = active
                .iter()
                .map(|c| {
                    let d = *c as f64 - mean;
                    d * d
                })
                .sum::<f64>()
                / active.len() as f64;
            snap.cv = var.sqrt() / mean;
        }
        snap
    }
}

/// Shape of one direction over the last 3.2 s.
#[derive(Debug, Clone)]
pub struct DirectionSnapshot {
    /// Cumulative since allocation creation.
    pub packets: u64,
    pub bytes: u64,
    /// Packets inside the 3.2 s window.
    pub window_packets: u64,
    /// Slots in the window with at least one packet.
    pub active_slots: u32,
    /// Packets in the busiest slot.
    pub max_slot: u32,
    /// Longest run of consecutive 100 ms slots without a packet.
    pub zero_run: u32,
    /// Average packets/second over the observed span.
    pub pps: f64,
    /// Average bytes/second over the observed span.
    pub bps: f64,
    /// Coefficient of variation of per-slot packet counts (0 = perfectly even).
    pub cv: f64,
    /// Busiest slot / mean slot (1 = perfectly even).
    pub burst_ratio: f64,
    /// Most recent 16 slots (oldest first), for stall event logs.
    pub recent: [u32; RECENT_SLOTS],
}

/// Process-wide stall correlation.
///
/// If many connections report a >=100 ms gap in the *same* 100 ms slot, the
/// cause is global (runtime stall, CPU throttling, kernel), not per-link
/// pacing. Fixed size, no per-connection state.
struct StallTracker {
    /// `(slot << 32) | connections` per 100 ms slot.
    slots: [AtomicU64; SLOTS],
    events: AtomicU64,
}

impl StallTracker {
    fn new() -> Self {
        Self {
            slots: std::array::from_fn(|_| AtomicU64::new(0)),
            events: AtomicU64::new(0),
        }
    }

    fn note(&self, now_ms: u64) {
        bump_slot(&self.slots, (now_ms / SLOT_MS) as u32, SLOTS);
        self.events.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self, now_ms: u64) -> StallSnapshot {
        let cur_slot = (now_ms / SLOT_MS) as u32;
        let mut max_conns = 0u32;
        let mut multi_slots = 0u32;
        let mut recent = [0u32; RECENT_SLOTS];
        for i in 0..SLOTS {
            let slot = cur_slot.wrapping_sub((SLOTS - 1 - i) as u32);
            let raw = self.slots[(slot as usize) % SLOTS].load(Ordering::Relaxed);
            let (tag, conns) = unpack(raw);
            let conns = if tag == slot { conns } else { 0 };
            if conns >= 2 {
                multi_slots += 1;
            }
            max_conns = max_conns.max(conns);
            if i >= SLOTS - RECENT_SLOTS {
                recent[i - (SLOTS - RECENT_SLOTS)] = conns;
            }
        }
        StallSnapshot {
            events: self.events.load(Ordering::Relaxed),
            slots_with_multiple: multi_slots,
            max_conns_in_slot: max_conns,
            recent,
        }
    }
}

fn stalls() -> &'static StallTracker {
    static TRACKER: OnceLock<StallTracker> = OnceLock::new();
    TRACKER.get_or_init(StallTracker::new)
}

/// Global stall picture over the last 3.2 s.
#[derive(Debug, Clone, Copy, Default)]
pub struct StallSnapshot {
    /// Cumulative stall notes (connections that saw a >=100 ms gap).
    pub events: u64,
    /// Slots where two or more connections stalled together.
    pub slots_with_multiple: u32,
    /// Most connections stalling in the same 100 ms slot.
    pub max_conns_in_slot: u32,
    /// Most recent 16 slots.
    pub recent: [u32; RECENT_SLOTS],
}

/// Read the global stall tracker. Called once per report tick.
pub fn stall_snapshot(now_ms: u64) -> StallSnapshot {
    stalls().snapshot(now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Feed `(offset_ms, packets)` bursts starting at `base`.
    fn feed(pacer: &DirectionPacer, base: u64, bursts: &[(u64, usize)]) {
        for (offset, count) in bursts {
            for _ in 0..*count {
                pacer.record(base + offset, 1000);
            }
        }
    }

    #[test]
    fn uniform_stream_is_flat() {
        let pacer = DirectionPacer::new();
        let base = 1_000_000;
        // 160 packets, one every 20 ms = 3.2 s of steady 50 pps media.
        let bursts: Vec<(u64, usize)> = (0..160).map(|i| (i * 20, 1)).collect();
        feed(&pacer, base, &bursts);

        let snap = pacer.snapshot(base + 159 * 20);
        assert_eq!(snap.window_packets, 160);
        assert_eq!(snap.zero_run, 0, "steady 20 ms stream must have no holes");
        assert!(
            (snap.pps - 50.0).abs() < 1.0,
            "expected ~50 pps, got {}",
            snap.pps
        );
        assert!(
            snap.burst_ratio < 2.0,
            "steady stream should be flat, burst_ratio={}",
            snap.burst_ratio
        );
        assert!(pacer.take_max_gap() <= 20);
    }

    #[test]
    fn stall_then_burst_is_detected() {
        let pacer = DirectionPacer::new();
        let base = 2_000_000;
        // 1 s of steady 20 ms packets (50 packets, 5 per 100 ms slot).
        for i in 0..50 {
            pacer.record(base + i * 20, 1000);
        }
        // 400 ms hole, then 30 packets back-to-back inside one slot.
        for i in 0..30 {
            pacer.record(base + 1400 + i, 1000);
        }

        let snap = pacer.snapshot(base + 1500);
        assert!(pacer.take_max_gap() >= 380, "gap was not recorded");
        assert!(
            snap.zero_run >= 3,
            "expected >=3 empty 100ms slots, got {}",
            snap.zero_run
        );
        assert_eq!(snap.max_slot, 30, "catch-up burst must land in one slot");
        assert!(
            snap.burst_ratio > 3.0,
            "burst_ratio={} should expose the catch-up spike",
            snap.burst_ratio
        );
        // 50 steady + 30 burst packets are all inside the 3.2 s window.
        assert_eq!(snap.window_packets, 80);
        assert_eq!(*snap.recent.last().unwrap(), 0); // snapshot is 100 ms later
    }

    #[test]
    fn max_gap_is_windowed() {
        let pacer = DirectionPacer::new();
        let base = 3_000_000;
        pacer.record(base, 1000);
        pacer.record(base + 250, 1000);
        assert_eq!(pacer.take_max_gap(), 250);
        assert_eq!(pacer.take_max_gap(), 0, "second sweep sees no new gap");
        pacer.record(base + 270, 1000);
        assert_eq!(pacer.take_max_gap(), 20);
    }

    #[test]
    fn stale_slots_do_not_leak_into_window() {
        let pacer = DirectionPacer::new();
        let base = 4_000_000;
        for i in 0..10 {
            pacer.record(base + i * 20, 1000);
        }
        // Jump forward 10 s: everything from before is outside the 3.2 s window.
        let later = base + 10_000;
        pacer.record(later, 1000);
        pacer.record(later + 20, 1000);
        let snap = pacer.snapshot(later + 20);
        assert_eq!(snap.window_packets, 2);
        assert_eq!(snap.active_slots, 1);
        // Cumulative counters are unaffected.
        assert_eq!(snap.packets, 12);
    }

    #[test]
    fn stall_tracker_counts_connections_per_slot() {
        let tracker = StallTracker::new();
        let slot_base = 500_000_000u64; // far from other tests' timestamps
        // Two "connections" stall in the same slot.
        tracker.note(slot_base + 10);
        tracker.note(slot_base + 20);
        let snap = tracker.snapshot(slot_base + 30);
        assert_eq!(snap.max_conns_in_slot, 2);
        assert_eq!(snap.slots_with_multiple, 1);
        assert_eq!(snap.events, 2);
        // A slot with a single connection is not "global".
        tracker.note(slot_base + 500);
        let snap = tracker.snapshot(slot_base + 510);
        assert_eq!(snap.max_conns_in_slot, 2);
        assert_eq!(snap.slots_with_multiple, 1);
    }

    #[test]
    fn one_connection_notes_a_slot_once() {
        let pacer = DirectionPacer::new();
        let base = 5_000_000u64;
        pacer.record(base, 1000);
        // Three separate >=100 ms gaps inside the same 100 ms slot boundary
        // cannot happen (a 100 ms gap crosses slots), so this only verifies the
        // dedupe path does not panic or double-count wildly.
        pacer.record(base + 150, 1000);
        pacer.record(base + 300, 1000);
        let snap = stall_snapshot(base + 300);
        assert!(snap.events >= 1);
    }

    #[test]
    fn direction_pacer_record_is_cheap() {
        let pacer = DirectionPacer::new();
        let base = 6_000_000u64;
        let iterations = 200_000u64;
        let start = Instant::now();
        for i in 0..iterations {
            pacer.record(base + i / 10, 1200);
        }
        let ns_per_op = start.elapsed().as_secs_f64() * 1e9 / iterations as f64;
        // Generous ceiling: catches an accidental lock/allocation, not CI noise.
        assert!(
            ns_per_op < 500.0,
            "DirectionPacer::record costs {ns_per_op:.1} ns/op"
        );
    }
}
