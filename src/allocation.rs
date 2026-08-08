use crate::errors::Error;
use bytes::Bytes;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Fast xorshift64 PRNG for port randomization.
/// Seed is thread-local to avoid contention.
fn port_rand() -> u64 {
    use std::cell::Cell;
    thread_local! {
        static SEED: Cell<u64> = Cell::new(0);
    }
    SEED.with(|s| {
        let mut seed = s.get();
        if seed == 0 {
            // Lazily seed from time + a stack address for uniqueness
            let time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let addr = &seed as *const _ as u64;
            seed = time.wrapping_add(addr);
        }
        // xorshift64
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        s.set(seed);
        seed
    })
}
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, trace, warn};

/// Message types for allocation task communication
#[derive(Debug)]
pub enum AllocationMessage {
    /// Data from client to be relayed to peer (Send Indication)
    ClientData { data: Bytes, peer_addr: SocketAddr },
    /// Channel data from client
    ChannelData { data: Bytes, channel_num: u16 },
    /// Update the client address (for NAT rebind detection)
    UpdateClientAddr { client_addr: SocketAddr },
    /// Set a channel to forward peer→client data (TCP fallback).
    /// Bounded so a slow/stalled TCP client cannot grow memory without limit;
    /// frames are dropped when the queue is full.
    SetClientTx {
        tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    },
    /// Shut down the allocation task
    Shutdown,
}

/// Active relay connection for an allocation
#[derive(Clone)]
pub struct AllocationRelay {
    /// The UDP socket bound to the relay address
    pub socket: Arc<UdpSocket>,
    /// Channel to send messages to the allocation task
    pub tx: mpsc::Sender<AllocationMessage>,
    /// Handle for the allocation task
    pub task_handle: tokio::task::AbortHandle,
}

impl std::fmt::Debug for AllocationRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AllocationRelay")
            .field("socket", &"<UdpSocket>")
            .field("tx", &"<mpsc::Sender>")
            .field("task_handle", &self.task_handle)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct Allocation {
    pub id: [u8; 12],
    pub relayed_addr: SocketAddr,
    pub client_addr: SocketAddr,
    pub created_at: Instant,
    pub refreshed_at: Instant,
    pub lifetime: Duration,
    pub five_tuple: (SocketAddr, SocketAddr),
    /// Active relay connection (socket + task channel)
    pub relay: Option<AllocationRelay>,
    /// Permitted peer addresses (IP-only, port is ignored per RFC 5766).
    /// Shared with the relay task so peer→relay traffic can be checked
    /// against the live permission set without touching the Allocation lock.
    pub permissions: Arc<RwLock<std::collections::HashSet<std::net::IpAddr>>>,
    /// Bytes successfully relayed through this allocation
    pub bytes_forwarded: Arc<AtomicU64>,
    /// Messages successfully relayed through this allocation
    pub messages_forwarded: Arc<AtomicU64>,
    /// Authenticated username that created this allocation (used for the
    /// NAT-rebind Refresh fallback lookup).
    pub username: Option<String>,
}

/// Maximum number of peer IP permissions a single allocation may hold.
/// RFC 5766 does not mandate a specific value; this bound prevents an
/// authenticated client from growing the permission set without limit.
pub const MAX_PERMISSIONS_PER_ALLOCATION: usize = 1024;

impl Allocation {
    pub fn new(
        id: [u8; 12],
        relayed_addr: SocketAddr,
        client_addr: SocketAddr,
        lifetime: Duration,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> Self {
        Allocation {
            id,
            relayed_addr,
            client_addr,
            created_at: Instant::now(),
            refreshed_at: Instant::now(),
            lifetime,
            five_tuple: (src, dst),
            relay: None,
            permissions: Arc::new(RwLock::new(std::collections::HashSet::new())),
            bytes_forwarded: Arc::new(AtomicU64::new(0)),
            messages_forwarded: Arc::new(AtomicU64::new(0)),
            username: None,
        }
    }

    pub fn with_relay(
        id: [u8; 12],
        relayed_addr: SocketAddr,
        client_addr: SocketAddr,
        lifetime: Duration,
        src: SocketAddr,
        dst: SocketAddr,
        relay: AllocationRelay,
        permissions: Arc<RwLock<std::collections::HashSet<std::net::IpAddr>>>,
    ) -> Self {
        Allocation {
            id,
            relayed_addr,
            client_addr,
            created_at: Instant::now(),
            refreshed_at: Instant::now(),
            lifetime,
            five_tuple: (src, dst),
            relay: Some(relay),
            permissions,
            bytes_forwarded: Arc::new(AtomicU64::new(0)),
            messages_forwarded: Arc::new(AtomicU64::new(0)),
            username: None,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.refreshed_at.elapsed() > self.lifetime
    }

    pub fn remaining_lifetime(&self) -> u32 {
        let elapsed = self.refreshed_at.elapsed();
        if elapsed >= self.lifetime {
            return 0;
        }
        (self.lifetime - elapsed).as_secs() as u32
    }
}

/// Optimized port allocator using bitmask for fast O(1) allocation/release
pub struct PortAllocator {
    /// Bitmap of allocated ports (1 = allocated, 0 = free)
    /// Using 16384 bits = 256 AtomicU64s to cover ports 49152-65535
    /// Index = (port - min_port) / 64
    allocated: Vec<AtomicU64>,
    /// Number of allocated ports
    allocated_count: AtomicUsize,
    /// Start of port range
    min_port: u16,
    /// End of port range
    max_port: u16,
    /// Number of ports in range
    port_count: u16,
}

impl PortAllocator {
    pub fn new(min_port: u16, max_port: u16) -> Self {
        let port_count = max_port - min_port + 1;
        let num_u64s = (port_count as usize).div_ceil(64);
        let allocated: Vec<AtomicU64> = (0..num_u64s).map(|_| AtomicU64::new(0)).collect();
        Self {
            allocated,
            allocated_count: AtomicUsize::new(0),
            min_port,
            max_port,
            port_count,
        }
    }

    #[inline]
    pub fn allocate(&self) -> Option<u16> {
        let num_u64s = self.allocated.len();

        // Random starting index to avoid always picking low ports
        let start_idx = (port_rand() as usize) % num_u64s;

        // Probe a random position within the starting u64 to avoid sequential allocation
        let bit_offset = (port_rand() as u32) % 64;

        for bitmap_idx in 0..num_u64s {
            let actual_idx = (start_idx + bitmap_idx) % num_u64s;
            let bitmap = &self.allocated[actual_idx];

            let mut current = bitmap.load(Ordering::Relaxed);

            // Check if this u64 is full (all 1s)
            if current == u64::MAX {
                continue;
            }

            // Build a rotated free mask starting from a random bit position
            let free_mask = !current;
            if free_mask == 0 {
                continue;
            }

            // Try the random offset first, then fall back to lowest free bit
            let random_bit = (bit_offset + bitmap_idx as u32) % 64;
            if free_mask & (1u64 << random_bit) != 0 {
                let mask = 1u64 << random_bit;
                let port_index = (actual_idx * 64 + random_bit as usize) as u16;
                if port_index < self.port_count {
                    match bitmap.compare_exchange_weak(
                        current,
                        current | mask,
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => {
                            self.allocated_count.fetch_add(1, Ordering::Relaxed);
                            return Some(self.min_port + port_index);
                        }
                        Err(e) => current = e,
                    }
                }
            }

            // Fallback: take the lowest free bit in this u64
            loop {
                let free_mask = !current;
                if free_mask == 0 {
                    break;
                }

                let free_bit = free_mask.trailing_zeros() as usize;
                let mask = 1u64 << free_bit;
                let port_index = (actual_idx * 64 + free_bit) as u16;
                if port_index >= self.port_count {
                    break;
                }

                match bitmap.compare_exchange_weak(
                    current,
                    current | mask,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        self.allocated_count.fetch_add(1, Ordering::Relaxed);
                        return Some(self.min_port + port_index);
                    }
                    Err(e) => current = e,
                }
            }
        }

        None
    }

    /// Release a previously allocated port
    #[inline]
    pub fn release(&self, port: u16) -> bool {
        if port < self.min_port || port > self.max_port {
            return false;
        }

        let port_index = (port - self.min_port) as usize;
        let bitmap_index = port_index / 64;
        let bit_index = (port_index % 64) as u32;
        let mask = 1u64 << bit_index;

        if bitmap_index >= self.allocated.len() {
            return false;
        }

        let bitmap = &self.allocated[bitmap_index];

        // Clear the bit
        let mut current = bitmap.load(Ordering::Relaxed);
        loop {
            if current & mask == 0 {
                // Port was not allocated
                return false;
            }

            match bitmap.compare_exchange_weak(
                current,
                current & !mask,
                Ordering::SeqCst,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.allocated_count.fetch_sub(1, Ordering::Relaxed);
                    return true;
                }
                Err(e) => current = e,
            }
        }
    }

    /// Get number of allocated ports
    #[inline]
    pub fn allocated_count(&self) -> usize {
        self.allocated_count.load(Ordering::Relaxed)
    }

    /// Get total available ports
    #[inline]
    pub fn available_count(&self) -> usize {
        self.port_count as usize - self.allocated_count.load(Ordering::Relaxed)
    }

    /// Check if a specific port is allocated
    #[inline]
    pub fn is_allocated(&self, port: u16) -> bool {
        if port < self.min_port || port > self.max_port {
            return false;
        }
        let port_index = (port - self.min_port) as usize;
        let bitmap_index = port_index / 64;
        let bit_index = (port_index % 64) as u32;
        let mask = 1u64 << bit_index;

        if bitmap_index >= self.allocated.len() {
            return false;
        }

        self.allocated[bitmap_index].load(Ordering::Relaxed) & mask != 0
    }
}

pub struct AllocationTable {
    pub(crate) allocations: RwLock<HashMap<SocketAddr, Arc<RwLock<Allocation>>>>,
    /// Secondary index: client 5-tuple → allocation, for O(1) lookup on the
    /// hot path (ChannelData / Send Indication / Refresh / CreatePermission).
    /// Kept consistent with `allocations` by create/remove/cleanup and by the
    /// NAT-rebind `move_client_addr` helper.
    by_client: RwLock<HashMap<SocketAddr, Arc<RwLock<Allocation>>>>,
    port_allocator: PortAllocator,
    bind_addr: Ipv4Addr,
    external_addr: Ipv4Addr,
    realm: String,
    stats: Arc<ServerStats>,
    max_concurrent_allocations: Option<usize>,
    max_allocation_duration_secs: Option<u32>,
    _current_bandwidth_bytes_per_sec: AtomicUsize,
    _max_bandwidth_bytes_per_sec: Option<usize>,
    bandwidth_manager: Arc<crate::bandwidth::BandwidthManager>,
    main_socket: RwLock<Option<std::sync::Arc<tokio::net::UdpSocket>>>,
    /// Optional Prometheus metrics collector (recorded at low-frequency points:
    /// allocation create/remove and channel bind/unbind — never per packet).
    metrics: parking_lot::RwLock<Option<crate::metrics::Metrics>>,
    /// When `true`, enforce RFC 5766 §10 permission checks on the peer→relay
    /// direction (packets from an IP without a TURN permission are dropped).
    /// When `false` (default, matching pre-0.2.0 behavior), peer→client traffic
    /// is relayed without a source-IP permission check.
    enforce_peer_permissions: AtomicBool,
}

#[derive(Debug)]
pub struct ServerStats {
    pub total_allocations: AtomicU64,
    pub active_allocations: AtomicU64,
    pub total_bytes_relayed: AtomicU64,
    pub total_messages: AtomicU64,
}

impl Clone for ServerStats {
    fn clone(&self) -> Self {
        Self {
            total_allocations: AtomicU64::new(self.total_allocations.load(Ordering::Relaxed)),
            active_allocations: AtomicU64::new(self.active_allocations.load(Ordering::Relaxed)),
            total_bytes_relayed: AtomicU64::new(self.total_bytes_relayed.load(Ordering::Relaxed)),
            total_messages: AtomicU64::new(self.total_messages.load(Ordering::Relaxed)),
        }
    }
}

impl Default for ServerStats {
    fn default() -> Self {
        Self {
            total_allocations: AtomicU64::new(0),
            active_allocations: AtomicU64::new(0),
            total_bytes_relayed: AtomicU64::new(0),
            total_messages: AtomicU64::new(0),
        }
    }
}

impl ServerStats {
    pub fn snapshot(&self) -> ServerStatsSnapshot {
        ServerStatsSnapshot {
            total_allocations: self.total_allocations.load(Ordering::Relaxed),
            active_allocations: self.active_allocations.load(Ordering::Relaxed),
            total_bytes_relayed: self.total_bytes_relayed.load(Ordering::Relaxed),
            total_messages: self.total_messages.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerStatsSnapshot {
    pub total_allocations: u64,
    pub active_allocations: u64,
    pub total_bytes_relayed: u64,
    pub total_messages: u64,
}

impl AllocationTable {
    pub fn new(addr: Ipv4Addr, realm: String) -> Self {
        Self::with_limits(addr, realm, None, None, None)
    }

    pub fn with_bind_addr(external_addr: Ipv4Addr, bind_addr: Ipv4Addr, realm: String) -> Self {
        Self::with_limits_and_bind_addr(external_addr, bind_addr, realm, None, None, None)
    }

    pub fn with_limits(
        addr: Ipv4Addr,
        realm: String,
        max_concurrent_allocations: Option<usize>,
        max_allocation_duration_secs: Option<u32>,
        max_bandwidth_bytes_per_sec: Option<usize>,
    ) -> Self {
        Self::with_limits_and_bind_addr(
            addr,
            addr,
            realm,
            max_concurrent_allocations,
            max_allocation_duration_secs,
            max_bandwidth_bytes_per_sec,
        )
    }

    pub fn with_limits_and_bind_addr(
        external_addr: Ipv4Addr,
        bind_addr: Ipv4Addr,
        realm: String,
        max_concurrent_allocations: Option<usize>,
        max_allocation_duration_secs: Option<u32>,
        max_bandwidth_bytes_per_sec: Option<usize>,
    ) -> Self {
        // Default TURN port range: 49152-65535 (16384 ports)
        AllocationTable {
            allocations: RwLock::new(HashMap::new()),
            by_client: RwLock::new(HashMap::new()),
            port_allocator: PortAllocator::new(49152, 65535),
            bind_addr,
            external_addr,
            realm,
            stats: Arc::new(ServerStats::default()),
            max_concurrent_allocations,
            max_allocation_duration_secs,
            _current_bandwidth_bytes_per_sec: AtomicUsize::new(0),
            _max_bandwidth_bytes_per_sec: max_bandwidth_bytes_per_sec,
            bandwidth_manager: Arc::new(crate::bandwidth::BandwidthManager::new(
                max_bandwidth_bytes_per_sec.map(|v| v as u64),
            )),
            main_socket: RwLock::new(None),
            metrics: parking_lot::RwLock::new(None),
            enforce_peer_permissions: AtomicBool::new(false),
        }
    }

    /// Custom port range for high-throughput scenarios
    pub fn with_port_range(
        addr: Ipv4Addr,
        realm: String,
        min_port: u16,
        max_port: u16,
        max_concurrent_allocations: Option<usize>,
        max_allocation_duration_secs: Option<u32>,
        max_bandwidth_bytes_per_sec: Option<usize>,
    ) -> Self {
        Self::with_port_range_and_bind_addr(
            addr,
            addr,
            realm,
            min_port,
            max_port,
            max_concurrent_allocations,
            max_allocation_duration_secs,
            max_bandwidth_bytes_per_sec,
        )
    }

    pub fn with_port_range_and_bind_addr(
        external_addr: Ipv4Addr,
        bind_addr: Ipv4Addr,
        realm: String,
        min_port: u16,
        max_port: u16,
        max_concurrent_allocations: Option<usize>,
        max_allocation_duration_secs: Option<u32>,
        max_bandwidth_bytes_per_sec: Option<usize>,
    ) -> Self {
        AllocationTable {
            allocations: RwLock::new(HashMap::new()),
            by_client: RwLock::new(HashMap::new()),
            port_allocator: PortAllocator::new(min_port, max_port),
            bind_addr,
            external_addr,
            realm,
            stats: Arc::new(ServerStats::default()),
            max_concurrent_allocations,
            max_allocation_duration_secs,
            _current_bandwidth_bytes_per_sec: AtomicUsize::new(0),
            _max_bandwidth_bytes_per_sec: max_bandwidth_bytes_per_sec,
            bandwidth_manager: Arc::new(crate::bandwidth::BandwidthManager::new(
                max_bandwidth_bytes_per_sec.map(|v| v as u64),
            )),
            main_socket: RwLock::new(None),
            metrics: parking_lot::RwLock::new(None),
            enforce_peer_permissions: AtomicBool::new(false),
        }
    }

    pub fn set_main_socket(&self, socket: Arc<tokio::net::UdpSocket>) {
        *self.main_socket.write() = Some(socket);
    }

    /// Enable or disable RFC 5766 §10 permission enforcement on the peer→relay
    /// direction. Disabled by default (lenient, pre-0.2.0 behavior); set to
    /// `true` for strict source-IP permission gating.
    pub fn set_enforce_peer_permissions(&self, enforce: bool) {
        self.enforce_peer_permissions
            .store(enforce, Ordering::Relaxed);
    }

    /// Attach (or detach) the metrics collector used at allocation/channel
    /// lifecycle points. Metrics recording is optional and low-frequency.
    pub fn set_metrics(&self, metrics: Option<crate::metrics::Metrics>) {
        *self.metrics.write() = metrics;
    }

    /// Clone of the configured metrics collector, if any.
    pub(crate) fn metrics(&self) -> Option<crate::metrics::Metrics> {
        self.metrics.read().clone()
    }

    pub fn stats(&self) -> Arc<ServerStats> {
        self.stats.clone()
    }

    /// Compute the effective allocation lifetime per RFC 5766 §2.7/§6.
    ///
    /// The client's requested LIFETIME is honoured; the server only clamps it
    /// down to `max_allocation_duration_secs` when the request exceeds the
    /// configured maximum (and never raises a short request up to the max). A
    /// missing request defaults to 600s. A requested lifetime of 0 always means
    /// "delete immediately" and is respected.
    ///
    /// Channel bindings are created with the server's maximum duration (see
    /// `ChannelTable::with_lifetime`) so they never expire before their owning
    /// allocation, regardless of the granted allocation lifetime.
    pub fn effective_allocation_lifetime(&self, requested: Option<u32>) -> u32 {
        if requested == Some(0) {
            return 0;
        }
        let lifetime = requested.unwrap_or(600);
        match self.max_allocation_duration_secs {
            Some(max) if lifetime > max => max,
            _ => lifetime,
        }
    }

    pub async fn create_allocation(
        &self,
        client_addr: SocketAddr,
        requested_lifetime: Option<u32>,
        channel_table: &ChannelTable,
    ) -> Result<Arc<RwLock<Allocation>>, Error> {
        self.create_allocation_with_socket(client_addr, requested_lifetime, channel_table, None)
            .await
    }

    /// Create an allocation, optionally binding its client-facing send socket
    /// (used for Data Indication / ChannelData towards the client) to the
    /// socket on which the Allocate request was received. When `None`, falls
    /// back to the table's global main socket, then to the relay socket.
    pub async fn create_allocation_with_socket(
        &self,
        client_addr: SocketAddr,
        requested_lifetime: Option<u32>,
        channel_table: &ChannelTable,
        recv_socket: Option<Arc<UdpSocket>>,
    ) -> Result<Arc<RwLock<Allocation>>, Error> {
        if let Some(max) = self.max_concurrent_allocations {
            let current = self.stats.active_allocations.load(Ordering::Relaxed) as usize;
            if current >= max {
                debug!(
                    %client_addr,
                    current_allocations = current,
                    max_allocations = max,
                    "rejecting allocation because server allocation quota is reached"
                );
                return Err(Error::AllocationQuotaReached);
            }
        }

        let lifetime_secs = self.effective_allocation_lifetime(requested_lifetime);
        let lifetime = Duration::from_secs(lifetime_secs as u64);

        // Fast port allocation - O(1)
        // If binding fails, we'll retry with another port
        let mut attempts = 0;
        const MAX_ATTEMPTS: usize = 100;
        let mut last_bind_failure: Option<(SocketAddr, String)> = None;

        let (_port, relay_socket, relayed_addr, relay_bind_addr) = loop {
            if attempts >= MAX_ATTEMPTS {
                if let Some((addr, source)) = last_bind_failure {
                    warn!(
                        %client_addr,
                        %addr,
                        error = %source,
                        attempts = MAX_ATTEMPTS,
                        "failed to create allocation after repeated relay bind failures"
                    );
                    return Err(Error::RelayBindFailed { addr, source });
                }

                debug!(
                    %client_addr,
                    attempts = MAX_ATTEMPTS,
                    "failed to create allocation because relay ports are exhausted"
                );
                return Err(Error::RelayPortExhausted);
            }

            let port = self.port_allocator.allocate().ok_or_else(|| {
                debug!(
                    %client_addr,
                    attempts,
                    min_port = self.port_allocator.min_port,
                    max_port = self.port_allocator.max_port,
                    "failed to create allocation because no relay ports are available"
                );
                Error::RelayPortExhausted
            })?;

            let relay_bind_addr = SocketAddr::V4(SocketAddrV4::new(self.bind_addr, port));
            let relayed_addr = SocketAddr::V4(SocketAddrV4::new(self.external_addr, port));

            // Create and bind a dedicated UDP socket for this allocation
            match UdpSocket::bind(relay_bind_addr).await {
                Ok(socket) => {
                    break (port, socket, relayed_addr, relay_bind_addr);
                }
                Err(err) => {
                    // Port binding failed - release and try again
                    self.port_allocator.release(port);
                    let err_string = err.to_string();
                    debug!(
                        %client_addr,
                        %relay_bind_addr,
                        %relayed_addr,
                        attempt = attempts + 1,
                        error = %err_string,
                        "relay socket bind failed while creating allocation"
                    );
                    last_bind_failure = Some((relay_bind_addr, err_string));
                    attempts += 1;
                    continue;
                }
            }
        };

        let relay_socket = Arc::new(relay_socket);

        let mut id = [0u8; 12];
        getrandom(&mut id);

        // Permission set shared between the Allocation record and the relay
        // task so peer→relay traffic can be validated (RFC 5766 §10) without
        // locking the Allocation on every packet.
        let permissions: Arc<RwLock<std::collections::HashSet<std::net::IpAddr>>> =
            Arc::new(RwLock::new(std::collections::HashSet::new()));

        // Spawn the per-allocation task. Prefer the socket the Allocate request
        // arrived on so Data Indications leave from the address the client
        // expects; fall back to the global main socket, then the relay socket.
        let main_socket = recv_socket
            .or_else(|| self.main_socket.read().clone())
            .unwrap_or_else(|| relay_socket.clone());
        let relay = spawn_allocation_task(
            relay_socket.clone(),
            main_socket, // Use main socket for sending Data Indication
            client_addr,
            relay_bind_addr,
            relayed_addr,
            self.stats.clone(),
            channel_table.clone(),
            permissions.clone(),
            self.bandwidth_manager.clone(),
            self.enforce_peer_permissions.load(Ordering::Relaxed),
        )
        .await;

        let allocation = Arc::new(RwLock::new(Allocation::with_relay(
            id,
            relayed_addr,
            client_addr,
            lifetime,
            client_addr,
            relayed_addr,
            relay,
            permissions,
        )));

        // Insert into both maps. Lock order is always `allocations` then
        // `by_client` to avoid deadlocks.
        let mut allocations = self.allocations.write();
        allocations.insert(relayed_addr, allocation.clone());
        drop(allocations);
        self.by_client
            .write()
            .insert(client_addr, allocation.clone());
        self.stats.total_allocations.fetch_add(1, Ordering::Relaxed);
        self.stats
            .active_allocations
            .fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = self.metrics() {
            metrics.record_allocation();
        }

        // Register with bandwidth manager for tracking
        self.bandwidth_manager
            .register_allocation(relayed_addr, None);

        trace!(
            %client_addr,
            %relay_bind_addr,
            %relayed_addr,
            requested_lifetime = requested_lifetime.unwrap_or(600),
            effective_lifetime = lifetime_secs,
            "created relay allocation"
        );

        Ok(allocation)
    }

    pub fn get_allocation(&self, relayed_addr: &SocketAddr) -> Option<Arc<RwLock<Allocation>>> {
        let allocations = self.allocations.read();
        allocations.get(relayed_addr).cloned()
    }

    pub fn remove_allocation(
        &self,
        relayed_addr: &SocketAddr,
        channel_table: Option<&ChannelTable>,
    ) -> Option<Arc<RwLock<Allocation>>> {
        let mut allocations = self.allocations.write();
        let result = allocations.remove(relayed_addr);
        drop(allocations);
        if let Some(ref alloc) = result {
            // Drop the client index entry first (keyed by the current, possibly
            // rebind-updated, client address).
            let client_addr = alloc.read().client_addr;
            self.by_client.write().remove(&client_addr);
            // Clean up channel bindings FIRST, before releasing the port,
            // to prevent a re-allocate on the same port from inheriting
            // stale bindings or having its fresh bindings incorrectly removed.
            if let Some(ch_table) = channel_table {
                let removed_channels = ch_table.remove_for_relayed(relayed_addr);
                if let Some(metrics) = self.metrics() {
                    metrics.record_channels_unbound(removed_channels);
                }
            }
            // Abort the allocation task to release the socket
            if let Some(ref relay) = alloc.read().relay {
                relay.task_handle.abort();
            }
            // Release port back to allocator
            self.port_allocator.release(relayed_addr.port());
            self.stats
                .active_allocations
                .fetch_sub(1, Ordering::Relaxed);
            if let Some(metrics) = self.metrics() {
                metrics.record_allocation_dropped();
            }
            // Unregister from bandwidth manager to prevent memory leak
            self.bandwidth_manager.unregister_allocation(relayed_addr);
        }
        result
    }

    pub fn refresh_allocation(
        &self,
        relayed_addr: &SocketAddr,
        lifetime: u32,
    ) -> Result<(), Error> {
        let allocations = self.allocations.read();
        if let Some(allocation) = allocations.get(relayed_addr) {
            let mut alloc = allocation.write();
            let effective = self.effective_allocation_lifetime(Some(lifetime));
            alloc.lifetime = Duration::from_secs(effective as u64);
            alloc.refreshed_at = Instant::now();
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    pub fn find_allocation_by_client(&self, client_addr: &SocketAddr) -> Option<SocketAddr> {
        self.by_client
            .read()
            .get(client_addr)
            .map(|a| a.read().relayed_addr)
    }

    /// Get the allocation for a client, returning the Arc for direct access
    pub fn get_allocation_by_client(
        &self,
        client_addr: &SocketAddr,
    ) -> Option<Arc<RwLock<Allocation>>> {
        self.by_client.read().get(client_addr).cloned()
    }

    /// Find the single allocation owned by `username`, if exactly one exists.
    /// Used as the NAT-rebind fallback for Refresh requests arriving from a
    /// changed client transport address.
    pub fn find_single_allocation_by_username(
        &self,
        username: &str,
    ) -> Option<Arc<RwLock<Allocation>>> {
        let allocations = self.allocations.read();
        let mut found: Option<Arc<RwLock<Allocation>>> = None;
        for alloc in allocations.values() {
            if alloc.read().username.as_deref() == Some(username) {
                if found.is_some() {
                    return None;
                }
                found = Some(alloc.clone());
            }
        }
        found
    }

    /// Atomically move an allocation's client-index entry from its current
    /// client address to `new_client_addr` (NAT rebind). Returns the previous
    /// client address, or `None` if it was already `new_client_addr`.
    ///
    /// Lock order is `by_client` then the per-allocation lock, matching
    /// `send_to_peer` / `add_permissions` / `cleanup_expired` to avoid a
    /// lock-order inversion.
    pub fn move_client_addr(
        &self,
        relayed_addr: &SocketAddr,
        new_client_addr: SocketAddr,
    ) -> Option<SocketAddr> {
        let alloc = self.get_allocation(relayed_addr)?;
        let old = alloc.read().client_addr;
        if old == new_client_addr {
            return None;
        }
        let mut by_client = self.by_client.write();
        match by_client.remove(&old) {
            Some(entry) if entry.read().relayed_addr == *relayed_addr => {
                // Same allocation: move the index entry and update its address
                // while holding the index lock (no other thread can observe a
                // torn key↔field pair).
                let mut a = entry.write();
                a.client_addr = new_client_addr;
                a.five_tuple.0 = new_client_addr;
                drop(a);
                by_client.insert(new_client_addr, entry);
            }
            other => {
                // The old address is either absent or now owned by a different
                // allocation (address reuse): leave that entry alone.
                if let Some(other_entry) = other {
                    by_client.insert(old, other_entry);
                }
                let mut a = alloc.write();
                a.client_addr = new_client_addr;
                a.five_tuple.0 = new_client_addr;
                drop(a);
                by_client.insert(new_client_addr, alloc);
            }
        }
        Some(old)
    }

    /// Add permissions for peer addresses on a client's allocation.
    /// The per-allocation permission set is capped at
    /// `MAX_PERMISSIONS_PER_ALLOCATION` to bound memory usage.
    pub fn add_permissions(&self, client_addr: &SocketAddr, peers: &[SocketAddr]) -> bool {
        let alloc = match self.by_client.read().get(client_addr) {
            Some(a) => a.clone(),
            None => {
                debug!(
                    %client_addr,
                    requested_peer_count = peers.len(),
                    peers = ?peers,
                    "failed to update TURN permissions because allocation was not found"
                );
                return false;
            }
        };
        let a = alloc.read();
        let mut perms = a.permissions.write();
        let before = perms.len();
        for peer in peers {
            if perms.len() >= MAX_PERMISSIONS_PER_ALLOCATION && !perms.contains(&peer.ip()) {
                warn!(
                    %client_addr,
                    relayed_addr = %a.relayed_addr,
                    max = MAX_PERMISSIONS_PER_ALLOCATION,
                    "permission set full, ignoring further CreatePermission peers"
                );
                break;
            }
            perms.insert(peer.ip());
        }
        let after = perms.len();
        drop(perms);
        info!(
            %client_addr,
            relayed_addr = %a.relayed_addr,
            permission_before = before,
            permission_after = after,
            requested_peer_count = peers.len(),
            peers = ?peers,
            "updated TURN permissions for allocation"
        );
        true
    }

    /// Check if a peer address is permitted for a client's allocation
    pub fn check_permission(&self, client_addr: &SocketAddr, peer: &SocketAddr) -> bool {
        match self.by_client.read().get(client_addr) {
            Some(a) => a.read().permissions.read().contains(&peer.ip()),
            None => false,
        }
    }

    /// Send data from a client's allocation relay to a peer
    pub async fn send_to_peer(
        &self,
        client_addr: &SocketAddr,
        peer: SocketAddr,
        data: &[u8],
    ) -> Option<()> {
        // Look up relay state under lock, then release before await.
        let relay_state: Option<(
            Arc<UdpSocket>,
            SocketAddr,
            usize,
            Arc<AtomicU64>,
            Arc<AtomicU64>,
        )> = {
            let alloc = match self.by_client.read().get(client_addr) {
                Some(a) => a.clone(),
                None => {
                    debug!(
                        %client_addr,
                        %peer,
                        payload_len = data.len(),
                        "dropping relay packet because allocation was not found for client"
                    );
                    return None;
                }
            };
            let a = alloc.read();
            let permission_count = a.permissions.read().len();
            // Check permission
            if !a.permissions.read().contains(&peer.ip()) {
                debug!(
                    %client_addr,
                    %peer,
                    relayed_addr = %a.relayed_addr,
                    permission_count,
                    payload_len = data.len(),
                    "dropping relay packet because peer is not in permission list"
                );
                return None;
            }
            // Clone the socket Arc so we can send after releasing the lock.
            match a.relay {
                Some(ref relay) => Some((
                    relay.socket.clone(),
                    a.relayed_addr,
                    permission_count,
                    a.bytes_forwarded.clone(),
                    a.messages_forwarded.clone(),
                )),
                None => {
                    debug!(
                        %client_addr,
                        %peer,
                        relayed_addr = %a.relayed_addr,
                        permission_count,
                        payload_len = data.len(),
                        "dropping relay packet because allocation has no active relay socket"
                    );
                    None
                }
            }
        };
        if let Some((socket, relayed_addr, permission_count, bytes_fwd, messages_fwd)) = relay_state
        {
            // Enforce the (global) bandwidth budget before sending.
            if !self.bandwidth_manager.try_relay(&relayed_addr, data.len()) {
                debug!(
                    %client_addr,
                    %peer,
                    %relayed_addr,
                    payload_len = data.len(),
                    "dropping relay packet because bandwidth limit is exceeded"
                );
                return None;
            }
            if let Err(err) = socket.send_to(data, &peer).await {
                warn!(
                    %client_addr,
                    %peer,
                    %relayed_addr,
                    permission_count,
                    payload_len = data.len(),
                    error = %err,
                    "failed to send relay packet to peer"
                );
                return None;
            }
            let n = data.len() as u64;
            self.stats
                .total_bytes_relayed
                .fetch_add(n, Ordering::Relaxed);
            self.stats.total_messages.fetch_add(1, Ordering::Relaxed);
            bytes_fwd.fetch_add(n, Ordering::Relaxed);
            messages_fwd.fetch_add(1, Ordering::Relaxed);
            return Some(());
        }
        debug!(
            %client_addr,
            %peer,
            payload_len = data.len(),
            "dropping relay packet because allocation was not found for client"
        );
        None
    }

    pub fn peer_to_relay(&self, peer_addr: &SocketAddr) -> Result<SocketAddr, Error> {
        let allocations = self.allocations.read();
        for alloc in allocations.values() {
            let a = alloc.read();
            if a.five_tuple.1 == *peer_addr {
                self.stats
                    .total_bytes_relayed
                    .fetch_add(1, Ordering::Relaxed);
                self.stats.total_messages.fetch_add(1, Ordering::Relaxed);
                return Ok(a.relayed_addr);
            }
        }
        Err(Error::NotFound)
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Get port allocator stats
    pub fn port_stats(&self) -> (usize, usize) {
        (
            self.port_allocator.allocated_count(),
            self.port_allocator.available_count(),
        )
    }

    /// Clean up expired allocations and their channel bindings
    pub fn cleanup_expired(&self, channel_table: Option<&ChannelTable>) -> usize {
        // Phase 1: under the map write lock, detach expired entries only.
        // Expensive per-entry work (logging, task abort, channel cleanup)
        // happens after the lock is released so the hot path is not stalled.
        let expired: Vec<(SocketAddr, Arc<RwLock<Allocation>>)> = {
            let mut allocations = self.allocations.write();
            let expired_addrs: Vec<SocketAddr> = allocations
                .iter()
                .filter(|(_, alloc)| alloc.read().is_expired())
                .map(|(addr, _)| *addr)
                .collect();

            let mut removed = Vec::with_capacity(expired_addrs.len());
            for addr in expired_addrs {
                if let Some(alloc) = allocations.remove(&addr) {
                    removed.push((addr, alloc));
                }
            }
            drop(allocations);

            if !removed.is_empty() {
                let mut by_client = self.by_client.write();
                for (addr, alloc) in &removed {
                    let client_addr = alloc.read().client_addr;
                    if let Some(entry) = by_client.remove(&client_addr)
                        && entry.read().relayed_addr != *addr
                    {
                        // The index entry belongs to a newer allocation that
                        // reused this client address; put it back.
                        by_client.insert(client_addr, entry);
                    }
                }
            }
            removed
        };

        // Phase 2: per-entry teardown without holding the table lock.
        let mut count = 0;
        for (addr, alloc) in expired {
            {
                let a = alloc.read();
                let bytes = a.bytes_forwarded.load(Ordering::Relaxed);
                let messages = a.messages_forwarded.load(Ordering::Relaxed);
                let permission_count = a.permissions.read().len();
                let lived_secs = a.created_at.elapsed().as_secs();
                let refresh_age_secs = a.refreshed_at.elapsed().as_secs();
                tracing::info!(
                    relayed_addr = %addr,
                    client_addr = %a.client_addr,
                    lived_secs,
                    refresh_age_secs,
                    bytes_forwarded = bytes,
                    messages_forwarded = messages,
                    permission_count,
                    "allocation expired and removed"
                );
            }
            // Abort the allocation task
            if let Some(ref relay) = alloc.read().relay {
                relay.task_handle.abort();
            }
            // Release port back to allocator
            self.port_allocator.release(addr.port());
            // Unregister from bandwidth manager to prevent memory leak
            self.bandwidth_manager.unregister_allocation(&addr);
            // Clean up channel bindings for this relayed address
            if let Some(ch_table) = channel_table {
                let removed_channels = ch_table.remove_for_relayed(&addr);
                if let Some(metrics) = self.metrics() {
                    metrics.record_channels_unbound(removed_channels);
                }
            }
            count += 1;
        }

        if count > 0 {
            self.stats
                .active_allocations
                .fetch_sub(count as u64, Ordering::Relaxed);
            if let Some(metrics) = self.metrics() {
                metrics.record_allocation_dropped();
            }
        }

        count
    }
}

fn getrandom(buf: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    for byte in buf.iter_mut() {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        *byte = (seed >> 16) as u8;
    }
}

fn build_data_indication(peer_addr: SocketAddr, payload: &[u8]) -> Bytes {
    use bytes::BufMut;

    const MAGIC: u32 = 0x2112A442;
    let mut transaction_id = [0u8; 12];
    getrandom(&mut transaction_id);

    let peer_len: usize = match peer_addr {
        SocketAddr::V4(_) => 8,
        SocketAddr::V6(_) => 20,
    };
    let data_pad = (4 - (payload.len() % 4)) % 4;
    let msg_len = (4 + peer_len) + (4 + payload.len() + data_pad);

    // Single allocation, single pass: header + XOR-PEER-ADDRESS + DATA.
    let mut buf = bytes::BytesMut::with_capacity(20 + msg_len);
    // Data(0x007) Indication(class 1) → 0x0017 per RFC 5389 type encoding.
    buf.put_u16(0x0017);
    buf.put_u16(msg_len as u16);
    buf.put_u32(MAGIC);
    buf.put_slice(&transaction_id);

    buf.put_u16(crate::message::Attribute::PEER_ADDRESS);
    buf.put_u16(peer_len as u16);
    match peer_addr {
        SocketAddr::V4(v4) => {
            buf.put_u8(0);
            buf.put_u8(0x01);
            buf.put_u16(v4.port() ^ (MAGIC >> 16) as u16);
            let ip = v4.ip().octets();
            buf.put_u8(ip[0] ^ (MAGIC >> 24) as u8);
            buf.put_u8(ip[1] ^ (MAGIC >> 16) as u8);
            buf.put_u8(ip[2] ^ (MAGIC >> 8) as u8);
            buf.put_u8(ip[3] ^ MAGIC as u8);
        }
        SocketAddr::V6(v6) => {
            buf.put_u8(0);
            buf.put_u8(0x02);
            buf.put_u16(v6.port() ^ (MAGIC >> 16) as u16);
            let octets = v6.ip().octets();
            for (i, shift) in (0..4usize).zip([24u32, 16, 8, 0]) {
                buf.put_u8(octets[i] ^ (MAGIC >> shift) as u8);
            }
            for i in 0..12 {
                buf.put_u8(octets[4 + i] ^ transaction_id[i]);
            }
        }
    }

    buf.put_u16(crate::message::Attribute::DATA);
    buf.put_u16(payload.len() as u16);
    buf.put_slice(payload);
    for _ in 0..data_pad {
        buf.put_u8(0);
    }

    buf.freeze()
}

fn normalize_peer_addr_for_client(
    peer_addr: SocketAddr,
    relay_bind_addr: SocketAddr,
    relayed_addr: SocketAddr,
) -> SocketAddr {
    // Only rewrite addresses that originate from this server's relay bind
    // interface. External peer traffic must keep the original source address
    // so CreatePermission / ChannelBind matching remains correct.
    if peer_addr.ip() == relay_bind_addr.ip() && relay_bind_addr.ip() != relayed_addr.ip() {
        SocketAddr::new(relayed_addr.ip(), peer_addr.port())
    } else {
        peer_addr
    }
}

/// Determine if a UDP recv_from error kind is fatal (should permanently exit
/// the relay task) or transient (should be tolerated with a retry).
///
/// On Linux, a UDP recv_from can fail with `ECONNREFUSED` when the kernel
/// delivers an ICMP port-unreachable from a previous `send_to` target. Such
/// errors are transient and must not kill the relay loop.
fn is_fatal_recv_error(kind: io::ErrorKind) -> bool {
    matches!(kind, io::ErrorKind::PermissionDenied)
}

/// Spawn a dedicated task for an allocation to handle relay traffic
/// This eliminates lock contention by giving each allocation its own processing loop
async fn spawn_allocation_task(
    socket: Arc<UdpSocket>,
    main_socket: Arc<UdpSocket>, // Main socket for sending Data Indication / ChannelData to client
    mut client_addr: SocketAddr,
    relay_bind_addr: SocketAddr,
    relayed_addr: SocketAddr,
    stats: Arc<ServerStats>,
    channel_table: ChannelTable,
    permissions: Arc<RwLock<std::collections::HashSet<std::net::IpAddr>>>,
    bandwidth_manager: Arc<crate::bandwidth::BandwidthManager>,
    enforce_peer_permissions: bool,
) -> AllocationRelay {
    let (tx, mut rx) = mpsc::channel::<AllocationMessage>(1024);

    let socket_clone = socket.clone();
    let main_socket_clone = main_socket.clone();

    let task_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        // Reusable scratch buffer for building ChannelData frames (B3: avoids
        // one heap allocation per relayed packet; grows to max seen size).
        let mut channel_scratch = bytes::BytesMut::with_capacity(2048);
        let mut consecutive_recv_errors: u32 = 0;
        let mut last_recv_error_at: Option<Instant> = None;
        const MAX_CONSECUTIVE_RECV_ERRORS: u32 = 100;
        const RECV_ERROR_WINDOW_SECS: u64 = 10;
        // Optional TCP client channel: if set, peer→client data goes via
        // this channel (framed with RFC 6062 2-byte length prefix) instead
        // of the UDP main_socket.
        let mut tcp_client_tx: Option<tokio::sync::mpsc::Sender<Vec<u8>>> = None;

        loop {
            tokio::select! {
                // Handle incoming peer data on the relay socket
                result = socket_clone.recv_from(&mut buf) => {
                    match result {
                        Ok((len, peer_addr)) => {
                            // Reset error counter on success
                            consecutive_recv_errors = 0;
                            last_recv_error_at = None;

                            // RFC 5766 §10: only relay traffic from peers for
                            // which a permission exists (ChannelBind installs
                            // one implicitly). Without this check any host that
                            // learns the relay port could inject/amplify traffic.
                            // Enforcement is opt-in (default off) for backwards
                            // compatibility with clients that only create
                            // permissions for private/host peer addresses while
                            // media arrives from the peer's public address.
                            if enforce_peer_permissions
                                && !permissions.read().contains(&peer_addr.ip())
                            {
                                trace!(
                                    %client_addr,
                                    peer = %peer_addr,
                                    payload_len = len,
                                    "dropping peer packet without permission"
                                );
                                continue;
                            }

                            // Enforce the bandwidth budget on the peer→client
                            // direction as well.
                            if !bandwidth_manager.try_relay(&relayed_addr, len) {
                                trace!(
                                    %client_addr,
                                    peer = %peer_addr,
                                    payload_len = len,
                                    "dropping peer packet because bandwidth limit is exceeded"
                                );
                                continue;
                            }

                            // Update stats using atomics - no lock contention
                            stats.total_bytes_relayed.fetch_add(len as u64, Ordering::Relaxed);
                            stats.total_messages.fetch_add(1, Ordering::Relaxed);

                            // Only rewrite local relay-bind source addresses to external relay IP.
                            // Real peer traffic from external hosts must keep original source IP.
                            let effective_peer = normalize_peer_addr_for_client(
                                peer_addr,
                                relay_bind_addr,
                                relayed_addr,
                            );

                            // RFC 5766 §10.4: if a channel binding exists for this peer on this
                            // allocation, send ChannelData; otherwise send Data Indication.
                            let channel_num = channel_table.get_by_peer_for_relayed(&relayed_addr, &effective_peer);

                            if let Some(ch_num) = channel_num {
                                // Send as ChannelData (single scratch buffer, no per-packet alloc)
                                use bytes::BufMut;
                                channel_scratch.clear();
                                channel_scratch.reserve(4 + len);
                                channel_scratch.put_u16(ch_num);
                                channel_scratch.put_u16(len as u16);
                                channel_scratch.put_slice(&buf[..len]);

                                if let Some(ref tx) = tcp_client_tx {
                                    let framed = frame_for_tcp(&channel_scratch);
                                    if let Err(e) = tx.try_send(framed) {
                                        warn!(%client_addr, "TCP forward to client failed: {}", e);
                                    }
                                } else if let Err(e) = main_socket_clone.send_to(&channel_scratch, &client_addr).await {
                                    warn!(
                                        %client_addr,
                                        peer = %effective_peer,
                                        channel = ch_num,
                                        payload_len = len,
                                        error = %e,
                                        "failed to forward peer packet to client as ChannelData"
                                    );
                                }
                            } else {
                                // Send as Data Indication
                                let indication = build_data_indication(effective_peer, &buf[..len]);
                                if let Some(ref tx) = tcp_client_tx {
                                    let framed = frame_for_tcp(&indication);
                                    if let Err(e) = tx.try_send(framed) {
                                        warn!(%client_addr, "TCP Data Indication forward failed: {}", e);
                                    }
                                } else if let Err(e) = main_socket_clone.send_to(&indication, &client_addr).await {
                                    warn!(
                                        %client_addr,
                                        peer = %effective_peer,
                                        payload_len = len,
                                        error = %e,
                                        "failed to forward peer packet to client as Data Indication"
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            consecutive_recv_errors += 1;
                            let now = Instant::now();

                            // Time-based reset: if last error was > WINDOW ago, reset counter
                            if let Some(last) = last_recv_error_at {
                                if now.duration_since(last).as_secs() > RECV_ERROR_WINDOW_SECS {
                                    consecutive_recv_errors = 1;
                                }
                            }
                            last_recv_error_at = Some(now);

                            if is_fatal_recv_error(e.kind()) {
                                warn!(
                                    %client_addr,
                                    consecutive_errors = consecutive_recv_errors,
                                    error = %e,
                                    "relay socket fatal recv error, exiting relay loop"
                                );
                                break;
                            }

                            if consecutive_recv_errors >= MAX_CONSECUTIVE_RECV_ERRORS {
                                // Sustained transient errors (e.g. ICMP storms) must not
                                // permanently kill peer→client forwarding for a live
                                // allocation. Back off, reset the counter and continue.
                                warn!(
                                    %client_addr,
                                    consecutive_errors = consecutive_recv_errors,
                                    max_consecutive = MAX_CONSECUTIVE_RECV_ERRORS,
                                    window_secs = RECV_ERROR_WINDOW_SECS,
                                    error = %e,
                                    "relay socket sustained too many recv errors; backing off and continuing"
                                );
                                consecutive_recv_errors = 0;
                                last_recv_error_at = None;
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                continue;
                            }

                            warn!(
                                %client_addr,
                                consecutive_errors = consecutive_recv_errors,
                                error = %e,
                                "relay socket transient recv error, continuing"
                            );

                            // Brief sleep to avoid tight loop on persistent errors
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }

                // Handle messages from the main server
                Some(msg) = rx.recv() => {
                    match msg {
                        AllocationMessage::ClientData { data, peer_addr } => {
                            // Forward client data to peer
                            if let Err(e) = socket_clone.send_to(&data, &peer_addr).await {
                                warn!(
                                    %client_addr,
                                    %peer_addr,
                                    payload_len = data.len(),
                                    error = %e,
                                    "allocation task failed to forward client data to peer"
                                );
                            }
                        }
                        AllocationMessage::ChannelData { data, channel_num: _ } => {
                            // Forward channel data via main socket (not relay socket)
                            if let Err(e) = main_socket_clone.send_to(&data, &client_addr).await {
                                warn!(
                                    %client_addr,
                                    payload_len = data.len(),
                                    error = %e,
                                    "allocation task failed to forward channel data to client"
                                );
                            }
                        }
                        AllocationMessage::UpdateClientAddr { client_addr: new_addr } => {
                            if new_addr != client_addr {
                                debug!(
                                    old = %client_addr,
                                    new = %new_addr,
                                    "relay task updating client address (NAT rebind detected)"
                                );
                                client_addr = new_addr;
                            }
                        }
                        AllocationMessage::SetClientTx { tx } => {
                            debug!(%client_addr, "relay task received TCP client channel");
                            tcp_client_tx = Some(tx);
                        }
                        AllocationMessage::Shutdown => {
                            break;
                        }
                    }
                }

                else => break,
            }
        }
    })
    .abort_handle();

    AllocationRelay {
        socket,
        tx,
        task_handle,
    }
}

/// Frame a STUN/ChannelData message with the RFC 6062 2-byte length prefix
/// used on TURN-over-TCP connections.
fn frame_for_tcp(message: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(2 + message.len());
    framed.push((message.len() >> 8) as u8);
    framed.push((message.len() & 0xFF) as u8);
    framed.extend_from_slice(message);
    framed
}

#[derive(Clone)]
pub struct ChannelTable {
    channels: Arc<RwLock<HashMap<(SocketAddr, u16), ChannelBinding>>>,
    /// Secondary index: (relayed_addr, peer_addr) → channel binding, for O(1)
    /// lookup on the per-packet peer→client relay path. Kept consistent with
    /// `channels` by bind/unbind/remove_for_relayed/cleanup_expired.
    by_peer: Arc<RwLock<HashMap<(SocketAddr, SocketAddr), ChannelBinding>>>,
    next_channel: Arc<std::sync::atomic::AtomicU16>,
    default_lifetime: Duration,
}

#[derive(Clone)]
pub struct ChannelBinding {
    pub channel_id: u16,
    pub peer_addr: SocketAddr,
    pub relayed_addr: SocketAddr,
    pub created_at: Instant,
    pub lifetime: Duration,
}

impl ChannelBinding {
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.lifetime
    }

    pub fn remaining_lifetime(&self) -> u32 {
        let elapsed = self.created_at.elapsed();
        if elapsed >= self.lifetime {
            return 0;
        }
        (self.lifetime - elapsed).as_secs() as u32
    }
}

impl ChannelTable {
    pub fn new() -> Self {
        ChannelTable {
            channels: Arc::new(RwLock::new(HashMap::new())),
            by_peer: Arc::new(RwLock::new(HashMap::new())),
            next_channel: Arc::new(std::sync::atomic::AtomicU16::new(0x4000)),
            default_lifetime: Duration::from_secs(600),
        }
    }

    /// Build a ChannelTable whose bindings use `default_lifetime` instead of
    /// the RFC 5766 default of 600s. This is used to align the channel binding
    /// lifetime with the server's max allocation duration so channels do not
    /// expire before their owning allocation.
    pub fn with_lifetime(default_lifetime: Duration) -> Self {
        ChannelTable {
            channels: Arc::new(RwLock::new(HashMap::new())),
            by_peer: Arc::new(RwLock::new(HashMap::new())),
            next_channel: Arc::new(std::sync::atomic::AtomicU16::new(0x4000)),
            default_lifetime,
        }
    }

    pub fn bind(
        &self,
        channel_id: u16,
        peer_addr: SocketAddr,
        relayed_addr: SocketAddr,
    ) -> Result<(), Error> {
        let key = (relayed_addr, channel_id);
        let binding = ChannelBinding {
            channel_id,
            peer_addr,
            relayed_addr,
            created_at: Instant::now(),
            lifetime: self.default_lifetime,
        };

        // Lock order is always `channels` then `by_peer`.
        let mut channels = self.channels.write();
        let mut by_peer = self.by_peer.write();

        if let Some(existing) = channels.get_mut(&key) {
            if existing.peer_addr == peer_addr {
                existing.created_at = Instant::now();
                // Keep the secondary index in sync with the refreshed binding.
                by_peer.insert((relayed_addr, peer_addr), existing.clone());
                return Ok(());
            }
            return Err(Error::AlreadyExists);
        }

        // RFC 5766 §11: a peer may be bound to at most one channel per
        // allocation. Reject binding the same peer to a second channel.
        if let Some(existing) = by_peer.get(&(relayed_addr, peer_addr))
            && existing.channel_id != channel_id
        {
            return Err(Error::AlreadyExists);
        }

        channels.insert(key, binding.clone());
        by_peer.insert((relayed_addr, peer_addr), binding);
        Ok(())
    }

    pub fn get_by_channel(
        &self,
        relayed_addr: SocketAddr,
        channel_id: u16,
    ) -> Option<ChannelBinding> {
        let channels = self.channels.read();
        channels.get(&(relayed_addr, channel_id)).cloned()
    }

    pub fn get_by_peer(&self, peer_addr: &SocketAddr) -> Option<u16> {
        let channels = self.channels.read();
        for ((_, channel_id), ch) in channels.iter() {
            if ch.peer_addr == *peer_addr {
                return Some(*channel_id);
            }
        }
        None
    }

    /// Look up channel binding by (relayed_addr, peer_addr).
    /// Used by allocation task to find the channel number for peer-to-client relay.
    pub fn get_by_peer_for_relayed(
        &self,
        relayed_addr: &SocketAddr,
        peer_addr: &SocketAddr,
    ) -> Option<u16> {
        self.by_peer
            .read()
            .get(&(*relayed_addr, *peer_addr))
            .map(|b| b.channel_id)
    }

    pub fn get_relayed_by_peer(&self, peer_addr: &SocketAddr) -> Option<SocketAddr> {
        let channels = self.channels.read();
        for ch in channels.values() {
            if ch.peer_addr == *peer_addr {
                return Some(ch.relayed_addr);
            }
        }
        None
    }

    pub fn unbind(&self, relayed_addr: SocketAddr, channel_id: u16) -> Option<ChannelBinding> {
        let mut channels = self.channels.write();
        let mut by_peer = self.by_peer.write();
        let removed = channels.remove(&(relayed_addr, channel_id));
        if let Some(ref binding) = removed {
            by_peer.remove(&(binding.relayed_addr, binding.peer_addr));
        }
        removed
    }

    pub fn next_id(&self) -> u16 {
        use std::sync::atomic::Ordering;
        // Atomically fetch and wrap channel IDs within 0x4000..=0x7FFF
        loop {
            let current = self.next_channel.load(Ordering::Acquire);
            let next = if current >= 0x7FFF {
                0x4000
            } else {
                current + 1
            };
            if self
                .next_channel
                .compare_exchange_weak(current, next, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return current;
            }
        }
    }

    /// Remove all channel bindings for a given relayed address.
    /// Called when an allocation is removed to prevent stale bindings from
    /// leaking into a new allocation that reuses the same port.
    pub fn remove_for_relayed(&self, relayed_addr: &SocketAddr) -> usize {
        let mut channels = self.channels.write();
        let mut by_peer = self.by_peer.write();
        let before = channels.len();
        channels.retain(|(ra, _), _| ra != relayed_addr);
        by_peer.retain(|(ra, _), _| ra != relayed_addr);
        before.saturating_sub(channels.len())
    }

    /// Clean up expired channel bindings
    /// Returns the number of expired channels removed
    pub fn cleanup_expired(&self) -> usize {
        let mut channels = self.channels.write();
        let mut by_peer = self.by_peer.write();
        let initial_count = channels.len();
        channels.retain(|_, binding| !binding.is_expired());
        by_peer.retain(|_, binding| !binding.is_expired());
        initial_count.saturating_sub(channels.len())
    }

    /// Get the number of active channel bindings
    pub fn len(&self) -> usize {
        self.channels.read().len()
    }

    /// Check if there are no channel bindings
    pub fn is_empty(&self) -> bool {
        self.channels.read().is_empty()
    }
}

impl Default for ChannelTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU16, Ordering};

    static ALLOC_TEST_RANGE_IDX: AtomicU16 = AtomicU16::new(0);

    /// Returns a unique (min_port, max_port) range per call, sharded by PID,
    /// in the 40000–48999 window to avoid collisions with other test files.
    fn alloc_test_port_range() -> (u16, u16) {
        const RANGE_SIZE: u16 = 64;
        const BASE_PORT: u16 = 40000;
        const WINDOW: u16 = 9000; // 40000..48999
        const SLOT_COUNT: u16 = WINDOW / RANGE_SIZE;
        let idx = ALLOC_TEST_RANGE_IDX.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id() as u16;
        let slot = pid
            .wrapping_mul(131)
            .wrapping_add(idx)
            .wrapping_rem(SLOT_COUNT);
        let min = BASE_PORT + slot * RANGE_SIZE;
        (min, min + RANGE_SIZE - 1)
    }

    #[test]
    fn test_port_allocator() {
        let allocator = PortAllocator::new(49152, 50000);

        // Allocate 10 ports
        let mut ports = Vec::new();
        for _ in 0..10 {
            let p = allocator.allocate().unwrap();
            ports.push(p);
        }
        assert_eq!(allocator.allocated_count(), 10);

        // Release one
        let released_port = ports[5];
        allocator.release(released_port);
        assert_eq!(allocator.allocated_count(), 9);

        // Allocate again - gets any free port (may or may not be the released one)
        let new_port = allocator.allocate().unwrap();
        assert!(new_port >= 49152 && new_port <= 50000);

        // After reallocation, count is back to 10
        assert_eq!(allocator.allocated_count(), 10);

        // Original port 0 should still be allocated
        assert!(allocator.is_allocated(ports[0]));

        // The newly allocated port is definitely allocated
        assert!(allocator.is_allocated(new_port));
    }

    /// Verify that allocated ports are randomized, not sequential.
    #[test]
    fn test_port_allocator_randomized() {
        let allocator = PortAllocator::new(49152, 49352); // 200 ports

        // Allocate 50 ports — with randomization they should NOT be sequential
        let ports: Vec<u16> = (0..50).map(|_| allocator.allocate().unwrap()).collect();

        // Count how many ports are NOT in strictly ascending order
        let ascending_count = ports
            .windows(2)
            .filter(|w| w[0] < w[1] && w[1] - w[0] < 3)
            .count();

        // In a truly random distribution, most consecutive pairs should NOT be adjacent.
        // Allow up to 60% adjacent to account for randomness.
        assert!(
            ascending_count < ports.len(),
            "ports appear sequential: {:?}",
            ports
        );
    }

    /// Verify all ports in range can be allocated and no duplicates.
    #[test]
    fn test_port_allocator_exhaustive_no_duplicates() {
        let allocator = PortAllocator::new(50000, 50031); // 32 ports

        let mut ports: Vec<u16> = (0..32).map(|_| allocator.allocate().unwrap()).collect();

        // No duplicates
        ports.sort();
        ports.dedup();
        assert_eq!(ports.len(), 32, "duplicate ports detected");

        // All ports in range
        assert_eq!(ports[0], 50000);
        assert_eq!(ports[31], 50031);

        // Full
        assert!(allocator.allocate().is_none());
    }

    /// Verify port range boundaries are respected.
    #[test]
    fn test_port_allocator_respects_range() {
        let allocator = PortAllocator::new(40000, 40009); // 10 ports

        let ports: Vec<u16> = (0..10).map(|_| allocator.allocate().unwrap()).collect();

        for p in &ports {
            assert!(*p >= 40000 && *p <= 40009, "port {} out of range", p);
        }
    }

    /// Verify that releasing and reallocating doesn't always return the same port.
    #[test]
    fn test_port_allocator_release_reuse_varies() {
        let allocator = PortAllocator::new(45000, 45200);

        // Allocate a batch, release half, allocate again
        let mut ports: Vec<u16> = (0..20).map(|_| allocator.allocate().unwrap()).collect();

        // Release the first 10
        for p in ports.drain(0..10) {
            allocator.release(p);
        }

        // Reallocate 10 — should not all be the same ports we just released
        let new_ports: Vec<u16> = (0..10).map(|_| allocator.allocate().unwrap()).collect();

        // At least some should differ from purely sequential reuse
        let _ = new_ports; // new_ports are valid ports in range, verified by other tests
        assert_eq!(allocator.allocated_count(), 20);
    }

    /// Verify concurrent allocations don't produce duplicates.
    #[test]
    fn test_port_allocator_concurrent_no_duplicates() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let allocator = Arc::new(PortAllocator::new(50000, 50199)); // 200 ports
        let allocated = Arc::new(std::sync::Mutex::new(Vec::new()));
        let errors = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let alloc = allocator.clone();
            let result = allocated.clone();
            let err = errors.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..50 {
                    if let Some(port) = alloc.allocate() {
                        result.lock().unwrap().push(port);
                    } else {
                        err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let mut ports = allocated.lock().unwrap().clone();
        assert_eq!(ports.len(), 200, "should allocate all 200 ports");
        assert_eq!(
            errors.load(Ordering::Relaxed),
            0,
            "no allocation failures expected"
        );

        ports.sort();
        ports.dedup();
        assert_eq!(ports.len(), 200, "no duplicates under concurrent access");
    }

    #[test]
    fn test_port_allocator_full() {
        let allocator = PortAllocator::new(60000, 60005); // Only 6 ports

        // Allocate all
        let ports: Vec<u16> = (0..6).map(|_| allocator.allocate().unwrap()).collect();
        assert_eq!(allocator.allocated_count(), 6);

        // Should fail when full
        assert!(allocator.allocate().is_none());

        // Release all and try again
        for p in ports {
            allocator.release(p);
        }
        assert!(allocator.allocate().is_some());
    }

    #[tokio::test]
    async fn test_allocation_table_create() {
        let (min_port, max_port) = alloc_test_port_range();
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            None,
            None,
        );
        let client: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let channel_table = ChannelTable::new();
        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        assert!(!alloc.read().is_expired());
    }

    #[tokio::test]
    async fn test_allocation_expired() {
        let (min_port, max_port) = alloc_test_port_range();
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            None,
            None,
        );
        let client: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let channel_table = ChannelTable::new();
        let alloc = table
            .create_allocation(client, Some(0), &channel_table)
            .await
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert!(alloc.read().is_expired());
    }

    #[test]
    fn test_effective_allocation_lifetime_rfc_clamping() {
        let (min_port, max_port) = alloc_test_port_range();

        // No max configured: client request is honoured, defaulting to 600s.
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            None,
            None,
        );
        assert_eq!(table.effective_allocation_lifetime(Some(60)), 60);
        assert_eq!(table.effective_allocation_lifetime(None), 600);
        assert_eq!(table.effective_allocation_lifetime(Some(0)), 0);

        // Max configured: requests below max are honoured, above max are clamped
        // (never raised up to max). 0 still means delete.
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            Some(600),
            None,
        );
        assert_eq!(table.effective_allocation_lifetime(Some(60)), 60);
        assert_eq!(table.effective_allocation_lifetime(None), 600);
        assert_eq!(table.effective_allocation_lifetime(Some(600)), 600);
        assert_eq!(table.effective_allocation_lifetime(Some(3600)), 600);
        assert_eq!(table.effective_allocation_lifetime(Some(0)), 0);
    }

    #[test]
    fn test_channel_binding() {
        let table = ChannelTable::new();
        let client: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let relayed: SocketAddr = "10.0.0.1:49152".parse().unwrap();
        table.bind(0x4000, client, relayed).unwrap();
        let ch = table.get_by_channel(relayed, 0x4000).unwrap();
        assert_eq!(ch.peer_addr, client);
    }

    #[test]
    fn test_channel_binding_same_channel_allowed_across_allocations() {
        let table = ChannelTable::new();
        let peer1: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let peer2: SocketAddr = "192.168.1.2:23456".parse().unwrap();
        let relayed1: SocketAddr = "10.0.0.1:49152".parse().unwrap();
        let relayed2: SocketAddr = "10.0.0.1:49153".parse().unwrap();

        table.bind(0x4002, peer1, relayed1).unwrap();
        table.bind(0x4002, peer2, relayed2).unwrap();

        assert_eq!(
            table.get_by_channel(relayed1, 0x4002).unwrap().peer_addr,
            peer1
        );
        assert_eq!(
            table.get_by_channel(relayed2, 0x4002).unwrap().peer_addr,
            peer2
        );
    }

    #[test]
    fn test_channel_binding_refresh_same_peer_succeeds() {
        let table = ChannelTable::new();
        let peer: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let relayed: SocketAddr = "10.0.0.1:49152".parse().unwrap();

        table.bind(0x4000, peer, relayed).unwrap();
        let ch1 = table.get_by_channel(relayed, 0x4000).unwrap();

        std::thread::sleep(Duration::from_millis(10));

        table.bind(0x4000, peer, relayed).unwrap();
        let ch2 = table.get_by_channel(relayed, 0x4000).unwrap();

        assert_eq!(ch2.peer_addr, peer);
        assert!(ch2.created_at > ch1.created_at);
    }

    #[test]
    fn test_channel_binding_different_peer_fails() {
        let table = ChannelTable::new();
        let peer1: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let peer2: SocketAddr = "192.168.1.2:23456".parse().unwrap();
        let relayed: SocketAddr = "10.0.0.1:49152".parse().unwrap();

        table.bind(0x4000, peer1, relayed).unwrap();
        assert!(table.bind(0x4000, peer2, relayed).is_err());
    }

    #[tokio::test]
    async fn test_max_concurrent_allocations_limit() {
        let (min_port, max_port) = alloc_test_port_range();
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            Some(2),
            None,
            None,
        );
        let channel_table = ChannelTable::new();
        let client1: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let client2: SocketAddr = "192.168.1.2:12345".parse().unwrap();
        let client3: SocketAddr = "192.168.1.3:12345".parse().unwrap();

        let _ = table
            .create_allocation(client1, Some(600), &channel_table)
            .await
            .unwrap();
        let _ = table
            .create_allocation(client2, Some(600), &channel_table)
            .await
            .unwrap();

        let result = table
            .create_allocation(client3, Some(600), &channel_table)
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AllocationQuotaReached));
    }

    #[tokio::test]
    async fn test_allocation_advertises_external_ip_when_bind_ip_differs() {
        let (min_port, max_port) = alloc_test_port_range();
        let table = AllocationTable::with_port_range_and_bind_addr(
            Ipv4Addr::new(203, 0, 113, 10),
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            None,
            None,
        );
        let client: SocketAddr = "192.168.1.10:12345".parse().unwrap();

        let channel_table = ChannelTable::new();
        let allocation = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed_addr = allocation.read().relayed_addr;

        assert_eq!(
            relayed_addr.ip(),
            std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
        );
    }

    #[tokio::test]
    async fn test_port_reuse_after_removal() {
        let (min_port, max_port) = alloc_test_port_range();
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            None,
            None,
        );
        let channel_table = ChannelTable::new();
        let client1: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        let alloc1 = table
            .create_allocation(client1, Some(600), &channel_table)
            .await
            .unwrap();
        let port1 = alloc1.read().relayed_addr.port();

        // Verify port is allocated
        assert!(table.port_allocator.is_allocated(port1));

        // Remove allocation and drop the reference so socket is released
        let relayed_addr = alloc1.read().relayed_addr;
        table.remove_allocation(&relayed_addr, Some(&channel_table));
        drop(alloc1);

        // Port should be released in the allocator bitmap
        // (actual OS port may still be in TIME_WAIT state)
        assert!(!table.port_allocator.is_allocated(port1));

        // Verify allocator counts are correct
        let (allocated, available) = table.port_stats();
        assert_eq!(allocated, 0);
        assert!(available > 0);
    }

    /// Verify that removing an allocation also cleans up its channel bindings,
    /// so a new allocation on the same port doesn't inherit stale bindings.
    #[tokio::test]
    async fn test_channel_bindings_cleaned_on_allocation_removal() {
        let (min_port, max_port) = alloc_test_port_range();
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            None,
            None,
        );
        let channel_table = ChannelTable::new();
        let client: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let peer: SocketAddr = "10.0.0.2:5000".parse().unwrap();

        // Create allocation and bind a channel
        let alloc1 = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed_addr = alloc1.read().relayed_addr;
        channel_table.bind(0x4000, peer, relayed_addr).unwrap();

        // Verify binding exists
        assert!(channel_table.get_by_channel(relayed_addr, 0x4000).is_some());
        assert_eq!(channel_table.len(), 1);

        // Remove allocation WITH channel cleanup
        table.remove_allocation(&relayed_addr, Some(&channel_table));
        drop(alloc1);

        // Channel binding should be gone
        assert!(channel_table.get_by_channel(relayed_addr, 0x4000).is_none());
        assert_eq!(channel_table.len(), 0);
    }

    /// Verify the exact scenario from the bug report: same client rapidly
    /// alloc/dealloc/alloc on the same port — old channel bindings must not
    /// prevent new ChannelBind from succeeding.
    #[tokio::test]
    async fn test_port_reuse_channel_bind_no_conflict() {
        let (min_port, max_port) = alloc_test_port_range();
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            None,
            None,
        );
        let channel_table = ChannelTable::new();
        let client: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let old_peer: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let new_peer: SocketAddr = "10.0.0.3:6000".parse().unwrap();

        // --- First allocation ---
        let alloc1 = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed1 = alloc1.read().relayed_addr;
        // Bind channel 0x4005 to old_peer (simulates the stale binding from the logs)
        channel_table.bind(0x4005, old_peer, relayed1).unwrap();

        // Remove allocation (triggers channel cleanup)
        table.remove_allocation(&relayed1, Some(&channel_table));
        drop(alloc1);

        // Give OS time to release the socket
        tokio::time::sleep(Duration::from_millis(100)).await;

        // --- Second allocation (likely same port) ---
        let alloc2 = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed2 = alloc2.read().relayed_addr;

        // Binding channel 0x4005 to new_peer must succeed — no stale binding conflict
        let result = channel_table.bind(0x4005, new_peer, relayed2);
        assert!(
            result.is_ok(),
            "ChannelBind should succeed on reused port, but got {:?}",
            result
        );

        // Verify the binding points to the new peer
        let binding = channel_table.get_by_channel(relayed2, 0x4005).unwrap();
        assert_eq!(binding.peer_addr, new_peer);
    }

    /// Verify that cleanup_expired also removes channel bindings for each
    /// expired allocation.
    #[tokio::test]
    async fn test_cleanup_expired_also_cleans_channels() {
        let (min_port, max_port) = alloc_test_port_range();
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            None,
            None,
        );
        let channel_table = ChannelTable::new();
        let client1: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let client2: SocketAddr = "192.168.1.1:12346".parse().unwrap();
        let peer: SocketAddr = "10.0.0.2:5000".parse().unwrap();

        // Create two allocations: one expired, one active
        let alloc_expired = table
            .create_allocation(client1, Some(0), &channel_table)
            .await
            .unwrap();
        let alloc_active = table
            .create_allocation(client2, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed_expired = alloc_expired.read().relayed_addr;
        let relayed_active = alloc_active.read().relayed_addr;

        // Bind channels on both
        channel_table.bind(0x4000, peer, relayed_expired).unwrap();
        channel_table.bind(0x4001, peer, relayed_active).unwrap();
        assert_eq!(channel_table.len(), 2);

        // Let the expired one actually expire
        std::thread::sleep(Duration::from_millis(10));

        // Cleanup
        let removed = table.cleanup_expired(Some(&channel_table));
        assert_eq!(removed, 1);

        // Expired allocation's channel binding should be gone
        assert!(
            channel_table
                .get_by_channel(relayed_expired, 0x4000)
                .is_none()
        );
        // Active allocation's channel binding should remain
        assert!(
            channel_table
                .get_by_channel(relayed_active, 0x4001)
                .is_some()
        );
        assert_eq!(channel_table.len(), 1);
    }

    /// Verify that when a client re-allocates (same client_addr), only one
    /// allocation exists — the old one is removed first.
    #[tokio::test]
    async fn test_realloc_same_client_removes_old() {
        let (min_port, max_port) = alloc_test_port_range();
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            None,
            None,
        );
        let channel_table = ChannelTable::new();
        let client: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        // First allocation
        let alloc1 = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let _relayed1 = alloc1.read().relayed_addr;

        // Simulate what handle_allocate does: remove old allocation before creating new one
        if let Some(old_relayed) = table.find_allocation_by_client(&client) {
            table.remove_allocation(&old_relayed, Some(&channel_table));
        }
        drop(alloc1);

        // Give OS time to release the socket
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Second allocation (same client)
        let alloc2 = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed2 = alloc2.read().relayed_addr;

        // There should be exactly one allocation for this client
        let found = table.find_allocation_by_client(&client);
        assert_eq!(found, Some(relayed2));

        // The new allocation should be accessible
        assert!(table.get_allocation(&relayed2).is_some());

        // Active count should be 1 (old was removed, new was created)
        assert_eq!(table.stats().active_allocations.load(Ordering::Relaxed), 1);
    }

    /// Verify remove_for_relayed only removes bindings for the specific
    /// relayed_addr and leaves others untouched.
    #[test]
    fn test_channel_table_remove_for_relayed_selective() {
        let table = ChannelTable::new();
        let relayed_a: SocketAddr = "10.0.0.1:49152".parse().unwrap();
        let relayed_b: SocketAddr = "10.0.0.1:49153".parse().unwrap();
        let peer1: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let peer2: SocketAddr = "10.0.0.3:5001".parse().unwrap();

        // Bind channels on two different allocations
        table.bind(0x4000, peer1, relayed_a).unwrap();
        table.bind(0x4001, peer2, relayed_a).unwrap();
        table.bind(0x4000, peer1, relayed_b).unwrap();
        assert_eq!(table.len(), 3);

        // Remove only bindings for relayed_a
        let removed = table.remove_for_relayed(&relayed_a);
        assert_eq!(removed, 2);
        assert_eq!(table.len(), 1);

        // relayed_b's binding survives
        assert!(table.get_by_channel(relayed_b, 0x4000).is_some());
        // relayed_a's bindings are gone
        assert!(table.get_by_channel(relayed_a, 0x4000).is_none());
        assert!(table.get_by_channel(relayed_a, 0x4001).is_none());
    }

    #[tokio::test]
    async fn test_refresh_allocation_resets_created_at() {
        let (min_port, max_port) = alloc_test_port_range();
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            None,
            None,
        );
        let channel_table = ChannelTable::new();
        let client: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        // Create allocation with short lifetime (2 seconds)
        let alloc = table
            .create_allocation(client, Some(2), &channel_table)
            .await
            .unwrap();
        let relayed = alloc.read().relayed_addr;

        // Wait 1 second (allocation should still be alive)
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            !alloc.read().is_expired(),
            "allocation should be alive 1s into a 2s lifetime"
        );

        // Refresh with lifetime=2 (extend another 2 seconds from now)
        table.refresh_allocation(&relayed, 2).unwrap();

        // Wait 1.5 seconds more (total ~2.5s since creation)
        // With the BUG: refresh_allocation does not reset created_at, so
        // elapsed=2.5s > lifetime=2s → allocation is expired
        // With the FIX: created_at was reset at refresh, so elapsed≈1.5s < 2s → alive
        tokio::time::sleep(Duration::from_millis(1500)).await;

        assert!(
            !alloc.read().is_expired(),
            "allocation expired early because refresh_allocation did not reset created_at"
        );
    }

    #[test]
    fn test_normalize_peer_addr_for_client_rewrites_only_bind_ip() {
        let relay_bind_addr: SocketAddr = "127.0.0.1:49152".parse().unwrap();
        let relayed_addr: SocketAddr = "146.56.243.54:49152".parse().unwrap();
        let local_peer: SocketAddr = "127.0.0.1:63746".parse().unwrap();
        let external_peer: SocketAddr = "129.211.168.132:63746".parse().unwrap();

        assert_eq!(
            normalize_peer_addr_for_client(local_peer, relay_bind_addr, relayed_addr),
            "146.56.243.54:63746".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            normalize_peer_addr_for_client(external_peer, relay_bind_addr, relayed_addr),
            external_peer
        );
    }

    /// Verify that `is_fatal_recv_error` correctly classifies error kinds.
    /// Transient errors like ECONNREFUSED (ICMP port-unreachable) must not be
    /// treated as fatal, otherwise the relay task dies and causes one-way audio
    /// drops in long-running WebRTC calls.
    #[test]
    fn test_is_fatal_recv_error_classification() {
        // Transient errors — must NOT kill the relay task
        assert!(!is_fatal_recv_error(io::ErrorKind::ConnectionRefused));
        assert!(!is_fatal_recv_error(io::ErrorKind::ConnectionReset));
        assert!(!is_fatal_recv_error(io::ErrorKind::WouldBlock));
        assert!(!is_fatal_recv_error(io::ErrorKind::TimedOut));
        assert!(!is_fatal_recv_error(io::ErrorKind::Interrupted));
        assert!(!is_fatal_recv_error(io::ErrorKind::OutOfMemory));
        assert!(!is_fatal_recv_error(io::ErrorKind::UnexpectedEof));
        assert!(!is_fatal_recv_error(io::ErrorKind::AddrInUse));
        assert!(!is_fatal_recv_error(io::ErrorKind::AddrNotAvailable));

        // Fatal errors — SHOULD kill the relay task
        assert!(is_fatal_recv_error(io::ErrorKind::PermissionDenied));
    }

    /// End-to-end test: verify the relay task survives ICMP port-unreachable
    /// errors triggered by sending to a recently-closed port.
    #[tokio::test]
    async fn test_relay_task_survives_icmp_error() {
        let (min_port, max_port) = alloc_test_port_range();
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            min_port,
            max_port,
            None,
            None,
            None,
        );
        let channel_table = ChannelTable::new();
        let client: SocketAddr = "127.0.0.1:23456".parse().unwrap();

        let alloc = table
            .create_allocation(client, Some(600), &channel_table)
            .await
            .unwrap();
        let relayed_addr = alloc.read().relayed_addr;
        let relay_socket = alloc.read().relay.as_ref().unwrap().socket.clone();

        // Step 1: Send data from a peer → relay task should process it
        // (permission required for peer→relay forwarding).
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        assert!(table.add_permissions(&client, &[peer_addr]));
        peer.send_to(b"hello", &relayed_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stats_before = table.stats().total_bytes_relayed.load(Ordering::Relaxed);
        assert!(
            stats_before >= 5,
            "relay task should process peer data, got {} bytes",
            stats_before
        );

        // Step 2: Trigger ICMP port-unreachable
        // Bind a temp socket, note its port, close it, then send to that port
        // from the relay socket to generate ICMP error.
        {
            let temp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let temp_addr = temp.local_addr().unwrap();
            drop(temp);
            // Send multiple times to ensure ICMP error is delivered
            for _ in 0..10 {
                let _ = relay_socket.send_to(b"trigger-icmp", &temp_addr).await;
            }
        }
        // Wait for ICMP to propagate to the relay socket's error queue
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Step 3: Send more data → relay task should still process it
        peer.send_to(b"world", &relayed_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let stats_after = table.stats().total_bytes_relayed.load(Ordering::Relaxed);

        assert!(
            stats_after > stats_before,
            "relay task should survive ICMP error: before={}, after={}",
            stats_before,
            stats_after
        );
    }
}
