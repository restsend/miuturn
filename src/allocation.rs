use crate::errors::Error;
use bytes::Bytes;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

/// Message types for allocation task communication
#[derive(Debug)]
pub enum AllocationMessage {
    /// Data from peer to be relayed to client
    PeerData { data: Bytes, peer_addr: SocketAddr },
    /// Data from client to be relayed to peer (Send Indication)
    ClientData { data: Bytes, peer_addr: SocketAddr },
    /// Channel data from client
    ChannelData { data: Bytes, channel_num: u16 },
    /// Refresh the allocation lifetime
    Refresh { lifetime: u32 },
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
    pub lifetime: Duration,
    pub five_tuple: (SocketAddr, SocketAddr),
    /// Active relay connection (socket + task channel)
    pub relay: Option<AllocationRelay>,
}

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
            lifetime,
            five_tuple: (src, dst),
            relay: None,
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
    ) -> Self {
        Allocation {
            id,
            relayed_addr,
            client_addr,
            created_at: Instant::now(),
            lifetime,
            five_tuple: (src, dst),
            relay: Some(relay),
        }
    }

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
        assert!(port_count <= 16384, "Port range too large");
        // Calculate number of u64s needed: ceil(port_count / 64)
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

    /// Allocate a port, returns None if no ports available
    #[inline]
    pub fn allocate(&self) -> Option<u16> {
        let num_u64s = self.allocated.len();

        // Fast path: try to find a free port using atomic operations
        // Start from a random-ish position to reduce contention
        let start_idx = self.allocated_count.load(Ordering::Relaxed) % num_u64s;

        for bitmap_idx in 0..num_u64s {
            let actual_idx = (start_idx + bitmap_idx) % num_u64s;
            let bitmap = &self.allocated[actual_idx];

            let mut current = bitmap.load(Ordering::Relaxed);

            // Check if this u64 is full (all 1s)
            if current == u64::MAX {
                continue;
            }

            loop {
                // Find first zero bit (free port) in this u64
                let free_mask = !current;
                if free_mask == 0 {
                    break; // This u64 is full, try next
                }

                let free_bit = free_mask.trailing_zeros() as usize;
                let bit_index = free_bit;
                let mask = 1u64 << bit_index;

                // Calculate the actual port index
                let port_index = (actual_idx * 64 + bit_index) as u16;
                if port_index >= self.port_count {
                    break; // Beyond our port range
                }

                // Try to set the bit
                let new_value = current | mask;
                match bitmap.compare_exchange_weak(
                    current,
                    new_value,
                    Ordering::SeqCst,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => {
                        self.allocated_count.fetch_add(1, Ordering::Relaxed);
                        let port = self.min_port + port_index;
                        return Some(port);
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
    allocations: RwLock<HashMap<SocketAddr, Arc<RwLock<Allocation>>>>,
    port_allocator: PortAllocator,
    addr: Ipv4Addr,
    realm: String,
    stats: ServerStats,
    max_concurrent_allocations: Option<usize>,
    max_allocation_duration_secs: Option<u32>,
    _current_bandwidth_bytes_per_sec: AtomicUsize,
    _max_bandwidth_bytes_per_sec: Option<usize>,
}

#[derive(Debug)]
pub struct ServerStats {
    pub total_allocations: AtomicU64,
    pub active_allocations: AtomicU64,
    pub total_bytes_relayed: AtomicU64,
    pub total_messages: AtomicU64,
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

    pub fn with_limits(
        addr: Ipv4Addr,
        realm: String,
        max_concurrent_allocations: Option<usize>,
        max_allocation_duration_secs: Option<u32>,
        max_bandwidth_bytes_per_sec: Option<usize>,
    ) -> Self {
        // Default TURN port range: 49152-65535 (16384 ports)
        AllocationTable {
            allocations: RwLock::new(HashMap::new()),
            port_allocator: PortAllocator::new(49152, 65535),
            addr,
            realm,
            stats: ServerStats::default(),
            max_concurrent_allocations,
            max_allocation_duration_secs,
            _current_bandwidth_bytes_per_sec: AtomicUsize::new(0),
            _max_bandwidth_bytes_per_sec: max_bandwidth_bytes_per_sec,
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
        AllocationTable {
            allocations: RwLock::new(HashMap::new()),
            port_allocator: PortAllocator::new(min_port, max_port),
            addr,
            realm,
            stats: ServerStats::default(),
            max_concurrent_allocations,
            max_allocation_duration_secs,
            _current_bandwidth_bytes_per_sec: AtomicUsize::new(0),
            _max_bandwidth_bytes_per_sec: max_bandwidth_bytes_per_sec,
        }
    }

    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    pub async fn create_allocation(
        &self,
        client_addr: SocketAddr,
        requested_lifetime: Option<u32>,
    ) -> Result<Arc<RwLock<Allocation>>, Error> {
        if let Some(max) = self.max_concurrent_allocations {
            let current = self.stats.active_allocations.load(Ordering::Relaxed) as usize;
            if current >= max {
                return Err(Error::AllocationFailed);
            }
        }

        let mut lifetime_secs = requested_lifetime.unwrap_or(600);
        if let Some(max_lifetime) = self.max_allocation_duration_secs
            && lifetime_secs > max_lifetime {
                lifetime_secs = max_lifetime;
            }
        let lifetime = Duration::from_secs(lifetime_secs as u64);

        // Fast port allocation - O(1)
        // If binding fails, we'll retry with another port
        let mut attempts = 0;
        const MAX_ATTEMPTS: usize = 100;

        let (_port, relay_socket, relayed_addr) = loop {
            if attempts >= MAX_ATTEMPTS {
                return Err(Error::AllocationFailed);
            }

            let port = self
                .port_allocator
                .allocate()
                .ok_or(Error::AllocationFailed)?;

            let relayed_addr = SocketAddr::V4(SocketAddrV4::new(self.addr, port));

            // Create and bind a dedicated UDP socket for this allocation
            match UdpSocket::bind(relayed_addr).await {
                Ok(socket) => {
                    break (port, socket, relayed_addr);
                }
                Err(_) => {
                    // Port binding failed - release and try again
                    self.port_allocator.release(port);
                    attempts += 1;
                    continue;
                }
            }
        };

        let relay_socket = Arc::new(relay_socket);

        let mut id = [0u8; 12];
        getrandom(&mut id);

        // Spawn the per-allocation task
        let relay =
            spawn_allocation_task(relay_socket.clone(), client_addr, relayed_addr, &self.stats)
                .await;

        let allocation = Arc::new(RwLock::new(Allocation::with_relay(
            id,
            relayed_addr,
            client_addr,
            lifetime,
            client_addr,
            relayed_addr,
            relay,
        )));

        let mut allocations = self.allocations.write();
        allocations.insert(relayed_addr, allocation.clone());
        self.stats.total_allocations.fetch_add(1, Ordering::Relaxed);
        self.stats
            .active_allocations
            .fetch_add(1, Ordering::Relaxed);

        Ok(allocation)
    }

    pub fn get_allocation(&self, relayed_addr: &SocketAddr) -> Option<Arc<RwLock<Allocation>>> {
        let allocations = self.allocations.read();
        allocations.get(relayed_addr).cloned()
    }

    pub fn remove_allocation(&self, relayed_addr: &SocketAddr) -> Option<Arc<RwLock<Allocation>>> {
        let mut allocations = self.allocations.write();
        let result = allocations.remove(relayed_addr);
        if let Some(ref alloc) = result {
            // Abort the allocation task to release the socket
            if let Some(ref relay) = alloc.read().relay {
                relay.task_handle.abort();
            }
            // Release port back to allocator
            self.port_allocator.release(relayed_addr.port());
            self.stats
                .active_allocations
                .fetch_sub(1, Ordering::Relaxed);
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
            alloc.lifetime = Duration::from_secs(lifetime as u64);
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    pub fn find_allocation_by_client(&self, client_addr: &SocketAddr) -> Option<SocketAddr> {
        let allocations = self.allocations.read();
        for alloc in allocations.values() {
            let a = alloc.read();
            if a.client_addr == *client_addr {
                return Some(a.relayed_addr);
            }
        }
        None
    }

    pub fn relay_to_peer(
        &self,
        relayed_addr: &SocketAddr,
        data: Bytes,
    ) -> Result<SocketAddr, Error> {
        let allocations = self.allocations.read();
        if let Some(allocation) = allocations.get(relayed_addr) {
            let alloc = allocation.read();
            self.stats
                .total_bytes_relayed
                .fetch_add(data.len() as u64, Ordering::Relaxed);
            self.stats.total_messages.fetch_add(1, Ordering::Relaxed);
            Ok(alloc.client_addr)
        } else {
            Err(Error::NoAllocation)
        }
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

    /// Clean up expired allocations
    pub fn cleanup_expired(&self) -> usize {
        let mut count = 0;
        let mut allocations = self.allocations.write();

        // Find expired allocations
        let expired: Vec<SocketAddr> = allocations
            .iter()
            .filter(|(_, alloc)| alloc.read().is_expired())
            .map(|(addr, _)| *addr)
            .collect();

        for addr in expired {
            if allocations.remove(&addr).is_some() {
                self.port_allocator.release(addr.port());
                count += 1;
            }
        }

        if count > 0 {
            self.stats
                .active_allocations
                .fetch_sub(count as u64, Ordering::Relaxed);
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

/// Spawn a dedicated task for an allocation to handle relay traffic
/// This eliminates lock contention by giving each allocation its own processing loop
async fn spawn_allocation_task(
    socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    _relayed_addr: SocketAddr,
    stats: &ServerStats,
) -> AllocationRelay {
    let (tx, mut rx) = mpsc::channel::<AllocationMessage>(1024);

    let socket_clone = socket.clone();
    let stats_ref = unsafe {
        // SAFETY: ServerStats lives as long as AllocationTable which lives as long as the server
        &*(stats as *const ServerStats)
    };

    let task_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];

        loop {
            tokio::select! {
                // Handle incoming peer data on the relay socket
                result = socket_clone.recv_from(&mut buf) => {
                    match result {
                        Ok((len, _peer_addr)) => {
                            // Update stats using atomics - no lock contention
                            stats_ref.total_bytes_relayed.fetch_add(len as u64, Ordering::Relaxed);
                            stats_ref.total_messages.fetch_add(1, Ordering::Relaxed);

                            // Forward to client as Data Indication
                            // For now, just forward raw data
                            if let Err(_e) = socket_clone.send_to(&buf[..len], &client_addr).await {
                                // Silently drop send errors (client may be unreachable)
                            }
                        }
                        Err(_e) => {
                            // Socket error, likely allocation closed
                            break;
                        }
                    }
                }

                // Handle messages from the main server
                Some(msg) = rx.recv() => {
                    match msg {
                        AllocationMessage::ClientData { data, peer_addr } => {
                            // Forward client data to peer
                            if let Err(_e) = socket_clone.send_to(&data, &peer_addr).await {
                                // Silently drop send errors
                            }
                        }
                        AllocationMessage::ChannelData { data, channel_num: _ } => {
                            // Forward channel data - data already has channel header
                            if let Err(_e) = socket_clone.send_to(&data, &client_addr).await {
                                // Silently drop send errors
                            }
                        }
                        AllocationMessage::Shutdown => {
                            break;
                        }
                        _ => {}
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

pub struct ChannelTable {
    channels: RwLock<HashMap<u16, ChannelBinding>>,
    next_channel: u16,
}

#[derive(Clone)]
pub struct ChannelBinding {
    pub channel_id: u16,
    pub peer_addr: SocketAddr,
    pub relayed_addr: SocketAddr,
    pub created_at: Instant,
    pub lifetime: Duration,
}

impl ChannelTable {
    pub fn new() -> Self {
        ChannelTable {
            channels: RwLock::new(HashMap::new()),
            next_channel: 0x4000,
        }
    }

    pub fn bind(
        &self,
        channel_id: u16,
        peer_addr: SocketAddr,
        relayed_addr: SocketAddr,
    ) -> Result<(), Error> {
        let mut channels = self.channels.write();
        if channels.contains_key(&channel_id) {
            return Err(Error::AlreadyExists);
        }
        channels.insert(
            channel_id,
            ChannelBinding {
                channel_id,
                peer_addr,
                relayed_addr,
                created_at: Instant::now(),
                lifetime: Duration::from_secs(600),
            },
        );
        Ok(())
    }

    pub fn get_by_channel(&self, channel_id: u16) -> Option<ChannelBinding> {
        let channels = self.channels.read();
        channels.get(&channel_id).cloned()
    }

    pub fn get_by_peer(&self, peer_addr: &SocketAddr) -> Option<u16> {
        let channels = self.channels.read();
        for (id, ch) in channels.iter() {
            if ch.peer_addr == *peer_addr {
                return Some(*id);
            }
        }
        None
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

    pub fn unbind(&self, channel_id: u16) -> Option<ChannelBinding> {
        let mut channels = self.channels.write();
        channels.remove(&channel_id)
    }

    pub fn next_id(&mut self) -> u16 {
        let id = self.next_channel;
        self.next_channel = self.next_channel.wrapping_add(1);
        if self.next_channel == 0 {
            self.next_channel = 0x4000;
        }
        id
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
        // Use unique port range to avoid conflicts with concurrent tests
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            50000,
            51000,
            None,
            None,
            None,
        );
        let client: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let alloc = table.create_allocation(client, Some(600)).await.unwrap();
        assert!(!alloc.read().is_expired());
    }

    #[tokio::test]
    async fn test_allocation_expired() {
        // Use unique port range to avoid conflicts with concurrent tests
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            53001,
            54000,
            None,
            None,
            None,
        );
        let client: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let alloc = table.create_allocation(client, Some(0)).await.unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert!(alloc.read().is_expired());
    }

    #[test]
    fn test_channel_binding() {
        let table = ChannelTable::new();
        let client: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let relayed: SocketAddr = "10.0.0.1:49152".parse().unwrap();
        table.bind(0x4000, client, relayed).unwrap();
        let ch = table.get_by_channel(0x4000).unwrap();
        assert_eq!(ch.peer_addr, client);
    }

    #[tokio::test]
    async fn test_max_concurrent_allocations_limit() {
        // Use unique port range to avoid conflicts with concurrent tests
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            51001,
            52000,
            Some(2),
            None,
            None,
        );
        let client1: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let client2: SocketAddr = "192.168.1.2:12345".parse().unwrap();
        let client3: SocketAddr = "192.168.1.3:12345".parse().unwrap();

        let _ = table.create_allocation(client1, Some(600)).await.unwrap();
        let _ = table.create_allocation(client2, Some(600)).await.unwrap();

        let result = table.create_allocation(client3, Some(600)).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), Error::AllocationFailed));
    }

    #[tokio::test]
    async fn test_port_reuse_after_removal() {
        // Use unique port range to avoid conflicts with concurrent tests
        let table = AllocationTable::with_port_range(
            Ipv4Addr::new(127, 0, 0, 1),
            "test".to_string(),
            52001,
            53000,
            None,
            None,
            None,
        );
        let client1: SocketAddr = "192.168.1.1:12345".parse().unwrap();

        let alloc1 = table.create_allocation(client1, Some(600)).await.unwrap();
        let port1 = alloc1.read().relayed_addr.port();

        // Verify port is allocated
        assert!(table.port_allocator.is_allocated(port1));

        // Remove allocation and drop the reference so socket is released
        let relayed_addr = alloc1.read().relayed_addr;
        table.remove_allocation(&relayed_addr);
        drop(alloc1);

        // Port should be released in the allocator bitmap
        // (actual OS port may still be in TIME_WAIT state)
        assert!(!table.port_allocator.is_allocated(port1));

        // Verify allocator counts are correct
        let (allocated, available) = table.port_stats();
        assert_eq!(allocated, 0);
        assert!(available > 0);
    }
}
