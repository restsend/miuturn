use crate::allocation::{AllocationTable, ChannelTable, ServerStatsSnapshot};
use crate::auth::AuthManager;
use crate::message::{
    Attribute, ErrorCode, EventType, Message, MessageHeader, Method, encode_xor_address,
};
use bytes::{Buf, Bytes, BytesMut};
use hmac::{Hmac, KeyInit, Mac};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::RwLock as TokioRwLock;
use tracing::{debug, error, info, trace, warn};

type HmacSha1 = Hmac<sha1::Sha1>;

/// Format bytes into human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format bytes and rate for stats output
fn format_bytes_and_rate(total: u64, delta: u64, interval_secs: u64) -> (String, String) {
    let total_str = format_bytes(total);
    let rate = if interval_secs > 0 {
        delta / interval_secs
    } else {
        0
    };
    let rate_str = format!("{}/s", format_bytes(rate));
    (total_str, rate_str)
}

/// Format messages and rate for stats output
fn format_messages_and_rate(total: u64, delta: u64, interval_secs: u64) -> (String, String) {
    let total_str = format!("{}", total);
    let rate = if interval_secs > 0 {
        delta / interval_secs
    } else {
        0
    };
    let rate_str = format!("{}", rate);
    (total_str, rate_str)
}

#[derive(Clone)]
pub struct TurnServer {
    pub allocation_table: Arc<AllocationTable>,
    pub channel_table: Arc<TokioRwLock<ChannelTable>>,
    pub relay_addr: Ipv4Addr,
    pub relay_bind_addr: Ipv4Addr,
    pub realm: String,
    nonce_map: Arc<RwLock<HashMap<String, NonceEntry>>>,
    password: String,
    auth_disabled: bool,
    auth_manager: Option<Arc<AuthManager>>,
    stats_dump_interval_secs: u64,
    stats_dump_skip_if_no_change: bool,
    server_name: String,
}

struct NonceEntry {
    _nonce: String,
    created_at: std::time::Instant,
}

impl TurnServer {
    pub fn new(relay_addr: Ipv4Addr, realm: String) -> Self {
        Self::with_limits_and_password(
            relay_addr,
            realm,
            None,
            None,
            None,
            "password".to_string(),
            false,
        )
    }

    pub fn set_stats_dump_interval(&mut self, interval_secs: u64) {
        self.stats_dump_interval_secs = interval_secs;
    }

    pub fn set_stats_dump_skip_if_no_change(&mut self, skip: bool) {
        self.stats_dump_skip_if_no_change = skip;
    }

    pub fn set_server_name(&mut self, server_name: String) {
        self.server_name = server_name;
    }

    pub fn with_password(relay_addr: Ipv4Addr, realm: String, password: String) -> Self {
        Self::with_limits_and_password(relay_addr, realm, None, None, None, password, false)
    }

    pub fn with_auth_disabled(relay_addr: Ipv4Addr, realm: String) -> Self {
        Self::with_limits_and_password(relay_addr, realm, None, None, None, String::new(), true)
    }

    pub fn with_port_range_and_password(
        relay_addr: Ipv4Addr,
        realm: String,
        min_port: u16,
        max_port: u16,
        password: String,
    ) -> Self {
        Self::with_port_range_and_bind_address_and_password(
            relay_addr, relay_addr, realm, min_port, max_port, password,
        )
    }

    pub fn with_port_range_and_bind_address_and_password(
        relay_addr: Ipv4Addr,
        relay_bind_addr: Ipv4Addr,
        realm: String,
        min_port: u16,
        max_port: u16,
        password: String,
    ) -> Self {
        let server = TurnServer {
            allocation_table: Arc::new(AllocationTable::with_port_range_and_bind_addr(
                relay_addr,
                relay_bind_addr,
                realm.clone(),
                min_port,
                max_port,
                None,
                None,
                None,
            )),
            channel_table: Arc::new(TokioRwLock::new(ChannelTable::new())),
            relay_addr,
            relay_bind_addr,
            realm,
            nonce_map: Arc::new(RwLock::new(HashMap::new())),
            password,
            auth_disabled: false,
            auth_manager: None,
            stats_dump_interval_secs: 30,
            stats_dump_skip_if_no_change: true,
            server_name: format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        };
        server.start_nonce_cleanup_task();
        server.start_channel_cleanup_task();
        server.start_allocation_cleanup_task();
        server
    }

    pub fn with_port_range_limits_and_password(
        relay_addr: Ipv4Addr,
        realm: String,
        min_port: u16,
        max_port: u16,
        max_concurrent_allocations: Option<usize>,
        max_allocation_duration_secs: Option<u32>,
        max_bandwidth_bytes_per_sec: Option<usize>,
        password: String,
        auth_disabled: bool,
    ) -> Self {
        Self::with_port_range_limits_bind_address_and_password(
            relay_addr,
            relay_addr,
            realm,
            min_port,
            max_port,
            max_concurrent_allocations,
            max_allocation_duration_secs,
            max_bandwidth_bytes_per_sec,
            password,
            auth_disabled,
        )
    }

    pub fn with_port_range_limits_bind_address_and_password(
        relay_addr: Ipv4Addr,
        relay_bind_addr: Ipv4Addr,
        realm: String,
        min_port: u16,
        max_port: u16,
        max_concurrent_allocations: Option<usize>,
        max_allocation_duration_secs: Option<u32>,
        max_bandwidth_bytes_per_sec: Option<usize>,
        password: String,
        auth_disabled: bool,
    ) -> Self {
        let server = TurnServer {
            allocation_table: Arc::new(AllocationTable::with_port_range_and_bind_addr(
                relay_addr,
                relay_bind_addr,
                realm.clone(),
                min_port,
                max_port,
                max_concurrent_allocations,
                max_allocation_duration_secs,
                max_bandwidth_bytes_per_sec,
            )),
            channel_table: Arc::new(TokioRwLock::new(ChannelTable::new())),
            relay_addr,
            relay_bind_addr,
            realm,
            nonce_map: Arc::new(RwLock::new(HashMap::new())),
            password,
            auth_disabled,
            auth_manager: None,
            stats_dump_interval_secs: 30,
            stats_dump_skip_if_no_change: true,
            server_name: format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        };
        server.start_nonce_cleanup_task();
        server.start_channel_cleanup_task();
        server.start_allocation_cleanup_task();
        server
    }

    pub fn with_port_range_auth_disabled(
        relay_addr: Ipv4Addr,
        realm: String,
        min_port: u16,
        max_port: u16,
    ) -> Self {
        let server = TurnServer {
            allocation_table: Arc::new(AllocationTable::with_port_range(
                relay_addr,
                realm.clone(),
                min_port,
                max_port,
                None,
                None,
                None,
            )),
            channel_table: Arc::new(TokioRwLock::new(ChannelTable::new())),
            relay_addr,
            relay_bind_addr: relay_addr,
            realm,
            nonce_map: Arc::new(RwLock::new(HashMap::new())),
            password: String::new(),
            auth_disabled: true,
            auth_manager: None,
            stats_dump_interval_secs: 30,
            stats_dump_skip_if_no_change: true,
            server_name: format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        };
        server.start_nonce_cleanup_task();
        server.start_channel_cleanup_task();
        server.start_allocation_cleanup_task();
        server
    }

    pub fn with_limits(
        relay_addr: Ipv4Addr,
        realm: String,
        max_concurrent_allocations: Option<usize>,
        max_allocation_duration_secs: Option<u32>,
        max_bandwidth_bytes_per_sec: Option<usize>,
    ) -> Self {
        Self::with_limits_and_password(
            relay_addr,
            realm,
            max_concurrent_allocations,
            max_allocation_duration_secs,
            max_bandwidth_bytes_per_sec,
            "password".to_string(),
            false,
        )
    }

    pub fn with_limits_and_password(
        relay_addr: Ipv4Addr,
        realm: String,
        max_concurrent_allocations: Option<usize>,
        max_allocation_duration_secs: Option<u32>,
        max_bandwidth_bytes_per_sec: Option<usize>,
        password: String,
        auth_disabled: bool,
    ) -> Self {
        let server = TurnServer {
            allocation_table: Arc::new(AllocationTable::with_limits(
                relay_addr,
                realm.clone(),
                max_concurrent_allocations,
                max_allocation_duration_secs,
                max_bandwidth_bytes_per_sec,
            )),
            channel_table: Arc::new(TokioRwLock::new(ChannelTable::new())),
            relay_addr,
            relay_bind_addr: relay_addr,
            realm,
            nonce_map: Arc::new(RwLock::new(HashMap::new())),
            password,
            auth_disabled,
            auth_manager: None,
            stats_dump_interval_secs: 30,
            stats_dump_skip_if_no_change: true,
            server_name: format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        };
        server.start_nonce_cleanup_task();
        server.start_channel_cleanup_task();
        server.start_allocation_cleanup_task();
        server
    }

    /// Set the auth manager for per-user password lookup
    pub fn set_auth_manager(&mut self, auth_manager: Arc<AuthManager>) {
        self.auth_manager = Some(auth_manager);
    }

    /// Look up password for a given username.
    /// First tries auth_manager, then falls back to the global password.
    fn get_password_for_user(&self, username: &str) -> Option<String> {
        if let Some(ref am) = self.auth_manager {
            if let Some(pw) = am.get_user_password(username) {
                return Some(pw);
            }
        }
        // Fallback to global password if non-empty
        if !self.password.is_empty() {
            Some(self.password.clone())
        } else {
            None
        }
    }

    pub fn stats(&self) -> ServerStatsSnapshot {
        self.allocation_table.stats().snapshot()
    }

    /// Start a background task to periodically dump statistics
    pub fn start_stats_dump_task(&self, interval_secs: u64, skip_if_no_change: bool) {
        if interval_secs == 0 {
            return;
        }

        let stats = self.allocation_table.stats();

        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
            let mut prev_bytes = 0u64;
            let mut prev_messages = 0u64;
            let mut prev_active = 0u64;
            let mut prev_total = 0u64;

            loop {
                interval.tick().await;

                let current_bytes = stats
                    .total_bytes_relayed
                    .load(std::sync::atomic::Ordering::Relaxed);
                let current_messages = stats
                    .total_messages
                    .load(std::sync::atomic::Ordering::Relaxed);
                let active = stats
                    .active_allocations
                    .load(std::sync::atomic::Ordering::Relaxed) as u64;
                let total = stats
                    .total_allocations
                    .load(std::sync::atomic::Ordering::Relaxed) as u64;

                let has_change = if skip_if_no_change {
                    current_bytes != prev_bytes
                        || current_messages != prev_messages
                        || active != prev_active
                        || total != prev_total
                } else {
                    true
                };

                if has_change {
                    let bytes_delta = current_bytes.saturating_sub(prev_bytes);
                    let messages_delta = current_messages.saturating_sub(prev_messages);

                    // Format bytes
                    let (bytes_str, bytes_rate_str) =
                        format_bytes_and_rate(current_bytes, bytes_delta, interval_secs);
                    let (msg_str, msg_rate_str) =
                        format_messages_and_rate(current_messages, messages_delta, interval_secs);

                    tracing::info!(
                        "[STATS] Active: {} | Total: {} | Bytes: {} (+{}/s) | Messages: {} (+{}/s)",
                        active,
                        total,
                        bytes_str,
                        bytes_rate_str,
                        msg_str,
                        msg_rate_str
                    );
                }

                prev_bytes = current_bytes;
                prev_messages = current_messages;
                prev_active = active;
                prev_total = total;
            }
        });
    }

    /// Start a background task to clean up expired allocations
    pub fn start_allocation_cleanup_task(&self) {
        let allocation_table = self.allocation_table.clone();
        const CLEANUP_INTERVAL_SECONDS: u64 = 30;

        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECONDS));
            loop {
                interval.tick().await;
                let removed_count = allocation_table.cleanup_expired();
                if removed_count > 0 {
                    let (active_count, total_allocations) = allocation_table.port_stats();
                    tracing::info!(
                        active_count,
                        total_allocations,
                        removed_count,
                        "Cleaned up expired allocations"
                    );
                }
            }
        });
    }

    /// Start a background task to clean up expired nonces
    pub fn start_nonce_cleanup_task(&self) {
        let nonce_map = self.nonce_map.clone();
        const NONCE_EXPIRY_SECONDS: u64 = 600;
        const CLEANUP_INTERVAL_SECONDS: u64 = 30;

        // Check if we're running in a Tokio runtime context
        if tokio::runtime::Handle::try_current().is_err() {
            // Not in a runtime context, skip spawning (will be called again from run methods)
            return;
        }

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECONDS));
            loop {
                interval.tick().await;

                let now = std::time::Instant::now();
                let mut nonce_map = nonce_map.write();
                let initial_count = nonce_map.len();
                nonce_map.retain(|_, entry| {
                    now.duration_since(entry.created_at).as_secs() < NONCE_EXPIRY_SECONDS
                });
                let removed_count = initial_count.saturating_sub(nonce_map.len());
                drop(nonce_map);

                if removed_count > 0 {
                    tracing::debug!("Cleaned up {} expired nonces", removed_count);
                }
            }
        });
    }

    /// Start a background task to clean up expired channel bindings
    pub fn start_channel_cleanup_task(&self) {
        let channel_table = self.channel_table.clone();
        const CLEANUP_INTERVAL_SECONDS: u64 = 60; // Check every minute

        // Check if we're running in a Tokio runtime context
        if tokio::runtime::Handle::try_current().is_err() {
            // Not in a runtime context, skip spawning (will be called again from run methods)
            return;
        }

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECONDS));
            loop {
                interval.tick().await;

                let channel_table = channel_table.read().await;
                let removed_count = channel_table.cleanup_expired();
                drop(channel_table);

                if removed_count > 0 {
                    tracing::info!("Cleaned up {} expired channel bindings", removed_count);
                }
            }
        });
    }

    pub async fn run_tcp(
        &self,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(addr).await?;
        info!("TURN TCP server listening on {}", addr);
        loop {
            let (mut socket, peer_addr) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                const MAX_TCP_BUFFER_SIZE: usize = 10 * 1024 * 1024; // 10MB limit
                let mut buf = BytesMut::with_capacity(65536);
                loop {
                    buf.reserve(1024);

                    // Check buffer size limit to prevent memory exhaustion
                    if buf.capacity() > MAX_TCP_BUFFER_SIZE {
                        error!("TCP buffer exceeded maximum size from {}", peer_addr);
                        break;
                    }

                    match socket.read_buf(&mut buf).await {
                        Ok(0) => break,
                        Ok(_n) => {
                            let data = buf.split().freeze();
                            if let Some(response) =
                                handle_tcp_message(&data, &server, peer_addr).await
                                && socket.write_all(&response).await.is_err()
                            {
                                break;
                            }
                            if buf.is_empty() {
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Read error: {}", e);
                            break;
                        }
                    }
                }
            });
        }
    }

    pub async fn run_udp(
        &self,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Start cleanup tasks now that we're in an async runtime context
        self.start_nonce_cleanup_task();
        self.start_channel_cleanup_task();
        self.start_allocation_cleanup_task();
        self.start_stats_dump_task(
            self.stats_dump_interval_secs,
            self.stats_dump_skip_if_no_change,
        );

        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!("TURN UDP server listening on {}", addr);

        // Set main socket for Data Indication NAT traversal
        self.allocation_table.set_main_socket(socket.clone());

        // Optimized worker pool with round-robin message distribution
        let num_workers = num_cpus::get().max(4);
        info!("Starting {} UDP worker tasks", num_workers);

        // Create mpsc channels for each worker instead of broadcast
        let mut senders: Vec<tokio::sync::mpsc::Sender<(Bytes, SocketAddr)>> =
            Vec::with_capacity(num_workers);

        // Spawn worker tasks - each with its own channel
        for _i in 0..num_workers {
            let server = self.clone();
            let socket = socket.clone();
            let (tx, mut rx) = tokio::sync::mpsc::channel::<(Bytes, SocketAddr)>(1024);
            senders.push(tx);

            tokio::spawn(async move {
                // Each worker processes only messages sent to its channel
                while let Some((data, peer_addr)) = rx.recv().await {
                    if let Some(response) =
                        handle_udp_message(&socket, data, peer_addr, &server).await
                        && let Err(e) = socket.send_to(&response, &peer_addr).await
                    {
                        error!("UDP send error: {}", e);
                    }
                }
            });
        }

        // Main loop - receives datagrams and distributes round-robin to workers
        let socket_clone = socket.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut worker_idx: usize = 0;

            loop {
                let (len, peer_addr) = match socket_clone.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(e) => {
                        error!("UDP recv error: {}", e);
                        continue;
                    }
                };

                let data = Bytes::copy_from_slice(&buf[..len]);

                // Round-robin distribution: each message goes to exactly one worker
                if senders[worker_idx].try_send((data, peer_addr)).is_err() {
                    error!("Worker {} queue full, dropping message", worker_idx);
                }

                worker_idx = (worker_idx + 1) % num_workers;
            }
        });

        Ok(())
    }
}

async fn handle_tcp_message(
    data: &Bytes,
    server: &TurnServer,
    peer_addr: SocketAddr,
) -> Option<Bytes> {
    if let Some(msg) = Message::parse(&data[..]) {
        let response = process_message(msg, server, peer_addr).await;
        if let Some(r) = response {
            return Some(r);
        }
    }
    None
}

async fn handle_udp_message(
    _socket: &Arc<UdpSocket>,
    data: Bytes,
    peer_addr: SocketAddr,
    server: &TurnServer,
) -> Option<Bytes> {
    if data.len() < 4 {
        return None;
    }
    let channel_num = (data[0] as u16) << 8 | (data[1] as u16);
    if (0x4000..=0x7FFF).contains(&channel_num) {
        let data_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        let payload_end = 4 + data_len.min(data.len().saturating_sub(4));
        let payload = data.slice(4..payload_end);

        let allocation = server.allocation_table.get_allocation_by_client(&peer_addr);
        let has_allocation = allocation.is_some();
        let relayed_addr = allocation.as_ref().map(|alloc| alloc.read().relayed_addr);
        let channel_binding = if let Some(relayed_addr) = relayed_addr {
            server
                .channel_table
                .read()
                .await
                .get_by_channel(relayed_addr, channel_num)
        } else {
            None
        };

        if let Some(channel) = channel_binding {
            // Get the relay socket from the allocation (must release lock before await)
            let relay_socket = allocation.and_then(|alloc| {
                let a = alloc.read();
                a.relay.as_ref().map(|r| r.socket.clone())
            });

            if let Some(relay_sock) = relay_socket {
                let _ = relay_sock.send_to(&payload, &channel.peer_addr).await;
            }
        } else {
            tracing::debug!(
                "ChannelData dropped: has_alloc={} binding={}",
                has_allocation,
                channel_binding.is_some()
            );
        }
        return None;
    }

    // Try to parse as STUN message
    if let Some(msg) = Message::parse(&data[..]) {
        let response = process_message(msg, server, peer_addr).await;
        return response;
    }

    // If parsing fails, check if it might be a TURN message with non-standard header
    // The turn crate may send messages where first 2 bytes are the method
    if data.len() >= 20 {
        let method_bytes = (data[0] as u16) << 8 | (data[1] as u16);
        let len_bytes = (data[2] as u16) << 8 | (data[3] as u16);
        if len_bytes > 0
            && len_bytes < 1500
            && data[4] == 0x21
            && data[5] == 0x12
            && data[6] == 0xa4
            && data[7] == 0x42
        {
            let mut transaction_id = [0u8; 12];
            transaction_id.copy_from_slice(&data[8..20]);

            let method = match method_bytes {
                0x0001 => crate::message::Method::Binding,
                0x0003 => crate::message::Method::Allocate,
                0x0004 => crate::message::Method::Refresh,
                0x0006 => crate::message::Method::Send,
                0x0007 => crate::message::Method::Data,
                0x0009 => crate::message::Method::ChannelBind,
                _ => return None,
            };

            let header = MessageHeader {
                method,
                event_type: crate::message::EventType::Request,
                message_length: len_bytes,
                magic_cookie: 0x2112A442,
                transaction_id,
            };

            let mut offset = 20;
            let mut attributes = Vec::new();
            let end = 20 + len_bytes as usize;
            while offset < end && offset + 4 <= data.len() {
                let attr_type = (data[offset] as u16) << 8 | (data[offset + 1] as u16);
                let attr_len = (data[offset + 2] as u16) << 8 | (data[offset + 3] as u16);
                if offset + 4 + attr_len as usize <= data.len() {
                    let value =
                        Bytes::copy_from_slice(&data[offset + 4..offset + 4 + attr_len as usize]);
                    attributes.push(Attribute { attr_type, value });
                    let padding = (4 - ((attr_len + 4) % 4)) % 4;
                    offset += 4 + attr_len as usize + padding as usize;
                } else {
                    break;
                }
            }

            let msg = Message { header, attributes };
            return process_message(msg, server, peer_addr).await;
        }
    }

    None
}

async fn process_message(
    msg: Message,
    server: &TurnServer,
    client_addr: SocketAddr,
) -> Option<Bytes> {
    match msg.header.method {
        Method::Binding => handle_binding(msg, client_addr).await,
        Method::Allocate => handle_allocate(msg, server, client_addr).await,
        Method::Refresh => handle_refresh(msg, server, client_addr).await,
        Method::CreatePermission => handle_create_permission(msg, server, client_addr).await,
        Method::ChannelBind => handle_channel_bind(msg, server, client_addr).await,
        Method::Send => handle_send(msg, server, client_addr).await,
        _ => None,
    }
}

async fn handle_binding(msg: Message, client_addr: SocketAddr) -> Option<Bytes> {
    // Use fast path for STUN binding response
    Some(crate::message::create_binding_response_fast(
        msg.header.transaction_id,
        client_addr,
    ))
}

fn generate_nonce() -> String {
    use rand::Rng;
    let mut hash: [u8; 16] = [0; 16];
    rand::rng().fill_bytes(&mut hash);
    hex::encode(hash)
}

fn compute_message_integrity_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let key_input = format!("{}:{}:{}", username, realm, password);
    md5::compute(key_input.as_bytes()).to_vec()
}

fn verify_message_integrity(msg: &Message, key: &[u8]) -> bool {
    let integrity_attr = match msg.get_attribute(Attribute::MESSAGE_INTEGRITY) {
        Some(a) => a,
        None => return false,
    };

    // Per RFC 5389 and stun crate implementation:
    // HMAC is computed over: STUN header (with message_length including MI)
    // + all attributes BEFORE MESSAGE-INTEGRITY.
    // The MI attribute bytes themselves are NOT included.
    let mut partial_msg = Message {
        header: msg.header.clone(),
        attributes: Vec::new(),
    };

    for attr in &msg.attributes {
        if attr.attr_type == Attribute::MESSAGE_INTEGRITY {
            break;
        }
        partial_msg.attributes.push(attr.clone());
    }

    // Manually encode with adjusted message_length = attrs_before_MI + 24 (MI size)
    let mut attr_buf = BytesMut::new();
    for attr in &partial_msg.attributes {
        attr.encode(&mut attr_buf);
    }
    let mut header = partial_msg.header.clone();
    header.message_length = (attr_buf.len() + 24) as u16; // include MI: 4 header + 20 value
    header.magic_cookie = 0x2112A442;
    let mut buf = BytesMut::new();
    header.encode(&mut buf);
    buf.extend_from_slice(&attr_buf.freeze());

    let mut mac = HmacSha1::new_from_slice(key).ok().unwrap();
    mac.update(&buf);
    let computed = mac.finalize().into_bytes();
    computed[..20] == integrity_attr.value[..20]
}

fn add_response_message_integrity(response: &mut Message, key: &[u8]) {
    let mut attr_buf = BytesMut::new();
    for attr in &response.attributes {
        attr.encode(&mut attr_buf);
    }

    // MESSAGE-INTEGRITY is 24 bytes total on wire (type+len+20-byte HMAC value).
    let mut header = response.header.clone();
    header.message_length = (attr_buf.len() + 24) as u16;
    header.magic_cookie = 0x2112A442;

    let mut buf = BytesMut::new();
    header.encode(&mut buf);
    buf.extend_from_slice(&attr_buf.freeze());

    let mut mac = HmacSha1::new_from_slice(key).ok().unwrap();
    mac.update(&buf);
    let computed = mac.finalize().into_bytes();

    response.attributes.push(Attribute {
        attr_type: Attribute::MESSAGE_INTEGRITY,
        value: Bytes::copy_from_slice(&computed[..20]),
    });
}

/// Verify TURN long-term credential auth (nonce + username + MESSAGE-INTEGRITY).
/// Returns Ok(username) on success, or a 401 response bytes on failure.
fn verify_turn_auth(
    msg: &Message,
    server: &TurnServer,
    client_addr: SocketAddr,
) -> Result<String, Bytes> {
    if server.auth_disabled {
        // Return username from attribute if present, or empty string
        if let Some(username_attr) = msg.get_attribute(Attribute::USERNAME) {
            return Ok(String::from_utf8_lossy(&username_attr.value).to_string());
        }
        return Ok(String::new());
    }

    if let Some(ref am) = server.auth_manager {
        let client_ip = client_addr.ip().to_string();
        if !am.check_acl(&client_ip) {
            return Err(create_error_response_bytes(msg, ErrorCode::Forbidden, server));
        }
    }

    let nonce_attr = msg.get_attribute(Attribute::NONCE);
    let username_attr = msg.get_attribute(Attribute::USERNAME);

    if nonce_attr.is_none() || username_attr.is_none() {
        debug!(
            %client_addr,
            method = ?msg.header.method,
            "Returning 401: missing nonce or username attribute"
        );
        return Err(create_401_response(msg, server, client_addr, None));
    }

    let nonce = String::from_utf8_lossy(&nonce_attr.unwrap().value).to_string();
    let username = String::from_utf8_lossy(&username_attr.unwrap().value).to_string();

    // Validate nonce exists and hasn't expired
    let nonce_map = server.nonce_map.read();
    if !nonce_map.contains_key(&nonce) {
        drop(nonce_map);
        debug!(
            %client_addr,
            method = ?msg.header.method,
            %username,
            %nonce,
            "Returning 401: invalid nonce"
        );
        return Err(create_401_response(
            msg,
            server,
            client_addr,
            Some("Invalid nonce".to_string()),
        ));
    }
    let nonce_entry = nonce_map.get(&nonce).unwrap();
    let nonce_age = nonce_entry.created_at.elapsed();
    drop(nonce_map);

    // Nonce expires after 600 seconds
    if nonce_age.as_secs() > 600 {
        debug!(
            %client_addr,
            method = ?msg.header.method,
            %username,
            %nonce,
            nonce_age_secs = nonce_age.as_secs(),
            "Returning 401: nonce expired"
        );
        return Err(create_401_response(
            msg,
            server,
            client_addr,
            Some("Nonce expired".to_string()),
        ));
    }

    // Look up password for this user (from AuthManager or global password)
    let password = match server.get_password_for_user(&username) {
        Some(pw) => pw,
        None => {
            debug!(
                %client_addr,
                method = ?msg.header.method,
                %username,
                "Returning 401: unknown user or credentials expired"
            );
            return Err(create_401_response(
                msg,
                server,
                client_addr,
                Some("Unknown user".to_string()),
            ));
        }
    };

    let key = compute_message_integrity_key(&username, &server.realm, &password);

    if !verify_message_integrity(msg, &key) {
        debug!(
            %client_addr,
            method = ?msg.header.method,
            %username,
            "Returning 401: message integrity verification failed"
        );
        return Err(create_401_response(
            msg,
            server,
            client_addr,
            Some("Bad integrity".to_string()),
        ));
    }

    // Do NOT remove the nonce after successful auth.
    // The turn crate client reuses the same nonce for CreatePermission, ChannelBind, etc.
    // Nonce will expire naturally after 600 seconds via the cleanup task.

    Ok(username)
}

async fn handle_allocate(
    msg: Message,
    server: &TurnServer,
    client_addr: SocketAddr,
) -> Option<Bytes> {
    // Verify auth
    let username = match verify_turn_auth(&msg, server, client_addr) {
        Ok(username) => username,
        Err(resp) => return Some(resp),
    };

    let lifetime = get_lifetime(&msg);
    trace!(
        %client_addr,
        %username,
        lifetime,
        "received TURN Allocate request"
    );

    let ch_table = server.channel_table.read().await.clone();
    let allocation = match server
        .allocation_table
        .create_allocation(client_addr, Some(lifetime), &ch_table)
        .await
    {
        Ok(a) => a,
        Err(err) => {
            let (code, reason) = match &err {
                crate::errors::Error::AllocationQuotaReached => (
                    ErrorCode::AllocationQuotaReached,
                    "server allocation quota reached".to_string(),
                ),
                crate::errors::Error::RelayPortExhausted
                | crate::errors::Error::RelayBindFailed { .. } => {
                    (ErrorCode::InsufficientCapacity, err.to_string())
                }
                _ => (ErrorCode::ServerError, err.to_string()),
            };

            warn!(
                %client_addr,
                %username,
                lifetime,
                error = %err,
                reason = %reason,
                ?code,
                "TURN Allocate request failed"
            );

            return Some(create_error_response_bytes_with_reason(&msg, code, &reason, server));
        }
    };

    let relayed_addr = allocation.read().relayed_addr;
    let magic = 0x2112A442;

    let mut response = Message {
        header: MessageHeader {
            method: msg.header.method,
            event_type: EventType::Success,
            message_length: 0,
            magic_cookie: magic,
            transaction_id: msg.header.transaction_id,
        },
        attributes: Vec::new(),
    };

    response.attributes.push(Attribute {
        attr_type: Attribute::XOR_RELAYED_ADDRESS,
        value: encode_xor_address(relayed_addr, magic, &msg.header.transaction_id),
    });
    response.attributes.push(Attribute {
        attr_type: Attribute::XOR_MAPPED_ADDRESS,
        value: encode_xor_address(client_addr, magic, &msg.header.transaction_id),
    });
    response.attributes.push(Attribute {
        attr_type: Attribute::LIFETIME,
        value: Bytes::from(lifetime.to_be_bytes().to_vec()),
    });
    response.attributes.push(Attribute {
        attr_type: Attribute::REALM,
        value: Bytes::from(server.realm.as_bytes().to_vec()),
    });
    response.attributes.push(Attribute {
        attr_type: Attribute::SOFTWARE,
        value: Bytes::from(server.server_name.as_bytes().to_vec()),
    });

    if !server.auth_disabled {
        if let Some(password) = server.get_password_for_user(&username) {
            let key = compute_message_integrity_key(&username, &server.realm, &password);
            add_response_message_integrity(&mut response, &key);
        } else {
            warn!(
                %client_addr,
                %username,
                "could not add MESSAGE-INTEGRITY to Allocate success response because user password was unavailable"
            );
        }
    }

    info!(
        %client_addr,
        %username,
        relayed_addr = %relayed_addr,
        lifetime,
        "TURN Allocate request succeeded"
    );

    Some(response.encode())
}

async fn handle_refresh(
    msg: Message,
    server: &TurnServer,
    client_addr: SocketAddr,
) -> Option<Bytes> {
    // Verify auth
    let username = match verify_turn_auth(&msg, server, client_addr) {
        Ok(u) => u,
        Err(resp) => return Some(resp),
    };

    let lifetime = get_lifetime(&msg);
    if let Some(relayed) = server
        .allocation_table
        .find_allocation_by_client(&client_addr)
    {
        if server
            .allocation_table
            .refresh_allocation(&relayed, lifetime)
            .is_err()
        {
            return Some(create_error_response_bytes(
                &msg,
                ErrorCode::AllocationMismatch,
                server,
            ));
        }
        tracing::info!(
            %client_addr,
            relayed = %relayed,
            lifetime,
            "TURN Refresh succeeded"
        );
        // Return Refresh Success with LIFETIME
        let mut response = crate::message::create_success_response(&msg.header);
        response.attributes.push(Attribute {
            attr_type: Attribute::LIFETIME,
            value: Bytes::from(lifetime.to_be_bytes().to_vec()),
        });
        if !server.auth_disabled {
            if let Some(password) = server.get_password_for_user(&username) {
                let key = compute_message_integrity_key(&username, &server.realm, &password);
                add_response_message_integrity(&mut response, &key);
            }
        }
        return Some(response.encode());
    }
    Some(create_error_response_bytes(
        &msg,
        ErrorCode::AllocationMismatch,
        server,
    ))
}

/// Handle CreatePermission (RFC 5766 Section 9).
/// Creates a permission for the client to send data to peers via the relay.
async fn handle_create_permission(
    msg: Message,
    server: &TurnServer,
    client_addr: SocketAddr,
) -> Option<Bytes> {
    // Verify auth
    let username = match verify_turn_auth(&msg, server, client_addr) {
        Ok(u) => u,
        Err(resp) => return Some(resp),
    };

    // Client must have an active allocation
    if server
        .allocation_table
        .find_allocation_by_client(&client_addr)
        .is_none()
    {
        debug!(
            %client_addr,
            "CreatePermission rejected because client has no active allocation"
        );
        return Some(create_error_response_bytes(
            &msg,
            ErrorCode::AllocationMismatch,
            server,
        ));
    }

    // Parse XOR-PEER-ADDRESS attributes and add permissions
    let mut peers = Vec::new();
    for attr in &msg.attributes {
        if attr.attr_type == Attribute::PEER_ADDRESS {
            if let Some(peer_addr) = crate::message::decode_xor_address(
                &attr.value,
                0x2112A442,
                &msg.header.transaction_id,
            ) {
                peers.push(peer_addr);
            }
        }
    }

    if peers.is_empty() {
        debug!(
            %client_addr,
            "CreatePermission rejected because no valid XOR-PEER-ADDRESS was provided"
        );
        return Some(create_error_response_bytes(&msg, ErrorCode::BadRequest, server));
    }

    server
        .allocation_table
        .add_permissions(&client_addr, &peers);

    debug!(
        %client_addr,
        peer_count = peers.len(),
        "CreatePermission succeeded"
    );

    // Return CreatePermission Success
    let mut response = crate::message::create_success_response(&msg.header);
    if !server.auth_disabled {
        if let Some(password) = server.get_password_for_user(&username) {
            let key = compute_message_integrity_key(&username, &server.realm, &password);
            add_response_message_integrity(&mut response, &key);
        }
    }
    Some(response.encode())
}

async fn handle_channel_bind(
    msg: Message,
    server: &TurnServer,
    client_addr: SocketAddr,
) -> Option<Bytes> {
    // Verify auth
    let username = match verify_turn_auth(&msg, server, client_addr) {
        Ok(u) => u,
        Err(resp) => return Some(resp),
    };

    if let Some(relayed_addr) = server
        .allocation_table
        .find_allocation_by_client(&client_addr)
    {
        let peer_attr = msg.get_attribute(Attribute::PEER_ADDRESS);
        if let Some(peer_attr) = peer_attr {
            let peer_addr = crate::message::decode_xor_address(
                &peer_attr.value,
                0x2112A442,
                &msg.header.transaction_id,
            )
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
            let channel_attr = msg.get_attribute(Attribute::CHANNEL_NUMBER);
            if let Some(channel_attr) = channel_attr {
                let channel_num =
                    ((channel_attr.value[0] as u16) << 8) | (channel_attr.value[1] as u16);
                if server
                    .channel_table
                    .write()
                    .await
                    .bind(channel_num, peer_addr, relayed_addr)
                    .is_ok()
                {
                    debug!(
                        %client_addr,
                        %peer_addr,
                        %relayed_addr,
                        channel_num,
                        "ChannelBind succeeded"
                    );
                    let mut response = crate::message::create_success_response(&msg.header);
                    if !server.auth_disabled {
                        if let Some(password) = server.get_password_for_user(&username) {
                            let key = compute_message_integrity_key(&username, &server.realm, &password);
                            add_response_message_integrity(&mut response, &key);
                        }
                    }
                    return Some(response.encode());
                }
                debug!(
                    %client_addr,
                    %peer_addr,
                    %relayed_addr,
                    channel_num,
                    "ChannelBind failed while creating binding"
                );
                return Some(create_error_response_bytes_with_reason(
                    &msg,
                    ErrorCode::BadRequest,
                    "Channel number already bound for this allocation",
                    server,
                ));
            }
        }
    }
    debug!(
        %client_addr,
        "ChannelBind ignored because required attributes or allocation were missing"
    );
    None
}

/// Handle Send Indication (RFC 5766 Section 11).
/// Relays data from the client to a peer via the XOR-PEER-ADDRESS.
async fn handle_send(msg: Message, server: &TurnServer, client_addr: SocketAddr) -> Option<Bytes> {
    // Send indications don't require MESSAGE-INTEGRITY (they're indications, not requests)
    // But the client must have an allocation
    if server
        .allocation_table
        .find_allocation_by_client(&client_addr)
        .is_none()
    {
        debug!(
            %client_addr,
            "Send indication dropped because client has no active allocation"
        );
        return None;
    }

    let peer_attr = match msg.get_attribute(Attribute::PEER_ADDRESS) {
        Some(attr) => attr,
        None => {
            debug!(
                %client_addr,
                "Send indication dropped because PEER-ADDRESS is missing"
            );
            return None;
        }
    };
    let peer_addr = crate::message::decode_xor_address(
        &peer_attr.value,
        0x2112A442,
        &msg.header.transaction_id,
    )?;

    let data_attr = match msg.get_attribute(Attribute::DATA) {
        Some(attr) => attr,
        None => {
            debug!(
                %client_addr,
                %peer_addr,
                "Send indication dropped because DATA is missing"
            );
            return None;
        }
    };
    let data = &data_attr.value;

    // Relay data through the allocation's relay socket (enforces permission check)
    if server
        .allocation_table
        .send_to_peer(&client_addr, peer_addr, data)
        .await
        .is_none()
    {
        debug!(
            %client_addr,
            %peer_addr,
            payload_len = data.len(),
            "Send indication dropped because permission check failed or relay socket was unavailable"
        );
        return None;
    }
    // Send indication doesn't generate a response
    None
}

fn create_401_response(
    msg: &Message,
    server: &TurnServer,
    client_addr: SocketAddr,
    reason: Option<String>,
) -> Bytes {
    let nonce = generate_nonce();
    debug!(
        %client_addr,
        method = ?msg.header.method,
        transaction_id = ?msg.header.transaction_id,
        nonce = %nonce,
        reason = ?reason,
        "Creating 401 Unauthorized response"
    );
    server.nonce_map.write().insert(
        nonce.clone(),
        NonceEntry {
            _nonce: nonce.clone(),
            created_at: std::time::Instant::now(),
        },
    );

    let mut response = crate::message::create_error_response_with_reason(
        &msg.header,
        ErrorCode::Unauthorized,
        reason.as_deref(),
    );
    response.attributes.push(Attribute {
        attr_type: Attribute::REALM,
        value: Bytes::from(server.realm.as_bytes().to_vec()),
    });
    response.attributes.push(Attribute {
        attr_type: Attribute::NONCE,
        value: Bytes::from(nonce.into_bytes()),
    });
    response.attributes.push(Attribute {
        attr_type: Attribute::SOFTWARE,
        value: Bytes::from(server.server_name.as_bytes().to_vec()),
    });
    response.encode()
}

fn create_error_response_bytes(msg: &Message, code: ErrorCode, server: &TurnServer) -> Bytes {
    let mut response = crate::message::create_error_response(&msg.header, code);
    response.attributes.push(Attribute {
        attr_type: Attribute::SOFTWARE,
        value: Bytes::from(server.server_name.as_bytes().to_vec()),
    });
    response.encode()
}

fn create_error_response_bytes_with_reason(
    msg: &Message,
    code: ErrorCode,
    reason: &str,
    server: &TurnServer,
) -> Bytes {
    let mut response =
        crate::message::create_error_response_with_reason(&msg.header, code, Some(reason));
    response.attributes.push(Attribute {
        attr_type: Attribute::SOFTWARE,
        value: Bytes::from(server.server_name.as_bytes().to_vec()),
    });
    response.encode()
}

fn get_lifetime(msg: &Message) -> u32 {
    if let Some(attr) = msg.get_attribute(Attribute::LIFETIME) {
        let mut buf = attr.value.clone();
        buf.get_u32()
    } else {
        600
    }
}

pub struct TurnServerHandle {
    pub allocation_table: Arc<AllocationTable>,
    pub channel_table: Arc<TokioRwLock<ChannelTable>>,
}

impl TurnServerHandle {
    pub fn new(relay_addr: Ipv4Addr, realm: String) -> Self {
        TurnServerHandle {
            allocation_table: Arc::new(AllocationTable::new(relay_addr, realm)),
            channel_table: Arc::new(TokioRwLock::new(ChannelTable::new())),
        }
    }

    pub fn stats(&self) -> ServerStatsSnapshot {
        self.allocation_table.stats().snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_allocate_request(transaction_id: [u8; 12]) -> Message {
        Message {
            header: MessageHeader {
                method: Method::Allocate,
                event_type: EventType::Request,
                message_length: 0,
                magic_cookie: 0x2112A442,
                transaction_id,
            },
            attributes: vec![Attribute {
                attr_type: Attribute::REQUESTED_TRANSPORT,
                value: Bytes::from_static(&[0x11, 0x00, 0x00, 0x00]),
            }],
        }
    }

    fn build_authenticated_allocate_request(
        transaction_id: [u8; 12],
        username: &str,
        realm: &str,
        nonce: &str,
        password: &str,
    ) -> Message {
        let mut msg = build_allocate_request(transaction_id);
        msg.attributes.push(Attribute {
            attr_type: Attribute::USERNAME,
            value: Bytes::copy_from_slice(username.as_bytes()),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::REALM,
            value: Bytes::copy_from_slice(realm.as_bytes()),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::NONCE,
            value: Bytes::copy_from_slice(nonce.as_bytes()),
        });

        let key = compute_message_integrity_key(username, realm, password);
        add_response_message_integrity(&mut msg, &key);
        msg
    }

    #[test]
    fn test_create_server() {
        let server = TurnServer::new(Ipv4Addr::new(0, 0, 0, 0), "test".to_string());
        assert_eq!(server.relay_addr, Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(server.relay_bind_addr, Ipv4Addr::new(0, 0, 0, 0));
    }

    #[tokio::test]
    async fn test_stats() {
        let server = TurnServer::new(Ipv4Addr::new(0, 0, 0, 0), "test".to_string());
        let stats = server.stats();
        assert_eq!(stats.total_allocations, 0);
    }

    #[test]
    fn test_server_with_limits() {
        let server = TurnServer::with_limits(
            Ipv4Addr::new(127, 0, 0, 1),
            "test-realm".to_string(),
            Some(100),
            Some(600),
            Some(1024),
        );
        assert_eq!(server.relay_addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(server.relay_bind_addr, Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 32);
        // Verify nonce bytes are not all identical (bug: old LCG produced "151515...")
        let unique_bytes = nonce1
            .as_bytes()
            .chunks(2)
            .collect::<std::collections::HashSet<_>>()
            .len();
        assert!(
            unique_bytes > 4,
            "nonce has too few unique bytes: {}",
            nonce1
        );
    }

    #[test]
    fn test_message_integrity_key() {
        let key = compute_message_integrity_key("user", "realm", "pass");
        assert_eq!(key.len(), 16);
    }

    #[tokio::test]
    async fn test_authenticated_allocate_success_contains_required_attributes() {
        let realm = "test-realm".to_string();
        let username = "admin";
        let password = "password";
        let server = TurnServer::with_password(
            Ipv4Addr::new(127, 0, 0, 1),
            realm.clone(),
            password.to_string(),
        );
        let client_addr: SocketAddr = "127.0.0.1:50000".parse().unwrap();

        // First Allocate without auth to obtain nonce.
        let unauth_msg = build_allocate_request([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        let nonce_response = process_message(unauth_msg, &server, client_addr)
            .await
            .unwrap();
        let nonce_msg = Message::parse(&nonce_response).unwrap();
        assert_eq!(nonce_msg.header.event_type, EventType::Error);
        let nonce = String::from_utf8(
            nonce_msg
                .get_attribute(Attribute::NONCE)
                .unwrap()
                .value
                .to_vec(),
        )
        .unwrap();

        // Retry Allocate with long-term auth and verify success attributes.
        // Under parallel test load, relay port contention can cause transient 486/508.
        let mut success_msg: Option<Message> = None;
        for attempt in 0..5 {
            let mut tid = [0u8; 12];
            tid[11] = attempt;
            let auth_msg =
                build_authenticated_allocate_request(tid, username, &realm, &nonce, password);
            let response = process_message(auth_msg, &server, client_addr)
                .await
                .unwrap();
            let parsed = Message::parse(&response).unwrap();

            if parsed.header.event_type == EventType::Success {
                success_msg = Some(parsed);
                break;
            }

            let err_attr = parsed
                .get_attribute(Attribute::ERROR_CODE)
                .expect("error response should include ERROR-CODE");
            let raw = u32::from_be_bytes([
                err_attr.value[0],
                err_attr.value[1],
                err_attr.value[2],
                err_attr.value[3],
            ]);
            let code = ((raw >> 8) & 0x7) * 100 + (raw & 0xff);
            assert!(
                code == 486 || code == 508,
                "unexpected Allocate error code in auth test: {}",
                code
            );
        }

        let success_msg = success_msg.expect(
            "authenticated Allocate should eventually succeed (no Success after transient retries)",
        );

        assert_eq!(success_msg.header.method, Method::Allocate);
        assert_eq!(success_msg.header.event_type, EventType::Success);
        assert!(
            success_msg
                .get_attribute(Attribute::MESSAGE_INTEGRITY)
                .is_some()
        );
        assert!(
            success_msg
                .get_attribute(Attribute::XOR_RELAYED_ADDRESS)
                .is_some()
        );
        assert!(
            success_msg
                .get_attribute(Attribute::XOR_MAPPED_ADDRESS)
                .is_some()
        );
        assert!(success_msg.get_attribute(Attribute::LIFETIME).is_some());
    }

    fn build_authenticated_create_permission_request(
        transaction_id: [u8; 12],
        peer_addr: SocketAddr,
        username: &str,
        realm: &str,
        nonce: &str,
        password: &str,
    ) -> Message {
        let mut msg = Message {
            header: MessageHeader {
                method: Method::CreatePermission,
                event_type: EventType::Request,
                message_length: 0,
                magic_cookie: 0x2112A442,
                transaction_id,
            },
            attributes: Vec::new(),
        };
        msg.attributes.push(Attribute {
            attr_type: Attribute::USERNAME,
            value: Bytes::copy_from_slice(username.as_bytes()),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::REALM,
            value: Bytes::copy_from_slice(realm.as_bytes()),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::NONCE,
            value: Bytes::copy_from_slice(nonce.as_bytes()),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::PEER_ADDRESS,
            value: crate::message::encode_xor_address(peer_addr, 0x2112A442, &transaction_id),
        });
        let key = compute_message_integrity_key(username, realm, password);
        add_response_message_integrity(&mut msg, &key);
        msg
    }

    fn build_authenticated_channel_bind_request(
        transaction_id: [u8; 12],
        peer_addr: SocketAddr,
        channel_num: u16,
        username: &str,
        realm: &str,
        nonce: &str,
        password: &str,
    ) -> Message {
        let mut msg = Message {
            header: MessageHeader {
                method: Method::ChannelBind,
                event_type: EventType::Request,
                message_length: 0,
                magic_cookie: 0x2112A442,
                transaction_id,
            },
            attributes: Vec::new(),
        };
        msg.attributes.push(Attribute {
            attr_type: Attribute::USERNAME,
            value: Bytes::copy_from_slice(username.as_bytes()),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::REALM,
            value: Bytes::copy_from_slice(realm.as_bytes()),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::NONCE,
            value: Bytes::copy_from_slice(nonce.as_bytes()),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::PEER_ADDRESS,
            value: crate::message::encode_xor_address(peer_addr, 0x2112A442, &transaction_id),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::CHANNEL_NUMBER,
            value: Bytes::from(vec![(channel_num >> 8) as u8, (channel_num & 0xFF) as u8]),
        });
        let key = compute_message_integrity_key(username, realm, password);
        add_response_message_integrity(&mut msg, &key);
        msg
    }

    fn build_authenticated_refresh_request(
        transaction_id: [u8; 12],
        lifetime: u32,
        username: &str,
        realm: &str,
        nonce: &str,
        password: &str,
    ) -> Message {
        let mut msg = Message {
            header: MessageHeader {
                method: Method::Refresh,
                event_type: EventType::Request,
                message_length: 0,
                magic_cookie: 0x2112A442,
                transaction_id,
            },
            attributes: Vec::new(),
        };
        msg.attributes.push(Attribute {
            attr_type: Attribute::USERNAME,
            value: Bytes::copy_from_slice(username.as_bytes()),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::REALM,
            value: Bytes::copy_from_slice(realm.as_bytes()),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::NONCE,
            value: Bytes::copy_from_slice(nonce.as_bytes()),
        });
        msg.attributes.push(Attribute {
            attr_type: Attribute::LIFETIME,
            value: Bytes::from(lifetime.to_be_bytes().to_vec()),
        });
        let key = compute_message_integrity_key(username, realm, password);
        add_response_message_integrity(&mut msg, &key);
        msg
    }

    #[tokio::test]
    async fn test_authenticated_create_permission_success_contains_message_integrity() {
        let realm = "test-realm".to_string();
        let username = "admin";
        let password = "password";
        let server = TurnServer::with_password(
            Ipv4Addr::new(127, 0, 0, 1),
            realm.clone(),
            password.to_string(),
        );
        let client_addr: SocketAddr = "127.0.0.1:50001".parse().unwrap();

        let unauth_msg = build_allocate_request([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        let nonce_response = process_message(unauth_msg, &server, client_addr)
            .await
            .unwrap();
        let nonce_msg = Message::parse(&nonce_response).unwrap();
        let nonce = String::from_utf8(
            nonce_msg
                .get_attribute(Attribute::NONCE)
                .unwrap()
                .value
                .to_vec(),
        )
        .unwrap();

        let mut relayed_addr = None;
        for attempt in 0..5 {
            let mut tid = [0u8; 12];
            tid[11] = attempt;
            let auth_msg =
                build_authenticated_allocate_request(tid, username, &realm, &nonce, password);
            let response = process_message(auth_msg, &server, client_addr)
                .await
                .unwrap();
            let parsed = Message::parse(&response).unwrap();
            if parsed.header.event_type == EventType::Success {
                if let Some(attr) = parsed.get_attribute(Attribute::XOR_RELAYED_ADDRESS) {
                    relayed_addr = crate::message::decode_xor_address(
                        &attr.value,
                        0x2112A442,
                        &parsed.header.transaction_id,
                    );
                }
                break;
            }
        }
        let relayed_addr = relayed_addr.expect("allocation should succeed");

        let cp_msg = build_authenticated_create_permission_request(
            [11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
            relayed_addr,
            username,
            &realm,
            &nonce,
            password,
        );
        let cp_response = process_message(cp_msg, &server, client_addr)
            .await
            .unwrap();
        let cp_parsed = Message::parse(&cp_response).unwrap();
        assert_eq!(cp_parsed.header.event_type, EventType::Success);
        assert!(
            cp_parsed
                .get_attribute(Attribute::MESSAGE_INTEGRITY)
                .is_some(),
            "CreatePermission success should include MESSAGE-INTEGRITY"
        );
    }

    #[tokio::test]
    async fn test_authenticated_channel_bind_success_contains_message_integrity() {
        let realm = "test-realm".to_string();
        let username = "admin";
        let password = "password";
        let server = TurnServer::with_password(
            Ipv4Addr::new(127, 0, 0, 1),
            realm.clone(),
            password.to_string(),
        );
        let client_addr: SocketAddr = "127.0.0.1:50002".parse().unwrap();

        let unauth_msg = build_allocate_request([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        let nonce_response = process_message(unauth_msg, &server, client_addr)
            .await
            .unwrap();
        let nonce_msg = Message::parse(&nonce_response).unwrap();
        let nonce = String::from_utf8(
            nonce_msg
                .get_attribute(Attribute::NONCE)
                .unwrap()
                .value
                .to_vec(),
        )
        .unwrap();

        let mut relayed_addr = None;
        for attempt in 0..5 {
            let mut tid = [0u8; 12];
            tid[11] = attempt;
            let auth_msg =
                build_authenticated_allocate_request(tid, username, &realm, &nonce, password);
            let response = process_message(auth_msg, &server, client_addr)
                .await
                .unwrap();
            let parsed = Message::parse(&response).unwrap();
            if parsed.header.event_type == EventType::Success {
                if let Some(attr) = parsed.get_attribute(Attribute::XOR_RELAYED_ADDRESS) {
                    relayed_addr = crate::message::decode_xor_address(
                        &attr.value,
                        0x2112A442,
                        &parsed.header.transaction_id,
                    );
                }
                break;
            }
        }
        let _relayed_addr = relayed_addr.expect("allocation should succeed");

        let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let cb_msg = build_authenticated_channel_bind_request(
            [11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
            peer_addr,
            0x4000,
            username,
            &realm,
            &nonce,
            password,
        );
        let cb_response = process_message(cb_msg, &server, client_addr)
            .await
            .unwrap();
        let cb_parsed = Message::parse(&cb_response).unwrap();
        assert_eq!(cb_parsed.header.event_type, EventType::Success);
        assert!(
            cb_parsed
                .get_attribute(Attribute::MESSAGE_INTEGRITY)
                .is_some(),
            "ChannelBind success should include MESSAGE-INTEGRITY"
        );
    }

    #[tokio::test]
    async fn test_authenticated_refresh_success_contains_message_integrity() {
        let realm = "test-realm".to_string();
        let username = "admin";
        let password = "password";
        let server = TurnServer::with_password(
            Ipv4Addr::new(127, 0, 0, 1),
            realm.clone(),
            password.to_string(),
        );
        let client_addr: SocketAddr = "127.0.0.1:50003".parse().unwrap();

        let unauth_msg = build_allocate_request([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
        let nonce_response = process_message(unauth_msg, &server, client_addr)
            .await
            .unwrap();
        let nonce_msg = Message::parse(&nonce_response).unwrap();
        let nonce = String::from_utf8(
            nonce_msg
                .get_attribute(Attribute::NONCE)
                .unwrap()
                .value
                .to_vec(),
        )
        .unwrap();

        for attempt in 0..5 {
            let mut tid = [0u8; 12];
            tid[11] = attempt;
            let auth_msg =
                build_authenticated_allocate_request(tid, username, &realm, &nonce, password);
            let response = process_message(auth_msg, &server, client_addr)
                .await
                .unwrap();
            let parsed = Message::parse(&response).unwrap();
            if parsed.header.event_type == EventType::Success {
                break;
            }
            if attempt == 4 {
                panic!("allocation should succeed");
            }
        }

        let refresh_msg = build_authenticated_refresh_request(
            [11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
            600,
            username,
            &realm,
            &nonce,
            password,
        );
        let refresh_response = process_message(refresh_msg, &server, client_addr)
            .await
            .unwrap();
        let refresh_parsed = Message::parse(&refresh_response).unwrap();
        assert_eq!(refresh_parsed.header.event_type, EventType::Success);
        assert!(
            refresh_parsed
                .get_attribute(Attribute::MESSAGE_INTEGRITY)
                .is_some(),
            "Refresh success should include MESSAGE-INTEGRITY"
        );
        assert!(
            refresh_parsed.get_attribute(Attribute::LIFETIME).is_some(),
            "Refresh success should include LIFETIME"
        );
    }
}
