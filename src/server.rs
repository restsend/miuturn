use crate::allocation::{AllocationTable, ChannelTable, ServerStatsSnapshot};
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
use tracing::{error, info};

type HmacSha1 = Hmac<sha1::Sha1>;

#[derive(Clone)]
pub struct TurnServer {
    pub allocation_table: Arc<AllocationTable>,
    pub channel_table: Arc<TokioRwLock<ChannelTable>>,
    pub relay_addr: Ipv4Addr,
    pub realm: String,
    nonce_map: Arc<RwLock<HashMap<String, NonceEntry>>>,
    password: String,
    auth_disabled: bool,
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

    pub fn with_password(relay_addr: Ipv4Addr, realm: String, password: String) -> Self {
        Self::with_limits_and_password(relay_addr, realm, None, None, None, password, false)
    }

    pub fn with_auth_disabled(relay_addr: Ipv4Addr, realm: String) -> Self {
        Self::with_limits_and_password(relay_addr, realm, None, None, None, String::new(), true)
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
            realm,
            nonce_map: Arc::new(RwLock::new(HashMap::new())),
            password: String::new(),
            auth_disabled: true,
        };
        server.start_nonce_cleanup_task();
        server.start_channel_cleanup_task();
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
            realm,
            nonce_map: Arc::new(RwLock::new(HashMap::new())),
            password,
            auth_disabled,
        };
        server.start_nonce_cleanup_task();
        server.start_channel_cleanup_task();
        server
    }

    pub fn stats(&self) -> ServerStatsSnapshot {
        self.allocation_table.stats().snapshot()
    }

    /// Start a background task to clean up expired nonces
    pub fn start_nonce_cleanup_task(&self) {
        let nonce_map = self.nonce_map.clone();
        const NONCE_EXPIRY_SECONDS: u64 = 60;
        const CLEANUP_INTERVAL_SECONDS: u64 = 30;

        // Check if we're running in a Tokio runtime context
        if tokio::runtime::Handle::try_current().is_err() {
            // Not in a runtime context, skip spawning (will be called again from run methods)
            return;
        }

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECONDS));
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
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(CLEANUP_INTERVAL_SECONDS));
            loop {
                interval.tick().await;

                let channel_table = channel_table.read().await;
                let removed_count = channel_table.cleanup_expired();
                drop(channel_table);

                if removed_count > 0 {
                    tracing::debug!("Cleaned up {} expired channel bindings", removed_count);
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
                                && socket.write_all(&response).await.is_err() {
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

        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!("TURN UDP server listening on {}", addr);

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
                        && let Err(e) = socket.send_to(&response, &peer_addr).await {
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
    socket: &Arc<UdpSocket>,
    data: Bytes,
    peer_addr: SocketAddr,
    server: &TurnServer,
) -> Option<Bytes> {
    if data.len() < 4 {
        return None;
    }
    let channel_num = (data[0] as u16) << 8 | (data[1] as u16);
    if (0x4000..=0x7FFF).contains(&channel_num) {
        if let Some(relayed_addr) = server
            .allocation_table
            .find_allocation_by_client(&peer_addr)
            && let Some(channel) = server
                .channel_table
                .read()
                .await
                .get_by_channel(channel_num)
            {
                let _ = socket.send_to(&data[4..], &channel.peer_addr).await;
                let _ = socket.send_to(&data[4..], &relayed_addr).await;
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
        Method::ChannelBind => handle_channel_bind(msg, server, client_addr).await,
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
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut hash: [u8; 16] = [0; 16];
    for (i, byte) in hash.iter_mut().enumerate() {
        let s = seed
            .wrapping_mul(1103515245u128)
            .wrapping_add(12345 ^ (i as u128));
        *byte = (s >> 16) as u8;
    }
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

    let encoded = partial_msg.encode();
    let mut mac = HmacSha1::new_from_slice(key).ok().unwrap();
    mac.update(&encoded);
    let computed = mac.finalize().into_bytes();
    computed[..20] == integrity_attr.value[..20]
}

async fn handle_allocate(
    msg: Message,
    server: &TurnServer,
    client_addr: SocketAddr,
) -> Option<Bytes> {
    let realm = server.realm.clone();

    // Skip auth if disabled
    if !server.auth_disabled {
        let nonce_attr = msg.get_attribute(Attribute::NONCE);
        let username_attr = msg.get_attribute(Attribute::USERNAME);

        if nonce_attr.is_none() || username_attr.is_none() {
            return Some(create_401_response(&msg, server, None));
        }

        let nonce = String::from_utf8_lossy(&nonce_attr.unwrap().value).to_string();
        let username = String::from_utf8_lossy(&username_attr.unwrap().value).to_string();

        // Validate nonce exists and hasn't expired
        let nonce_map = server.nonce_map.read();
        if !nonce_map.contains_key(&nonce) {
            drop(nonce_map);
            return Some(create_401_response(
                &msg,
                server,
                Some("Invalid nonce".to_string()),
            ));
        }
        let nonce_entry = nonce_map.get(&nonce).unwrap();
        let nonce_age = nonce_entry.created_at.elapsed();
        drop(nonce_map);

        // Nonce expires after 60 seconds
        if nonce_age.as_secs() > 60 {
            return Some(create_401_response(
                &msg,
                server,
                Some("Nonce expired".to_string()),
            ));
        }

        let key = compute_message_integrity_key(&username, &realm, &server.password);

        if !verify_message_integrity(&msg, &key) {
            return Some(create_401_response(
                &msg,
                server,
                Some("Bad integrity".to_string()),
            ));
        }

        // Remove used nonce to prevent replay attacks
        server.nonce_map.write().remove(&nonce);
    }

    let lifetime = get_lifetime(&msg);
    let allocation = match server
        .allocation_table
        .create_allocation(client_addr, Some(lifetime))
        .await
    {
        Ok(a) => a,
        Err(_) => {
            return Some(create_error_response_bytes(
                &msg,
                ErrorCode::AllocationMismatch,
            ));
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
        attr_type: Attribute::LIFETIME,
        value: Bytes::from(lifetime.to_be_bytes().to_vec()),
    });
    response.attributes.push(Attribute {
        attr_type: Attribute::REALM,
        value: Bytes::from(realm.as_bytes().to_vec()),
    });

    Some(response.encode())
}

async fn handle_refresh(
    msg: Message,
    server: &TurnServer,
    client_addr: SocketAddr,
) -> Option<Bytes> {
    let lifetime = get_lifetime(&msg);
    if let Some(relayed) = server
        .allocation_table
        .find_allocation_by_client(&client_addr)
        && server
            .allocation_table
            .refresh_allocation(&relayed, lifetime).is_err()
        {
            return Some(create_error_response_bytes(
                &msg,
                ErrorCode::AllocationMismatch,
            ));
        }
    None
}

async fn handle_channel_bind(
    msg: Message,
    server: &TurnServer,
    client_addr: SocketAddr,
) -> Option<Bytes> {
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
                    let response = crate::message::create_success_response(&msg.header);
                    return Some(response.encode());
                }
            }
        }
    }
    None
}

fn create_401_response(msg: &Message, server: &TurnServer, _reason: Option<String>) -> Bytes {
    let nonce = generate_nonce();
    server.nonce_map.write().insert(
        nonce.clone(),
        NonceEntry {
            _nonce: nonce.clone(),
            created_at: std::time::Instant::now(),
        },
    );

    let mut response = crate::message::create_error_response(&msg.header, ErrorCode::Unauthorized);
    response.attributes.push(Attribute {
        attr_type: Attribute::REALM,
        value: Bytes::from(server.realm.as_bytes().to_vec()),
    });
    response.attributes.push(Attribute {
        attr_type: Attribute::NONCE,
        value: Bytes::from(nonce.into_bytes()),
    });
    response.encode()
}

fn create_error_response_bytes(msg: &Message, code: ErrorCode) -> Bytes {
    let response = crate::message::create_error_response(&msg.header, code);
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

    #[test]
    fn test_create_server() {
        let server = TurnServer::new(Ipv4Addr::new(0, 0, 0, 0), "test".to_string());
        assert_eq!(server.relay_addr, Ipv4Addr::new(0, 0, 0, 0));
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
    }

    #[test]
    fn test_nonce_generation() {
        let nonce1 = generate_nonce();
        let nonce2 = generate_nonce();
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), 32);
    }

    #[test]
    fn test_message_integrity_key() {
        let key = compute_message_integrity_key("user", "realm", "pass");
        assert_eq!(key.len(), 16);
    }
}
