//! E2E tests using the `stun` and `turn` crates to verify protocol compliance.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::sleep;

use webrtc_util::conn::Conn;

use miuturn::TurnServer;

// ── 14. turn crate e2e: 1MB at 100KB/s with packet loss check ─────────────

#[tokio::test]
async fn turn_crate_e2e_send_1mb_with_rate_limit_and_loss_check() {
    use std::collections::HashSet;

    let realm = "test-realm";
    let username = "admin";
    let password = "s3cret";

    // 1 MB payload, 1024-byte packet => 1024 packets.
    // 10 ms per packet => 100 packets/s => 102400 B/s (~100 KB/s).
    const TOTAL_BYTES: usize = 1024 * 1024;
    const PACKET_SIZE: usize = 1024;
    const TOTAL_PACKETS: usize = TOTAL_BYTES / PACKET_SIZE;
    const INTER_PACKET_DELAY: Duration = Duration::from_millis(10);
    const MAX_PACKET_LOSS_RATIO: f64 = 0.95;

    let (server_addr, _) = start_server("127.0.0.1", realm, password).await;

    let (conn_a, _) = bind_udp().await;
    let (conn_b, _) = bind_udp().await;

    let client_a = turn::client::Client::new(client_config(
        server_addr,
        username,
        password,
        realm,
        conn_a,
    ))
    .await
    .expect("create client_a");
    client_a.listen().await.expect("listen client_a");

    let client_b = turn::client::Client::new(client_config(
        server_addr,
        username,
        password,
        realm,
        conn_b,
    ))
    .await
    .expect("create client_b");
    client_b.listen().await.expect("listen client_b");

    let relay_conn_a = client_a.allocate().await.expect("allocate client_a");
    let relay_conn_b = client_b.allocate().await.expect("allocate client_b");
    let relay_b_addr = relay_conn_b.local_addr().expect("relay_b local addr");

    let receiver = tokio::spawn(async move {
        let mut buf = vec![0u8; PACKET_SIZE + 64];
        let mut received_seqs: HashSet<u32> = HashSet::with_capacity(TOTAL_PACKETS);
        let deadline = Instant::now() + Duration::from_secs(30);

        while Instant::now() < deadline && received_seqs.len() < TOTAL_PACKETS {
            let recv =
                tokio::time::timeout(Duration::from_millis(500), relay_conn_b.recv_from(&mut buf))
                    .await;

            match recv {
                Ok(Ok((n, _))) if n >= 4 => {
                    let seq = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    received_seqs.insert(seq);
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) => break,
                Err(_) => {}
            }
        }

        received_seqs.len()
    });

    let send_start = Instant::now();
    for seq in 0..(TOTAL_PACKETS as u32) {
        let mut packet = vec![0u8; PACKET_SIZE];
        packet[0..4].copy_from_slice(&seq.to_be_bytes());

        // Deterministic payload pattern for debugging and corruption detection.
        let pattern = (seq & 0xFF) as u8;
        packet[4..].fill(pattern);

        relay_conn_a
            .send_to(&packet, relay_b_addr)
            .await
            .expect("send packet via turn relay");
        sleep(INTER_PACKET_DELAY).await;
    }
    let send_elapsed = send_start.elapsed();

    let received_packets = tokio::time::timeout(Duration::from_secs(10), receiver)
        .await
        .expect("receiver task timeout")
        .expect("receiver join failed");

    let sent_packets = TOTAL_PACKETS as f64;
    let received_packets_f64 = received_packets as f64;
    let packet_loss_ratio = (sent_packets - received_packets_f64) / sent_packets;

    eprintln!(
        "turn crate e2e 1MB@100KB/s: sent={} received={} loss_ratio={:.4} send_elapsed={:?}",
        TOTAL_PACKETS, received_packets, packet_loss_ratio, send_elapsed
    );

    assert!(
        packet_loss_ratio <= MAX_PACKET_LOSS_RATIO,
        "packet loss ratio too high: {:.4} (received {}/{})",
        packet_loss_ratio,
        received_packets,
        TOTAL_PACKETS
    );

    let _ = client_a.close().await;
    let _ = client_b.close().await;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Bind a free UDP socket, return (socket, local_addr).
async fn bind_udp() -> (Arc<UdpSocket>, SocketAddr) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    (Arc::new(sock), addr)
}

static RELAY_RANGE_IDX: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

fn next_relay_range() -> (u16, u16) {
    // Keep test relay ranges in 10000..39999 to avoid collisions with other
    // tests in this repo that often use fixed ranges around 50000+.
    const RANGE_SIZE: u16 = 256;
    const BASE_PORT: u16 = 10000;
    const WINDOW_PORTS: u16 = 30000; // 10000..39999
    const SLOT_COUNT: u16 = WINDOW_PORTS / RANGE_SIZE;

    let idx = RELAY_RANGE_IDX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id() as u16;

    // Process-local sharding reduces collision probability across parallel
    // `cargo test` binaries that each start their own TURN server.
    let slot = pid
        .wrapping_mul(131)
        .wrapping_add(idx)
        .wrapping_rem(SLOT_COUNT);

    let min_relay = BASE_PORT + slot * RANGE_SIZE;
    let max_relay = min_relay + RANGE_SIZE - 1;
    (min_relay, max_relay)
}

fn pick_free_udp_port() -> u16 {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind temp udp socket");
    sock.local_addr().expect("temp udp local addr").port()
}

async fn wait_server_ready(server_addr: SocketAddr) {
    let probe_socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind probe socket");
    let request: [u8; 20] = [
        0x00, 0x01, 0x00, 0x00, // Binding Request
        0x21, 0x12, 0xA4, 0x42, // Magic cookie
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
    ];

    for _ in 0..20 {
        let _ = probe_socket.send_to(&request, server_addr).await;
        let mut buf = [0u8; 1500];
        let recv = tokio::time::timeout(Duration::from_millis(100), probe_socket.recv_from(&mut buf)).await;
        if let Ok(Ok((n, _))) = recv
            && n >= 20
            && buf[4] == 0x21
            && buf[5] == 0x12
            && buf[6] == 0xA4
            && buf[7] == 0x42
        {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }

    panic!("server was not ready on {} within startup timeout", server_addr);
}

/// Start a TurnServer with auth enabled.
/// Uses a unique port range for relay addresses to avoid conflicts between concurrent tests.
async fn start_server(relay: &str, realm: &str, password: &str) -> (SocketAddr, TurnServer) {
    let relay_addr: std::net::Ipv4Addr = relay.parse().unwrap();
    let port = pick_free_udp_port();
    let (min_relay, max_relay) = next_relay_range();
    let server = TurnServer::with_port_range_and_password(
        relay_addr,
        realm.to_string(),
        min_relay,
        max_relay,
        password.to_string(),
    );
    let srv = server.clone();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    tokio::spawn(async move {
        let _ = srv.run_udp(addr).await;
    });
    wait_server_ready(addr).await;
    (addr, server)
}

/// Start a TurnServer with auth disabled.
async fn start_server_no_auth(relay: &str, realm: &str) -> (SocketAddr, TurnServer) {
    let relay_addr: std::net::Ipv4Addr = relay.parse().unwrap();
    let port = pick_free_udp_port();
    let (min_relay, max_relay) = next_relay_range();
    let server = TurnServer::with_port_range_auth_disabled(
        relay_addr,
        realm.to_string(),
        min_relay,
        max_relay,
    );
    let srv = server.clone();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    tokio::spawn(async move {
        let _ = srv.run_udp(addr).await;
    });
    wait_server_ready(addr).await;
    (addr, server)
}

fn client_config(
    server_addr: SocketAddr,
    username: &str,
    password: &str,
    realm: &str,
    conn: Arc<UdpSocket>,
) -> turn::client::ClientConfig {
    let addr_str = server_addr.to_string();
    turn::client::ClientConfig {
        stun_serv_addr: addr_str.clone(),
        turn_serv_addr: addr_str,
        username: username.to_string(),
        password: password.to_string(),
        realm: realm.to_string(),
        software: "miuturn-e2e".to_string(),
        rto_in_ms: 200,
        conn,
        vnet: None,
    }
}

// ── 1. STUN Binding via stun crate ──────────────────────────────────────────

#[tokio::test]
async fn stun_binding_request_response_with_stun_crate() {
    use stun::agent::TransactionId;
    use stun::attributes::ATTR_SOFTWARE;
    use stun::message::*;
    use stun::textattrs::TextAttribute;
    use stun::xoraddr::XorMappedAddress;

    let (server_addr, _) = start_server_no_auth("0.0.0.0", "test").await;
    let (conn, _) = bind_udp().await;

    // Build a Binding Request with the stun crate
    let mut msg = Message::new();
    msg.build(&[
        Box::new(BINDING_REQUEST),
        Box::new(TransactionId([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])),
        Box::new(TextAttribute::new(
            ATTR_SOFTWARE,
            "miuturn-test".to_string(),
        )),
    ])
    .unwrap();

    conn.send_to(&msg.raw, server_addr).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    let mut buf = vec![0u8; 1500];
    let (len, _from) = tokio::select! {
        r = conn.recv_from(&mut buf) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("timeout waiting for binding response"),
    };

    // Decode with stun crate
    let mut resp = Message::new();
    resp.raw = buf[..len].to_vec();
    resp.decode().unwrap();

    // Verify type is Binding Success
    assert_eq!(resp.typ.class, CLASS_SUCCESS_RESPONSE, "expected success");
    assert_eq!(resp.typ.method, METHOD_BINDING, "expected binding method");

    // Parse XOR-MAPPED-ADDRESS
    let mut xaddr = XorMappedAddress::default();
    xaddr
        .get_from(&resp)
        .expect("should parse XOR-MAPPED-ADDRESS");

    // The mapped address should be our local address (127.0.0.1:some_port)
    assert!(xaddr.port > 0, "port should be > 0, got {}", xaddr.port);
}

// ── 2. STUN Binding roundtrip: encode → send → decode ──────────────────────

#[tokio::test]
async fn stun_binding_roundtrip_preserves_transaction_id() {
    use stun::agent::TransactionId;
    use stun::message::*;

    let (server_addr, _) = start_server_no_auth("0.0.0.0", "test").await;
    let (conn, _) = bind_udp().await;

    let tid = TransactionId([0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4, 5, 6, 7, 8]);

    let mut msg = Message::new();
    msg.build(&[Box::new(BINDING_REQUEST), Box::new(tid)])
        .unwrap();

    conn.send_to(&msg.raw, server_addr).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    let mut buf = vec![0u8; 1500];
    let (len, _) = tokio::select! {
        r = conn.recv_from(&mut buf) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("timeout"),
    };

    let mut resp = Message::new();
    resp.raw = buf[..len].to_vec();
    resp.decode().unwrap();

    // Transaction ID must match
    assert_eq!(resp.transaction_id.0, tid.0, "transaction ID mismatch");
}

// ── 3. TURN Allocate with auth via turn crate ──────────────────────────────

#[tokio::test]
async fn turn_allocate_with_long_term_auth() {
    let realm = "test-realm";
    let username = "admin";
    let password = "s3cret";

    let (server_addr, _) = start_server("127.0.0.1", realm, password).await;
    let (conn, _) = bind_udp().await;

    let config = client_config(server_addr, username, password, realm, conn);
    let client = turn::client::Client::new(config)
        .await
        .expect("client create");
    client.listen().await.expect("listen");

    let result = client.allocate().await;
    assert!(result.is_ok(), "allocate failed: {:?}", result.err());

    let _ = client.close().await;
}

// ── 4. TURN Allocate → SendIndication (triggers permission+channel internally) ──

#[tokio::test]
async fn turn_allocate_and_get_relay_addr() {
    let realm = "test-realm";
    let username = "admin";
    let password = "s3cret";

    let (server_addr, _) = start_server("127.0.0.1", realm, password).await;
    let (conn, _) = bind_udp().await;

    let config = client_config(server_addr, username, password, realm, conn);
    let client = turn::client::Client::new(config)
        .await
        .expect("client create");
    client.listen().await.expect("listen");

    // Allocate first
    let relay_conn = client.allocate().await.expect("allocate");

    // Get relay address via local_addr (from the Conn trait)
    let relay_addr = relay_conn.local_addr().expect("get relay addr");
    assert!(
        relay_addr.port() > 0,
        "relay port should be > 0, got {}",
        relay_addr.port()
    );

    let _ = client.close().await;
}

// ── 5. Wrong password → allocation fails ───────────────────────────────────

#[tokio::test]
async fn turn_allocate_wrong_password_fails() {
    let realm = "test-realm";
    let (server_addr, _) = start_server("127.0.0.1", realm, "correct-password").await;
    let (conn, _) = bind_udp().await;

    let config = client_config(server_addr, "admin", "wrong-password", realm, conn);
    let client = turn::client::Client::new(config)
        .await
        .expect("client create");
    client.listen().await.expect("listen");

    let result = client.allocate().await;
    assert!(
        result.is_err(),
        "expected allocate to fail with wrong password"
    );
}

// ── 6. Auth disabled → anonymous allocate returns success (raw packet test) ──
// The `turn` crate client always does 2-phase auth, so we test this with raw STUN.

#[tokio::test]
async fn turn_allocate_auth_disabled_raw_succeeds() {
    use stun::agent::TransactionId;
    use stun::message::*;

    let (server_addr, _) = start_server_no_auth("0.0.0.0", "test").await;
    let (conn, _) = bind_udp().await;

    // Build an Allocate Request (anonymous, no credentials)
    let mut msg = Message::new();
    msg.build(&[
        Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)),
        Box::new(TransactionId::new()),
    ])
    .unwrap();

    conn.send_to(&msg.raw, server_addr).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    let mut buf = vec![0u8; 1500];
    let (len, _) = tokio::select! {
        r = conn.recv_from(&mut buf) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("timeout"),
    };

    let mut resp = Message::new();
    resp.raw = buf[..len].to_vec();
    resp.decode().unwrap();

    // When auth is disabled, server should return Allocate Success directly
    assert_eq!(resp.typ.method, METHOD_ALLOCATE);
    assert_eq!(
        resp.typ.class, CLASS_SUCCESS_RESPONSE,
        "expected success, got class {:?}",
        resp.typ.class
    );
}

// ── 7. STUN message type encoding roundtrip (all methods × all classes) ────

#[test]
fn stun_type_encoding_matches_stun_crate() {
    use stun::attributes::*;
    use stun::message::*;

    // Verify our constants match the stun crate
    assert_eq!(
        miuturn::message::Attribute::USERNAME,
        ATTR_USERNAME.0 as u16
    );
    assert_eq!(miuturn::message::Attribute::REALM, ATTR_REALM.0 as u16);
    assert_eq!(miuturn::message::Attribute::NONCE, ATTR_NONCE.0 as u16);
    assert_eq!(
        miuturn::message::Attribute::MESSAGE_INTEGRITY,
        ATTR_MESSAGE_INTEGRITY.0 as u16
    );
    assert_eq!(
        miuturn::message::Attribute::ERROR_CODE,
        ATTR_ERROR_CODE.0 as u16
    );
    assert_eq!(
        miuturn::message::Attribute::XOR_MAPPED_ADDRESS,
        ATTR_XORMAPPED_ADDRESS.0 as u16
    );
    assert_eq!(
        miuturn::message::Attribute::XOR_RELAYED_ADDRESS,
        ATTR_XOR_RELAYED_ADDRESS.0 as u16
    );
    assert_eq!(
        miuturn::message::Attribute::REQUESTED_TRANSPORT,
        ATTR_REQUESTED_TRANSPORT.0 as u16
    );
    assert_eq!(
        miuturn::message::Attribute::LIFETIME,
        ATTR_LIFETIME.0 as u16
    );
    assert_eq!(
        miuturn::message::Attribute::FINGERPRINT,
        ATTR_FINGERPRINT.0 as u16
    );
    assert_eq!(
        miuturn::message::Attribute::CHANNEL_NUMBER,
        ATTR_CHANNEL_NUMBER.0 as u16
    );
    assert_eq!(miuturn::message::Attribute::DATA, ATTR_DATA.0 as u16);
    assert_eq!(
        miuturn::message::Attribute::PEER_ADDRESS,
        ATTR_XOR_PEER_ADDRESS.0 as u16
    );

    // Verify type encoding for key message types
    // We use the stun crate's own encoding as ground truth and verify our
    // implementation matches by comparing encoded values.
    let cases: Vec<(u16, u16, u16)> = vec![
        // (method_raw, class_raw, expected_encoded)
        (0x0001, 0, BINDING_REQUEST.value()),
        (0x0001, 2, BINDING_SUCCESS.value()),
        (0x0001, 3, BINDING_ERROR.value()),
        (
            0x0003,
            0,
            MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST).value(),
        ),
        (
            0x0003,
            2,
            MessageType::new(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE).value(),
        ),
        (
            0x0003,
            3,
            MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE).value(),
        ),
    ];

    for (method_raw, class_raw, expected) in &cases {
        let encoded = stun_type_encode(*method_raw, *class_raw);
        assert_eq!(
            encoded, *expected,
            "type encoding mismatch for method=0x{:04x} class={}: got 0x{:04x}, expected 0x{:04x}",
            method_raw, class_raw, encoded, expected
        );
    }
}

/// Mirror our server's RFC 5389 type encoding in pure Rust for testing.
fn stun_type_encode(method: u16, class: u16) -> u16 {
    let a = method & 0x000F;
    let b = method & 0x0070;
    let d = method & 0x0F80;
    let method_enc = a + (b << 1) + (d << 2);
    let c0 = (class & 1) << 4;
    let c1 = (class & 2) << 7;
    method_enc + c0 + c1
}

// ── 8. STUN Binding response parsed by stun crate (XOR-MAPPED-ADDRESS) ────

#[tokio::test]
async fn stun_binding_xor_mapped_address_decodes_correctly() {
    use stun::agent::TransactionId;
    use stun::message::*;
    use stun::xoraddr::XorMappedAddress;

    let (server_addr, _) = start_server_no_auth("0.0.0.0", "test").await;
    let (conn, local_addr) = bind_udp().await;

    let mut msg = Message::new();
    msg.build(&[Box::new(BINDING_REQUEST), Box::new(TransactionId::new())])
        .unwrap();

    conn.send_to(&msg.raw, server_addr).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    let mut buf = vec![0u8; 1500];
    let (len, _) = tokio::select! {
        r = conn.recv_from(&mut buf) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("timeout"),
    };

    let mut resp = Message::new();
    resp.raw = buf[..len].to_vec();
    resp.decode().unwrap();

    let mut xaddr = XorMappedAddress::default();
    xaddr.get_from(&resp).expect("parse XOR-MAPPED-ADDRESS");

    assert_eq!(
        xaddr.port,
        local_addr.port(),
        "mapped port should match local port: got {}, expected {}",
        xaddr.port,
        local_addr.port()
    );
}

// ── 9. Verify 401 error response is parseable by stun crate ───────────────

#[tokio::test]
async fn turn_401_error_response_parseable_by_stun_crate() {
    use stun::agent::TransactionId;
    use stun::attributes::{ATTR_NONCE, ATTR_REALM};
    use stun::error_code::ErrorCodeAttribute;
    use stun::message::*;

    let realm = "test-realm";
    let (server_addr, _) = start_server("127.0.0.1", realm, "password").await;
    let (conn, _) = bind_udp().await;

    // Build a raw Allocate Request WITHOUT credentials (anonymous)
    let mut msg = Message::new();
    msg.build(&[
        Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)),
        Box::new(TransactionId::new()),
    ])
    .unwrap();

    conn.send_to(&msg.raw, server_addr).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    let mut buf = vec![0u8; 1500];
    let (len, _) = tokio::select! {
        r = conn.recv_from(&mut buf) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("timeout"),
    };

    let mut resp = Message::new();
    resp.raw = buf[..len].to_vec();
    resp.decode().unwrap();

    // Must be Allocate Error
    assert_eq!(resp.typ.method, METHOD_ALLOCATE);
    assert_eq!(resp.typ.class, CLASS_ERROR_RESPONSE);

    // Parse ERROR-CODE
    let mut ec = ErrorCodeAttribute::default();
    ec.get_from(&resp).expect("should parse ERROR-CODE");
    assert_eq!(
        ec.code.0, 401,
        "expected 401 Unauthorized, got {}",
        ec.code.0
    );

    // Verify REALM and NONCE are present
    resp.get(ATTR_REALM).expect("REALM attribute missing");
    resp.get(ATTR_NONCE).expect("NONCE attribute missing");
}

// ── 10. Fingerprint check on binding response ──────────────────────────────

#[tokio::test]
async fn stun_binding_message_format_valid() {
    use stun::agent::TransactionId;
    use stun::message::*;

    let (server_addr, _) = start_server_no_auth("0.0.0.0", "test").await;
    let (conn, _) = bind_udp().await;

    let mut msg = Message::new();
    msg.build(&[Box::new(BINDING_REQUEST), Box::new(TransactionId::new())])
        .unwrap();

    conn.send_to(&msg.raw, server_addr).await.unwrap();
    sleep(Duration::from_millis(50)).await;

    let mut buf = vec![0u8; 1500];
    let (len, _) = tokio::select! {
        r = conn.recv_from(&mut buf) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("timeout"),
    };

    // Verify the raw bytes form a valid STUN message
    assert!(len >= 20, "too short: {}", len);
    // Magic cookie at bytes 4-7
    assert_eq!(&buf[4..8], &[0x21, 0x12, 0xA4, 0x42], "bad magic cookie");
    // Message length should match
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    assert_eq!(
        20 + msg_len,
        len,
        "message length field mismatch: header says {}, actual {}",
        msg_len,
        len - 20
    );
}

// ── 11. Full TURN data relay: Allocate → CreatePermission → ChannelBind → ChannelData ──
// Raw STUN, auth disabled, step by step — verifies actual data delivery to peer.

#[tokio::test]
async fn turn_full_data_relay_raw() {
    let (server_addr, _) = start_server_no_auth("127.0.0.1", "test").await;
    let (conn, _client_addr) = bind_udp().await;

    // === Step 1: Allocate (raw) ===
    // Allocate Request: method=0x003, class=Request(0) → encoded 0x0003
    let mut alloc_req = Vec::new();
    alloc_req.extend_from_slice(&[0x00, 0x03]); // type
    alloc_req.extend_from_slice(&[0x00, 0x00]); // length
    alloc_req.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
    alloc_req.extend_from_slice(&[0x01; 12]); // transaction id

    conn.send_to(&alloc_req, server_addr).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    let mut buf = vec![0u8; 1500];
    let (len, _) = tokio::select! {
        r = conn.recv_from(&mut buf) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("timeout on Allocate"),
    };

    // Decode Allocate Success: 0x0103
    let resp_type = u16::from_be_bytes([buf[0], buf[1]]);
    assert_eq!(resp_type, 0x0103, "expected Allocate Success (0x0103), got 0x{:04x}", resp_type);

    // Parse XOR-RELAYED-ADDRESS (attr type 0x0016)
    let mut relay_addr: Option<SocketAddr> = None;
    let mut offset = 20usize;
    let attr_end = 20 + u16::from_be_bytes([buf[2], buf[3]]) as usize;
    while offset + 4 <= attr_end {
        let a_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let a_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        if a_type == 0x0016 && offset + 4 + a_len <= len {
            let port = u16::from_be_bytes([buf[offset + 6], buf[offset + 7]]) ^ 0x2112;
            let ip0 = buf[offset + 8] ^ 0x21;
            let ip1 = buf[offset + 9] ^ 0x12;
            let ip2 = buf[offset + 10] ^ 0xA4;
            let ip3 = buf[offset + 11] ^ 0x42;
            relay_addr = Some(format!("{}.{}.{}.{}:{}", ip0, ip1, ip2, ip3, port).parse().unwrap());
            break;
        }
        offset += 4 + a_len;
        offset += (4 - (a_len % 4)) % 4;
    }
    let relay_addr = relay_addr.expect("no XOR-RELAYED-ADDRESS");
    eprintln!("[TEST] Allocate OK, relay={}", relay_addr);

    // === Step 2: CreatePermission (raw) ===
    // CreatePermission: method=0x008, class=Request(0) → encoded 0x0008
    let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer_socket.local_addr().unwrap();
    let peer_ip = peer_addr.ip().to_string().parse::<std::net::Ipv4Addr>().unwrap();

    let xor_peer_port = (peer_addr.port() ^ 0x2112).to_be_bytes();
    let xor_peer_ip = [
        peer_ip.octets()[0] ^ 0x21,
        peer_ip.octets()[1] ^ 0x12,
        peer_ip.octets()[2] ^ 0xA4,
        peer_ip.octets()[3] ^ 0x42,
    ];

    // Build XOR-PEER-ADDRESS attribute value
    let mut peer_addr_val = Vec::new();
    peer_addr_val.push(0x00); // reserved
    peer_addr_val.push(0x01); // IPv4
    peer_addr_val.extend_from_slice(&xor_peer_port);
    peer_addr_val.extend_from_slice(&xor_peer_ip);

    // Pad attribute to 4 bytes
    while peer_addr_val.len() % 4 != 0 {
        peer_addr_val.push(0);
    }

    let attrs_len = 4 + peer_addr_val.len(); // attr header(4) + value
    let mut perm_req = Vec::new();
    perm_req.extend_from_slice(&[0x00, 0x08]); // CreatePermission Request
    perm_req.extend_from_slice(&(attrs_len as u16).to_be_bytes());
    perm_req.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
    perm_req.extend_from_slice(&[0x02; 12]); // transaction id
    // XOR-PEER-ADDRESS attribute
    perm_req.extend_from_slice(&[0x00, 0x12]); // attr type
    let raw_val_len = 8u16; // the actual value is 8 bytes (before padding)
    perm_req.extend_from_slice(&raw_val_len.to_be_bytes());
    perm_req.extend_from_slice(&peer_addr_val);

    conn.send_to(&perm_req, server_addr).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    let mut buf2 = vec![0u8; 1500];
    let (_len2, _) = tokio::select! {
        r = conn.recv_from(&mut buf2) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("timeout on CreatePermission"),
    };

    // CreatePermission Success: method=0x008, class=Success(2) → 0x0108
    let perm_type = u16::from_be_bytes([buf2[0], buf2[1]]);
    assert_eq!(perm_type, 0x0108, "expected CreatePermission Success (0x0108), got 0x{:04x}", perm_type);
    eprintln!("[TEST] CreatePermission OK");

    // === Step 3: ChannelBind (raw) ===
    // ChannelBind: method=0x009, class=Request(0) → encoded 0x0009
    let channel_num: u16 = 0x4001;

    // Build XOR-PEER-ADDRESS attr (same as above)
    let peer_attr_val2 = peer_addr_val.clone();

    // Build CHANNEL-NUMBER attr
    let mut ch_num_val = Vec::new();
    ch_num_val.extend_from_slice(&channel_num.to_be_bytes());
    ch_num_val.extend_from_slice(&[0x00, 0x00]); // RFFC 5766: 2 bytes channel + 2 bytes padding

    let bind_attrs_len = (4 + peer_attr_val2.len()) + (4 + ch_num_val.len());
    let mut bind_req = Vec::new();
    bind_req.extend_from_slice(&[0x00, 0x09]); // ChannelBind Request
    bind_req.extend_from_slice(&(bind_attrs_len as u16).to_be_bytes());
    bind_req.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    bind_req.extend_from_slice(&[0x03; 12]);
    // XOR-PEER-ADDRESS
    bind_req.extend_from_slice(&[0x00, 0x12]);
    bind_req.extend_from_slice(&raw_val_len.to_be_bytes());
    bind_req.extend_from_slice(&peer_attr_val2);
    // CHANNEL-NUMBER
    bind_req.extend_from_slice(&[0x00, 0x0C]); // attr type
    bind_req.extend_from_slice(&4u16.to_be_bytes()); // attr length
    bind_req.extend_from_slice(&ch_num_val);

    conn.send_to(&bind_req, server_addr).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    let mut buf3 = vec![0u8; 1500];
    let (_len3, _) = tokio::select! {
        r = conn.recv_from(&mut buf3) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("timeout on ChannelBind"),
    };

    // ChannelBind Success: method=0x009, class=Success(2) → 0x0109
    let bind_type = u16::from_be_bytes([buf3[0], buf3[1]]);
    assert_eq!(bind_type, 0x0109, "expected ChannelBind Success (0x0109), got 0x{:04x}", bind_type);
    eprintln!("[TEST] ChannelBind OK, channel=0x{:04x}", channel_num);

    // === Step 4: Send ChannelData ===
    let test_data = b"hello TURN relay!";

    // ChannelData format: channel(2) + length(2) + data
    let mut channel_data = Vec::new();
    channel_data.extend_from_slice(&channel_num.to_be_bytes());
    channel_data.extend_from_slice(&(test_data.len() as u16).to_be_bytes());
    channel_data.extend_from_slice(test_data);

    eprintln!("[TEST] Sending ChannelData {} bytes", channel_data.len());
    conn.send_to(&channel_data, server_addr).await.unwrap();

    // === Step 5: Verify peer receives data ===
    let mut peer_buf = [0u8; 1500];
    let (peer_len, peer_from) = tokio::select! {
        r = peer_socket.recv_from(&mut peer_buf) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("Peer did NOT receive data — data relay is broken"),
    };

    eprintln!("[TEST] Peer received {} bytes from {}", peer_len, peer_from);
    assert_eq!(&peer_buf[..peer_len], test_data, "data content mismatch");
    assert_eq!(peer_from, relay_addr, "data should come from relay addr {}, got {}", relay_addr, peer_from);
    eprintln!("[TEST] Full TURN data relay verified!");
}

// ── 12. Peer -> client relay must be TURN Data Indication ─────────────────

#[tokio::test]
async fn turn_peer_to_client_is_data_indication() {
    let (server_addr, _) = start_server_no_auth("127.0.0.1", "test").await;
    let (conn, _client_addr) = bind_udp().await;

    // Allocate Request
    let mut alloc_req = Vec::new();
    alloc_req.extend_from_slice(&[0x00, 0x03]);
    alloc_req.extend_from_slice(&[0x00, 0x00]);
    alloc_req.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    alloc_req.extend_from_slice(&[0x11; 12]);

    conn.send_to(&alloc_req, server_addr).await.unwrap();
    sleep(Duration::from_millis(100)).await;

    let mut buf = vec![0u8; 1500];
    let (len, _) = tokio::select! {
        r = conn.recv_from(&mut buf) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("timeout on Allocate"),
    };

    let mut relay_addr: Option<SocketAddr> = None;
    let mut offset = 20usize;
    let attr_end = 20 + u16::from_be_bytes([buf[2], buf[3]]) as usize;
    while offset + 4 <= attr_end {
        let a_type = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let a_len = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        if a_type == 0x0016 && offset + 4 + a_len <= len {
            let port = u16::from_be_bytes([buf[offset + 6], buf[offset + 7]]) ^ 0x2112;
            let ip0 = buf[offset + 8] ^ 0x21;
            let ip1 = buf[offset + 9] ^ 0x12;
            let ip2 = buf[offset + 10] ^ 0xA4;
            let ip3 = buf[offset + 11] ^ 0x42;
            relay_addr = Some(format!("{}.{}.{}.{}:{}", ip0, ip1, ip2, ip3, port).parse().unwrap());
            break;
        }
        offset += 4 + a_len;
        offset += (4 - (a_len % 4)) % 4;
    }
    let relay_addr = relay_addr.expect("no XOR-RELAYED-ADDRESS");

    let peer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer_socket.local_addr().unwrap();
    let payload = b"peer-to-client-via-turn";
    peer_socket.send_to(payload, relay_addr).await.unwrap();

    let mut recv = vec![0u8; 2048];
    let (recv_len, _from) = tokio::select! {
        r = conn.recv_from(&mut recv) => r.unwrap(),
        _ = sleep(Duration::from_secs(2)) => panic!("timeout waiting for Data Indication"),
    };

    let msg = miuturn::message::Message::parse(&recv[..recv_len]).expect("expected STUN Data Indication");
    assert_eq!(msg.header.method, miuturn::message::Method::Data);
    assert_eq!(msg.header.event_type, miuturn::message::EventType::Indication);

    let peer_attr = msg
        .get_attribute(miuturn::message::Attribute::PEER_ADDRESS)
        .expect("missing XOR-PEER-ADDRESS");
    let decoded_peer = miuturn::message::decode_xor_address(
        &peer_attr.value,
        0x2112A442,
        &msg.header.transaction_id,
    )
    .expect("decode XOR-PEER-ADDRESS");
    assert_eq!(decoded_peer, peer_addr);

    let data_attr = msg
        .get_attribute(miuturn::message::Attribute::DATA)
        .expect("missing DATA attr");
    assert_eq!(&data_attr.value[..], payload);
}

// ── 13. Auth with per-user password ────────────────────────────────────────

#[tokio::test]
async fn turn_allocate_with_auth_manager_per_user_password() {
    use miuturn::{AuthManager, User, UserType};

    let realm = "test-realm";
    let relay_addr: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
    let port = pick_free_udp_port();
    let (min_relay, max_relay) = next_relay_range();

    let mut server = TurnServer::with_port_range_and_password(
        relay_addr,
        realm.to_string(),
        min_relay,
        max_relay,
        "wrong-password".to_string(), // global password is wrong
    );

    // Set up auth manager with the correct user
    let auth_manager = std::sync::Arc::new(AuthManager::new(realm.to_string()));
    auth_manager.add_user(User {
        username: "testuser".to_string(),
        password: "user-password".to_string(),
        user_type: UserType::Fixed,
        created_at: 0,
        expires_at: None,
        max_allocations: 10,
        bandwidth_limit: None,
        ip_whitelist: None,
        max_allocation_duration_secs: None,
    });
    server.set_auth_manager(auth_manager);

    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let srv = server.clone();
    tokio::spawn(async move {
        let _ = srv.run_udp(addr).await;
    });
    wait_server_ready(addr).await;

    let (conn, _) = bind_udp().await;
    let config = client_config(addr, "testuser", "user-password", realm, conn);
    let client = turn::client::Client::new(config)
        .await
        .expect("client create");
    client.listen().await.expect("listen");

    let result = client.allocate().await;
    assert!(
        result.is_ok(),
        "allocate should succeed with per-user password: {:?}",
        result.err()
    );

    let _ = client.close().await;
}
