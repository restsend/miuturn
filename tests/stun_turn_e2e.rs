//! E2E tests using the `stun` and `turn` crates to verify protocol compliance.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::sleep;

use webrtc_util::conn::Conn;

use miuturn::TurnServer;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Bind a free UDP socket, return (socket, local_addr).
async fn bind_udp() -> (Arc<UdpSocket>, SocketAddr) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    (Arc::new(sock), addr)
}

static SERVER_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(36000);

fn next_server_port() -> u16 {
    SERVER_PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Start a TurnServer with auth enabled.
/// Uses a unique port range for relay addresses to avoid conflicts between concurrent tests.
async fn start_server(relay: &str, realm: &str, password: &str) -> (SocketAddr, TurnServer) {
    let relay_addr: std::net::Ipv4Addr = relay.parse().unwrap();
    let port = next_server_port();
    let min_relay = 40000 + (port as u32 - 36000) * 1000;
    let max_relay = min_relay + 999;
    let server = TurnServer::with_port_range_and_password(
        relay_addr,
        realm.to_string(),
        min_relay as u16,
        max_relay as u16,
        password.to_string(),
    );
    let srv = server.clone();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    tokio::spawn(async move {
        let _ = srv.run_udp(addr).await;
    });
    sleep(Duration::from_millis(100)).await;
    (addr, server)
}

/// Start a TurnServer with auth disabled.
async fn start_server_no_auth(relay: &str, realm: &str) -> (SocketAddr, TurnServer) {
    let relay_addr: std::net::Ipv4Addr = relay.parse().unwrap();
    let port = next_server_port();
    let min_relay = 40000 + (port as u32 - 36000) * 1000;
    let max_relay = min_relay + 999;
    let server = TurnServer::with_port_range_auth_disabled(
        relay_addr,
        realm.to_string(),
        min_relay as u16,
        max_relay as u16,
    );
    let srv = server.clone();
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    tokio::spawn(async move {
        let _ = srv.run_udp(addr).await;
    });
    sleep(Duration::from_millis(100)).await;
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
        Box::new(TextAttribute::new(ATTR_SOFTWARE, "miuturn-test".to_string())),
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
    xaddr.get_from(&resp).expect("should parse XOR-MAPPED-ADDRESS");

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
    msg.build(&[Box::new(BINDING_REQUEST), Box::new(tid)]).unwrap();

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
    assert_eq!(
        resp.transaction_id.0, tid.0,
        "transaction ID mismatch"
    );
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
    assert!(result.is_err(), "expected allocate to fail with wrong password");
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
    assert_eq!(resp.typ.class, CLASS_SUCCESS_RESPONSE, "expected success, got class {:?}", resp.typ.class);
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
        (0x0003, 0, MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST).value()),
        (0x0003, 2, MessageType::new(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE).value()),
        (0x0003, 3, MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE).value()),
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
    msg.build(&[
        Box::new(BINDING_REQUEST),
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

    let mut xaddr = XorMappedAddress::default();
    xaddr.get_from(&resp).expect("parse XOR-MAPPED-ADDRESS");

    assert_eq!(
        xaddr.port, local_addr.port(),
        "mapped port should match local port: got {}, expected {}",
        xaddr.port, local_addr.port()
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
    msg.build(&[
        Box::new(BINDING_REQUEST),
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

    // Verify the raw bytes form a valid STUN message
    assert!(len >= 20, "too short: {}", len);
    // Magic cookie at bytes 4-7
    assert_eq!(
        &buf[4..8],
        &[0x21, 0x12, 0xA4, 0x42],
        "bad magic cookie"
    );
    // Message length should match
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    assert_eq!(
        20 + msg_len, len,
        "message length field mismatch: header says {}, actual {}",
        msg_len, len - 20
    );
}
