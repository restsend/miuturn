//! Reproduction of the vendor case a1368cfd (call interrupted ~13s after
//! answer, `timed out waiting for WebRTC DTLS/SRTP setup after 5s`).
//!
//! Topology: miuturn behind 1:1 NAT. `external_ip` is a public VIP that is
//! NOT assigned to the machine, relay sockets bind 0.0.0.0. Both media ends
//! (rustpbx leg + restsend-pc) allocate on this server and ICE nominates the
//! relay↔relay pair, so packets between the two allocations hairpin through
//! the NAT and come back with the machine's internal interface IP as source —
//! an address the receiving client never permissioned. The permission check
//! dropped the PBX→client direction, the DTLS handshake starved, and both
//! watchdogs hung the call up.
//!
//! This test drives the REAL wire protocol (raw STUN Allocate /
//! CreatePermission / Send indication) against a running server configured
//! exactly like the field deployment, and asserts the relay↔relay path is
//! bidirectional with XOR-PEER-ADDRESS values matching the advertised
//! (SDP-visible) relay candidates.
//!
//! RED before the fix (B receives nothing — the packet hairpinned out to the
//! unroutable VIP / arrived with a non-permitted internal source), GREEN after
//! (same-server internal delivery with advertised source addresses).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket as StdUdp};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use miuturn::TurnServer;

/// TEST-NET-2 — guaranteed not assigned to the test host (mirrors the field
/// 1:1 NAT VIP `117.51.133.203`).
const VIP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const MAGIC: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

fn stun_header(msg_type: u16, body: &[u8], tx_id: [u8; 12]) -> Vec<u8> {
    let mut m = Vec::with_capacity(20 + body.len());
    m.extend_from_slice(&msg_type.to_be_bytes());
    m.extend_from_slice(&(body.len() as u16).to_be_bytes());
    m.extend_from_slice(&MAGIC);
    m.extend_from_slice(&tx_id);
    m.extend_from_slice(body);
    m
}

fn tlv(attr_type: u16, value: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(4 + value.len());
    t.extend_from_slice(&attr_type.to_be_bytes());
    t.extend_from_slice(&(value.len() as u16).to_be_bytes());
    t.extend_from_slice(value);
    let pad = (4 - (value.len() % 4)) % 4;
    t.extend(std::iter::repeat(0u8).take(pad));
    t
}

fn xor_peer_address(addr: SocketAddr, tx_id: [u8; 12]) -> Vec<u8> {
    let mut v = vec![0u8, 0x01];
    let SocketAddr::V4(v4) = addr else {
        panic!("IPv6 not exercised by this test");
    };
    let _ = tx_id; // IPv4 XOR uses the magic cookie only
    v.extend_from_slice(&(v4.port() ^ (0x2112A442u32 >> 16) as u16).to_be_bytes());
    let o = v4.ip().octets();
    v.push(o[0] ^ MAGIC[0]);
    v.push(o[1] ^ MAGIC[1]);
    v.push(o[2] ^ MAGIC[2]);
    v.push(o[3] ^ MAGIC[3]);
    v
}

fn parse_tlvs(buf: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    if buf.len() < 20 {
        return out;
    }
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let end = (20 + msg_len).min(buf.len());
    let mut off = 20;
    while off + 4 <= end {
        let t = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let l = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        if off + 4 + l > end {
            break;
        }
        out.push((t, buf[off + 4..off + 4 + l].to_vec()));
        off += 4 + l + ((4 - (l % 4)) % 4);
    }
    out
}

fn xor_v4_decode(raw: &[u8]) -> SocketAddr {
    let xport = u16::from_be_bytes([raw[2], raw[3]]) ^ (0x2112A442u32 >> 16) as u16;
    let ip = Ipv4Addr::new(
        raw[4] ^ MAGIC[0],
        raw[5] ^ MAGIC[1],
        raw[6] ^ MAGIC[2],
        raw[7] ^ MAGIC[3],
    );
    SocketAddr::new(ip.into(), xport)
}

fn attr<'a>(tlvs: &'a [(u16, Vec<u8>)], attr_type: u16) -> Option<&'a [u8]> {
    tlvs.iter().find(|(t, _)| *t == attr_type).map(|(_, v)| v.as_slice())
}

async fn allocate(sock: &UdpSocket, server_addr: SocketAddr) -> SocketAddr {
    let tx_id = rand_tx();
    let msg = stun_header(0x0003, &[], tx_id); // Allocate request
    sock.send_to(&msg, server_addr).await.unwrap();

    let mut buf = vec![0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .expect("Allocate response")
        .unwrap();
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0x0103, "Allocate success");

    let tlvs = parse_tlvs(&buf[..len]);
    let relayed = attr(&tlvs, 0x0016).expect("XOR-RELAYED-ADDRESS present");
    let relayed = xor_v4_decode(relayed);
    assert_eq!(relayed.ip(), VIP, "relayed address must advertise the VIP");
    relayed
}

async fn create_permission(sock: &UdpSocket, server_addr: SocketAddr, peer: SocketAddr) {
    let tx_id = rand_tx();
    let body = tlv(0x0012 /* XOR-PEER-ADDRESS */, &xor_peer_address(peer, tx_id));
    let msg = stun_header(0x0008, &body, tx_id); // CreatePermission request
    sock.send_to(&msg, server_addr).await.unwrap();

    let mut buf = vec![0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .expect("CreatePermission response")
        .unwrap();
    assert_eq!(
        u16::from_be_bytes([buf[0], buf[1]]),
        0x0108,
        "CreatePermission success"
    );
}

async fn send_indication(sock: &UdpSocket, server_addr: SocketAddr, peer: SocketAddr, payload: &[u8]) {
    let tx_id = rand_tx();
    let mut body = tlv(0x0012 /* XOR-PEER-ADDRESS */, &xor_peer_address(peer, tx_id));
    body.extend(tlv(0x0013 /* DATA */, payload));
    let msg = stun_header(0x0016, &body, tx_id); // Send indication
    sock.send_to(&msg, server_addr).await.unwrap();
}

fn rand_tx() -> [u8; 12] {
    let s = StdUdp::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    let mut tx = [0u8; 12];
    for (i, b) in tx.iter_mut().enumerate() {
        *b = ((port >> (i % 8)) as u8).wrapping_mul(37).wrapping_add(i as u8 * 11);
    }
    tx
}

#[tokio::test]
async fn same_server_relay_relay_is_bidirectional_on_advertised_addresses() {
    // Field config: external VIP not on the machine, relay bind 0.0.0.0.
    let server = TurnServer::with_port_range_limits_bind_address_and_password(
        VIP,
        Ipv4Addr::UNSPECIFIED,
        "test".to_string(),
        58100,
        58199,
        None,
        None,
        None,
        String::new(),
        true, // auth disabled, like tests/e2e_turn_test.rs
    );

    let server_addr: SocketAddr = "127.0.0.1:3591".parse().unwrap();
    let handle = tokio::spawn({
        let server = server.clone();
        async move {
            if let Err(e) = server.run_udp(server_addr).await {
                eprintln!("server error: {e}");
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    // rustpbx leg and restsend-pc allocate on the same server.
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relayed_a = allocate(&sock_a, server_addr).await;
    let relayed_b = allocate(&sock_b, server_addr).await;
    assert_ne!(relayed_a, relayed_b);

    // Each side permissions the peer's ADVERTISED (SDP-visible) relay candidate.
    create_permission(&sock_a, server_addr, relayed_b).await;
    create_permission(&sock_b, server_addr, relayed_a).await;

    // A → B: a DTLS ClientHello flight.
    send_indication(&sock_a, server_addr, relayed_b, b"clienthello-from-a").await;

    let mut buf = vec![0u8; 2048];
    let (len, _) = timeout(Duration::from_secs(3), sock_b.recv_from(&mut buf))
        .await
        .expect(
            "relay↔relay through one server must be bidirectional: \
             A→B must arrive at B as a Data indication",
        )
        .unwrap();
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0x0017, "Data indication");
    let tlvs = parse_tlvs(&buf[..len]);
    let peer = attr(&tlvs, 0x0012).expect("XOR-PEER-ADDRESS");
    assert_eq!(xor_v4_decode(peer), relayed_a, "source = A's advertised relay");
    let data = attr(&tlvs, 0x0013).expect("DATA");
    assert_eq!(data, b"clienthello-from-a", "payload intact");

    // B → A: the ServerHello flight — the direction that died in the field.
    send_indication(&sock_b, server_addr, relayed_a, b"serverhello-from-b").await;

    let (len, _) = timeout(Duration::from_secs(3), sock_a.recv_from(&mut buf))
        .await
        .expect("B→A must also arrive (field case died exactly here)")
        .unwrap();
    assert_eq!(u16::from_be_bytes([buf[0], buf[1]]), 0x0017, "Data indication");
    let tlvs = parse_tlvs(&buf[..len]);
    let peer = attr(&tlvs, 0x0012).expect("XOR-PEER-ADDRESS");
    assert_eq!(xor_v4_decode(peer), relayed_b, "source = B's advertised relay");
    let data = attr(&tlvs, 0x0013).expect("DATA");
    assert_eq!(data, b"serverhello-from-b");

    handle.abort();
}
