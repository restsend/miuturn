//! Integration test: use rustrtc PeerConnection with TURN relay against miuturn.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use miuturn::TurnServer;
use rustrtc::{
    IceCandidateType, IceCredentialType, IceServer, IceTransportPolicy, PeerConnection,
    RtcConfiguration,
};
use tokio::time::{sleep, timeout};

fn pick_free_udp_port() -> u16 {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind temp udp socket");
    sock.local_addr().expect("temp udp local addr").port()
}

async fn wait_server_ready(server_addr: SocketAddr) {
    let probe_socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind probe socket");
    let request: [u8; 20] = [
        0x00, 0x01, 0x00, 0x00, // Binding Request
        0x21, 0x12, 0xA4, 0x42, // Magic cookie
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
    ];

    for _ in 0..40 {
        let _ = probe_socket.send_to(&request, server_addr).await;
        let mut buf = [0u8; 1500];
        let recv = timeout(Duration::from_millis(100), probe_socket.recv_from(&mut buf)).await;
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

static RELAY_BASE: AtomicU16 = AtomicU16::new(25000);

async fn start_turn_server() -> (SocketAddr, TurnServer) {
    let relay_addr: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
    let port = pick_free_udp_port();
    let base = RELAY_BASE.fetch_add(200, Ordering::SeqCst);
    let server = TurnServer::with_port_range_and_password(
        relay_addr,
        "test-realm".to_string(),
        base,
        base + 199,
        "testpass".to_string(),
    );
    let addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();
    let srv = server.clone();
    tokio::spawn(async move {
        let _ = srv.run_udp(addr).await;
    });
    wait_server_ready(addr).await;
    (addr, server)
}

fn turn_config(turn_addr: SocketAddr) -> RtcConfiguration {
    let ice_server = IceServer {
        urls: vec![format!("turn:{}", turn_addr)],
        username: Some("admin".to_string()),
        credential: Some("testpass".to_string()),
        credential_type: IceCredentialType::Password,
    };
    let mut config = RtcConfiguration::default();
    config.ice_servers = vec![ice_server];
    config.ice_transport_policy = IceTransportPolicy::Relay;
    config
}

/// Exchange SDP between two rustrtc PeerConnections.
async fn exchange_sdp(
    offerer: &PeerConnection,
    answerer: &PeerConnection,
) -> anyhow::Result<()> {
    // Offerer
    let _ = offerer.create_offer().await?;
    loop {
        if offerer.ice_transport().gather_state() == rustrtc::transports::ice::IceGathererState::Complete {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let offer = offerer.create_offer().await?;
    offerer.set_local_description(offer.clone())?;

    // Answerer
    answerer.set_remote_description(offer).await?;
    let _ = answerer.create_answer().await?;
    loop {
        if answerer.ice_transport().gather_state() == rustrtc::transports::ice::IceGathererState::Complete {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let answer = answerer.create_answer().await?;
    answerer.set_local_description(answer.clone())?;

    offerer.set_remote_description(answer).await?;
    Ok(())
}

#[tokio::test]
async fn rustrtc_turn_relay_data_channel() -> anyhow::Result<()> {
    // rustrtc initialises its own crypto provider internally; no explicit install needed.

    let (turn_addr, _server) = start_turn_server().await;

    let config = turn_config(turn_addr);

    let pc_a = PeerConnection::new(config.clone());
    let pc_b = PeerConnection::new(config);

    // Negotiated data channel (ID 0) so both sides know it immediately.
    let dc_a = pc_a.create_data_channel(
        "turn-test",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    let dc_b = pc_b.create_data_channel(
        "turn-test",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    exchange_sdp(&pc_a, &pc_b).await?;

    // Wait for ICE connection (which requires working TURN relay).
    timeout(Duration::from_secs(15), pc_a.wait_for_connected()).await??;
    timeout(Duration::from_secs(15), pc_b.wait_for_connected()).await??;

    // Verify that both sides selected a relay candidate pair.
    let pair_a = pc_a
        .ice_transport()
        .subscribe_selected_pair()
        .borrow()
        .clone();
    let pair_b = pc_b
        .ice_transport()
        .subscribe_selected_pair()
        .borrow()
        .clone();

    let pair_a = pair_a.expect("pc_a should have a selected ICE pair");
    let pair_b = pair_b.expect("pc_b should have a selected ICE pair");

    assert_eq!(
        pair_a.local.typ, IceCandidateType::Relay,
        "pc_a local candidate should be relay, got {:?}", pair_a.local.typ
    );
    assert_eq!(
        pair_b.local.typ, IceCandidateType::Relay,
        "pc_b local candidate should be relay, got {:?}", pair_b.local.typ
    );

    // Allow DTLS/SCTP handshake to settle.
    sleep(Duration::from_millis(500)).await;

    // Record server relay stats before data transfer.
    let stats_before = _server.stats();

    // A -> B
    let msg_a = b"hello from A via TURN";
    pc_a.send_data(0, msg_a).await?;

    let mut received_b = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if let Ok(Some(event)) = timeout(Duration::from_millis(200), dc_b.recv()).await {
            match event {
                rustrtc::transports::sctp::DataChannelEvent::Message(data) => {
                    assert_eq!(&data[..], &msg_a[..], "B received wrong data");
                    received_b = true;
                    break;
                }
                _ => {}
            }
        }
    }
    assert!(received_b, "B did not receive data from A");

    // B -> A
    let msg_b = b"hello from B via TURN";
    pc_b.send_data(0, msg_b).await?;

    let mut received_a = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if let Ok(Some(event)) = timeout(Duration::from_millis(200), dc_a.recv()).await {
            match event {
                rustrtc::transports::sctp::DataChannelEvent::Message(data) => {
                    assert_eq!(&data[..], &msg_b[..], "A received wrong data");
                    received_a = true;
                    break;
                }
                _ => {}
            }
        }
    }
    assert!(received_a, "A did not receive data from B");

    // Verify that the TURN server actually relayed bytes.
    let stats_after = _server.stats();
    assert!(
        stats_after.total_bytes_relayed > stats_before.total_bytes_relayed,
        "TURN server did not relay any bytes: before={}, after={}",
        stats_before.total_bytes_relayed,
        stats_after.total_bytes_relayed
    );
    assert!(
        stats_after.total_messages > stats_before.total_messages,
        "TURN server did not relay any messages: before={}, after={}",
        stats_before.total_messages,
        stats_after.total_messages
    );
    println!(
        "Confirmed TURN relay: bytes_relayed={} (delta={}), messages={} (delta={})",
        stats_after.total_bytes_relayed,
        stats_after.total_bytes_relayed - stats_before.total_bytes_relayed,
        stats_after.total_messages,
        stats_after.total_messages - stats_before.total_messages,
    );

    pc_a.close();
    pc_b.close();

    Ok(())
}

/// Simple LCG pseudo-random generator for deterministic payloads.
fn generate_payload(seed: u64, len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    let mut state = seed;
    for b in &mut data {
        state = state.wrapping_mul(1103515245).wrapping_add(12345);
        *b = (state >> 24) as u8;
    }
    data
}

#[tokio::test]
async fn rustrtc_turn_relay_data_channel_consistency() -> anyhow::Result<()> {
    let (turn_addr, _server) = start_turn_server().await;
    let config = turn_config(turn_addr);

    let pc_a = PeerConnection::new(config.clone());
    let pc_b = PeerConnection::new(config);

    let dc_a = pc_a.create_data_channel(
        "consistency-test",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    let dc_b = pc_b.create_data_channel(
        "consistency-test",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    exchange_sdp(&pc_a, &pc_b).await?;

    timeout(Duration::from_secs(15), pc_a.wait_for_connected()).await??;
    timeout(Duration::from_secs(15), pc_b.wait_for_connected()).await??;

    // Verify relay candidates are selected.
    let pair_a = pc_a
        .ice_transport()
        .subscribe_selected_pair()
        .borrow()
        .clone();
    let pair_b = pc_b
        .ice_transport()
        .subscribe_selected_pair()
        .borrow()
        .clone();
    let pair_a = pair_a.expect("pc_a should have a selected ICE pair");
    let pair_b = pair_b.expect("pc_b should have a selected ICE pair");
    assert_eq!(pair_a.local.typ, IceCandidateType::Relay);
    assert_eq!(pair_b.local.typ, IceCandidateType::Relay);

    sleep(Duration::from_millis(500)).await;

    // Build payloads: varying sizes including small, medium, large.
    let sizes_a: Vec<usize> = vec![64, 1024, 4096, 16384, 32768, 65535];
    let sizes_b: Vec<usize> = vec![128, 512, 8192, 15000, 45000];

    let payloads_a: Vec<Vec<u8>> = sizes_a
        .iter()
        .enumerate()
        .map(|(i, &size)| generate_payload(0xA5A5_A5A5_u64.wrapping_add(i as u64), size))
        .collect();
    let payloads_b: Vec<Vec<u8>> = sizes_b
        .iter()
        .enumerate()
        .map(|(i, &size)| generate_payload(0x5A5A_5A5A_u64.wrapping_add(i as u64), size))
        .collect();

    // Spawn receiver tasks.
    let expected_count_a = payloads_a.len();
    let expected_count_b = payloads_b.len();

    let recv_b = tokio::spawn(async move {
        let mut received: Vec<Vec<u8>> = Vec::with_capacity(expected_count_a);
        let start = std::time::Instant::now();
        while received.len() < expected_count_a && start.elapsed() < Duration::from_secs(30) {
            if let Ok(Some(event)) = timeout(Duration::from_millis(200), dc_b.recv()).await {
                match event {
                    rustrtc::transports::sctp::DataChannelEvent::Message(data) => {
                        received.push(data.to_vec());
                    }
                    _ => {}
                }
            }
        }
        received
    });

    let recv_a = tokio::spawn(async move {
        let mut received: Vec<Vec<u8>> = Vec::with_capacity(expected_count_b);
        let start = std::time::Instant::now();
        while received.len() < expected_count_b && start.elapsed() < Duration::from_secs(30) {
            if let Ok(Some(event)) = timeout(Duration::from_millis(200), dc_a.recv()).await {
                match event {
                    rustrtc::transports::sctp::DataChannelEvent::Message(data) => {
                        received.push(data.to_vec());
                    }
                    _ => {}
                }
            }
        }
        received
    });

    // Send all payloads.
    for payload in &payloads_a {
        pc_a.send_data(0, payload).await?;
    }
    for payload in &payloads_b {
        pc_b.send_data(0, payload).await?;
    }

    // Wait for receivers.
    let received_b = recv_b.await?;
    let received_a = recv_a.await?;

    // Verify counts.
    assert_eq!(
        received_b.len(),
        payloads_a.len(),
        "B did not receive all messages from A"
    );
    assert_eq!(
        received_a.len(),
        payloads_b.len(),
        "A did not receive all messages from B"
    );

    // Verify exact byte-for-byte consistency and order.
    for (i, (sent, recv)) in payloads_a.iter().zip(received_b.iter()).enumerate() {
        assert_eq!(
            sent.len(),
            recv.len(),
            "Payload {} from A->B size mismatch: sent={}, received={}",
            i,
            sent.len(),
            recv.len()
        );
        assert_eq!(
            sent[..],
            recv[..],
            "Payload {} from A->B data mismatch (first byte diff may indicate corruption)",
            i
        );
    }

    for (i, (sent, recv)) in payloads_b.iter().zip(received_a.iter()).enumerate() {
        assert_eq!(
            sent.len(),
            recv.len(),
            "Payload {} from B->A size mismatch: sent={}, received={}",
            i,
            sent.len(),
            recv.len()
        );
        assert_eq!(
            sent[..],
            recv[..],
            "Payload {} from B->A data mismatch (first byte diff may indicate corruption)",
            i
        );
    }

    // Verify TURN server relayed the bulk traffic.
    let stats = _server.stats();
    assert!(
        stats.total_bytes_relayed > 100_000,
        "TURN server did not relay enough bytes: {}",
        stats.total_bytes_relayed
    );

    println!(
        "Data consistency verified: A->B {} messages ({} bytes), B->A {} messages ({} bytes), total relayed bytes={}",
        payloads_a.len(),
        payloads_a.iter().map(|v| v.len()).sum::<usize>(),
        payloads_b.len(),
        payloads_b.iter().map(|v| v.len()).sum::<usize>(),
        stats.total_bytes_relayed
    );

    pc_a.close();
    pc_b.close();

    Ok(())
}
