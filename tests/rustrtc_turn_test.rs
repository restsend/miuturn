//! Integration test: use rustrtc PeerConnection with TURN relay against miuturn.

use std::net::SocketAddr;
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

async fn start_turn_server() -> (SocketAddr, TurnServer) {
    let relay_addr: std::net::Ipv4Addr = "127.0.0.1".parse().unwrap();
    let port = pick_free_udp_port();
    let server = TurnServer::with_port_range_and_password(
        relay_addr,
        "test-realm".to_string(),
        25000,
        25100,
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
