//! Reproduction test for the ~40-second ICE disconnect issue.
//!
//! The browser disconnects after ~40 seconds through miuturn because
//! ICE Consent Freshness (RFC 7675) STUN binding requests sent through
//! the TURN relay never get responses back.
//!
//! This test holds a TURN relay connection for 60+ seconds and monitors
//! the ICE connection state to reproduce the issue with rustrtc.

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
        0x00, 0x01, 0x00, 0x00,
        0x21, 0x12, 0xA4, 0x42,
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

static RELAY_BASE: AtomicU16 = AtomicU16::new(27000);

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

async fn exchange_sdp(
    offerer: &PeerConnection,
    answerer: &PeerConnection,
) -> anyhow::Result<()> {
    let _ = offerer.create_offer().await?;
    loop {
        if offerer.ice_transport().gather_state()
            == rustrtc::transports::ice::IceGathererState::Complete
        {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let offer = offerer.create_offer().await?;
    offerer.set_local_description(offer.clone())?;

    answerer.set_remote_description(offer).await?;
    let _ = answerer.create_answer().await?;
    loop {
        if answerer.ice_transport().gather_state()
            == rustrtc::transports::ice::IceGathererState::Complete
        {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    let answer = answerer.create_answer().await?;
    answerer.set_local_description(answer.clone())?;

    offerer.set_remote_description(answer).await?;
    Ok(())
}

/// Reproduce: hold TURN relay connection for 60 seconds and monitor ICE state.
/// In the real browser scenario, Chrome sends ICE Consent Freshness probes
/// (STUN binding requests) through the TURN relay every ~15 seconds. If no
/// response comes back within ~30 seconds, the ICE agent marks the pair as
/// "disconnected", then "failed".
///
/// This test checks whether the connection survives past the 40-second mark.
#[tokio::test]
async fn rustrtc_consent_freshness_40s_disconnect_repro() -> anyhow::Result<()> {
    let (turn_addr, _server) = start_turn_server().await;
    let config = turn_config(turn_addr);

    let pc_a = PeerConnection::new(config.clone());
    let pc_b = PeerConnection::new(config);

    // Negotiated data channel (ID 0)
    let _dc_a = pc_a.create_data_channel(
        "consent-test",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    let dc_b = pc_b.create_data_channel(
        "consent-test",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    exchange_sdp(&pc_a, &pc_b).await?;

    timeout(Duration::from_secs(15), pc_a.wait_for_connected()).await??;
    timeout(Duration::from_secs(15), pc_b.wait_for_connected()).await??;

    println!("[0s] ICE connected successfully");

    // Verify relay candidates
    let pair_a = pc_a
        .ice_transport()
        .subscribe_selected_pair()
        .borrow()
        .clone()
        .expect("pc_a should have a selected pair");
    assert_eq!(pair_a.local.typ, IceCandidateType::Relay);

    sleep(Duration::from_millis(500)).await;

    // Send initial data to confirm relay works
    pc_a.send_data(0, b"ping-at-0s").await?;
    let mut got_initial = false;
    let recv_start = std::time::Instant::now();
    while recv_start.elapsed() < Duration::from_secs(3) {
        if let Ok(Some(event)) = timeout(Duration::from_millis(200), dc_b.recv()).await {
            match event {
                rustrtc::transports::sctp::DataChannelEvent::Message(data) => {
                    assert_eq!(&data[..], b"ping-at-0s");
                    got_initial = true;
                    break;
                }
                _ => {}
            }
        }
    }
    assert!(got_initial, "Initial data transfer failed");
    println!("[0s] Initial data transfer confirmed: TURN relay is working");

    // Now hold the connection and monitor for 60 seconds.
    // The critical window is 30-45 seconds where consent freshness would fail.
    let hold_duration = Duration::from_secs(60);
    let start = std::time::Instant::now();
    let mut last_ping_at = start;
    let mut ping_count = 0u32;
    let mut connection_dropped = false;

    while start.elapsed() < hold_duration {
        let elapsed = start.elapsed().as_secs();

        // Send periodic pings every 10 seconds to generate traffic
        if last_ping_at.elapsed() >= Duration::from_secs(10) {
            ping_count += 1;
            let msg = format!("ping-at-{}s", elapsed);
            match pc_a.send_data(0, msg.as_bytes()).await {
                Ok(_) => {
                    println!("[{}s] Sent ping #{}: {}", elapsed, ping_count, msg);
                }
                Err(e) => {
                    println!("[{}s] FAILED to send ping #{}: {}", elapsed, ping_count, e);
                    connection_dropped = true;
                    break;
                }
            }
            last_ping_at = std::time::Instant::now();
        }

        // Try to receive the ping on the other side
        if let Ok(Some(event)) = timeout(Duration::from_millis(100), dc_b.recv()).await {
            match event {
                rustrtc::transports::sctp::DataChannelEvent::Message(data) => {
                    println!(
                        "[{}s] B received: {}",
                        elapsed,
                        String::from_utf8_lossy(&data)
                    );
                }
                rustrtc::transports::sctp::DataChannelEvent::Open => {
                    println!("[{}s] Data channel opened", elapsed);
                }
                rustrtc::transports::sctp::DataChannelEvent::Close => {
                    println!("[{}s] Data channel CLOSED - connection lost!", elapsed);
                    connection_dropped = true;
                    break;
                }
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    let final_elapsed = start.elapsed().as_secs();
    println!("[{}s] Test completed", final_elapsed);

    if connection_dropped {
        println!(
            "ISSUE REPRODUCED: Connection dropped during the hold period \
             (browsers typically disconnect at ~40s due to ICE consent freshness failure)"
        );
    } else {
        println!(
            "Connection survived {} seconds. If browsers still disconnect at ~40s, \
             the issue may be in how Chrome implements consent freshness probes \
             (STUN binding requests through TURN relay), not in basic relay functionality.",
            final_elapsed
        );
    }

    // Log final server stats
    let stats = _server.stats();
    println!(
        "Server stats: bytes_relayed={}, messages={}, active_allocations={}",
        stats.total_bytes_relayed, stats.total_messages, stats.active_allocations
    );

    pc_a.close();
    pc_b.close();

    Ok(())
}

/// Variant: explicitly test bidirectional data after 45 seconds to see
/// if the relay channel is still alive.
#[tokio::test]
async fn rustrtc_data_after_45s_hold() -> anyhow::Result<()> {
    let (turn_addr, _server) = start_turn_server().await;
    let config = turn_config(turn_addr);

    let pc_a = PeerConnection::new(config.clone());
    let pc_b = PeerConnection::new(config);

    let _dc_a = pc_a.create_data_channel(
        "hold-45s",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;
    let dc_b = pc_b.create_data_channel(
        "hold-45s",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    exchange_sdp(&pc_a, &pc_b).await?;
    timeout(Duration::from_secs(15), pc_a.wait_for_connected()).await??;
    timeout(Duration::from_secs(15), pc_b.wait_for_connected()).await??;

    println!("[0s] Connected, waiting 45 seconds...");
    sleep(Duration::from_secs(45)).await;

    println!("[45s] Attempting data transfer after 45s hold...");
    let test_msg = b"data-after-45s-hold";
    let send_result = pc_a.send_data(0, test_msg).await;
    println!("[45s] Send result: {:?}", send_result.is_ok());

    if send_result.is_ok() {
        let mut received = false;
        let recv_start = std::time::Instant::now();
        while recv_start.elapsed() < Duration::from_secs(5) {
            if let Ok(Some(event)) = timeout(Duration::from_millis(200), dc_b.recv()).await {
                match event {
                    rustrtc::transports::sctp::DataChannelEvent::Message(data) => {
                        assert_eq!(&data[..], test_msg, "Data corrupted after 45s hold");
                        received = true;
                        break;
                    }
                    _ => {}
                }
            }
        }
        if received {
            println!("[45s] SUCCESS: Data received correctly after 45s hold");
        } else {
            println!("[45s] FAILURE: Send succeeded but data was NOT received");
        }
        assert!(received, "Data sent at 45s was not received by peer");
    }

    pc_a.close();
    pc_b.close();
    Ok(())
}
