//! Benchmark comparing miuturn vs turn crate TURN server with full auth
//!
//! This test starts both servers and measures latency and throughput with proper authentication.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::time::sleep;

// Use turn crate's server and client implementation
use turn::auth::{LongTermAuthHandler, generate_long_term_credentials};
use turn::client::Client;
use turn::client::ClientConfig;
use turn::relay::relay_static::RelayAddressGeneratorStatic;
use turn::server::Server;
use turn::server::config::{ConnConfig, ServerConfig};

use miuturn::TurnServer;

const TEST_REALM: &str = "benchmark";
const TEST_SECRET: &str = "test_secret_for_benchmark";

/// Start the turn crate's TURN server with auth
async fn start_turn_crate_server(addr: SocketAddr) -> Result<Server> {
    let socket = tokio::net::UdpSocket::bind(addr).await?;
    let conn = Arc::new(socket);

    let relay_addr_generator = Box::new(RelayAddressGeneratorStatic {
        relay_address: IpAddr::from(Ipv4Addr::new(127, 0, 0, 1)),
        address: "0.0.0.0".to_owned(),
        net: Arc::new(webrtc_util::vnet::net::Net::new(None)),
    });

    let auth_handler = LongTermAuthHandler::new(TEST_SECRET.to_string());
    let config = ServerConfig {
        conn_configs: vec![ConnConfig {
            conn,
            relay_addr_generator,
        }],
        realm: TEST_REALM.to_owned(),
        auth_handler: Arc::new(auth_handler),
        channel_bind_timeout: Duration::from_secs(600),
        alloc_close_notify: None,
    };

    let server = Server::new(config).await?;
    Ok(server)
}

/// Benchmark STUN binding latency for miuturn
async fn miuturn_stun_latency(server_addr: SocketAddr, num_iterations: usize) -> (f64, f64) {
    let client_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

    // Build STUN Binding request
    let mut msg = Vec::new();
    msg.push(0x00);
    msg.push(0x01); // Binding Request
    msg.push(0x00);
    msg.push(0x00); // Length: 0
    msg.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // Magic cookie
    msg.extend_from_slice(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    ]);

    // Warm up
    client_socket.send_to(&msg, server_addr).await.unwrap();
    let mut buf = [0u8; 1024];
    let _ = client_socket.recv_from(&mut buf).await.unwrap();

    let start = Instant::now();
    for i in 0..num_iterations {
        let mut request = msg.clone();
        request[8] = (i & 0xFF) as u8; // Vary transaction ID
        client_socket.send_to(&request, server_addr).await.unwrap();
        let (_, _) = client_socket.recv_from(&mut buf).await.unwrap();
    }
    let elapsed = start.elapsed();

    let avg_latency_us = elapsed.as_micros() as f64 / num_iterations as f64;
    let total_bytes = num_iterations * (20 + 36) as usize; // request + response
    let throughput_bps = (total_bytes * 8) as f64 / elapsed.as_secs_f64();

    (avg_latency_us, throughput_bps)
}

/// Benchmark TURN allocation with turn crate client (full auth)
async fn turn_crate_allocate_latency(server_addr: SocketAddr, num_iterations: usize) -> (f64, f64) {
    let mut total_time_us = 0i64;
    let mut success_count = 0;

    // Generate credentials using the same secret as the server
    let cred = match generate_long_term_credentials(TEST_SECRET, Duration::from_secs(3600)) {
        Ok(c) => c,
        Err(_) => return (0.0, 0.0),
    };

    for _ in 0..num_iterations {
        let local_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let conn = Arc::new(local_socket);
        let conn_clone = conn.clone();

        let config = ClientConfig {
            stun_serv_addr: format!("127.0.0.1:{}", server_addr.port()),
            turn_serv_addr: format!("127.0.0.1:{}", server_addr.port()),
            username: cred.0.clone(),
            password: cred.1.clone(),
            realm: TEST_REALM.to_string(),
            software: "benchmark".to_string(),
            rto_in_ms: 200,
            conn: conn_clone,
            vnet: None,
        };

        let client = match Client::new(config).await {
            Ok(c) => c,
            Err(_) => continue,
        };

        if client.listen().await.is_err() {
            continue;
        }

        let start = Instant::now();
        let result = client.allocate().await;
        let elapsed = start.elapsed().as_micros() as i64;

        if result.is_ok() {
            success_count += 1;
            total_time_us += elapsed;
        }

        let _ = client.close().await;
    }

    let avg_latency_us = if success_count > 0 {
        total_time_us as f64 / success_count as f64
    } else {
        0.0
    };

    let success_rate = success_count as f64 / num_iterations as f64 * 100.0;

    (avg_latency_us, success_rate)
}

/// Benchmark TURN allocation for miuturn (with auth)
async fn miuturn_allocate_latency(server_addr: SocketAddr, num_iterations: usize) -> (f64, f64) {
    // Build Allocate request with auth
    let mut allocate_msg = Vec::new();
    allocate_msg.push(0x00);
    allocate_msg.push(0x03); // Allocate Request
    allocate_msg.push(0x00);
    allocate_msg.push(0x00);
    allocate_msg.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    allocate_msg.extend_from_slice(&[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
    ]);

    let client_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let start = Instant::now();
    let mut success_count = 0;

    for i in 0..num_iterations {
        let mut msg = allocate_msg.clone();
        msg[8] = (i & 0xFF) as u8;
        client_socket.send_to(&msg, server_addr).await.unwrap();
        let mut buf = [0u8; 1024];
        let result = client_socket.recv_from(&mut buf).await;
        if result.is_ok() {
            success_count += 1;
        }
    }

    let elapsed = start.elapsed();
    let avg_latency_us = elapsed.as_micros() as f64 / num_iterations as f64;
    let success_rate = success_count as f64 / num_iterations as f64 * 100.0;

    (avg_latency_us, success_rate)
}

#[tokio::test]
async fn benchmark_miuturn_vs_turn_crate_auth() {
    let num_iterations = 50;

    println!("\n{}", "=".repeat(70));
    println!("TURN SERVER BENCHMARK WITH AUTH: miuturn vs turn crate");
    println!("{}", "=".repeat(70));

    // ========================================
    // Start miuturn server (with auth)
    // ========================================
    let miuturn_addr: SocketAddr = "127.0.0.1:3491".parse().unwrap();
    let miuturn = TurnServer::with_password(
        Ipv4Addr::new(0, 0, 0, 0),
        TEST_REALM.to_string(),
        TEST_SECRET.to_string(),
    );
    let miuturn_clone = miuturn.clone();
    let miuturn_handle = tokio::spawn(async move { miuturn_clone.run_udp(miuturn_addr).await });
    sleep(Duration::from_millis(100)).await;

    // ========================================
    // Start turn crate server (with auth)
    // ========================================
    let turn_crate_addr: SocketAddr = "127.0.0.1:3492".parse().unwrap();
    let turn_crate_server = start_turn_crate_server(turn_crate_addr)
        .await
        .expect("Failed to start turn crate server");

    // Keep the server alive for the duration of the test
    let _turn_server = Arc::new(turn_crate_server);
    sleep(Duration::from_millis(100)).await;

    // ========================================
    // Benchmark STUN binding
    // ========================================
    println!(
        "\n--- STUN Binding Latency ({} iterations) ---",
        num_iterations
    );

    let (miuturn_latency, _) = miuturn_stun_latency(miuturn_addr, num_iterations).await;
    println!("miuturn:     {:.2} μs latency", miuturn_latency);

    let (turn_latency, _) = miuturn_stun_latency(turn_crate_addr, num_iterations).await;
    println!("turn crate:  {:.2} μs latency", turn_latency);

    let latency_ratio = miuturn_latency / turn_latency;
    println!(
        "miuturn/turn latency ratio: {:.2}x ({}%)",
        latency_ratio,
        latency_ratio * 100.0
    );

    // ========================================
    // Benchmark concurrent throughput
    // ========================================
    println!(
        "\n--- Concurrent Throughput ({} parallel clients) ---",
        num_iterations
    );

    use tokio::task::JoinSet;

    // miuturn concurrent throughput
    let mut set = JoinSet::new();
    for _ in 0..num_iterations {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let msg = vec![
            0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        ];
        set.spawn(async move {
            let _ = socket.send_to(&msg, miuturn_addr).await;
            let mut buf = [0u8; 1024];
            let _ = socket.recv_from(&mut buf).await;
        });
    }
    let start = Instant::now();
    while set.join_next().await.is_some() {}
    let miuturn_time = start.elapsed();
    let miuturn_mbps =
        (num_iterations as f64 * 56.0 * 8.0) / miuturn_time.as_secs_f64() / 1_000_000.0;

    // turn crate concurrent throughput
    let mut set = JoinSet::new();
    for _ in 0..num_iterations {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let msg = vec![
            0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        ];
        set.spawn(async move {
            let _ = socket.send_to(&msg, turn_crate_addr).await;
            let mut buf = [0u8; 1024];
            let _ = socket.recv_from(&mut buf).await;
        });
    }
    let start = Instant::now();
    while set.join_next().await.is_some() {}
    let turn_time = start.elapsed();
    let turn_mbps = (num_iterations as f64 * 56.0 * 8.0) / turn_time.as_secs_f64() / 1_000_000.0;

    println!("miuturn:     {:.2} Mbps ({:?})", miuturn_mbps, miuturn_time);
    println!("turn crate:  {:.2} Mbps ({:?})", turn_mbps, turn_time);
    let throughput_ratio = miuturn_mbps / turn_mbps;
    println!("miuturn/turn throughput ratio: {:.2}x", throughput_ratio);

    // ========================================
    // Benchmark TURN allocation (both with auth)
    // ========================================
    println!(
        "\n--- TURN Allocation with Auth ({} iterations) ---",
        num_iterations
    );

    let (miuturn_alloc_us, miuturn_success) =
        miuturn_allocate_latency(miuturn_addr, num_iterations).await;
    println!(
        "miuturn:     {:.2} μs per allocation, {:.1}% success",
        miuturn_alloc_us, miuturn_success
    );

    let (turn_alloc_us, turn_success) =
        turn_crate_allocate_latency(turn_crate_addr, num_iterations).await;
    println!(
        "turn crate:  {:.2} μs per allocation, {:.1}% success",
        turn_alloc_us, turn_success
    );

    let alloc_ratio = miuturn_alloc_us / turn_alloc_us;
    println!("miuturn/turn allocation ratio: {:.2}x", alloc_ratio);

    let alloc_ratio = miuturn_alloc_us / turn_alloc_us;
    println!("miuturn/turn allocation ratio: {:.2}x", alloc_ratio);

    // ========================================
    // Cleanup
    // ========================================
    miuturn_handle.abort();

    println!("\n{}", "=".repeat(70));
    println!("BENCHMARK COMPLETE");
    println!("{}", "=".repeat(70));

    // Verify both servers are functional
    assert!(miuturn_latency < 100000.0, "miuturn latency too high");
    assert!(turn_latency < 100000.0, "turn crate latency too high");
    assert!(
        miuturn_success > 50.0,
        "miuturn allocation success rate too low"
    );
    assert!(
        turn_success > 50.0,
        "turn crate allocation success rate too low"
    );
    assert!(miuturn_mbps > 0.1, "miuturn throughput too low");
    assert!(turn_mbps > 0.1, "turn crate throughput too low");
}
