//! Throughput optimization benchmark
//!
//! Tests different approaches to maximize throughput.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::sleep;

use miuturn::TurnServer;

const ITERATIONS: usize = 1000;

/// Benchmark 1: Many parallel clients (current approach)
async fn benchmark_many_clients(server_addr: SocketAddr, num_clients: usize) -> f64 {
    let mut set = JoinSet::new();
    for i in 0..num_clients {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let tid = i as u8;
        let msg = vec![
            0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, tid, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        ];
        set.spawn(async move {
            socket.send_to(&msg, server_addr).await.unwrap();
            let mut buf = [0u8; 1024];
            socket.recv_from(&mut buf).await.unwrap();
        });
    }
    let start = Instant::now();
    while set.join_next().await.is_some() {}
    let elapsed = start.elapsed();
    let mbps = (num_clients as f64 * 56.0 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
    mbps
}

/// Benchmark 2: Single socket, many sequential requests
async fn benchmark_single_socket_sequential(server_addr: SocketAddr) -> f64 {
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let msg = vec![
        0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B,
    ];

    let start = Instant::now();
    for i in 0..ITERATIONS {
        let mut m = msg.clone();
        m[8] = (i & 0xFF) as u8;
        socket.send_to(&m, server_addr).await.unwrap();
        let mut buf = [0u8; 1024];
        socket.recv_from(&mut buf).await.unwrap();
    }
    let elapsed = start.elapsed();
    let mbps = (ITERATIONS as f64 * 56.0 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
    mbps
}

/// Benchmark 3: Single socket, async concurrent requests (pipelined)
async fn benchmark_single_socket_pipelined(server_addr: SocketAddr, concurrency: usize) -> f64 {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
    let msg = vec![
        0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B,
    ];

    let mut handles = vec![];
    for _ in 0..concurrency {
        let socket = socket.clone();
        let m = msg.clone();
        handles.push(tokio::spawn(async move {
            socket.send_to(&m, server_addr).await.unwrap();
            let mut buf = [0u8; 1024];
            socket.recv_from(&mut buf).await.unwrap();
        }));
    }

    // Do multiple rounds
    let rounds = ITERATIONS / concurrency;
    let start = Instant::now();
    for round in 0..rounds {
        for (i, h) in handles.iter_mut().enumerate() {
            let mut m = msg.clone();
            m[8] = ((round * concurrency + i) & 0xFF) as u8;
            let socket = socket.clone();
            *h = tokio::spawn(async move {
                socket.send_to(&m, server_addr).await.unwrap();
                let mut buf = [0u8; 1024];
                socket.recv_from(&mut buf).await.unwrap();
            });
        }
        // Wait for all in round to complete
        for h in handles.iter_mut() {
            h.await.unwrap();
        }
    }
    let elapsed = start.elapsed();
    let total_requests = rounds * concurrency;
    let mbps = (total_requests as f64 * 56.0 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
    mbps
}

/// Benchmark 4: Optimal - many clients with minimal overhead
async fn benchmark_optimized_clients(server_addr: SocketAddr, num_clients: usize) -> f64 {
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
    let msg = Arc::new(vec![
        0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x07, 0x08, 0x09, 0x0A, 0x0B,
    ]);

    let mut handles = vec![];
    for _ in 0..num_clients {
        let socket = socket.clone();
        let msg = msg.clone();
        handles.push(tokio::spawn(async move {
            socket.send_to(&msg, server_addr).await.unwrap();
            let mut buf = [0u8; 1024];
            socket.recv_from(&mut buf).await.unwrap();
        }));
    }

    let start = Instant::now();
    futures::future::join_all(handles).await;
    let elapsed = start.elapsed();
    let mbps = (num_clients as f64 * 56.0 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
    mbps
}

#[tokio::test]
async fn throughput_optimization_benchmark() {
    let server_addr: SocketAddr = "127.0.0.1:3491".parse().unwrap();
    let server = TurnServer::with_auth_disabled(Ipv4Addr::new(0, 0, 0, 0), "test".to_string());
    let server_clone = server.clone();
    let handle = tokio::spawn(async move { server_clone.run_udp(server_addr).await });
    sleep(Duration::from_millis(100)).await;

    println!("\n{}", "=".repeat(70));
    println!("THROUGHPUT OPTIMIZATION BENCHMARK (miuturn only)");
    println!("{}", "=".repeat(70));

    // Test different client counts
    for num_clients in [10, 50, 100, 200, 500] {
        let mbps = benchmark_many_clients(server_addr, num_clients).await;
        println!("{} clients:  {:.2} Mbps", num_clients, mbps);
    }

    println!();

    // Single socket sequential
    let mbps = benchmark_single_socket_sequential(server_addr).await;
    println!(
        "single socket (sequential {}): {:.2} Mbps",
        ITERATIONS, mbps
    );

    // Single socket pipelined
    for conc in [10, 50, 100] {
        let mbps = benchmark_single_socket_pipelined(server_addr, conc).await;
        println!("single socket (pipelined x{}): {:.2} Mbps", conc, mbps);
    }

    // Optimized clients
    println!();
    for num_clients in [50, 100, 200] {
        let mbps = benchmark_optimized_clients(server_addr, num_clients).await;
        println!("optimized {} clients: {:.2} Mbps", num_clients, mbps);
    }

    handle.abort();

    println!("\n{}", "=".repeat(70));
}
