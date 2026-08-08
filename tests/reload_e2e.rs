//! End-to-end test for the `/metrics` endpoint and the config reload flow:
//!  1. start a real TURN UDP server + admin HTTP server against a temp config
//!  2. allocate with long-term credentials, confirm /metrics shows real data
//!  3. edit the config file (add user, change TURN REST secret, log level)
//!  4. POST /api/v1/reload, confirm auth / turn_rest / log_level all applied
//!  5. the newly-added user can allocate; TURN REST credentials change

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use miuturn::{AuthManager, ListenConfig, Metrics, TurnServer, User, UserType};
use tokio::net::UdpSocket;
use turn::client::Client;

static RANGE_IDX: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

/// Pick a relay port range unlikely to collide with other test binaries.
fn next_relay_range() -> (u16, u16) {
    const RANGE_SIZE: u16 = 128;
    const BASE: u16 = 40200;
    let idx = RANGE_IDX.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let slot = (std::process::id() as u16)
        .wrapping_mul(131)
        .wrapping_add(idx);
    let min = BASE + (slot % 100) * RANGE_SIZE;
    (min, min + RANGE_SIZE - 1)
}

fn pick_free_udp_port() -> u16 {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind temp");
    sock.local_addr().expect("local addr").port()
}

fn write_config(
    path: &PathBuf,
    users_toml: &str,
    rest_secret: &str,
    log_level: &str,
    udp_port: u16,
    http_port: u16,
) {
    let body = format!(
        r#"[server]
realm = "test-realm"
external_ip = "127.0.0.1"
start_port = 49152
end_port = 65535

[[server.listening]]
protocol = "udp"
address = "127.0.0.1:{udp_port}"

[http]
address = "127.0.0.1:{http_port}"
turn_rest_enabled = true
turn_rest_secret = "{rest_secret}"
turn_rest_default_lifetime = 3600

[log]
log_level = "{log_level}"

[auth]
users = [ {users_toml} ]
"#
    );
    std::fs::write(path, body).unwrap();
}

async fn allocate_turn(server_addr: SocketAddr, username: &str, password: &str) -> bool {
    let conn = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
    let client = match Client::new(turn::client::ClientConfig {
        stun_serv_addr: server_addr.to_string(),
        turn_serv_addr: server_addr.to_string(),
        username: username.to_string(),
        password: password.to_string(),
        realm: "test-realm".to_string(),
        software: "reload-e2e".to_string(),
        rto_in_ms: 200,
        conn,
        vnet: None,
    })
    .await
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    client.listen().await.is_ok() && client.allocate().await.is_ok()
}

async fn wait_http_ready(addr: SocketAddr) {
    let client = reqwest::Client::new();
    let url = format!("http://{}/health", addr);
    for _ in 0..50 {
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("admin HTTP server did not become ready at {}", addr);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_and_reload_e2e() {
    let dir = std::env::temp_dir().join(format!("miuturn-reload-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("miuturn.toml");

    let udp_port = pick_free_udp_port();
    let http_port = pick_free_udp_port();
    let udp_addr: SocketAddr = format!("127.0.0.1:{}", udp_port).parse().unwrap();
    let http_addr: SocketAddr = format!("127.0.0.1:{}", http_port).parse().unwrap();

    // Initial config: only "bob", TURN REST secret "secret-a", log "info".
    write_config(
        &config_path,
        r#"{ username = "bob", password = "pass", user_type = "fixed" }"#,
        "secret-a",
        "info",
        udp_port,
        http_port,
    );

    // Build the TURN server + auth.
    let (relay_min, relay_max) = next_relay_range();
    let mut server = TurnServer::with_port_range_and_password(
        Ipv4Addr::new(127, 0, 0, 1),
        "test-realm".to_string(),
        relay_min,
        relay_max,
        "password".to_string(),
    );
    let auth = Arc::new(AuthManager::new("test-realm".to_string()));
    auth.add_user(User {
        username: "bob".to_string(),
        password: "pass".to_string(),
        user_type: UserType::Fixed,
        created_at: 0,
        expires_at: None,
        max_allocations: 10,
        bandwidth_limit: None,
        ip_whitelist: None,
        max_allocation_duration_secs: None,
    });
    server.set_auth_manager(auth.clone());

    let metrics = Metrics::new();
    server.set_metrics(Some(metrics.clone()));
    let server = server;

    // Spawn the TURN UDP listener.
    let srv = server.clone();
    tokio::spawn(async move {
        let _ = srv.run_udp(udp_addr).await;
    });

    // Recording log-reload closure (stands in for the real tracing handle).
    let log_applied: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log_rec = log_applied.clone();
    let log_reload: Option<Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>> =
        Some(Arc::new(move |level: &str| {
            log_rec.lock().unwrap().push(level.to_string());
            Ok(())
        }));

    // Spawn the admin HTTP server.
    let stats_fn: Arc<dyn Fn() -> _ + Send + Sync> = {
        let t = server.allocation_table.clone();
        Arc::new(move || t.stats().snapshot())
    };
    let listen_configs = vec![ListenConfig {
        protocol: "udp".to_string(),
        address: udp_addr.to_string(),
    }];
    let admin_config_path = config_path.clone();
    let admin_task = tokio::spawn(async move {
        let _ = miuturn::create_admin_routes(
            http_addr.to_string(),
            stats_fn,
            None,
            None,
            auth,
            true,
            Some("secret-a".to_string()),
            3600,
            Some(metrics),
            Some(admin_config_path),
            "127.0.0.1".to_string(),
            listen_configs,
            vec!["127.0.0.1".to_string()],
            false,
            log_reload,
        )
        .await;
    });

    wait_http_ready(http_addr).await;
    tokio::time::sleep(Duration::from_millis(200)).await; // let UDP worker spawn

    let http = reqwest::Client::new();
    let base = format!("http://{}", http_addr);

    // ── 1. bob allocates via real TURN long-term credentials ───────────────
    assert!(
        allocate_turn(udp_addr, "bob", "pass").await,
        "bob should be able to allocate before reload"
    );

    // ── 2. /metrics shows real data (was all-zeros before the fix) ──────────
    let body = http
        .get(format!("{}/metrics", base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("turn_total_allocations 1"),
        "metrics should show 1 allocation: {}",
        body
    );
    assert!(body.contains("turn_total_requests"));
    assert!(body.contains("turn_successful_requests"));
    assert!(body.contains("turn_uptime_seconds"));

    // ── 3. TURN REST credential before reload ───────────────────────────────
    let rest_before = http
        .get(format!("{}/api/v1/iceservers?username=u", base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(rest_before.contains("turn:127.0.0.1"), "{}", rest_before);

    // ── 4. Edit the config: add alice, new secret, log level debug ──────────
    write_config(
        &config_path,
        r#"{ username = "bob", password = "pass", user_type = "fixed" }, { username = "alice", password = "secret2", user_type = "fixed" }"#,
        "secret-b",
        "debug",
        udp_port,
        http_port,
    );

    // ── 5. POST /api/v1/reload ──────────────────────────────────────────────
    let resp: serde_json::Value = http
        .post(format!("{}/api/v1/reload", base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(resp["success"], true, "reload failed: {}", resp);
    let applied = resp["applied"].as_array().unwrap();
    for key in ["auth", "turn_rest", "log_level"] {
        assert!(
            applied.iter().any(|v| v == key),
            "applied should include {}: {}",
            key,
            resp
        );
    }
    assert_eq!(resp["user_count"], 2, "{}", resp);

    // ── 6. newly-added alice can now allocate (auth reload is live) ─────────
    assert!(
        allocate_turn(udp_addr, "alice", "secret2").await,
        "alice should be able to allocate after reload"
    );

    // ── 7. TURN REST credential changed with the new secret ─────────────────
    let rest_after = http
        .get(format!("{}/api/v1/iceservers?username=u", base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_ne!(
        rest_before, rest_after,
        "TURN REST credential should change after secret reload"
    );

    // ── 8. log level reload reached the (recording) handle ──────────────────
    let applied_logs = log_applied.lock().unwrap().clone();
    assert!(
        applied_logs.contains(&"debug".to_string()),
        "log reload should have applied 'debug': {:?}",
        applied_logs
    );

    // ── 9. cumulative allocation counter reflects the second allocation ─────
    let body = http
        .get(format!("{}/metrics", base))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("turn_total_allocations 2"),
        "metrics should now show 2 allocations: {}",
        body
    );

    // Cleanup.
    admin_task.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
