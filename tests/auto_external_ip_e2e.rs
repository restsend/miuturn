//! End-to-end test for `server.auto_external_ip`:
//!
//!  1. serve a fake "what is my IP" endpoint returning a known public IPv4
//!  2. start the miuturn binary with `auto_external_ip` pointing at it
//!  3. assert the startup banner advertises the discovered address instead of
//!     the configured `external_ip` placeholder

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const DISCOVERED_IP: &str = "203.0.113.42";

fn free_udp_port() -> u16 {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind temp udp port");
    sock.local_addr().expect("local addr").port()
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "miuturn-{tag}-{}-{}",
        std::process::id(),
        free_udp_port()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// One-shot HTTP server returning `DISCOVERED_IP` as plain text.
async fn spawn_ip_endpoint() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _ = socket.read(&mut request).await.unwrap();
        let body = format!("{DISCOVERED_IP}\n");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.shutdown().await;
    });
    format!("http://{addr}/ip")
}

/// Read stdout lines until one contains `needle`, then return it.
fn wait_for_stdout_line(
    stdout: impl std::io::Read + Send + 'static,
    needle: &'static str,
) -> Option<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().map_while(Result::ok) {
            if line.contains(needle) {
                let _ = tx.send(line);
                return;
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(20)).ok()
}

/// Start the binary with `config_body` and return the banner's External IP line.
fn startup_external_ip(
    tag: &str,
    config_body: String,
    envs: &[(&str, &str)],
) -> Option<String> {
    let dir = temp_dir(tag);
    let config_path = dir.join("miuturn.toml");
    std::fs::write(&config_path, config_body).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_miuturn"));
    cmd.env("CONFIG", &config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (key, value) in envs {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().expect("failed to spawn miuturn binary");
    let stdout = child.stdout.take().expect("stdout piped");
    let line = wait_for_stdout_line(stdout, "External IP:");

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    line
}

fn config_with_auto_external_ip(listen_port: u16, spec: &str) -> String {
    format!(
        r#"[server]
realm = "auto-ip-realm"
external_ip = "192.0.2.1"
auto_external_ip = "{spec}"
start_port = 49152
end_port = 65535

[[server.listening]]
protocol = "udp"
address = "127.0.0.1:{listen_port}"

[auth]
"#
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_resolves_auto_external_ip() {
    let ip_url = spawn_ip_endpoint().await;
    let line = startup_external_ip(
        "auto-external-ip",
        config_with_auto_external_ip(free_udp_port(), &ip_url),
        &[],
    )
    .expect("startup banner did not report an external IP");

    assert_eq!(
        line.trim(),
        format!("External IP: {DISCOVERED_IP}"),
        "auto_external_ip should replace the configured external_ip at startup"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_resolves_env_referenced_external_ip() {
    let ip_url = spawn_ip_endpoint().await;
    let line = startup_external_ip(
        "auto-external-ip-env",
        config_with_auto_external_ip(free_udp_port(), "$MIUTURN_TEST_IP_URL"),
        &[("MIUTURN_TEST_IP_URL", &ip_url)],
    )
    .expect("startup banner did not report an external IP");

    assert_eq!(
        line.trim(),
        format!("External IP: {DISCOVERED_IP}"),
        "auto_external_ip = \"$VAR\" should use the environment variable's URL"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_falls_back_when_discovery_fails() {
    let started = Instant::now();
    // Port 9 (discard) on localhost: nothing listens, connection fails fast.
    let line = startup_external_ip(
        "auto-external-ip-fallback",
        config_with_auto_external_ip(free_udp_port(), "http://127.0.0.1:9/ip"),
        &[],
    )
    .expect("startup banner did not report an external IP");

    assert_eq!(line.trim(), "External IP: 192.0.2.1");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "discovery failure must not block startup"
    );
}
