//! Startup public-IP discovery for `server.auto_external_ip`.
//!
//! Only plain HTTP(S) "what is my IP" endpoints are supported, e.g.
//!
//! ```toml
//! [server]
//! auto_external_ip = "https://ifconfig.me"
//! external_ip = "0.0.0.0"   # fallback when discovery fails
//! ```
//!
//! The response body is scanned for the first IPv4 literal, so both plain-text
//! endpoints (`1.2.3.4`) and JSON endpoints (`{"ip":"1.2.3.4"}`) work.
//! The spec may also be an environment-variable reference such as `"$IP_URL"`
//! or `"${IP_URL}"`, expanded once at startup.
//!
//! This is intentionally a tiny HTTP/1.1 client (one GET per process start)
//! rather than a full HTTP stack: no redirects, no keep-alive, no chunk
//! decoding (an IP literal in a chunked body is still found by the scan).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Total time budget for one discovery request (DNS + connect + TLS + body).
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Stop buffering responses larger than this; a public-IP endpoint returns a
/// few bytes, anything bigger is not something we should scan anyway.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Resolve the public IPv4 address advertised in `server.auto_external_ip`.
///
/// `spec` is an `http://` / `https://` URL, a literal IPv4 address, or an
/// environment-variable reference (`"$NAME"` / `"${NAME}"`) whose value is one
/// of those. The first IPv4 literal in the response body is returned. Errors
/// are human-readable; callers are expected to log them and fall back to
/// `server.external_ip` so a transient network failure never keeps the TURN
/// server from starting.
pub async fn resolve(spec: &str) -> Result<Ipv4Addr, String> {
    resolve_with_env(spec, |name| std::env::var(name).ok()).await
}

async fn resolve_with_env(
    spec: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Ipv4Addr, String> {
    let spec = expand_env_with(spec, &lookup)?;
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("auto_external_ip is empty".to_string());
    }

    // Allow pinning a literal IP in the same field for symmetry.
    if let Ok(ip) = spec.parse::<Ipv4Addr>() {
        return Ok(ip);
    }

    let url = Url::parse(spec)?;

    let body = tokio::time::timeout(REQUEST_TIMEOUT, fetch(&url))
        .await
        .map_err(|_| format!("GET {spec} timed out after {REQUEST_TIMEOUT:?}"))??;

    extract_ipv4(&body).ok_or_else(|| {
        format!(
            "no IPv4 address found in response from {spec} (body: {})",
            preview(&body)
        )
    })
}

/// Expand a whole-value environment reference: `"$NAME"` or `"${NAME}"`.
///
/// Anything else (URLs, IP literals, strings containing `$` elsewhere) is
/// returned unchanged. Missing or empty variables are reported as errors so a
/// typo in the config surfaces as a startup warning instead of a silent
/// fallback.
pub fn expand_env(spec: &str) -> Result<String, String> {
    expand_env_with(spec, &|name| std::env::var(name).ok())
}

fn expand_env_with(spec: &str, lookup: &impl Fn(&str) -> Option<String>) -> Result<String, String> {
    let spec = spec.trim();
    let name = if let Some(name) = spec.strip_prefix("${").and_then(|rest| rest.strip_suffix('}'))
    {
        name
    } else if let Some(name) = spec.strip_prefix('$') {
        name
    } else {
        return Ok(spec.to_string());
    };

    // Only treat `$NAME` as a variable when NAME looks like a variable name;
    // otherwise let normal URL parsing produce the error.
    let valid_name = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid_name {
        return Ok(spec.to_string());
    }

    match lookup(name) {
        Some(value) if value.trim().is_empty() => Err(format!(
            "environment variable {name} is set but empty (auto_external_ip = {spec:?})"
        )),
        Some(value) => Ok(value),
        None => Err(format!(
            "environment variable {name} is not set (auto_external_ip = {spec:?})"
        )),
    }
}

/// Find the first valid IPv4 literal in `body`.
///
/// Splitting on every character that cannot be part of an address keeps this
/// tolerant of plain text (`"1.2.3.4\n"`), JSON (`{"ip":"1.2.3.4"}`) and
/// endpoints that wrap the address in extra prose.
pub fn extract_ipv4(body: &str) -> Option<Ipv4Addr> {
    body.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .filter(|token| !token.is_empty())
        .find_map(|token| token.parse::<Ipv4Addr>().ok())
        .filter(|ip| !ip.is_unspecified())
}

#[derive(Debug, PartialEq)]
struct Url {
    tls: bool,
    host: String,
    port: u16,
    /// Path plus query, always starting with `/`.
    path: String,
}

impl Url {
    fn parse(spec: &str) -> Result<Self, String> {
        let (tls, rest) = match spec.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => (false, rest),
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => (true, rest),
            _ => {
                return Err(format!(
                    "unsupported auto_external_ip {spec:?}: expected an http:// or https:// URL"
                ));
            }
        };
        let default_port = if tls { 443 } else { 80 };

        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };

        // Drop optional userinfo; credentials in this URL are not meaningful.
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        if authority.is_empty() {
            return Err(format!("auto_external_ip {spec:?} has no host"));
        }

        // Authority is either `host[:port]` or `[ipv6][:port]`.
        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (host, after) = rest
                .split_once(']')
                .ok_or_else(|| format!("auto_external_ip {spec:?} has an unterminated IPv6 host"))?;
            let port = match after {
                "" => default_port,
                _ => after
                    .strip_prefix(':')
                    .ok_or_else(|| format!("auto_external_ip {spec:?} has an invalid authority"))?
                    .parse::<u16>()
                    .map_err(|_| format!("auto_external_ip {spec:?} has an invalid port"))?,
            };
            (host, port)
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => {
                    let port = port
                        .parse::<u16>()
                        .map_err(|_| format!("auto_external_ip {spec:?} has an invalid port"))?;
                    (host, port)
                }
                None => (authority, default_port),
            }
        };
        if host.is_empty() {
            return Err(format!("auto_external_ip {spec:?} has no host"));
        }

        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };

        Ok(Self {
            tls,
            host: host.to_string(),
            port,
            path,
        })
    }

    fn host_header(&self) -> String {
        let default_port = if self.tls { 443 } else { 80 };
        if self.host.contains(':') {
            // IPv6 literal.
            if self.port == default_port {
                format!("[{}]", self.host)
            } else {
                format!("[{}]:{}", self.host, self.port)
            }
        } else if self.port == default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

async fn fetch(url: &Url) -> Result<String, String> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((url.host.as_str(), url.port))
        .await
        .map_err(|e| format!("resolving {}: {e}", url.host))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("resolving {}: no addresses", url.host));
    }

    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                return if url.tls {
                    fetch_tls(stream, url).await
                } else {
                    fetch_plain(stream, url).await
                };
            }
            Err(e) => last_err = Some(format!("connecting to {addr}: {e}")),
        }
    }
    Err(last_err.unwrap_or_else(|| "no address to connect to".to_string()))
}

async fn fetch_plain(mut stream: TcpStream, url: &Url) -> Result<String, String> {
    send_request(&mut stream, url).await?;
    read_response(&mut stream).await
}

async fn fetch_tls(stream: TcpStream, url: &Url) -> Result<String, String> {
    let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let server_name = match url.host.parse::<IpAddr>() {
        Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
        Err(_) => rustls::pki_types::ServerName::try_from(url.host.clone())
            .map_err(|e| format!("invalid TLS server name {:?}: {e}", url.host))?,
    };

    let mut stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| format!("TLS handshake with {} failed: {e}", url.host))?;
    send_request(&mut stream, url).await?;
    read_response(&mut stream).await
}

async fn send_request<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    url: &Url,
) -> Result<(), String> {
    let request = format!(
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         User-Agent: miuturn/{}\r\n\
         Accept: */*\r\n\
         Connection: close\r\n\
         \r\n",
        url.path,
        url.host_header(),
        env!("CARGO_PKG_VERSION"),
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("sending request: {e}"))
}

async fn read_response<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<String, String> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("reading response: {e}"))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&buf[..n]);

        if let Some(header_end) = find_header_end(&raw) {
            let header = &raw[..header_end];
            if let Some(len) = content_length(header)
                && raw.len() >= header_end + 4 + len
            {
                break;
            }
            // Chunked bodies end with a zero-length chunk. We do not decode
            // chunks (the IP scan tolerates the framing), just stop early.
            if transfer_encoding_is_chunked(header) && raw.ends_with(b"0\r\n\r\n") {
                break;
            }
        }
        if raw.len() >= MAX_RESPONSE_BYTES {
            break;
        }
    }

    let header_end = find_header_end(&raw).ok_or_else(|| "malformed HTTP response".to_string())?;
    let header = String::from_utf8_lossy(&raw[..header_end]);
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| "malformed HTTP status line".to_string())?;
    if !(200..300).contains(&status) {
        // Give the operator something actionable for the common redirect case.
        if (300..400).contains(&status)
            && let Some(location) = header_value(&header, "location")
        {
            return Err(format!(
                "endpoint returned HTTP {status} redirect to {location}; \
                 set auto_external_ip to that https:// URL"
            ));
        }
        return Err(format!(
            "endpoint returned HTTP {status} (body: {})",
            preview(&String::from_utf8_lossy(&raw[header_end + 4..]))
        ));
    }

    Ok(String::from_utf8_lossy(&raw[header_end + 4..]).into_owned())
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

fn header_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            Some(value.trim())
        } else {
            None
        }
    })
}

fn content_length(header: &[u8]) -> Option<usize> {
    header_value(&String::from_utf8_lossy(header), "content-length")?.parse().ok()
}

fn transfer_encoding_is_chunked(header: &[u8]) -> bool {
    header_value(&String::from_utf8_lossy(header), "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
}

fn preview(body: &str) -> String {
    const MAX: usize = 200;
    let trimmed = body.trim();
    if trimmed.chars().count() <= MAX {
        trimmed.to_string()
    } else {
        let cut: String = trimmed.chars().take(MAX).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn extract_ipv4_plain_text() {
        assert_eq!(
            extract_ipv4("203.0.113.7\n"),
            Some(Ipv4Addr::new(203, 0, 113, 7))
        );
    }

    #[test]
    fn extract_ipv4_json() {
        assert_eq!(
            extract_ipv4(r#"{"ip":"198.51.100.42","country":"XX"}"#),
            Some(Ipv4Addr::new(198, 51, 100, 42))
        );
    }

    #[test]
    fn extract_ipv4_skips_invalid_tokens() {
        // "1.2.3" is not a valid IPv4 literal; the next candidate wins.
        assert_eq!(
            extract_ipv4("version 1.2.3 from 192.0.2.9"),
            Some(Ipv4Addr::new(192, 0, 2, 9))
        );
    }

    #[test]
    fn extract_ipv4_missing() {
        assert_eq!(extract_ipv4("no address here"), None);
        assert_eq!(extract_ipv4("0.0.0.0"), None);
    }

    #[test]
    fn url_parse_defaults() {
        assert_eq!(
            Url::parse("https://ifconfig.me").unwrap(),
            Url {
                tls: true,
                host: "ifconfig.me".to_string(),
                port: 443,
                path: "/".to_string(),
            }
        );
        assert_eq!(
            Url::parse("http://example.com/ip?format=text").unwrap(),
            Url {
                tls: false,
                host: "example.com".to_string(),
                port: 80,
                path: "/ip?format=text".to_string(),
            }
        );
        assert_eq!(
            Url::parse("https://127.0.0.1:8443/ip").unwrap(),
            Url {
                tls: true,
                host: "127.0.0.1".to_string(),
                port: 8443,
                path: "/ip".to_string(),
            }
        );
    }

    #[test]
    fn url_parse_rejects_other_schemes() {
        let err = Url::parse("stun:stun.example.com:3478").unwrap_err();
        assert!(err.contains("http://"), "unexpected error: {err}");
        assert!(Url::parse("https://").is_err());
        assert!(Url::parse("https://example.com:notaport/ip").is_err());
    }

    #[test]
    fn host_header_includes_non_default_port_only() {
        assert_eq!(
            Url::parse("https://ifconfig.me/ip").unwrap().host_header(),
            "ifconfig.me"
        );
        assert_eq!(
            Url::parse("http://ifconfig.me:8080/ip")
                .unwrap()
                .host_header(),
            "ifconfig.me:8080"
        );
    }

    #[test]
    fn url_parse_ipv6_host() {
        let url = Url::parse("https://[2001:db8::1]:8443/ip").unwrap();
        assert_eq!(url.host, "2001:db8::1");
        assert_eq!(url.port, 8443);
        assert_eq!(url.path, "/ip");
        assert_eq!(url.host_header(), "[2001:db8::1]:8443");

        let url = Url::parse("https://[2001:db8::1]").unwrap();
        assert_eq!(url.host_header(), "[2001:db8::1]");
    }

    #[tokio::test]
    async fn resolve_rejects_non_http_spec() {
        let err = resolve("stun:stun.example.com:3478").await.unwrap_err();
        assert!(err.contains("http://"), "unexpected error: {err}");
    }

    #[test]
    fn expand_env_forms() {
        let lookup = |name: &str| match name {
            "IP_URL" => Some("https://ifconfig.me".to_string()),
            _ => None,
        };
        assert_eq!(
            expand_env_with("$IP_URL", &lookup).unwrap(),
            "https://ifconfig.me"
        );
        assert_eq!(
            expand_env_with("${IP_URL}", &lookup).unwrap(),
            "https://ifconfig.me"
        );
        // Non-references pass through unchanged.
        assert_eq!(
            expand_env_with(" https://ifconfig.me ", &lookup).unwrap(),
            "https://ifconfig.me"
        );
        assert_eq!(expand_env_with("203.0.113.1", &lookup).unwrap(), "203.0.113.1");

        let err = expand_env_with("$MISSING", &lookup).unwrap_err();
        assert!(err.contains("MISSING"), "unexpected error: {err}");

        let empty = |_: &str| Some("   ".to_string());
        let err = expand_env_with("$EMPTY", &empty).unwrap_err();
        assert!(err.contains("empty"), "unexpected error: {err}");
    }

    #[test]
    fn expand_env_ignores_non_variable_dollar_forms() {
        let lookup = |name: &str| Some(format!("value-{name}"));
        for spec in ["$", "${}", "https://example.com/$PATH", "a$B"] {
            assert_eq!(
                expand_env_with(spec, &lookup).unwrap(),
                spec,
                "should not expand {spec:?}"
            );
        }
    }

    #[tokio::test]
    async fn resolve_expands_env_reference() {
        let url = mock_http_server("200 OK", "203.0.113.8\n").await;
        let lookup = move |name: &str| (name == "IP_URL").then(|| url.clone());
        assert_eq!(
            resolve_with_env("$IP_URL", lookup).await.unwrap(),
            Ipv4Addr::new(203, 0, 113, 8)
        );
    }

    #[tokio::test]
    async fn resolve_accepts_literal_ip() {
        assert_eq!(
            resolve(" 203.0.113.1 ").await.unwrap(),
            Ipv4Addr::new(203, 0, 113, 1)
        );
    }

    /// Spawn a one-shot HTTP server that answers with `status` and `body`.
    async fn mock_http_server(status: &'static str, body: &'static str) -> String {
        mock_http_raw(format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ))
        .await
    }

    /// Spawn a one-shot HTTP server that answers with a verbatim response.
    async fn mock_http_raw(response: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await.unwrap();
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
        format!("http://{addr}/ip")
    }

    #[tokio::test]
    async fn resolve_fetches_ip_from_http_endpoint() {
        let url = mock_http_server("200 OK", "203.0.113.7\n").await;
        assert_eq!(resolve(&url).await.unwrap(), Ipv4Addr::new(203, 0, 113, 7));
    }

    #[tokio::test]
    async fn resolve_handles_chunked_response() {
        let url = mock_http_raw(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
             b\r\n203.0.113.5\r\n0\r\n\r\n"
                .to_string(),
        )
        .await;
        assert_eq!(resolve(&url).await.unwrap(), Ipv4Addr::new(203, 0, 113, 5));
    }

    #[tokio::test]
    async fn resolve_reports_http_error_status() {
        let url = mock_http_server("503 Service Unavailable", "try later").await;
        let err = resolve(&url).await.unwrap_err();
        assert!(err.contains("503"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn resolve_reports_redirect_target() {
        let url = mock_http_raw(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://ifconfig.me/ip\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
                .to_string(),
        )
        .await;
        let err = resolve(&url).await.unwrap_err();
        assert!(err.contains("301"), "unexpected error: {err}");
        assert!(
            err.contains("https://ifconfig.me/ip"),
            "redirect target should be reported: {err}"
        );
    }
}
