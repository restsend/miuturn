use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub http: Option<HttpConfig>,
    pub auth: AuthConfig,
    #[serde(default)]
    pub log: LogConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub realm: String,
    pub external_ip: String,
    #[serde(default)]
    pub relay_bind_ip: Option<String>,
    pub start_port: u16,
    pub end_port: u16,
    pub listening: Vec<ListenConfig>,
    pub max_concurrent_allocations: Option<usize>,
    pub max_bandwidth_bytes_per_sec: Option<u64>,
    pub max_allocation_duration_secs: Option<u32>,
    #[serde(default = "ServerConfig::default_stats_dump_interval_secs")]
    pub stats_dump_interval_secs: u64,
    #[serde(default = "ServerConfig::default_stats_dump_skip_if_no_change")]
    pub stats_dump_skip_if_no_change: bool,
    #[serde(default = "ServerConfig::default_server_name")]
    pub server_name: String,
}

impl ServerConfig {
    fn default_stats_dump_interval_secs() -> u64 {
        30
    }

    fn default_stats_dump_skip_if_no_change() -> bool {
        true
    }

    fn default_server_name() -> String {
        format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ListenConfig {
    pub protocol: String,
    pub address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HttpConfig {
    pub address: String,
    /// Enable TURN REST API for WebRTC credential generation
    pub turn_rest_enabled: Option<bool>,
    /// Secret key for TURN REST API HMAC authentication
    pub turn_rest_secret: Option<String>,
    /// Default lifetime for TURN REST credentials in seconds
    pub turn_rest_default_lifetime: Option<u64>,
    /// Admin console username (separate from auth.users)
    pub admin_username: Option<String>,
    /// Admin console password
    pub admin_password: Option<String>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            address: "0.0.0.0:8080".to_string(),
            turn_rest_enabled: Some(false),
            turn_rest_secret: None,
            turn_rest_default_lifetime: Some(3600),
            admin_username: None,
            admin_password: None,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogConfig {
    pub log_file: Option<String>,
    #[serde(default = "LogConfig::default_level")]
    pub log_level: String,
}

impl LogConfig {
    fn default_level() -> String {
        "info".to_string()
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_file: None,
            log_level: Self::default_level(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AuthConfig {
    #[serde(default)]
    pub users: Vec<UserConfig>,
    #[serde(default)]
    pub api_keys: HashMap<String, String>,
    #[serde(default)]
    pub acl_rules: Vec<AclRuleConfig>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UserConfig {
    pub username: String,
    pub password: String,
    pub user_type: String,
    pub expires_at: Option<u64>,
    pub max_allocations: Option<usize>,
    pub bandwidth_limit: Option<u64>,
    pub ip_whitelist: Option<Vec<String>>,
    pub max_allocation_duration_secs: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AclRuleConfig {
    pub ip_range: String,
    pub action: String,
    pub priority: Option<u32>,
}

impl Config {
    pub fn load(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save(&self, path: PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server: ServerConfig {
                realm: "miuturn".to_string(),
                external_ip: "0.0.0.0".to_string(),
                relay_bind_ip: None,
                start_port: 49152,
                end_port: 65535,
                listening: vec![
                    ListenConfig {
                        protocol: "udp".to_string(),
                        address: "0.0.0.0:3478".to_string(),
                    },
                    ListenConfig {
                        protocol: "tcp".to_string(),
                        address: "0.0.0.0:3478".to_string(),
                    },
                ],
                max_concurrent_allocations: None,
                max_bandwidth_bytes_per_sec: None,
                max_allocation_duration_secs: None,
                stats_dump_interval_secs: 30,
                stats_dump_skip_if_no_change: true,
                server_name: ServerConfig::default_server_name(),
            },
            http: None,
            log: LogConfig::default(),
            auth: AuthConfig {
                users: vec![],
                api_keys: HashMap::new(),
                acl_rules: vec![AclRuleConfig {
                    ip_range: "0.0.0.0/0".to_string(),
                    action: "Allow".to_string(),
                    priority: Some(0),
                }],
            },
        }
    }
}

impl ListenConfig {
    pub fn addr(&self) -> SocketAddr {
        self.address.parse().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.server.realm, "miuturn");
        assert_eq!(config.server.external_ip, "0.0.0.0");
        assert_eq!(config.server.relay_bind_ip, None);
        assert_eq!(config.server.start_port, 49152);
        assert_eq!(config.server.end_port, 65535);
        assert!(config.server.max_concurrent_allocations.is_none());
    }

    #[test]
    fn test_http_config_default() {
        let http = HttpConfig::default();
        assert_eq!(http.address, "0.0.0.0:8080");
        assert_eq!(http.turn_rest_enabled, Some(false));
        assert_eq!(http.turn_rest_default_lifetime, Some(3600));
        assert!(http.turn_rest_secret.is_none());
    }

    #[test]
    fn test_config_toml_roundtrip() {
        let config = Config::default();
        let serialized = toml::to_string_pretty(&config).unwrap();
        let deserialized: Config = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.server.realm, config.server.realm);
        assert_eq!(deserialized.server.external_ip, config.server.external_ip);
    }

    #[test]
    fn test_config_with_turn_rest() {
        let toml_content = r#"
[server]
realm = "test-realm"
external_ip = "192.168.1.1"
relay_bind_ip = "0.0.0.0"
start_port = 49152
end_port = 65535
max_concurrent_allocations = 100
max_allocation_duration_secs = 600

[[server.listening]]
protocol = "udp"
address = "0.0.0.0:3478"

[[server.listening]]
protocol = "tcp"
address = "0.0.0.0:3478"

[http]
address = "0.0.0.0:8080"
turn_rest_enabled = true
turn_rest_secret = "my-secret-key"
turn_rest_default_lifetime = 7200

[auth]
users = []

[auth.api_keys]
key1 = "user1"

[[auth.acl_rules]]
ip_range = "0.0.0.0/0"
action = "Allow"
priority = 0
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(config.server.realm, "test-realm");
        assert_eq!(config.server.external_ip, "192.168.1.1");
        assert_eq!(config.server.relay_bind_ip.as_deref(), Some("0.0.0.0"));
        assert_eq!(config.http.as_ref().unwrap().turn_rest_enabled, Some(true));
        assert_eq!(
            config.http.as_ref().unwrap().turn_rest_secret,
            Some("my-secret-key".to_string())
        );
        assert_eq!(
            config.http.as_ref().unwrap().turn_rest_default_lifetime,
            Some(7200)
        );
        assert_eq!(config.auth.api_keys.get("key1"), Some(&"user1".to_string()));
    }

    #[test]
    fn test_listen_config_addr() {
        let config = ListenConfig {
            protocol: "udp".to_string(),
            address: "192.168.1.1:3478".to_string(),
        };
        let addr = config.addr();
        assert_eq!(addr.port(), 3478);
    }

    #[test]
    fn test_user_config() {
        let user = UserConfig {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
            user_type: "fixed".to_string(),
            expires_at: Some(9999999999),
            max_allocations: Some(5),
            bandwidth_limit: Some(1000000),
            ip_whitelist: None,
            max_allocation_duration_secs: Some(600),
        };
        assert_eq!(user.username, "testuser");
        assert_eq!(user.user_type, "fixed");
        assert!(user.expires_at.is_some());
    }

    #[test]
    fn test_acl_rule_config() {
        let rule = AclRuleConfig {
            ip_range: "10.0.0.0/8".to_string(),
            action: "Allow".to_string(),
            priority: Some(10),
        };
        assert_eq!(rule.ip_range, "10.0.0.0/8");
        assert_eq!(rule.action, "Allow");
        assert_eq!(rule.priority, Some(10));
    }

    #[test]
    fn test_config_toml_with_full_user_config() {
        let toml_content = r#"
[server]
realm = "test-realm"
external_ip = "192.168.1.1"
start_port = 49152
end_port = 65535

[[server.listening]]
protocol = "udp"
address = "0.0.0.0:3478"

[http]
address = "0.0.0.0:8080"

[[auth.users]]
username = "fulluser"
password = "secret"
user_type = "fixed"
max_allocations = 5
bandwidth_limit = 1048576
max_allocation_duration_secs = 600
ip_whitelist = ["192.168.1.0/24", "10.0.0.1"]

[auth.api_keys]

[[auth.acl_rules]]
ip_range = "0.0.0.0/0"
action = "Allow"
priority = 0
"#;
        let config: Config = toml::from_str(toml_content).unwrap();
        assert_eq!(config.auth.users.len(), 1);
        let user = &config.auth.users[0];
        assert_eq!(user.username, "fulluser");
        assert_eq!(user.bandwidth_limit, Some(1048576));
        assert_eq!(user.max_allocation_duration_secs, Some(600));
        assert_eq!(user.ip_whitelist.as_ref().unwrap().len(), 2);
        assert!(
            user.ip_whitelist
                .as_ref()
                .unwrap()
                .contains(&"192.168.1.0/24".to_string())
        );
    }

    #[test]
    fn test_user_config_with_minimal_fields() {
        let user = UserConfig {
            username: "minimal".to_string(),
            password: "pass".to_string(),
            user_type: "temporary".to_string(),
            expires_at: None,
            max_allocations: None,
            bandwidth_limit: None,
            ip_whitelist: None,
            max_allocation_duration_secs: None,
        };
        assert_eq!(user.username, "minimal");
        assert!(user.bandwidth_limit.is_none());
        assert!(user.ip_whitelist.is_none());
        assert!(user.max_allocation_duration_secs.is_none());
    }

    #[test]
    fn test_user_config_serialize_to_toml() {
        let user = UserConfig {
            username: "test".to_string(),
            password: "pass".to_string(),
            user_type: "fixed".to_string(),
            expires_at: Some(1234567890),
            max_allocations: Some(10),
            bandwidth_limit: Some(2097152),
            ip_whitelist: Some(vec!["192.168.0.0/16".to_string()]),
            max_allocation_duration_secs: Some(1800),
        };
        let toml = toml::to_string(&user).unwrap();
        assert!(toml.contains("bandwidth_limit = 2097152"));
        assert!(toml.contains("max_allocation_duration_secs = 1800"));
        assert!(toml.contains("\"192.168.0.0/16\""));
    }

    #[test]
    fn test_user_config_empty_ip_whitelist() {
        let toml_content = r#"
username = "nowhitelist"
password = "pass"
user_type = "fixed"
ip_whitelist = []
"#;
        let user: UserConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(user.ip_whitelist.as_ref().unwrap().len(), 0);
    }
}
