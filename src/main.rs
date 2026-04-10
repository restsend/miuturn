use miuturn::{
    AclAction, AclRule, AuthManager, Config, Metrics, SharedAuthManager, TurnServer, User, UserType,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config_path = std::env::var("CONFIG").unwrap_or_else(|_| "miuturn.toml".to_string());
    let config = Config::load(PathBuf::from(&config_path)).unwrap_or_else(|_| Config::default());
    println!("Loaded configuration from {}", config_path);
    println!("Log level: {}", config.log.log_level);
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log.log_level));

    if let Some(ref log_file) = config.log.log_file {
        println!("Logging to file: {}", log_file);
        let file_appender = tracing_appender::rolling::never(".", log_file);
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_writer(file_appender)
            .with_ansi(false)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }
    println!("Starting miuturn TURN server");
    println!("Realm: {}", config.server.realm);
    println!("External IP: {}", config.server.external_ip);
    println!(
        "Port range: {}-{}",
        config.server.start_port, config.server.end_port
    );

    let relay_addr: std::net::Ipv4Addr = config
        .server
        .external_ip
        .parse()
        .unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));
    let server = TurnServer::with_limits(
        relay_addr,
        config.server.realm.clone(),
        config.server.max_concurrent_allocations,
        config.server.max_allocation_duration_secs,
        config
            .server
            .max_bandwidth_bytes_per_sec
            .map(|b| b as usize),
    );

    let auth_manager: SharedAuthManager = Arc::new(AuthManager::new(config.server.realm.clone()));

    for user_config in &config.auth.users {
        let user = User {
            username: user_config.username.clone(),
            password: user_config.password.clone(),
            user_type: match user_config.user_type.as_str() {
                "Temporary" => UserType::Temporary,
                "ApiKey" => UserType::ApiKey,
                _ => UserType::Fixed,
            },
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expires_at: user_config.expires_at,
            max_allocations: user_config.max_allocations.unwrap_or(10),
            bandwidth_limit: user_config.bandwidth_limit,
            ip_whitelist: user_config.ip_whitelist.clone(),
            max_allocation_duration_secs: user_config.max_allocation_duration_secs,
        };
        auth_manager.add_user(user);
    }

    for username in config.auth.api_keys.values() {
        let user = User {
            username: username.clone(),
            password: String::new(),
            user_type: UserType::ApiKey,
            created_at: 0,
            expires_at: None,
            max_allocations: 100,
            bandwidth_limit: None,
            ip_whitelist: None,
            max_allocation_duration_secs: None,
        };
        auth_manager.add_user(user);
    }

    for acl_config in &config.auth.acl_rules {
        let rule = AclRule {
            ip_range: acl_config.ip_range.clone(),
            action: if acl_config.action == "Allow" {
                AclAction::Allow
            } else {
                AclAction::Deny
            },
            priority: acl_config.priority.unwrap_or(0),
        };
        auth_manager.add_acl_rule(rule);
    }

    for listener in &config.server.listening {
        let addr: SocketAddr = listener.addr();
        match listener.protocol.as_str() {
            "tcp" => {
                let srv = server.clone();
                tokio::spawn(async move {
                    if let Err(e) = srv.run_tcp(addr).await {
                        tracing::error!("TCP server error: {}", e);
                    }
                });
            }
            "udp" => {
                let srv = server.clone();
                tokio::spawn(async move {
                    if let Err(e) = srv.run_udp(addr).await {
                        tracing::error!("UDP server error: {}", e);
                    }
                });
            }
            _ => {
                tracing::warn!("Unknown protocol: {}", listener.protocol);
            }
        }
    }

    let stats_fn: Arc<dyn Fn() -> _ + Send + Sync> = {
        let allocation_table = server.allocation_table.clone();
        Arc::new(move || allocation_table.stats().snapshot())
    };

    // Admin console — only started if [http] is configured
    if let Some(http) = &config.http {
        let admin_username = http.admin_username.clone();
        let admin_password = http.admin_password.clone();
        let http_addr: SocketAddr = http
            .address
            .parse()
            .unwrap_or_else(|_| "0.0.0.0:8080".parse().unwrap());

        let turn_rest_enabled = http.turn_rest_enabled.unwrap_or(false);
        let turn_rest_secret = http.turn_rest_secret.clone();
        let turn_rest_default_lifetime = http.turn_rest_default_lifetime.unwrap_or(3600);

        let metrics = Metrics::new();

        let config_path = std::env::var("CONFIG")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("miuturn.toml"));

        tokio::spawn(async move {
            if let Err(e) = miuturn::create_admin_routes(
                http_addr.to_string(),
                stats_fn,
                admin_username,
                admin_password,
                auth_manager.clone(),
                turn_rest_enabled,
                turn_rest_secret,
                turn_rest_default_lifetime,
                Some(metrics),
                Some(config_path),
            )
            .await
            {
                tracing::error!("Admin server error: {}", e);
            }
        });

        info!("HTTP server available at http://{}", http.address);
    }

    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");
    Ok(())
}
