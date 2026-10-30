use miuturn::{
    AclAction, AclRule, AuthManager, Config, Metrics, SharedAuthManager,
    ShortTermCredentialManager, TurnServer, User, UserType,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};
use tracing_subscriber::Layer as _;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config_path = std::env::var("CONFIG").unwrap_or_else(|_| "miuturn.toml".to_string());
    let config = match Config::load(PathBuf::from(&config_path)) {
        Ok(cfg) => {
            println!("Loaded configuration from {}", config_path);
            cfg
        }
        Err(e) => {
            eprintln!("Failed to load config from {}: {}", config_path, e);
            Config::default()
        }
    };
    println!("Log level: {}", config.log.log_level);

    // Build the subscriber with a runtime-adjustable log level filter so the
    // log level can be changed via the admin /api/v1/reload endpoint. The
    // writer is boxed so the subscriber type is identical for the file and
    // console cases.
    //
    // DynamicLevelFilter answers Interest::sometimes() unconditionally, i.e.
    // every event consults the live atomic level - no callsite interest cache
    // is involved, so reload takes effect immediately on every platform.
    // (EnvFilter + reload::Layer::modify is correct per tracing-subscriber's
    // docs but the interest-cache rebuild never took effect in linux
    // containers, leaving the boot-time level in force - see AGENTS.md.)
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let writer: tracing_subscriber::fmt::writer::BoxMakeWriter =
        if let Some(ref log_file) = config.log.log_file {
            println!("Logging to file: {}", log_file);
            tracing_subscriber::fmt::writer::BoxMakeWriter::new(tracing_appender::rolling::never(
                ".", log_file,
            ))
        } else {
            tracing_subscriber::fmt::writer::BoxMakeWriter::new(std::io::stdout)
        };

    let log_filter = miuturn::logfilter::DynamicLevelFilter::new(&config.log.log_level);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .with_ansi(config.log.log_file.is_none())
        .with_filter(log_filter.clone());

    tracing_subscriber::Registry::default().with(fmt_layer).init();

    let log_reload: Option<Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>> =
        Some(Arc::new(move |level: &str| {
            log_filter.set_level(level);
            Ok(())
        }));
    println!("Starting miuturn TURN server");
    // Build identity: version + compile timestamp injected by build.rs, and
    // the process start time — the three things a production log reader needs
    // to know exactly which binary has been running for how long.
    let build_time = option_env!("MIUTURN_BUILD_TIME").unwrap_or("unknown");
    let started_at = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into());
    println!(
        "Version: {} (built {} UTC, git {}, started {} UTC)",
        env!("CARGO_PKG_VERSION"),
        build_time,
        option_env!("MIUTURN_BUILD_GIT").unwrap_or("unknown"),
        started_at
    );
    println!("Realm: {}", config.server.realm);
    println!("External IP: {}", config.server.external_ip);
    if let Some(ref relay_bind_ip) = config.server.relay_bind_ip {
        println!("Relay bind IP: {}", relay_bind_ip);
    }
    println!(
        "Port range: {}-{}",
        config.server.start_port, config.server.end_port
    );

    let relay_addr: std::net::Ipv4Addr = config
        .server
        .external_ip
        .parse()
        .unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));
    let relay_bind_addr: std::net::Ipv4Addr = config
        .server
        .relay_bind_ip
        .as_deref()
        .unwrap_or("0.0.0.0")
        .parse()
        .unwrap_or(std::net::Ipv4Addr::new(0, 0, 0, 0));
    let mut server = TurnServer::with_port_range_limits_bind_address(
        relay_addr,
        relay_bind_addr,
        config.server.realm.clone(),
        config.server.start_port,
        config.server.end_port,
        config.server.max_concurrent_allocations,
        config.server.max_allocation_duration_secs,
        config
            .server
            .max_bandwidth_bytes_per_sec
            .map(|b| b as usize),
        false,
    );

    // Resolve the shared secret for ephemeral TURN REST API credentials.
    // `auth.shared_secret` takes precedence over the legacy `http.turn_rest_secret`.
    let shared_secret = config.auth.resolve_shared_secret(config.http.as_ref());
    if config.auth.shared_secret.is_none()
        && config
            .http
            .as_ref()
            .and_then(|h| h.turn_rest_secret.as_ref())
            .is_some()
    {
        tracing::warn!(
            "http.turn_rest_secret is deprecated; use auth.shared_secret instead"
        );
    }
    let turn_rest_enabled = config
        .http
        .as_ref()
        .and_then(|h| h.turn_rest_enabled)
        .unwrap_or(false);
    if turn_rest_enabled && shared_secret.is_none() {
        return Err(
            "turn_rest_enabled = true but no secret configured: set auth.shared_secret \
             (or the legacy http.turn_rest_secret)"
                .into(),
        );
    }
    if let Some(ref secret) = shared_secret {
        server.set_short_term_manager(ShortTermCredentialManager::new(secret.clone()));
        println!(
            "TURN REST API ephemeral credentials: enabled (expired_token_policy = {:?})",
            config.auth.expired_token_policy
        );
    }
    server.set_expired_token_policy(config.auth.expired_token_policy);

    server.set_stats_dump_interval(config.server.stats_dump_interval_secs);
    server.set_stats_dump_skip_if_no_change(config.server.stats_dump_skip_if_no_change);
    server.set_server_name(config.server.server_name.clone());
    server.set_enforce_peer_permissions(config.server.relay_enforce_peer_permissions);

    info!(
        external_ip = %relay_addr,
        relay_bind_ip = %relay_bind_addr,
        stats_dump_interval = config.server.stats_dump_interval_secs,
        stats_dump_skip_if_no_change = config.server.stats_dump_skip_if_no_change,
        server_name = %config.server.server_name,
        relay_enforce_peer_permissions = config.server.relay_enforce_peer_permissions,
        "configured relay addressing"
    );

    let auth_manager: SharedAuthManager = Arc::new(
        AuthManager::new(config.server.realm.clone()).with_secret_credentials(
            miuturn::ShortTermCredentialManager::from_auth_config(&config.auth)?,
        ),
    );

    // The auth manager handles the configured TURN credential mode and ACLs.
    server.set_auth_manager(auth_manager.clone());

    let server = server; // remove mut

    // ── Persistence: load previous session state (restart restore) ──────────
    // Queues allocations/channels for re-attach on listener start, restores
    // nonces and lifetime counters immediately. Mismatched or corrupt state
    // is rotated aside and the server starts fresh.
    let persist_settings = miuturn::PersistSettings::from(&config.persist);
    let persist_fingerprint = miuturn::config_fingerprint(&config);
    if persist_settings.enabled {
        match miuturn::load_state(&persist_settings.path) {
            Ok(state) if state.config_fingerprint == persist_fingerprint => {
                server.allocation_table.restore_counters(&state.counters);
                let nonces_restored = server.restore_nonces(state.nonces);
                server.allocation_table.set_pending_restore(
                    state.allocations,
                    state.channels,
                );
                info!(
                    path = %persist_settings.path.display(),
                    saved_at_epoch = state.saved_at_epoch,
                    nonces_restored,
                    total_allocations = state.counters.total_allocations,
                    "persist: previous state loaded, sessions will be restored on listener start"
                );
            }
            Ok(state) => {
                // Config changed: sessions from the old config cannot be
                // resumed (relay range / external IP / listeners differ).
                let aside = miuturn::persist::rotate_aside(&persist_settings.path, "mismatch");
                warn!(
                    saved_fingerprint = %state.config_fingerprint,
                    current_fingerprint = %persist_fingerprint,
                    aside = aside.as_ref().map(|p| p.display().to_string()).as_deref(),
                    "persist: config changed since state was saved, starting fresh"
                );
            }
            Err(miuturn::PersistLoadError::NotFound) => {
                info!("persist: no previous state file, starting fresh");
            }
            Err(miuturn::PersistLoadError::Corrupt(e)) => {
                let aside = miuturn::persist::rotate_aside(&persist_settings.path, "corrupt");
                error!(
                    error = %e,
                    aside = aside.as_ref().map(|p| p.display().to_string()).as_deref(),
                    "persist: state file unusable, starting fresh"
                );
            }
        }

        // Periodic checkpoint while running.
        server.start_checkpoint_task(persist_settings.clone(), persist_fingerprint.clone());

        // Container deployments: a state path outside a mounted volume is
        // wiped on container recreation, silently degrading to the old
        // drop-everything restart. miuturn cannot see the host's mount table,
        // so just nudge the operator to double-check (see README warning).
        let in_container =
            std::path::Path::new("/.dockerenv").exists()
                || std::path::Path::new("/run/.containerenv").exists();
        if in_container {
            warn!(
                path = %persist_settings.path.display(),
                "persist: running inside a container — make sure the state \
                 directory is a mounted volume, or state will be lost on \
                 container recreation (see README: Persistence & Restarts)"
            );
        }
    }

    for user_config in &config.auth.users {
        let user = User {
            username: user_config.username.clone(),
            password: user_config.password.clone(),
            user_type: match user_config.user_type.as_str() {
                "temporary" => UserType::Temporary,
                "api_key" => UserType::ApiKey,
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
            action: if acl_config.action.eq_ignore_ascii_case("allow") {
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

        let turn_rest_default_lifetime = http.turn_rest_default_lifetime.unwrap_or(3600);

        let metrics = Metrics::new();
        // Feed real allocation/channel/request data into the collector exposed
        // at /metrics (recorded at low-frequency lifecycle points).
        server.allocation_table.set_metrics(Some(metrics.clone()));

        let config_path = std::env::var("CONFIG")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("miuturn.toml"));

        let external_ip = config.server.external_ip.clone();
        let listen_configs = config.server.listening.clone();

        let admin_acl = http.admin_acl.clone();
        let trust_proxy = http.trust_proxy.unwrap_or(false);

        let log_reload = log_reload.clone();

        tokio::spawn(async move {
            if let Err(e) = miuturn::create_admin_routes(
                http_addr.to_string(),
                stats_fn,
                admin_username,
                admin_password,
                auth_manager.clone(),
                turn_rest_enabled,
                shared_secret.clone(),
                turn_rest_default_lifetime,
                Some(metrics),
                Some(config_path),
                external_ip,
                listen_configs,
                admin_acl,
                trust_proxy,
                log_reload,
            )
            .await
            {
                tracing::error!("Admin server error: {}", e);
            }
        });

        info!("HTTP server available at http://{}", http.address);
    }

    // Wait for a shutdown signal: Ctrl+C (SIGINT), SIGTERM (docker stop /
    // systemctl stop / kill) or SIGUSR2 (explicit "save & restart" trigger,
    // useful with a restart policy / supervisor). All three trigger the same
    // graceful path; when persistence is enabled a final unconditional state
    // save runs so the next process resumes sessions.
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigusr2 = signal(SignalKind::user_defined2())?;
        tokio::select! {
            _ = sigint.recv() => info!("SIGINT received, shutting down"),
            _ = sigterm.recv() => info!("SIGTERM received, shutting down"),
            _ = sigusr2.recv() => info!("SIGUSR2 received, shutting down for restart"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        info!("Ctrl+C received, shutting down");
    }

    // Final save: covers sessions created since the last checkpoint. Even if
    // this fails, the last checkpoint is still on disk.
    if persist_settings.enabled {
        let state = server.build_persisted_state(&persist_fingerprint).await;
        match miuturn::save_state(&persist_settings.path, &state) {
            Ok(()) => info!(
                allocations = state.allocations.len(),
                channels = state.channels.len(),
                path = %persist_settings.path.display(),
                "persist: final state saved before shutdown"
            ),
            Err(e) => error!(
                path = %persist_settings.path.display(),
                error = %e,
                "persist: final state save failed (last checkpoint remains on disk)"
            ),
        }
    }

    info!("Shutting down...");
    Ok(())
}
