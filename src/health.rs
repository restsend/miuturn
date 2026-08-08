use crate::allocation::ServerStatsSnapshot;
use crate::auth::{AclAction, AclRule, SharedAuthManager, User, UserType};
use crate::config::{AclRuleConfig, Config, ListenConfig, UserConfig};
use crate::metrics::Metrics;
use crate::short_term::ShortTermCredentialManager;
use axum::{
    Form, Router,
    extract::{ConnectInfo, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Redirect},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde_json;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
pub struct HealthState {
    pub stats_fn: Arc<dyn Fn() -> ServerStatsSnapshot + Send + Sync>,
}

#[derive(Clone)]
pub struct AdminState {
    pub admin_username: Option<String>,
    pub admin_password: Option<String>,
}

#[derive(Clone)]
pub struct TurnRestState {
    pub enabled: bool,
    pub credential_manager: Option<ShortTermCredentialManager>,
}

/// Build the TURN REST credential state from an HTTP config section.
fn build_turn_rest_state(config: &Config) -> TurnRestState {
    let enabled = config
        .http
        .as_ref()
        .and_then(|h| h.turn_rest_enabled)
        .unwrap_or(false);
    if enabled {
        let secret = config
            .http
            .as_ref()
            .and_then(|h| h.turn_rest_secret.clone())
            .unwrap_or_else(|| "default-secret-key".to_string());
        let lifetime = config
            .http
            .as_ref()
            .and_then(|h| h.turn_rest_default_lifetime)
            .unwrap_or(3600);
        let manager = ShortTermCredentialManager::new(secret).with_lifetime(lifetime);
        TurnRestState {
            enabled: true,
            credential_manager: Some(manager),
        }
    } else {
        TurnRestState {
            enabled: false,
            credential_manager: None,
        }
    }
}

#[derive(Clone)]
struct AppState {
    admin: AdminState,
    health: HealthState,
    auth: SharedAuthManager,
    /// Shared so the reload endpoint can swap TURN REST credentials live.
    turn_rest: Arc<parking_lot::RwLock<TurnRestState>>,
    metrics: Option<Metrics>,
    config_path: Option<PathBuf>,
    external_ip: String,
    listen_configs: Vec<ListenConfig>,
    admin_acl: Vec<String>,
    trust_proxy: bool,
    /// Erased handle used to hot-reload the tracing log level.
    log_reload: Option<Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>>,
}

const SESSION_COOKIE: &str = "admin_session";
const SESSION_VALUE: &str = "authenticated";

// Helper function to check if user is authenticated
fn check_auth(jar: &CookieJar, admin_state: &AdminState) -> bool {
    // If no admin credentials configured, allow access
    if admin_state.admin_username.is_none() {
        return true;
    }
    // Check session cookie
    jar.get(SESSION_COOKIE)
        .map(|cookie| cookie.value() == SESSION_VALUE)
        .unwrap_or(false)
}

// Middleware to enforce admin ACL by IP
async fn admin_acl_middleware(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> impl IntoResponse {
    let ip = if state.trust_proxy {
        request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .or_else(|| {
                request
                    .headers()
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| addr.ip().to_string())
    } else {
        addr.ip().to_string()
    };
    let allowed = state.admin_acl.is_empty()
        || state
            .admin_acl
            .iter()
            .any(|range| crate::auth::AuthManager::ip_in_range(&ip, range));
    if allowed {
        next.run(request).await
    } else {
        tracing::warn!("Admin access denied for IP: {}", ip);
        (
            StatusCode::FORBIDDEN,
            [("content-type", "text/plain; charset=utf-8")],
            "Forbidden: admin access denied from this IP",
        )
            .into_response()
    }
}

// Helper function to save config to file
fn save_config(state: &AppState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config_path = match &state.config_path {
        Some(path) => path.clone(),
        None => return Ok(()), // No config path, skip saving
    };

    // Build Config from current state
    let users: Vec<UserConfig> = state
        .auth
        .list_users()
        .into_iter()
        .map(|u| UserConfig {
            username: u.username,
            password: u.password,
            user_type: match u.user_type {
                UserType::Temporary => "temporary".to_string(),
                UserType::Fixed => "fixed".to_string(),
                UserType::ApiKey => "api_key".to_string(),
            },
            expires_at: u.expires_at,
            max_allocations: Some(u.max_allocations),
            bandwidth_limit: u.bandwidth_limit,
            ip_whitelist: u.ip_whitelist,
            max_allocation_duration_secs: u.max_allocation_duration_secs,
        })
        .collect();

    let acl_rules: Vec<AclRuleConfig> = state
        .auth
        .list_acl_rules()
        .into_iter()
        .map(|r| AclRuleConfig {
            ip_range: r.ip_range,
            action: match r.action {
                AclAction::Allow => "Allow".to_string(),
                AclAction::Deny => "Deny".to_string(),
            },
            priority: Some(r.priority),
        })
        .collect();

    // Load existing config to preserve server and http settings
    let mut config = if config_path.exists() {
        Config::load(config_path.clone()).unwrap_or_default()
    } else {
        Config::default()
    };

    // Update only the auth section
    config.auth.users = users;
    config.auth.acl_rules = acl_rules;

    config.save(config_path)?;
    Ok(())
}

pub async fn create_admin_routes(
    addr: String,
    stats_fn: Arc<dyn Fn() -> ServerStatsSnapshot + Send + Sync>,
    admin_username: Option<String>,
    admin_password: Option<String>,
    auth: SharedAuthManager,
    turn_rest_enabled: bool,
    turn_rest_secret: Option<String>,
    turn_rest_default_lifetime: u64,
    metrics: Option<Metrics>,
    config_path: Option<PathBuf>,
    external_ip: String,
    listen_configs: Vec<ListenConfig>,
    admin_acl: Vec<String>,
    trust_proxy: bool,
    log_reload: Option<Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let turn_rest_state = Arc::new(parking_lot::RwLock::new(TurnRestState {
        enabled: turn_rest_enabled,
        credential_manager: if turn_rest_enabled {
            let secret = turn_rest_secret.unwrap_or_else(|| "default-secret-key".to_string());
            let manager =
                ShortTermCredentialManager::new(secret).with_lifetime(turn_rest_default_lifetime);
            Some(manager)
        } else {
            None
        },
    }));

    let state = AppState {
        admin: AdminState {
            admin_username,
            admin_password,
        },
        health: HealthState { stats_fn },
        auth,
        turn_rest: turn_rest_state,
        metrics,
        config_path,
        external_ip,
        listen_configs,
        admin_acl,
        trust_proxy,
        log_reload,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes (no ACL check)
    let public_routes = Router::new()
        .route("/health", get(health_proxy_handler))
        .route("/api/v1/turn-credentials", post(turn_credentials_handler))
        .route("/api/v1/iceservers", get(ice_servers_handler));

    // Admin routes (protected by ACL)
    let admin_routes = Router::new()
        .route("/", get(root_handler))
        .route("/console", get(console_handler))
        .route("/console/dashboard", get(dashboard_handler))
        .route("/login", post(login_handler))
        .route("/api/stats", get(stats_json_handler))
        .route("/api/v1/stats", get(stats_json_handler))
        .route("/api/v1/reload", post(reload_handler))
        .route("/api/login", post(api_login_handler))
        .route("/api/reload", post(reload_handler))
        .route(
            "/api/v1/users",
            post(add_user_handler)
                .delete(delete_user_handler)
                .put(update_user_handler),
        )
        .route(
            "/api/v1/acl",
            post(add_acl_handler)
                .delete(delete_acl_handler)
                .put(update_acl_handler),
        )
        .route("/logout", post(logout_handler))
        .route("/metrics", get(prometheus_metrics_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            admin_acl_middleware,
        ));

    let app = public_routes
        .merge(admin_routes)
        .layer(cors)
        .with_state(state);

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Admin console available at http://{}", addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn root_handler() -> Redirect {
    Redirect::to("/console")
}

async fn console_handler(
    jar: CookieJar,
    State(state): State<AppState>,
) -> impl axum::response::IntoResponse {
    // If already authenticated, redirect to dashboard
    if check_auth(&jar, &state.admin) {
        return Redirect::to("/console/dashboard").into_response();
    }

    // Not authenticated, show login page if admin is configured
    if state.admin.admin_username.is_some() {
        let html = include_str!("../static/login.html");
        return Html(html.to_string()).into_response();
    }

    // No admin configured, allow access (development mode)
    let html = include_str!("../static/admin.html");
    Html(html.to_string()).into_response()
}

async fn dashboard_handler(jar: CookieJar, State(state): State<AppState>) -> Html<String> {
    // Check authentication
    if !check_auth(&jar, &state.admin) {
        return Html(
            r#"<!DOCTYPE html>
<html>
<head><meta http-equiv="refresh" content="0; url=/console" /></head>
<body>Redirecting...</body>
</html>"#
                .to_string(),
        );
    }

    let html = include_str!("../static/admin.html");
    Html(html.to_string())
}

#[derive(Debug, serde::Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

async fn login_handler(
    jar: CookieJar,
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> (CookieJar, Redirect) {
    if let (Some(username), Some(password)) =
        (&state.admin.admin_username, &state.admin.admin_password)
        && form.username == *username
        && form.password == *password
    {
        // Set session cookie
        let cookie = Cookie::build((SESSION_COOKIE, SESSION_VALUE))
            .path("/")
            .http_only(true)
            .same_site(axum_extra::extract::cookie::SameSite::Lax);
        let jar = jar.add(cookie);
        return (jar, Redirect::to("/console/dashboard"));
    }

    (jar, Redirect::to("/console?error=1"))
}

async fn logout_handler(jar: CookieJar) -> (CookieJar, Redirect) {
    // Remove session cookie - must match all attributes of the original cookie
    let mut removal_cookie = Cookie::new(SESSION_COOKIE, "");
    removal_cookie.set_path("/");
    removal_cookie.set_http_only(true);
    removal_cookie.set_same_site(axum_extra::extract::cookie::SameSite::Lax);
    removal_cookie.make_removal();
    let jar = jar.add(removal_cookie);
    (jar, Redirect::to("/console"))
}

async fn stats_json_handler(
    jar: CookieJar,
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    // Check authentication
    if !check_auth(&jar, &state.admin) {
        return Json(serde_json::json!({
            "success": false,
            "error": "Unauthorized"
        }));
    }

    let stats = (state.health.stats_fn)();
    let users = state.auth.list_users();
    let acl_rules = state.auth.list_acl_rules();
    let realm = state.auth.realm().to_string();

    let users_json: Vec<serde_json::Value> = users
        .into_iter()
        .map(|u| {
            serde_json::json!({
                "username": u.username,
                "user_type": format!("{:?}", u.user_type),
                "max_allocations": u.max_allocations,
                "expires_at": u.expires_at,
                "bandwidth_limit": u.bandwidth_limit,
                "max_allocation_duration_secs": u.max_allocation_duration_secs,
                "ip_whitelist": u.ip_whitelist,
            })
        })
        .collect();

    let acl_json: Vec<serde_json::Value> = acl_rules
        .into_iter()
        .map(|r| {
            serde_json::json!({
                "ip_range": r.ip_range,
                "action": format!("{:?}", r.action),
                "priority": r.priority,
            })
        })
        .collect();

    Json(serde_json::json!({
        "status": "ok",
        "realm": realm,
        "total_allocations": stats.total_allocations,
        "active_allocations": stats.active_allocations,
        "total_bytes_relayed": stats.total_bytes_relayed,
        "total_messages": stats.total_messages,
        "users": users_json,
        "acl_rules": acl_json,
    }))
}

async fn api_login_handler(
    jar: CookieJar,
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> (CookieJar, Json<serde_json::Value>) {
    if let (Some(username), Some(password)) =
        (&state.admin.admin_username, &state.admin.admin_password)
        && form.username == *username
        && form.password == *password
    {
        // Set session cookie
        let cookie = Cookie::build((SESSION_COOKIE, SESSION_VALUE))
            .path("/")
            .http_only(true)
            .same_site(axum_extra::extract::cookie::SameSite::Lax);
        let jar = jar.add(cookie);
        return (
            jar,
            Json(serde_json::json!({"success": true, "token": "admin-token"})),
        );
    }

    (
        jar,
        Json(serde_json::json!({"success": false, "error": "Invalid credentials"})),
    )
}

async fn reload_handler(jar: CookieJar, State(state): State<AppState>) -> Json<serde_json::Value> {
    // Check authentication
    if !check_auth(&jar, &state.admin) {
        return Json(serde_json::json!({
            "success": false,
            "error": "Unauthorized"
        }));
    }

    let config_path = match &state.config_path {
        Some(p) => p.clone(),
        None => {
            return Json(serde_json::json!({
                "success": false,
                "error": "No config file configured (start miuturn with CONFIG=/path/to/miuturn.toml)",
            }));
        }
    };

    // Parse first; on failure leave the running state untouched.
    let config = match Config::load(config_path.clone()) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                "Config reload failed to parse {}: {}",
                config_path.display(),
                e
            );
            return Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to parse config: {}", e),
            }));
        }
    };

    let mut applied: Vec<String> = Vec::new();

    // 1. Auth: users + api_keys (as ApiKey users) + ACL rules.
    let mut users: Vec<User> = config
        .auth
        .users
        .iter()
        .map(|u| User {
            username: u.username.clone(),
            password: u.password.clone(),
            user_type: match u.user_type.as_str() {
                "temporary" => UserType::Temporary,
                "api_key" => UserType::ApiKey,
                _ => UserType::Fixed,
            },
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            expires_at: u.expires_at,
            max_allocations: u.max_allocations.unwrap_or(10),
            bandwidth_limit: u.bandwidth_limit,
            ip_whitelist: u.ip_whitelist.clone(),
            max_allocation_duration_secs: u.max_allocation_duration_secs,
        })
        .collect();
    for username in config.auth.api_keys.values() {
        users.push(User {
            username: username.clone(),
            password: String::new(),
            user_type: UserType::ApiKey,
            created_at: 0,
            expires_at: None,
            max_allocations: 100,
            bandwidth_limit: None,
            ip_whitelist: None,
            max_allocation_duration_secs: None,
        });
    }
    let acl_rules: Vec<AclRule> = config
        .auth
        .acl_rules
        .iter()
        .map(|r| AclRule {
            ip_range: r.ip_range.clone(),
            action: if r.action.eq_ignore_ascii_case("allow") {
                AclAction::Allow
            } else {
                AclAction::Deny
            },
            priority: r.priority.unwrap_or(0),
        })
        .collect();

    state
        .auth
        .reload_config(users, config.auth.api_keys.clone(), acl_rules);
    applied.push("auth".to_string());

    // 2. TURN REST credentials.
    let new_turn_rest = build_turn_rest_state(&config);
    *state.turn_rest.write() = new_turn_rest;
    applied.push("turn_rest".to_string());

    // 3. Log level (when the subscriber exposes a reload handle).
    if let Some(reload) = &state.log_reload {
        match reload(&config.log.log_level) {
            Ok(()) => applied.push("log_level".to_string()),
            Err(e) => tracing::warn!("Log level reload failed: {}", e),
        }
    }

    let stats = (state.health.stats_fn)();
    Json(serde_json::json!({
        "success": true,
        "message": "Configuration reloaded",
        "applied": applied,
        "restart_required": [
            "server.realm",
            "server.external_ip",
            "server.relay_bind_ip",
            "server.start_port",
            "server.end_port",
            "server.listening",
            "server.max_bandwidth_bytes_per_sec",
        ],
        "user_count": state.auth.list_users().len(),
        "acl_rule_count": state.auth.list_acl_rules().len(),
        "stats": {
            "total_allocations": stats.total_allocations,
            "active_allocations": stats.active_allocations,
        }
    }))
}

async fn health_proxy_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let stats = (state.health.stats_fn)();
    Json(serde_json::json!({
        "status": "ok",
        "total_allocations": stats.total_allocations,
        "active_allocations": stats.active_allocations,
        "total_bytes_relayed": stats.total_bytes_relayed,
        "total_messages": stats.total_messages,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct AddUserRequest {
    username: String,
    password: String,
    user_type: String,
    max_allocations: Option<u32>,
    expires_at: Option<u64>,
    bandwidth_limit: Option<u64>,
    ip_whitelist: Option<Vec<String>>,
    max_allocation_duration_secs: Option<u32>,
}

async fn add_user_handler(
    jar: CookieJar,
    State(state): State<AppState>,
    Json(req): Json<AddUserRequest>,
) -> Json<serde_json::Value> {
    // Check authentication
    if !check_auth(&jar, &state.admin) {
        return Json(serde_json::json!({
            "success": false,
            "error": "Unauthorized"
        }));
    }

    let user_type = match req.user_type.as_str() {
        "temporary" => UserType::Temporary,
        "api_key" => UserType::ApiKey,
        _ => UserType::Fixed,
    };

    let user = User {
        username: req.username.clone(),
        password: req.password.clone(),
        user_type,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        expires_at: req.expires_at,
        max_allocations: req.max_allocations.unwrap_or(10) as usize,
        bandwidth_limit: req.bandwidth_limit,
        ip_whitelist: req.ip_whitelist.clone(),
        max_allocation_duration_secs: req.max_allocation_duration_secs,
    };

    state.auth.add_user(user);

    // Save config to file
    if let Err(e) = save_config(&state) {
        tracing::warn!("Failed to save config: {}", e);
    }

    Json(serde_json::json!({
        "success": true,
        "message": "User added",
        "user": {
            "username": req.username,
            "user_type": req.user_type,
            "max_allocations": req.max_allocations.unwrap_or(10),
        }
    }))
}

async fn delete_user_handler(
    jar: CookieJar,
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    // Check authentication
    if !check_auth(&jar, &state.admin) {
        return Json(serde_json::json!({
            "success": false,
            "error": "Unauthorized"
        }));
    }

    let username = params.get("username").map(|s| s.as_str()).unwrap_or("");
    state.auth.remove_user(username);

    // Save config to file
    if let Err(e) = save_config(&state) {
        tracing::warn!("Failed to save config: {}", e);
    }

    Json(serde_json::json!({
        "success": true,
        "message": "User deleted"
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct AddAclRequest {
    ip_range: String,
    action: String,
    priority: u32,
}

async fn add_acl_handler(
    jar: CookieJar,
    State(state): State<AppState>,
    Json(req): Json<AddAclRequest>,
) -> Json<serde_json::Value> {
    // Check authentication
    if !check_auth(&jar, &state.admin) {
        return Json(serde_json::json!({
            "success": false,
            "error": "Unauthorized"
        }));
    }

    let action = if req.action == "Allow" {
        AclAction::Allow
    } else {
        AclAction::Deny
    };

    let rule = AclRule {
        ip_range: req.ip_range.clone(),
        action,
        priority: req.priority,
    };

    state.auth.add_acl_rule(rule);

    // Save config to file
    if let Err(e) = save_config(&state) {
        tracing::warn!("Failed to save config: {}", e);
    }

    Json(serde_json::json!({
        "success": true,
        "message": "ACL rule added",
        "rule": {
            "ip_range": req.ip_range,
            "action": req.action,
            "priority": req.priority,
        }
    }))
}

async fn delete_acl_handler(
    jar: CookieJar,
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    // Check authentication
    if !check_auth(&jar, &state.admin) {
        return Json(serde_json::json!({
            "success": false,
            "error": "Unauthorized"
        }));
    }

    let ip_range = params.get("ip_range").map(|s| s.as_str()).unwrap_or("");
    let priority = params
        .get("priority")
        .map(|s| s.parse::<u32>().unwrap_or(0))
        .unwrap_or(0);
    state.auth.remove_acl_rule(ip_range, priority);

    // Save config to file
    if let Err(e) = save_config(&state) {
        tracing::warn!("Failed to save config: {}", e);
    }

    Json(serde_json::json!({
        "success": true,
        "message": "ACL rule deleted"
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateUserRequest {
    username: String,
    password: Option<String>,
    user_type: String,
    max_allocations: Option<u32>,
    expires_at: Option<u64>,
    bandwidth_limit: Option<u64>,
    ip_whitelist: Option<Vec<String>>,
    max_allocation_duration_secs: Option<u32>,
}

async fn update_user_handler(
    jar: CookieJar,
    State(state): State<AppState>,
    Json(req): Json<UpdateUserRequest>,
) -> Json<serde_json::Value> {
    // Check authentication
    if !check_auth(&jar, &state.admin) {
        return Json(serde_json::json!({
            "success": false,
            "error": "Unauthorized"
        }));
    }

    // First remove the existing user
    state.auth.remove_user(&req.username);

    // Then add the updated user
    let user_type = match req.user_type.as_str() {
        "temporary" => UserType::Temporary,
        "api_key" => UserType::ApiKey,
        _ => UserType::Fixed,
    };

    let user = User {
        username: req.username.clone(),
        password: req.password.unwrap_or_default(),
        user_type,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        expires_at: req.expires_at,
        max_allocations: req.max_allocations.unwrap_or(10) as usize,
        bandwidth_limit: req.bandwidth_limit,
        ip_whitelist: req.ip_whitelist.clone(),
        max_allocation_duration_secs: req.max_allocation_duration_secs,
    };

    state.auth.add_user(user);

    // Save config to file
    if let Err(e) = save_config(&state) {
        tracing::warn!("Failed to save config: {}", e);
    }

    Json(serde_json::json!({
        "success": true,
        "message": "User updated",
        "user": {
            "username": req.username,
            "user_type": req.user_type,
            "max_allocations": req.max_allocations.unwrap_or(10),
        }
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct UpdateAclRequest {
    original_ip_range: String,
    original_priority: u32,
    ip_range: String,
    action: String,
    priority: u32,
}

async fn update_acl_handler(
    jar: CookieJar,
    State(state): State<AppState>,
    Json(req): Json<UpdateAclRequest>,
) -> Json<serde_json::Value> {
    // Check authentication
    if !check_auth(&jar, &state.admin) {
        return Json(serde_json::json!({
            "success": false,
            "error": "Unauthorized"
        }));
    }

    // Remove the old rule
    state
        .auth
        .remove_acl_rule(&req.original_ip_range, req.original_priority);

    // Add the new rule
    let action = if req.action == "Allow" {
        AclAction::Allow
    } else {
        AclAction::Deny
    };

    let rule = AclRule {
        ip_range: req.ip_range.clone(),
        action,
        priority: req.priority,
    };

    state.auth.add_acl_rule(rule);

    // Save config to file
    if let Err(e) = save_config(&state) {
        tracing::warn!("Failed to save config: {}", e);
    }

    Json(serde_json::json!({
        "success": true,
        "message": "ACL rule updated",
        "rule": {
            "ip_range": req.ip_range,
            "action": req.action,
            "priority": req.priority,
        }
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct TurnCredentialsRequest {
    username: String,
    lifetime: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
pub struct IceServersQuery {
    username: String,
    lifetime: Option<u64>,
}

async fn ice_servers_handler(
    State(state): State<AppState>,
    axum::extract::Query(req): axum::extract::Query<IceServersQuery>,
) -> Json<serde_json::Value> {
    let turn_rest = state.turn_rest.read();
    if !turn_rest.enabled {
        return Json(serde_json::json!([]));
    }

    let manager = match &turn_rest.credential_manager {
        Some(m) => m,
        None => {
            return Json(serde_json::json!([]));
        }
    };

    let (username, password, _expires) = manager.generate(&req.username, req.lifetime);

    let mut urls = Vec::new();
    for config in &state.listen_configs {
        let port = config.addr().port();
        match config.protocol.as_str() {
            "udp" => {
                urls.push(format!("turn:{}:{}", state.external_ip, port));
            }
            "tcp" => {
                urls.push(format!("turn:{}:{}?transport=tcp", state.external_ip, port));
            }
            "tls" | "dtls" => {
                urls.push(format!(
                    "turns:{}:{}?transport=tcp",
                    state.external_ip, port
                ));
            }
            _ => {}
        }
    }
    urls.sort();
    urls.dedup();

    Json(serde_json::json!([
        {
            "urls": urls,
            "username": username,
            "credential": password,
        }
    ]))
}

async fn turn_credentials_handler(
    State(state): State<AppState>,
    Json(req): Json<TurnCredentialsRequest>,
) -> Json<serde_json::Value> {
    let turn_rest = state.turn_rest.read();
    if !turn_rest.enabled {
        return Json(serde_json::json!({
            "error": "TURN REST API is not enabled",
            "success": false,
        }));
    }

    let manager = match &turn_rest.credential_manager {
        Some(m) => m,
        None => {
            return Json(serde_json::json!({
                "error": "TURN REST API credential manager not configured",
                "success": false,
            }));
        }
    };

    let (username, password, expires) = manager.generate(&req.username, req.lifetime);

    Json(serde_json::json!({
        "success": true,
        "username": username,
        "password": password,
        "expires": expires,
    }))
}

async fn prometheus_metrics_handler(
    State(state): State<AppState>,
) -> impl axum::response::IntoResponse {
    // Core counters always come from the live allocation stats (authoritative);
    // extended request/channel counters come from the in-band Metrics collector
    // when one is configured.
    let stats = (state.health.stats_fn)();
    let body = match &state.metrics {
        Some(metrics) => metrics.export_prometheus_with_stats(&stats),
        None => crate::metrics::export_core_metrics(&stats),
    };
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

pub async fn create_health_routes(
    addr: String,
    stats_fn: Arc<dyn Fn() -> ServerStatsSnapshot + Send + Sync>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = HealthState { stats_fn };
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);
    let app = Router::new()
        .route("/health", get(health_handler))
        .layer(cors)
        .with_state(state);
    let listener = TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_handler(State(state): State<HealthState>) -> Json<serde_json::Value> {
    let stats = (state.stats_fn)();
    Json(serde_json::json!({
        "status": "ok",
        "total_allocations": stats.total_allocations,
        "active_allocations": stats.active_allocations,
        "total_bytes_relayed": stats.total_bytes_relayed,
        "total_messages": stats.total_messages,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthManager;

    #[test]
    fn test_turn_rest_state_disabled() {
        let state = TurnRestState {
            enabled: false,
            credential_manager: None,
        };
        assert!(!state.enabled);
        assert!(state.credential_manager.is_none());
    }

    #[test]
    fn test_turn_rest_state_enabled_with_manager() {
        let manager = ShortTermCredentialManager::new("test-secret".to_string());
        let state = TurnRestState {
            enabled: true,
            credential_manager: Some(manager),
        };
        assert!(state.enabled);
        assert!(state.credential_manager.is_some());
    }

    #[test]
    fn test_admin_state_empty_credentials() {
        let state = AdminState {
            admin_username: None,
            admin_password: None,
        };
        assert!(state.admin_username.is_none());
        assert!(state.admin_password.is_none());
    }

    #[test]
    fn test_admin_state_with_credentials() {
        let state = AdminState {
            admin_username: Some("admin".to_string()),
            admin_password: Some("secret".to_string()),
        };
        assert_eq!(state.admin_username, Some("admin".to_string()));
        assert_eq!(state.admin_password, Some("secret".to_string()));
    }

    #[test]
    fn test_health_state_clone() {
        let stats_fn: Arc<dyn Fn() -> ServerStatsSnapshot + Send + Sync> =
            Arc::new(|| ServerStatsSnapshot {
                total_allocations: 10,
                active_allocations: 5,
                total_bytes_relayed: 1000,
                total_messages: 50,
            });
        let state = HealthState { stats_fn };
        let cloned = state.clone();
        let result = (cloned.stats_fn)();
        assert_eq!(result.total_allocations, 10);
        assert_eq!(result.active_allocations, 5);
    }

    #[test]
    fn test_check_auth_no_admin() {
        let jar = CookieJar::default();
        let admin_state = AdminState {
            admin_username: None,
            admin_password: None,
        };
        assert!(check_auth(&jar, &admin_state));
    }

    #[test]
    fn test_check_auth_with_cookie() {
        let cookie = Cookie::build((SESSION_COOKIE, SESSION_VALUE));
        let jar = CookieJar::default().add(cookie);
        let admin_state = AdminState {
            admin_username: Some("admin".to_string()),
            admin_password: Some("secret".to_string()),
        };
        assert!(check_auth(&jar, &admin_state));
    }

    #[test]
    fn test_check_auth_no_cookie() {
        let jar = CookieJar::default();
        let admin_state = AdminState {
            admin_username: Some("admin".to_string()),
            admin_password: Some("secret".to_string()),
        };
        assert!(!check_auth(&jar, &admin_state));
    }

    #[tokio::test]
    async fn test_ice_servers_handler_success() {
        use axum::extract::{Query, State};

        let manager = ShortTermCredentialManager::new("test-secret".to_string());
        let state = AppState {
            admin: AdminState {
                admin_username: None,
                admin_password: None,
            },
            health: HealthState {
                stats_fn: Arc::new(|| ServerStatsSnapshot {
                    total_allocations: 0,
                    active_allocations: 0,
                    total_bytes_relayed: 0,
                    total_messages: 0,
                }),
            },
            auth: Arc::new(AuthManager::new("test".to_string())),
            turn_rest: Arc::new(parking_lot::RwLock::new(TurnRestState {
                enabled: true,
                credential_manager: Some(manager),
            })),
            metrics: None,
            config_path: None,
            external_ip: "192.168.1.1".to_string(),
            listen_configs: vec![
                ListenConfig {
                    protocol: "udp".to_string(),
                    address: "0.0.0.0:3478".to_string(),
                },
                ListenConfig {
                    protocol: "tcp".to_string(),
                    address: "0.0.0.0:3478".to_string(),
                },
            ],
            admin_acl: vec!["127.0.0.1".to_string()],
            trust_proxy: false,
            log_reload: None,
        };

        let query = IceServersQuery {
            username: "testuser".to_string(),
            lifetime: Some(7200),
        };
        let response = ice_servers_handler(State(state), Query(query)).await;
        let json = response.0;

        let urls = json[0]["urls"].as_array().unwrap();
        assert!(urls.iter().any(|u| u == "turn:192.168.1.1:3478"));
        assert!(
            urls.iter()
                .any(|u| u == "turn:192.168.1.1:3478?transport=tcp")
        );
        assert!(json[0]["username"].as_str().unwrap().contains("testuser"));
        assert!(json[0]["credential"].as_str().is_some());
    }

    #[tokio::test]
    async fn test_ice_servers_handler_disabled() {
        use axum::extract::{Query, State};

        let state = AppState {
            admin: AdminState {
                admin_username: None,
                admin_password: None,
            },
            health: HealthState {
                stats_fn: Arc::new(|| ServerStatsSnapshot {
                    total_allocations: 0,
                    active_allocations: 0,
                    total_bytes_relayed: 0,
                    total_messages: 0,
                }),
            },
            auth: Arc::new(AuthManager::new("test".to_string())),
            turn_rest: Arc::new(parking_lot::RwLock::new(TurnRestState {
                enabled: false,
                credential_manager: None,
            })),
            metrics: None,
            config_path: None,
            external_ip: "192.168.1.1".to_string(),
            listen_configs: vec![],
            admin_acl: vec!["127.0.0.1".to_string()],
            trust_proxy: false,
            log_reload: None,
        };

        let query = IceServersQuery {
            username: "testuser".to_string(),
            lifetime: None,
        };
        let response = ice_servers_handler(State(state), Query(query)).await;
        let json = response.0;

        assert!(json.as_array().unwrap().is_empty());
    }

    // ── Config reload tests ──────────────────────────────────────────────────

    fn test_stats_fn() -> Arc<dyn Fn() -> ServerStatsSnapshot + Send + Sync> {
        Arc::new(|| ServerStatsSnapshot {
            total_allocations: 0,
            active_allocations: 0,
            total_bytes_relayed: 0,
            total_messages: 0,
        })
    }

    /// Build an AppState for reload tests.
    fn test_app_state(
        auth: SharedAuthManager,
        config_path: Option<PathBuf>,
        turn_rest_enabled: bool,
        log_reload: Option<Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>>,
    ) -> AppState {
        AppState {
            admin: AdminState {
                admin_username: None,
                admin_password: None,
            },
            health: HealthState {
                stats_fn: test_stats_fn(),
            },
            auth,
            turn_rest: Arc::new(parking_lot::RwLock::new(TurnRestState {
                enabled: turn_rest_enabled,
                credential_manager: None,
            })),
            metrics: None,
            config_path,
            external_ip: "192.168.1.1".to_string(),
            listen_configs: vec![],
            admin_acl: vec!["127.0.0.1".to_string()],
            trust_proxy: false,
            log_reload,
        }
    }

    fn write_temp_config(name: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("miuturn-test-{}-{}.toml", name, std::process::id()));
        std::fs::write(&path, body).unwrap();
        path
    }

    #[tokio::test]
    async fn test_reload_applies_auth_users_and_acl() {
        let auth = Arc::new(AuthManager::new("test".to_string()));
        auth.add_user(User {
            username: "olduser".to_string(),
            password: "oldpass".to_string(),
            user_type: UserType::Fixed,
            created_at: 0,
            expires_at: None,
            max_allocations: 5,
            bandwidth_limit: None,
            ip_whitelist: None,
            max_allocation_duration_secs: None,
        });

        let config_path = write_temp_config(
            "reload-auth",
            r#"
[server]
realm = "test"
external_ip = "127.0.0.1"
start_port = 49152
end_port = 65535

[[server.listening]]
protocol = "udp"
address = "0.0.0.0:3478"

[[auth.users]]
username = "alice"
password = "secret"
user_type = "fixed"
max_allocations = 3

[[auth.acl_rules]]
ip_range = "10.0.0.0/8"
action = "Allow"
priority = 5
"#,
        );

        let state = test_app_state(auth.clone(), Some(config_path), false, None);
        let response = reload_handler(CookieJar::default(), State(state)).await;
        let json = response.0;

        assert_eq!(json["success"], true, "reload should succeed: {}", json);
        assert!(
            json["applied"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "auth"),
            "applied should include auth: {}",
            json
        );

        // Old user replaced, new user from file present.
        assert!(auth.get_user_password("alice").is_some());
        assert!(auth.get_user_password("olduser").is_none());
        assert_eq!(json["user_count"], 1);
        assert_eq!(json["acl_rule_count"], 1);
        let acl = auth.list_acl_rules();
        assert_eq!(acl.len(), 1);
        assert_eq!(acl[0].ip_range, "10.0.0.0/8");
    }

    #[tokio::test]
    async fn test_reload_updates_turn_rest() {
        let auth = Arc::new(AuthManager::new("test".to_string()));
        let config_path = write_temp_config(
            "reload-rest",
            r#"
[server]
realm = "test"
external_ip = "127.0.0.1"
start_port = 49152
end_port = 65535

[[server.listening]]
protocol = "udp"
address = "0.0.0.0:3478"

[http]
address = "0.0.0.0:8080"
turn_rest_enabled = true
turn_rest_secret = "new-secret"
turn_rest_default_lifetime = 7200

[auth]
users = []
"#,
        );

        let state = test_app_state(auth, Some(config_path), false, None);
        let response = reload_handler(CookieJar::default(), State(state.clone())).await;
        let json = response.0;
        assert_eq!(json["success"], true, "reload failed: {}", json);

        let turn_rest = state.turn_rest.read();
        assert!(turn_rest.enabled);
        assert!(turn_rest.credential_manager.is_some());
    }

    #[tokio::test]
    async fn test_reload_applies_log_level() {
        use std::sync::Mutex;

        let auth = Arc::new(AuthManager::new("test".to_string()));
        let applied: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let applied2 = applied.clone();
        let log_reload: Option<Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>> =
            Some(Arc::new(move |level: &str| {
                applied2.lock().unwrap().push(level.to_string());
                Ok(())
            }));

        let config_path = write_temp_config(
            "reload-log",
            r#"
[server]
realm = "test"
external_ip = "127.0.0.1"
start_port = 49152
end_port = 65535

[[server.listening]]
protocol = "udp"
address = "0.0.0.0:3478"

[log]
log_level = "debug"

[auth]
users = []
"#,
        );

        let state = test_app_state(auth, Some(config_path), false, log_reload);
        let response = reload_handler(CookieJar::default(), State(state)).await;
        let json = response.0;
        assert_eq!(json["success"], true, "reload failed: {}", json);
        assert!(
            json["applied"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "log_level"),
            "applied should include log_level: {}",
            json
        );
        assert_eq!(*applied.lock().unwrap(), vec!["debug".to_string()]);
    }

    #[tokio::test]
    async fn test_reload_no_config_path_fails() {
        let auth = Arc::new(AuthManager::new("test".to_string()));
        let state = test_app_state(auth, None, false, None);
        let response = reload_handler(CookieJar::default(), State(state)).await;
        let json = response.0;
        assert_eq!(json["success"], false);
    }

    #[tokio::test]
    async fn test_reload_bad_config_file_fails_without_touching_state() {
        let auth = Arc::new(AuthManager::new("test".to_string()));
        auth.add_user(User {
            username: "keepme".to_string(),
            password: "pass".to_string(),
            user_type: UserType::Fixed,
            created_at: 0,
            expires_at: None,
            max_allocations: 1,
            bandwidth_limit: None,
            ip_whitelist: None,
            max_allocation_duration_secs: None,
        });

        let path =
            std::env::temp_dir().join(format!("miuturn-test-bad-{}.toml", std::process::id()));
        std::fs::write(&path, "this is not [valid toml = ").unwrap();

        let state = test_app_state(auth.clone(), Some(path), false, None);
        let response = reload_handler(CookieJar::default(), State(state)).await;
        let json = response.0;
        assert_eq!(json["success"], false);
        // Running state untouched.
        assert!(auth.get_user_password("keepme").is_some());
    }
}
