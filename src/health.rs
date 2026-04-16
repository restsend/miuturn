use crate::allocation::ServerStatsSnapshot;
use crate::auth::{AclAction, AclRule, SharedAuthManager, User, UserType};
use crate::config::{AclRuleConfig, Config, ListenConfig, UserConfig};
use crate::metrics::Metrics;
use crate::short_term::ShortTermCredentialManager;
use axum::{
    Form, Router,
    extract::State,
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

#[derive(Clone)]
struct AppState {
    admin: AdminState,
    health: HealthState,
    auth: SharedAuthManager,
    turn_rest: TurnRestState,
    metrics: Option<Metrics>,
    config_path: Option<PathBuf>,
    external_ip: String,
    listen_configs: Vec<ListenConfig>,
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let turn_rest_state = if turn_rest_enabled {
        let secret = turn_rest_secret.unwrap_or_else(|| "default-secret-key".to_string());
        let manager =
            ShortTermCredentialManager::new(secret).with_lifetime(turn_rest_default_lifetime);
        TurnRestState {
            enabled: true,
            credential_manager: Some(manager),
        }
    } else {
        TurnRestState {
            enabled: false,
            credential_manager: None,
        }
    };

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
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/console", get(console_handler))
        .route("/console/dashboard", get(dashboard_handler))
        .route("/login", post(login_handler))
        .route("/health", get(health_proxy_handler))
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
        .route("/api/v1/turn-credentials", post(turn_credentials_handler))
        .route("/api/v1/iceservers", get(ice_servers_handler))
        .route("/logout", post(logout_handler))
        .route("/metrics", get(prometheus_metrics_handler))
        .layer(cors)
        .with_state(state);

    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Admin console available at http://{}", addr);
    axum::serve(listener, app).await?;
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

    let stats = (state.health.stats_fn)();
    Json(serde_json::json!({
        "success": true,
        "message": "Configuration reloaded",
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
    if !state.turn_rest.enabled {
        return Json(serde_json::json!([]));
    }

    let manager = match &state.turn_rest.credential_manager {
        Some(m) => m,
        None => {
            return Json(serde_json::json!([]));
        }
    };

    let _lifetime = req.lifetime.unwrap_or(3600);
    let (username, password, _expires) = manager.generate(&req.username);

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
                urls.push(format!("turns:{}:{}?transport=tcp", state.external_ip, port));
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
    if !state.turn_rest.enabled {
        return Json(serde_json::json!({
            "error": "TURN REST API is not enabled",
            "success": false,
        }));
    }

    let manager = match &state.turn_rest.credential_manager {
        Some(m) => m,
        None => {
            return Json(serde_json::json!({
                "error": "TURN REST API credential manager not configured",
                "success": false,
            }));
        }
    };

    let lifetime = req.lifetime.unwrap_or(3600);
    let (username, password, expires) = manager.generate(&req.username);

    Json(serde_json::json!({
        "success": true,
        "username": username,
        "password": password,
        "expires": expires,
        "lifetime": lifetime,
    }))
}

async fn prometheus_metrics_handler(
    State(state): State<AppState>,
) -> impl axum::response::IntoResponse {
    if let Some(metrics) = &state.metrics {
        metrics.export_prometheus()
    } else {
        // Fallback: generate basic metrics from stats
        let stats = (state.health.stats_fn)();
        let mut output = String::new();
        output.push_str("# HELP turn_total_allocations Total number of allocations created\n");
        output.push_str("# TYPE turn_total_allocations counter\n");
        output.push_str(&format!(
            "turn_total_allocations {}\n",
            stats.total_allocations
        ));
        output.push_str("# HELP turn_active_allocations Current number of active allocations\n");
        output.push_str("# TYPE turn_active_allocations gauge\n");
        output.push_str(&format!(
            "turn_active_allocations {}\n",
            stats.active_allocations
        ));
        output.push_str("# HELP turn_total_bytes_relayed Total bytes relayed\n");
        output.push_str("# TYPE turn_total_bytes_relayed counter\n");
        output.push_str(&format!(
            "turn_total_bytes_relayed {}\n",
            stats.total_bytes_relayed
        ));
        output.push_str("# HELP turn_total_messages Total messages relayed\n");
        output.push_str("# TYPE turn_total_messages counter\n");
        output.push_str(&format!("turn_total_messages {}\n", stats.total_messages));
        output
    }
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
            turn_rest: TurnRestState {
                enabled: true,
                credential_manager: Some(manager),
            },
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
        };

        let query = IceServersQuery {
            username: "testuser".to_string(),
            lifetime: Some(7200),
        };
        let response = ice_servers_handler(State(state), Query(query)).await;
        let json = response.0;

        let urls = json[0]["urls"].as_array().unwrap();
        assert!(urls.iter().any(|u| u == "turn:192.168.1.1:3478"));
        assert!(urls.iter().any(|u| u == "turn:192.168.1.1:3478?transport=tcp"));
        assert!(
            json[0]["username"]
                .as_str()
                .unwrap()
                .contains("testuser")
        );
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
            turn_rest: TurnRestState {
                enabled: false,
                credential_manager: None,
            },
            metrics: None,
            config_path: None,
            external_ip: "192.168.1.1".to_string(),
            listen_configs: vec![],
        };

        let query = IceServersQuery {
            username: "testuser".to_string(),
            lifetime: None,
        };
        let response = ice_servers_handler(State(state), Query(query)).await;
        let json = response.0;

        assert!(json.as_array().unwrap().is_empty());
    }
}
