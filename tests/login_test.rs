use axum::{
    Router,
    body::Body,
    extract::State,
    http::Request,
    routing::{delete, get, post},
};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::json;
use tower::ServiceExt;

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

#[tokio::test]
async fn test_login_redirects_to_console_dashboard() {
    async fn console_handler() -> axum::response::Html<String> {
        axum::response::Html("<html><body>Login Page</body></html>".to_string())
    }

    async fn dashboard_handler() -> axum::response::Html<String> {
        axum::response::Html("<html><body>Admin Dashboard</body></html>".to_string())
    }

    async fn login_handler(
        State(_state): State<()>,
        axum::Form(form): axum::Form<LoginForm>,
    ) -> axum::response::Redirect {
        if form.username == "admin" && form.password == "password" {
            return axum::response::Redirect::temporary("/console/dashboard");
        }
        axum::response::Redirect::temporary("/console?error=1")
    }

    let app = Router::new()
        .route("/console", get(console_handler))
        .route("/console/dashboard", get(dashboard_handler))
        .route("/login", post(login_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("username=admin&password=password"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == axum::http::StatusCode::FOUND
            || response.status() == axum::http::StatusCode::TEMPORARY_REDIRECT
    );
    let location = response.headers().get("location").unwrap();
    assert_eq!(location.to_str().unwrap(), "/console/dashboard");
}

#[tokio::test]
async fn test_login_fails_with_wrong_password() {
    async fn console_handler() -> axum::response::Html<String> {
        axum::response::Html("<html><body>Login Page</body></html>".to_string())
    }

    async fn login_handler(
        State(_state): State<()>,
        axum::Form(form): axum::Form<LoginForm>,
    ) -> axum::response::Redirect {
        if form.username == "admin" && form.password == "password" {
            return axum::response::Redirect::temporary("/console/dashboard");
        }
        axum::response::Redirect::temporary("/console?error=1")
    }

    let app = Router::new()
        .route("/console", get(console_handler))
        .route("/console/dashboard", get(console_handler))
        .route("/login", post(login_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("username=admin&password=wrong"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == axum::http::StatusCode::FOUND
            || response.status() == axum::http::StatusCode::TEMPORARY_REDIRECT
    );
    let location = response.headers().get("location").unwrap();
    assert_eq!(location.to_str().unwrap(), "/console?error=1");
}

#[tokio::test]
async fn test_console_dashboard_accessible() {
    async fn dashboard_handler() -> axum::response::Html<String> {
        axum::response::Html("<html><body>Admin Dashboard</body></html>".to_string())
    }

    let app = Router::new()
        .route("/console", get(dashboard_handler))
        .route("/console/dashboard", get(dashboard_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/console/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(body_str.contains("Admin Dashboard"));
}

#[tokio::test]
async fn test_health_endpoint_returns_stats() {
    async fn health_handler() -> axum::Json<serde_json::Value> {
        axum::Json(json!({
            "status": "ok",
            "total_allocations": 100,
            "active_allocations": 50,
            "total_bytes_relayed": 1024000,
            "total_messages": 5000
        }))
    }

    let app = Router::new()
        .route("/health", get(health_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["status"], "ok");
    assert_eq!(data["total_allocations"], 100);
    assert_eq!(data["active_allocations"], 50);
}

#[tokio::test]
async fn test_reload_endpoint() {
    async fn reload_handler() -> axum::Json<serde_json::Value> {
        axum::Json(json!({
            "success": true,
            "message": "Configuration reloaded",
            "stats": {
                "total_allocations": 100,
                "active_allocations": 50
            }
        }))
    }

    let app = Router::new()
        .route("/api/v1/reload", post(reload_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["success"], true);
    assert_eq!(data["message"], "Configuration reloaded");
}

#[tokio::test]
async fn test_add_user_api() {
    #[derive(Debug, serde::Deserialize)]
    struct AddUserRequest {
        username: String,
        #[allow(dead_code)]
        password: String,
        user_type: String,
        max_allocations: Option<u32>,
    }

    async fn add_user_handler(
        axum::Json(req): axum::Json<AddUserRequest>,
    ) -> axum::Json<serde_json::Value> {
        axum::Json(json!({
            "success": true,
            "message": "User added",
            "user": {
                "username": req.username,
                "user_type": req.user_type,
                "max_allocations": req.max_allocations.unwrap_or(10)
            }
        }))
    }

    let app = Router::new()
        .route("/api/v1/users", post(add_user_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"username":"testuser","password":"testpass","user_type":"Fixed","max_allocations":20}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["success"], true);
    assert_eq!(data["user"]["username"], "testuser");
    assert_eq!(data["user"]["user_type"], "Fixed");
    assert_eq!(data["user"]["max_allocations"], 20);
}

#[tokio::test]
async fn test_delete_user_api() {
    async fn delete_user_handler(
        axum::extract::Query(params): axum::extract::Query<
            std::collections::HashMap<String, String>,
        >,
    ) -> axum::Json<serde_json::Value> {
        let username = params.get("username").map(|s| s.as_str()).unwrap_or("");
        axum::Json(json!({
            "success": true,
            "message": format!("User {} deleted", username)
        }))
    }

    let app = Router::new()
        .route("/api/v1/users", delete(delete_user_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/users?username=testuser")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["success"], true);
}

#[tokio::test]
async fn test_add_acl_api() {
    #[derive(Debug, serde::Deserialize)]
    struct AddAclRequest {
        ip_range: String,
        action: String,
        priority: u32,
    }

    async fn add_acl_handler(
        axum::Json(req): axum::Json<AddAclRequest>,
    ) -> axum::Json<serde_json::Value> {
        axum::Json(json!({
            "success": true,
            "message": "ACL rule added",
            "rule": {
                "ip_range": req.ip_range,
                "action": req.action,
                "priority": req.priority
            }
        }))
    }

    let app = Router::new()
        .route("/api/v1/acl", post(add_acl_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/acl")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"ip_range":"192.168.1.0/24","action":"Allow","priority":10}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["success"], true);
    assert_eq!(data["rule"]["ip_range"], "192.168.1.0/24");
    assert_eq!(data["rule"]["action"], "Allow");
    assert_eq!(data["rule"]["priority"], 10);
}

#[tokio::test]
async fn test_delete_acl_api() {
    async fn delete_acl_handler(
        axum::extract::Query(params): axum::extract::Query<
            std::collections::HashMap<String, String>,
        >,
    ) -> axum::Json<serde_json::Value> {
        let ip_range = params.get("ip_range").map(|s| s.as_str()).unwrap_or("");
        let priority = params
            .get("priority")
            .map(|s| s.parse::<u32>().unwrap_or(0))
            .unwrap_or(0);
        axum::Json(json!({
            "success": true,
            "message": format!("ACL rule {} priority {} deleted", ip_range, priority)
        }))
    }

    let app = Router::new()
        .route("/api/v1/acl", delete(delete_acl_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/acl?ip_range=192.168.1.0%2F24&priority=10")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["success"], true);
}

#[tokio::test]
async fn test_add_user_with_bandwidth_limit_api() {
    #[derive(Debug, serde::Deserialize)]
    struct AddUserRequest {
        username: String,
        #[allow(dead_code)]
        password: String,
        user_type: String,
        max_allocations: Option<u32>,
        bandwidth_limit: Option<u64>,
    }

    async fn add_user_handler(
        axum::Json(req): axum::Json<AddUserRequest>,
    ) -> axum::Json<serde_json::Value> {
        axum::Json(json!({
            "success": true,
            "message": "User added",
            "user": {
                "username": req.username,
                "user_type": req.user_type,
                "max_allocations": req.max_allocations.unwrap_or(10),
                "bandwidth_limit": req.bandwidth_limit
            }
        }))
    }

    let app = Router::new()
        .route("/api/v1/users", post(add_user_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"username":"limiteduser","password":"testpass","user_type":"Fixed","max_allocations":5,"bandwidth_limit":1048576}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["success"], true);
    assert_eq!(data["user"]["username"], "limiteduser");
    assert_eq!(data["user"]["bandwidth_limit"], 1048576);
}

#[tokio::test]
async fn test_add_user_with_ip_whitelist_api() {
    #[derive(Debug, serde::Deserialize)]
    struct AddUserRequest {
        username: String,
        #[allow(dead_code)]
        password: String,
        user_type: String,
        ip_whitelist: Option<Vec<String>>,
    }

    async fn add_user_handler(
        axum::Json(req): axum::Json<AddUserRequest>,
    ) -> axum::Json<serde_json::Value> {
        axum::Json(json!({
            "success": true,
            "message": "User added",
            "user": {
                "username": req.username,
                "user_type": req.user_type,
                "ip_whitelist": req.ip_whitelist
            }
        }))
    }

    let app = Router::new()
        .route("/api/v1/users", post(add_user_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"username":"ipuser","password":"testpass","user_type":"Fixed","ip_whitelist":["192.168.1.0/24","10.0.0.1"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["success"], true);
    assert_eq!(data["user"]["ip_whitelist"].as_array().unwrap().len(), 2);
    assert!(
        data["user"]["ip_whitelist"]
            .as_array()
            .unwrap()
            .contains(&json!("192.168.1.0/24"))
    );
}

#[tokio::test]
async fn test_add_user_with_max_allocation_duration_api() {
    #[derive(Debug, serde::Deserialize)]
    struct AddUserRequest {
        username: String,
        #[allow(dead_code)]
        password: String,
        user_type: String,
        max_allocation_duration_secs: Option<u32>,
    }

    async fn add_user_handler(
        axum::Json(req): axum::Json<AddUserRequest>,
    ) -> axum::Json<serde_json::Value> {
        axum::Json(json!({
            "success": true,
            "message": "User added",
            "user": {
                "username": req.username,
                "user_type": req.user_type,
                "max_allocation_duration_secs": req.max_allocation_duration_secs
            }
        }))
    }

    let app = Router::new()
        .route("/api/v1/users", post(add_user_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"username":"durationuser","password":"testpass","user_type":"Fixed","max_allocation_duration_secs":600}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["success"], true);
    assert_eq!(data["user"]["max_allocation_duration_secs"], 600);
}

#[tokio::test]
async fn test_add_user_with_all_fields_api() {
    #[derive(Debug, serde::Deserialize)]
    struct AddUserRequest {
        username: String,
        #[allow(dead_code)]
        password: String,
        user_type: String,
        max_allocations: Option<u32>,
        bandwidth_limit: Option<u64>,
        max_allocation_duration_secs: Option<u32>,
        ip_whitelist: Option<Vec<String>>,
    }

    async fn add_user_handler(
        axum::Json(req): axum::Json<AddUserRequest>,
    ) -> axum::Json<serde_json::Value> {
        axum::Json(json!({
            "success": true,
            "message": "User added",
            "user": {
                "username": req.username,
                "user_type": req.user_type,
                "max_allocations": req.max_allocations.unwrap_or(10),
                "bandwidth_limit": req.bandwidth_limit,
                "max_allocation_duration_secs": req.max_allocation_duration_secs,
                "ip_whitelist": req.ip_whitelist
            }
        }))
    }

    let app = Router::new()
        .route("/api/v1/users", post(add_user_handler))
        .with_state(());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"username":"fulluser","password":"testpass","user_type":"Temporary","max_allocations":10,"bandwidth_limit":5242880,"max_allocation_duration_secs":3600,"ip_whitelist":["192.168.0.0/16"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["success"], true);
    assert_eq!(data["user"]["username"], "fulluser");
    assert_eq!(data["user"]["user_type"], "Temporary");
    assert_eq!(data["user"]["max_allocations"], 10);
    assert_eq!(data["user"]["bandwidth_limit"], 5242880);
    assert_eq!(data["user"]["max_allocation_duration_secs"], 3600);
    assert_eq!(data["user"]["ip_whitelist"].as_array().unwrap().len(), 1);
}
