use axum::{
    Router,
    body::Body,
    http::Request,
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::json;
use tower::ServiceExt;

// Mock types for testing
#[derive(Clone)]
struct MockAdminState {
    admin_username: Option<String>,
    admin_password: Option<String>,
}

#[derive(Clone)]
struct MockAppState {
    admin: MockAdminState,
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

// Helper function to check auth (copied from health.rs)
fn check_auth(jar: &CookieJar, admin_state: &MockAdminState) -> bool {
    if admin_state.admin_username.is_none() {
        return true;
    }
    jar.get("admin_session")
        .map(|cookie| cookie.value() == "authenticated")
        .unwrap_or(false)
}

// Helper to create state with admin configured
fn create_state_with_admin() -> MockAppState {
    MockAppState {
        admin: MockAdminState {
            admin_username: Some("admin".to_string()),
            admin_password: Some("adminpass".to_string()),
        },
    }
}

// Helper to create state without admin (open access)
fn create_state_no_admin() -> MockAppState {
    MockAppState {
        admin: MockAdminState {
            admin_username: None,
            admin_password: None,
        },
    }
}

#[tokio::test]
async fn test_login_sets_session_cookie() {
    let state = create_state_with_admin();

    async fn login_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
        axum::Form(form): axum::Form<LoginForm>,
    ) -> (CookieJar, axum::response::Redirect) {
        if let (Some(username), Some(password)) =
            (&state.admin.admin_username, &state.admin.admin_password)
        {
            if form.username == *username && form.password == *password {
                let cookie = Cookie::build(("admin_session", "authenticated"))
                    .path("/")
                    .http_only(true);
                let jar = jar.add(cookie);
                return (
                    jar,
                    axum::response::Redirect::temporary("/console/dashboard"),
                );
            }
        }
        (jar, axum::response::Redirect::temporary("/console?error=1"))
    }

    let app = Router::new()
        .route("/login", post(login_handler))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("username=admin&password=adminpass"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Check redirect
    assert!(response.status().is_redirection());
    let location = response.headers().get("location").unwrap();
    assert_eq!(location.to_str().unwrap(), "/console/dashboard");

    // Check that session cookie is set
    let set_cookie = response.headers().get("set-cookie");
    assert!(set_cookie.is_some());
    let cookie_str = set_cookie.unwrap().to_str().unwrap();
    assert!(cookie_str.contains("admin_session=authenticated"));
    assert!(cookie_str.contains("HttpOnly"));
}

#[tokio::test]
async fn test_login_fails_with_wrong_credentials() {
    let state = create_state_with_admin();

    async fn login_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
        axum::Form(form): axum::Form<LoginForm>,
    ) -> (CookieJar, axum::response::Redirect) {
        if let (Some(username), Some(password)) =
            (&state.admin.admin_username, &state.admin.admin_password)
        {
            if form.username == *username && form.password == *password {
                let cookie = Cookie::build(("admin_session", "authenticated")).path("/");
                let jar = jar.add(cookie);
                return (
                    jar,
                    axum::response::Redirect::temporary("/console/dashboard"),
                );
            }
        }
        (jar, axum::response::Redirect::temporary("/console?error=1"))
    }

    let app = Router::new()
        .route("/login", post(login_handler))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("username=admin&password=wrongpass"))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should redirect to error page
    assert!(response.status().is_redirection());
    let location = response.headers().get("location").unwrap();
    assert_eq!(location.to_str().unwrap(), "/console?error=1");

    // Should NOT set session cookie
    let set_cookie = response.headers().get("set-cookie");
    assert!(set_cookie.is_none());
}

#[tokio::test]
async fn test_protected_endpoint_requires_auth() {
    let state = create_state_with_admin();

    async fn stats_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
    ) -> axum::Json<serde_json::Value> {
        if !check_auth(&jar, &state.admin) {
            return axum::Json(json!({
                "success": false,
                "error": "Unauthorized"
            }));
        }

        axum::Json(json!({
            "status": "ok",
            "total_allocations": 100,
        }))
    }

    let app = Router::new()
        .route("/api/stats", get(stats_handler))
        .with_state(state);

    // Request without cookie should fail
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["error"], "Unauthorized");
}

#[tokio::test]
async fn test_protected_endpoint_with_valid_cookie() {
    let state = create_state_with_admin();

    async fn stats_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
    ) -> axum::Json<serde_json::Value> {
        if !check_auth(&jar, &state.admin) {
            return axum::Json(json!({
                "success": false,
                "error": "Unauthorized"
            }));
        }

        axum::Json(json!({
            "status": "ok",
            "total_allocations": 100,
        }))
    }

    let app = Router::new()
        .route("/api/stats", get(stats_handler))
        .with_state(state);

    // Request with valid session cookie should succeed
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/stats")
                .header("Cookie", "admin_session=authenticated")
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
    assert!(data["error"].is_null());
}

#[tokio::test]
async fn test_protected_endpoint_open_when_no_admin_configured() {
    let state = create_state_no_admin();

    async fn stats_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
    ) -> axum::Json<serde_json::Value> {
        if !check_auth(&jar, &state.admin) {
            return axum::Json(json!({
                "success": false,
                "error": "Unauthorized"
            }));
        }

        axum::Json(json!({
            "status": "ok",
            "total_allocations": 100,
        }))
    }

    let app = Router::new()
        .route("/api/stats", get(stats_handler))
        .with_state(state);

    // Request without cookie should succeed when no admin configured
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/stats")
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
    assert!(data["error"].is_null());
}

#[tokio::test]
async fn test_invalid_session_cookie_rejected() {
    let state = create_state_with_admin();

    async fn stats_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
    ) -> axum::Json<serde_json::Value> {
        if !check_auth(&jar, &state.admin) {
            return axum::Json(json!({
                "success": false,
                "error": "Unauthorized"
            }));
        }

        axum::Json(json!({"status": "ok"}))
    }

    let app = Router::new()
        .route("/api/stats", get(stats_handler))
        .with_state(state);

    // Request with invalid session cookie should fail
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/stats")
                .header("Cookie", "admin_session=invalid_value")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["error"], "Unauthorized");
}

#[tokio::test]
async fn test_dashboard_redirects_when_not_authenticated() {
    let state = create_state_with_admin();

    async fn dashboard_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
    ) -> axum::response::Html<String> {
        if !check_auth(&jar, &state.admin) {
            return axum::response::Html(
                r#"<!DOCTYPE html>
<html>
<head><meta http-equiv="refresh" content="0; url=/console" /></head>
<body>Redirecting...</body>
</html>"#
                    .to_string(),
            );
        }

        axum::response::Html("<html><body>Dashboard</body></html>".to_string())
    }

    let app = Router::new()
        .route("/console/dashboard", get(dashboard_handler))
        .with_state(state);

    // Request without cookie should show redirect page
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
    assert!(body_str.contains("url=/console"));
}

#[tokio::test]
async fn test_user_management_endpoints_require_auth() {
    let state = create_state_with_admin();

    async fn add_user_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
        axum::Json(_req): axum::Json<serde_json::Value>,
    ) -> axum::Json<serde_json::Value> {
        if !check_auth(&jar, &state.admin) {
            return axum::Json(json!({
                "success": false,
                "error": "Unauthorized"
            }));
        }

        axum::Json(json!({"success": true, "message": "User added"}))
    }

    async fn delete_user_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
    ) -> axum::Json<serde_json::Value> {
        if !check_auth(&jar, &state.admin) {
            return axum::Json(json!({
                "success": false,
                "error": "Unauthorized"
            }));
        }

        axum::Json(json!({"success": true, "message": "User deleted"}))
    }

    let app = Router::new()
        .route(
            "/api/v1/users",
            post(add_user_handler).delete(delete_user_handler),
        )
        .with_state(state);

    // POST without cookie should fail
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/users")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"username":"test","password":"pass"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["error"], "Unauthorized");

    // DELETE without cookie should fail
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/users?username=test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["error"], "Unauthorized");
}

#[tokio::test]
async fn test_acl_management_endpoints_require_auth() {
    let state = create_state_with_admin();

    async fn add_acl_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
        axum::Json(_req): axum::Json<serde_json::Value>,
    ) -> axum::Json<serde_json::Value> {
        if !check_auth(&jar, &state.admin) {
            return axum::Json(json!({
                "success": false,
                "error": "Unauthorized"
            }));
        }

        axum::Json(json!({"success": true, "message": "ACL added"}))
    }

    async fn delete_acl_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
    ) -> axum::Json<serde_json::Value> {
        if !check_auth(&jar, &state.admin) {
            return axum::Json(json!({
                "success": false,
                "error": "Unauthorized"
            }));
        }

        axum::Json(json!({"success": true, "message": "ACL deleted"}))
    }

    let app = Router::new()
        .route(
            "/api/v1/acl",
            post(add_acl_handler).delete(delete_acl_handler),
        )
        .with_state(state);

    // POST without cookie should fail
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/acl")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"ip_range":"192.168.1.0/24","action":"Allow"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["error"], "Unauthorized");

    // DELETE without cookie should fail
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/v1/acl?ip_range=192.168.1.0/24")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["error"], "Unauthorized");
}

#[tokio::test]
async fn test_reload_endpoint_requires_auth() {
    let state = create_state_with_admin();

    async fn reload_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
    ) -> axum::Json<serde_json::Value> {
        if !check_auth(&jar, &state.admin) {
            return axum::Json(json!({
                "success": false,
                "error": "Unauthorized"
            }));
        }

        axum::Json(json!({"success": true, "message": "Reloaded"}))
    }

    let app = Router::new()
        .route("/api/reload", post(reload_handler))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/reload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["error"], "Unauthorized");
}

#[tokio::test]
async fn test_api_login_returns_success_and_sets_cookie() {
    let state = create_state_with_admin();

    async fn api_login_handler(
        jar: CookieJar,
        axum::extract::State(state): axum::extract::State<MockAppState>,
        axum::Form(form): axum::Form<LoginForm>,
    ) -> (CookieJar, axum::Json<serde_json::Value>) {
        if let (Some(username), Some(password)) =
            (&state.admin.admin_username, &state.admin.admin_password)
        {
            if form.username == *username && form.password == *password {
                let cookie = Cookie::build(("admin_session", "authenticated"))
                    .path("/")
                    .http_only(true);
                let jar = jar.add(cookie);
                return (
                    jar,
                    axum::Json(json!({"success": true, "token": "admin-token"})),
                );
            }
        }
        (
            jar,
            axum::Json(json!({"success": false, "error": "Invalid credentials"})),
        )
    }

    let app = Router::new()
        .route("/api/login", post(api_login_handler))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/login")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(Body::from("username=admin&password=adminpass"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Check cookie is set
    let set_cookie = response.headers().get("set-cookie");
    assert!(set_cookie.is_some());
    let cookie_str = set_cookie.unwrap().to_str().unwrap();
    assert!(cookie_str.contains("admin_session=authenticated"));

    // Check response body
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let data: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    assert_eq!(data["success"], true);
    assert_eq!(data["token"], "admin-token");
}

#[tokio::test]
async fn test_check_auth_function() {
    // Test when no admin configured
    let admin_state = MockAdminState {
        admin_username: None,
        admin_password: None,
    };
    let jar = CookieJar::default();
    assert!(check_auth(&jar, &admin_state));

    // Test when admin configured but no cookie
    let admin_state = MockAdminState {
        admin_username: Some("admin".to_string()),
        admin_password: Some("pass".to_string()),
    };
    let jar = CookieJar::default();
    assert!(!check_auth(&jar, &admin_state));

    // Test when admin configured with valid cookie
    let jar = jar.add(Cookie::new("admin_session", "authenticated"));
    assert!(check_auth(&jar, &admin_state));

    // Test when admin configured with invalid cookie
    let jar = CookieJar::default().add(Cookie::new("admin_session", "wrong_value"));
    assert!(!check_auth(&jar, &admin_state));
}
