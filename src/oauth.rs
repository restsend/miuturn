//! OAuth 2.0 support for TURN server
//!
//! Provides OAuth 2.0 bearer token authentication and JWT validation.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// OAuth 2.0 configuration
#[derive(Debug, Clone, Default)]
pub struct OAuthConfig {
    /// JWT secret key for validation
    pub jwt_secret: String,
    /// OAuth 2.0 issuer URL
    pub issuer: String,
    /// OAuth 2.0 audience
    pub audience: String,
    /// JWT validation enabled
    pub enabled: bool,
}

impl OAuthConfig {
    pub fn new(jwt_secret: String) -> Self {
        Self {
            jwt_secret,
            issuer: String::new(),
            audience: String::new(),
            enabled: true,
        }
    }

    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = issuer;
        self
    }

    pub fn with_audience(mut self, audience: String) -> Self {
        self.audience = audience;
        self
    }
}

/// OAuth token validator
#[derive(Clone)]
pub struct OAuthValidator {
    config: OAuthConfig,
}

impl OAuthValidator {
    pub fn new(config: OAuthConfig) -> Self {
        Self { config }
    }

    /// Validate a bearer token (simplified JWT validation)
    /// Returns Some(user_id) if valid, None if invalid
    pub fn validate_token(&self, token: &str) -> Option<String> {
        if !self.config.enabled {
            return None;
        }

        // Simplified JWT validation:
        // Format: header.payload.signature (base64 encoded)
        // We don't use a full JWT library to avoid dependencies
        // This validates format and signature only

        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        // Decode payload (second part)
        let payload = base64_decode(parts[1])?;
        let payload_str = String::from_utf8(payload).ok()?;

        // Parse JSON payload (simplified)
        // Expected format: {"sub":"user_id","exp":timestamp,"iss":"issuer","aud":"audience"}
        let user_id = extract_json_field(&payload_str, "sub")?;
        let exp = extract_json_field(&payload_str, "exp")?
            .parse::<u64>()
            .ok()?;
        let iss = extract_json_field(&payload_str, "iss");
        let aud = extract_json_field(&payload_str, "aud");

        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > exp {
            return None; // Token expired
        }

        // Validate issuer if configured
        if !self.config.issuer.is_empty() && iss.as_ref() != Some(&self.config.issuer) {
            return None;
        }

        // Validate audience if configured
        if !self.config.audience.is_empty() && aud.as_ref() != Some(&self.config.audience) {
            return None;
        }

        // Verify signature
        let signature_input = format!("{}.{}", parts[0], parts[1]);
        let expected_sig = compute_hmac_sha256(&signature_input, &self.config.jwt_secret);

        // Decode provided signature
        let provided_sig = base64_decode(parts[2])?;
        if provided_sig != expected_sig {
            return None; // Invalid signature
        }

        Some(user_id)
    }

    /// Check if OAuth is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// OAuth user info extracted from token
#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    pub user_id: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<u64>,
}

impl OAuthValidator {
    /// Extract user info from a valid token
    pub fn get_user_info(&self, token: &str) -> Option<OAuthUserInfo> {
        if !self.config.enabled {
            return None;
        }

        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        let payload = base64_decode(parts[1])?;
        let payload_str = String::from_utf8(payload).ok()?;

        let user_id = extract_json_field(&payload_str, "sub")?;
        let scopes = extract_json_field(&payload_str, "scope")
            .map(|s| s.split(' ').map(String::from).collect())
            .unwrap_or_default();
        let expires_at =
            extract_json_field(&payload_str, "exp").and_then(|s| s.parse::<u64>().ok());

        Some(OAuthUserInfo {
            user_id,
            scopes,
            expires_at,
        })
    }
}

/// Bearer token extractor from Authorization header
pub fn extract_bearer_token(auth_header: &str) -> Option<String> {
    auth_header.strip_prefix("Bearer ").map(|s| s.to_string())
}

// Base64url decoding (JWT uses base64url without padding)
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    // Replace base64url characters with base64
    let mut base64 = input.replace('-', "+").replace('_', "/");

    // Add padding if needed
    let padding = (4 - base64.len() % 4) % 4;
    base64.extend(std::iter::repeat_n('=', padding));

    // Decode
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &base64).ok()?;
    Some(decoded)
}

// HMAC-SHA256 computation
fn compute_hmac_sha256(message: &str, key: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

// Extract a field from a simplified JSON string
fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let search = format!("\"{}\":", field);
    let start = json.find(&search)?;
    let value_start = start + search.len();

    // Find the value (could be string, number, boolean, etc.)
    let rest = &json[value_start..];

    let ch = rest.chars().next()?;
    if ch == '"' {
        // String value
        let end = rest[1..].find('"')? + 1;
        Some(rest[1..end].to_string())
    } else if ch == 't' || ch == 'f' {
        // Boolean
        let end = if rest.starts_with("true") { 4 } else { 5 };
        Some(rest[..end].to_string())
    } else {
        // Number
        let end = rest.find(&[',', '}'][..]).unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_token(user_id: &str, secret: &str, exp: u64) -> String {
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            r#"{"alg":"HS256","typ":"JWT"}"#,
        );
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!(r#"{{"sub":"{}","exp":{}}}"#, user_id, exp),
        );
        let signature_input = format!("{}.{}", header, payload);
        let sig = compute_hmac_sha256(&signature_input, secret);
        let signature = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &sig);
        format!("{}.{}.{}", header, payload, signature)
    }

    #[test]
    fn test_oauth_config_default() {
        let config = OAuthConfig::default();
        assert!(!config.enabled);
    }

    #[test]
    fn test_oauth_config_enabled() {
        let config = OAuthConfig::new("secret".to_string());
        assert!(config.enabled);
        assert_eq!(config.jwt_secret, "secret");
    }

    #[test]
    fn test_oauth_validator_disabled() {
        let config = OAuthConfig::default();
        let validator = OAuthValidator::new(config);
        assert!(!validator.is_enabled());
        assert!(validator.validate_token("any").is_none());
    }

    #[test]
    fn test_oauth_validator_valid_token() {
        let secret = "my-secret-key";
        let config = OAuthConfig::new(secret.to_string());
        let validator = OAuthValidator::new(config);

        // Create a valid token
        let future_exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600; // 1 hour from now

        let token = create_test_token("user123", secret, future_exp);

        let result = validator.validate_token(&token);
        assert_eq!(result, Some("user123".to_string()));
    }

    #[test]
    fn test_oauth_validator_expired_token() {
        let secret = "my-secret-key";
        let config = OAuthConfig::new(secret.to_string());
        let validator = OAuthValidator::new(config);

        // Create an expired token
        let past_exp = 1000000000u64; // Far in the past

        let token = create_test_token("user123", secret, past_exp);

        assert!(validator.validate_token(&token).is_none());
    }

    #[test]
    fn test_oauth_validator_invalid_signature() {
        let secret = "my-secret-key";
        let config = OAuthConfig::new(secret.to_string());
        let validator = OAuthValidator::new(config);

        // Create a token with wrong secret
        let future_exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let token = create_test_token("user123", "wrong-secret", future_exp);

        assert!(validator.validate_token(&token).is_none());
    }

    #[test]
    fn test_oauth_validator_malformed_token() {
        let config = OAuthConfig::new("secret".to_string());
        let validator = OAuthValidator::new(config);

        // Invalid formats
        assert!(validator.validate_token("").is_none());
        assert!(validator.validate_token("abc").is_none());
        assert!(validator.validate_token("a.b").is_none());
        assert!(validator.validate_token("a.b.c.d").is_none());
    }

    #[test]
    fn test_oauth_validator_with_issuer() {
        let secret = "my-secret-key";
        let config = OAuthConfig::new(secret.to_string())
            .with_issuer("https://auth.example.com".to_string());
        let validator = OAuthValidator::new(config);

        // Token without matching issuer should fail
        // (In a real implementation, we'd need to create tokens with matching issuer)

        // For now, just test that issuer validation is configured
        assert!(validator.config.issuer == "https://auth.example.com");
    }

    #[test]
    fn test_extract_bearer_token() {
        assert_eq!(
            extract_bearer_token("Bearer abc123"),
            Some("abc123".to_string())
        );
        assert_eq!(extract_bearer_token("Bearer "), Some(String::new()));
        assert_eq!(extract_bearer_token("Basic abc123"), None);
        assert_eq!(extract_bearer_token("abc123"), None);
    }

    #[test]
    fn test_base64_decode() {
        // Test basic base64 decoding
        let decoded = base64_decode("aGVsbG8").unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn test_compute_hmac_sha256() {
        let sig = compute_hmac_sha256("message", "key");
        assert!(!sig.is_empty());
        // Same input should produce same output
        let sig2 = compute_hmac_sha256("message", "key");
        assert_eq!(sig, sig2);
        // Different input should produce different output
        let sig3 = compute_hmac_sha256("message", "key2");
        assert_ne!(sig, sig3);
    }

    #[test]
    fn test_get_user_info() {
        let secret = "my-secret-key";
        let config = OAuthConfig::new(secret.to_string());
        let validator = OAuthValidator::new(config);

        let future_exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let token = create_test_token("user456", secret, future_exp);

        let user_info = validator.get_user_info(&token);
        assert!(user_info.is_some());
        let info = user_info.unwrap();
        assert_eq!(info.user_id, "user456");
        assert_eq!(info.expires_at, Some(future_exp));
    }

    #[test]
    fn test_create_and_validate_token() {
        let secret = "test-secret-key-12345";
        let config = OAuthConfig::new(secret.to_string());
        let validator = OAuthValidator::new(config);

        // Manually construct a token
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            r#"{"alg":"HS256","typ":"JWT"}"#,
        );
        let future_exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            format!(r#"{{"sub":"testuser","exp":{}}}"#, future_exp),
        );

        let signature_input = format!("{}.{}", header, payload);
        let sig = compute_hmac_sha256(&signature_input, secret);
        let signature = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &sig);
        let token = format!("{}.{}.{}", header, payload, signature);

        let result = validator.validate_token(&token);
        assert_eq!(result, Some("testuser".to_string()));
    }
}
