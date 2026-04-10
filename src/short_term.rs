//! Short-term credentials support for WebRTC TURN
//!
//! Implements TURN REST API for generating short-term credentials.
//! Format: username = timestamp:user_id, password = HMAC(timestamp:user_id, key)

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<Sha1>;

/// Short-term credential generator
#[derive(Clone)]
pub struct ShortTermCredentialManager {
    /// Secret key for HMAC
    secret_key: Vec<u8>,
    /// Default lifetime in seconds
    default_lifetime_secs: u64,
}

impl ShortTermCredentialManager {
    pub fn new(secret_key: String) -> Self {
        Self {
            secret_key: secret_key.into_bytes(),
            default_lifetime_secs: 3600, // 1 hour default
        }
    }

    pub fn with_lifetime(mut self, lifetime_secs: u64) -> Self {
        self.default_lifetime_secs = lifetime_secs;
        self
    }

    /// Generate a short-term credential
    /// Returns (username, password, expires_at)
    pub fn generate(&self, user_id: &str) -> (String, String, u64) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + self.default_lifetime_secs;

        let username = format!("{}:{}", timestamp, user_id);
        let password = self.compute_password(&username);

        (username, password, timestamp)
    }

    /// Compute HMAC-SHA1 password for the given username
    pub fn compute_password(&self, username: &str) -> String {
        let mut mac = HmacSha1::new_from_slice(&self.secret_key).unwrap();
        mac.update(username.as_bytes());
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    /// Verify short-term credentials
    /// Returns true if valid, false if expired or invalid
    pub fn verify(&self, username: &str, password: &str) -> bool {
        // Parse username: timestamp:user_id
        let parts: Vec<&str> = username.split(':').collect();
        if parts.len() != 2 {
            return false;
        }

        let timestamp: u64 = match parts[0].parse() {
            Ok(t) => t,
            Err(_) => return false,
        };

        // Check if expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if timestamp < now {
            return false; // Expired
        }

        // Verify password
        let expected_password = self.compute_password(username);
        expected_password == password
    }

    /// Parse username to get expiration timestamp and user_id
    pub fn parse_username<'a>(&self, username: &'a str) -> Option<(u64, &'a str)> {
        let parts: Vec<&'a str> = username.split(':').collect();
        if parts.len() != 2 {
            return None;
        }

        let timestamp: u64 = parts[0].parse().ok()?;
        let user_id = parts[1];
        Some((timestamp, user_id))
    }

    /// Check if credentials are expired
    pub fn is_expired(&self, username: &str) -> bool {
        if let Some((timestamp, _)) = self.parse_username(username) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            timestamp < now
        } else {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_term_credential_generation() {
        let manager = ShortTermCredentialManager::new("my_secret_key".to_string());
        let (username, password, expires) = manager.generate("user123");

        assert!(username.contains("user123"));
        assert!(!password.is_empty());
        assert!(expires > 0);

        // Verify the credentials
        assert!(manager.verify(&username, &password));
    }

    #[test]
    fn test_short_term_credential_verification() {
        let manager = ShortTermCredentialManager::new("secret".to_string());
        let (username, password, _) = manager.generate("testuser");

        // Wrong password should fail
        assert!(!manager.verify(&username, "wrong_password"));

        // Correct password should pass
        assert!(manager.verify(&username, &password));
    }

    #[test]
    fn test_expired_credentials() {
        let manager = ShortTermCredentialManager::new("secret".to_string());

        // Create an expired username
        let expired_username = "1000000000:expired_user";
        assert!(manager.is_expired(expired_username));
    }

    #[test]
    fn test_parse_username() {
        let manager = ShortTermCredentialManager::new("secret".to_string());
        let (username, _, _) = manager.generate("myuser");

        if let Some((timestamp, user_id)) = manager.parse_username(&username) {
            assert_eq!(user_id, "myuser");
            assert!(timestamp > 0);
        } else {
            panic!("Failed to parse username");
        }
    }

    #[test]
    fn test_username_format_timestamp_userid() {
        let manager = ShortTermCredentialManager::new("secret".to_string());
        let (username, _, expires) = manager.generate("testuser");

        // Username should be in format timestamp:userid
        let parts: Vec<&str> = username.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[1], "testuser");

        // Timestamp should be parseable and match expires
        let timestamp: u64 = parts[0].parse().unwrap();
        assert_eq!(timestamp, expires);
    }

    #[test]
    fn test_verify_with_different_secrets() {
        let manager1 = ShortTermCredentialManager::new("secret1".to_string());
        let manager2 = ShortTermCredentialManager::new("secret2".to_string());

        let (username, password, _) = manager1.generate("user");

        // manager1 can verify
        assert!(manager1.verify(&username, &password));
        // manager2 cannot verify with different secret
        assert!(!manager2.verify(&username, &password));
    }

    #[test]
    fn test_invalid_username_format() {
        let manager = ShortTermCredentialManager::new("secret".to_string());

        // No colon
        assert!(!manager.verify("invalidusername", "password"));

        // Multiple colons
        assert!(!manager.verify("a:b:c", "password"));

        // Empty user id
        assert!(!manager.verify("12345:", "password"));
    }

    #[test]
    fn test_is_expired_with_future_timestamp() {
        let manager = ShortTermCredentialManager::new("secret".to_string());

        // Future timestamp should not be expired
        let future_username = "9999999999:future_user";
        assert!(!manager.is_expired(future_username));
    }

    #[test]
    fn test_with_lifetime() {
        let manager = ShortTermCredentialManager::new("secret".to_string()).with_lifetime(7200);

        let (_username, _, expires) = manager.generate("user");

        // Check that the expires time is in the future (approximately 7200 seconds from now)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(expires > now);
        assert!(expires <= now + 7200 + 1); // +1 for some tolerance
    }

    #[test]
    fn test_compute_password() {
        let manager = ShortTermCredentialManager::new("mykey".to_string());

        let password1 = manager.compute_password("1234567890:user1");
        let password2 = manager.compute_password("1234567890:user1");

        // Same input should produce same password
        assert_eq!(password1, password2);

        // Different input should produce different password
        let password3 = manager.compute_password("1234567890:user2");
        assert_ne!(password1, password3);
    }

    #[test]
    fn test_manager_clone() {
        let manager1 = ShortTermCredentialManager::new("secret".to_string());
        let manager2 = manager1.clone();

        let (username, password, _) = manager1.generate("user");

        // Both managers should verify the same credentials
        assert!(manager1.verify(&username, &password));
        assert!(manager2.verify(&username, &password));
    }

    #[test]
    fn test_different_user_different_credentials() {
        let manager = ShortTermCredentialManager::new("secret".to_string());

        let (user1_name, user1_pass, _) = manager.generate("user1");
        let (user2_name, user2_pass, _) = manager.generate("user2");

        assert_ne!(user1_name, user2_name);
        assert_ne!(user1_pass, user2_pass);

        assert!(manager.verify(&user1_name, &user1_pass));
        assert!(manager.verify(&user2_name, &user2_pass));
    }
}
