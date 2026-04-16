use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    pub user_type: UserType,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub max_allocations: usize,
    pub bandwidth_limit: Option<u64>,
    pub ip_whitelist: Option<Vec<String>>,
    pub max_allocation_duration_secs: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UserType {
    Temporary,
    Fixed,
    ApiKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    pub ip_range: String,
    pub action: AclAction,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    Allow,
    Deny,
}

pub struct AuthManager {
    users: RwLock<HashMap<String, User>>,
    api_keys: RwLock<HashMap<String, String>>,
    acl_rules: RwLock<Vec<AclRule>>,
    realm: String,
}

impl AuthManager {
    pub fn new(realm: String) -> Self {
        AuthManager {
            users: RwLock::new(HashMap::new()),
            api_keys: RwLock::new(HashMap::new()),
            acl_rules: RwLock::new(Vec::new()),
            realm,
        }
    }

    pub fn load_from_config(
        &self,
        users: Vec<User>,
        api_keys: HashMap<String, String>,
        acl_rules: Vec<AclRule>,
    ) {
        let mut users_guard = self.users.write();
        for user in users {
            users_guard.insert(user.username.clone(), user);
        }
        drop(users_guard);

        let mut api_keys_guard = self.api_keys.write();
        *api_keys_guard = api_keys;
        drop(api_keys_guard);

        let mut acl_guard = self.acl_rules.write();
        *acl_guard = acl_rules;
    }

    pub fn authenticate(&self, username: &str, password: &str) -> Option<User> {
        let users = self.users.read();
        if let Some(user) = users.get(username)
            && user.password == password
        {
            if let Some(expires) = user.expires_at {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if now > expires {
                    return None;
                }
            }
            return Some(user.clone());
        }
        None
    }

    pub fn authenticate_api_key(&self, key: &str) -> Option<String> {
        let api_keys = self.api_keys.read();
        api_keys.get(key).cloned()
    }

    pub fn check_acl(&self, ip: &str) -> bool {
        let rules = self.acl_rules.read();
        for rule in rules.iter() {
            if Self::ip_in_range(ip, &rule.ip_range) {
                return rule.action == AclAction::Allow;
            }
        }
        true
    }

    pub fn ip_in_range(ip: &str, range: &str) -> bool {
        if range.contains('/') {
            let parts: Vec<&str> = range.split('/').collect();
            if parts.len() != 2 {
                return false;
            }
            let base_ip = parts[0];
            let mask: u32 = parts[1].parse().unwrap_or(32);
            Self::ip_matches_subnet(ip, base_ip, mask)
        } else {
            ip == range
        }
    }

    fn ip_matches_subnet(ip: &str, base: &str, mask: u32) -> bool {
        if mask == 0 {
            return true;
        }
        let ip_parts: Vec<u8> = ip.split('.').map(|p| p.parse().unwrap_or(0)).collect();
        let base_parts: Vec<u8> = base.split('.').map(|p| p.parse().unwrap_or(0)).collect();
        if ip_parts.len() != 4 || base_parts.len() != 4 {
            return false;
        }
        let ip_int = ((ip_parts[0] as u32) << 24)
            | ((ip_parts[1] as u32) << 16)
            | ((ip_parts[2] as u32) << 8)
            | (ip_parts[3] as u32);
        let base_int = ((base_parts[0] as u32) << 24)
            | ((base_parts[1] as u32) << 16)
            | ((base_parts[2] as u32) << 8)
            | (base_parts[3] as u32);
        let mask_int = if mask >= 32 {
            0xFFFFFFFF
        } else {
            !((1u32 << (32 - mask)) - 1)
        };
        (ip_int & mask_int) == (base_int & mask_int)
    }

    pub fn add_user(&self, user: User) {
        let mut users = self.users.write();
        users.insert(user.username.clone(), user);
    }

    pub fn remove_user(&self, username: &str) {
        let mut users = self.users.write();
        users.remove(username);
    }

    pub fn list_users(&self) -> Vec<User> {
        let users = self.users.read();
        users.values().cloned().collect()
    }

    pub fn add_acl_rule(&self, rule: AclRule) {
        let mut rules = self.acl_rules.write();
        rules.push(rule);
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub fn list_acl_rules(&self) -> Vec<AclRule> {
        let rules = self.acl_rules.read();
        rules.clone()
    }

    pub fn remove_acl_rule(&self, ip_range: &str, priority: u32) {
        let mut rules = self.acl_rules.write();
        rules.retain(|r| !(r.ip_range == ip_range && r.priority == priority));
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Get the password for a user by username (for TURN HMAC key derivation).
    /// Returns None if the user doesn't exist or has expired.
    pub fn get_user_password(&self, username: &str) -> Option<String> {
        let users = self.users.read();
        let user = users.get(username)?;
        if let Some(expires) = user.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > expires {
                return None;
            }
        }
        Some(user.password.clone())
    }
}

pub type SharedAuthManager = Arc<AuthManager>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_manager() {
        let manager = AuthManager::new("test".to_string());
        let user = User {
            username: "test".to_string(),
            password: "password".to_string(),
            user_type: UserType::Fixed,
            created_at: 0,
            expires_at: None,
            max_allocations: 5,
            bandwidth_limit: None,
            ip_whitelist: None,
            max_allocation_duration_secs: None,
        };
        manager.add_user(user);
        let auth_result = manager.authenticate("test", "password");
        assert!(auth_result.is_some());
    }

    #[test]
    fn test_acl() {
        let manager = AuthManager::new("test".to_string());
        let allow_rule = AclRule {
            ip_range: "192.168.1.0/24".to_string(),
            action: AclAction::Allow,
            priority: 1,
        };
        let deny_rule = AclRule {
            ip_range: "10.0.0.0/8".to_string(),
            action: AclAction::Deny,
            priority: 2,
        };
        manager.add_acl_rule(deny_rule);
        manager.add_acl_rule(allow_rule);
        assert!(manager.check_acl("192.168.1.100"));
        assert!(!manager.check_acl("10.0.0.1"));
    }

    #[test]
    fn test_user_with_bandwidth_limit() {
        let manager = AuthManager::new("test".to_string());
        let user = User {
            username: "limited".to_string(),
            password: "pass".to_string(),
            user_type: UserType::Fixed,
            created_at: 0,
            expires_at: None,
            max_allocations: 5,
            bandwidth_limit: Some(1048576), // 1 MB/s
            ip_whitelist: None,
            max_allocation_duration_secs: None,
        };
        manager.add_user(user);
        let auth_result = manager.authenticate("limited", "pass");
        assert!(auth_result.is_some());
        assert_eq!(auth_result.unwrap().bandwidth_limit, Some(1048576));
    }

    #[test]
    fn test_user_with_ip_whitelist() {
        let manager = AuthManager::new("test".to_string());
        let user = User {
            username: "iprestricted".to_string(),
            password: "pass".to_string(),
            user_type: UserType::Fixed,
            created_at: 0,
            expires_at: None,
            max_allocations: 5,
            bandwidth_limit: None,
            ip_whitelist: Some(vec!["192.168.1.0/24".to_string(), "10.0.0.1".to_string()]),
            max_allocation_duration_secs: None,
        };
        manager.add_user(user);
        let auth_result = manager.authenticate("iprestricted", "pass");
        assert!(auth_result.is_some());
        let user = auth_result.unwrap();
        assert_eq!(user.ip_whitelist.as_ref().unwrap().len(), 2);
        assert!(
            user.ip_whitelist
                .as_ref()
                .unwrap()
                .contains(&"192.168.1.0/24".to_string())
        );
    }

    #[test]
    fn test_user_with_max_allocation_duration() {
        let manager = AuthManager::new("test".to_string());
        let user = User {
            username: "durationlimited".to_string(),
            password: "pass".to_string(),
            user_type: UserType::Fixed,
            created_at: 0,
            expires_at: None,
            max_allocations: 5,
            bandwidth_limit: None,
            ip_whitelist: None,
            max_allocation_duration_secs: Some(600), // 10 minutes
        };
        manager.add_user(user);
        let auth_result = manager.authenticate("durationlimited", "pass");
        assert!(auth_result.is_some());
        assert_eq!(auth_result.unwrap().max_allocation_duration_secs, Some(600));
    }

    #[test]
    fn test_user_with_all_fields() {
        let manager = AuthManager::new("test".to_string());
        let user = User {
            username: "fulluser".to_string(),
            password: "pass".to_string(),
            user_type: UserType::Temporary,
            created_at: 1234567890,
            expires_at: Some(9999999999),
            max_allocations: 10,
            bandwidth_limit: Some(5242880), // 5 MB/s
            ip_whitelist: Some(vec!["192.168.0.0/16".to_string()]),
            max_allocation_duration_secs: Some(3600), // 1 hour
        };
        manager.add_user(user);
        let auth_result = manager.authenticate("fulluser", "pass");
        assert!(auth_result.is_some());
        let user = auth_result.unwrap();
        assert_eq!(user.user_type, UserType::Temporary);
        assert_eq!(user.max_allocations, 10);
        assert_eq!(user.bandwidth_limit, Some(5242880));
        assert_eq!(user.max_allocation_duration_secs, Some(3600));
        assert!(user.ip_whitelist.is_some());
    }
}
