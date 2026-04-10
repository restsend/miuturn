//! TLS support for TURN server
//!
//! Provides TLS-encrypted TURN over TCP

use rcgen::generate_simple_self_signed;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// TLS configuration for TURN server
#[derive(Clone)]
pub struct TlsConfig {
    /// DER-encoded certificate
    pub cert_der: Vec<u8>,
    /// DER-encoded private key (PKCS#8)
    pub key_der: Vec<u8>,
}

impl TlsConfig {
    /// Load TLS configuration from files (PEM format)
    pub fn from_files(
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cert_data = fs::read(cert_path)?;
        let key_data = fs::read(key_path)?;

        // Parse PEM to DER
        let cert_der = pem::parse(&cert_data)?.into_contents();
        let key_der = pem::parse(&key_data)?.into_contents();

        Ok(Self { cert_der, key_der })
    }

    /// Generate self-signed certificate for testing
    pub fn generate_self_signed(
        domain: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cert = generate_simple_self_signed([domain.to_string()])?;

        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        Ok(Self { cert_der, key_der })
    }

    /// Create Rustls ServerConfig
    pub fn into_server_config(
        self,
    ) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
        let cert = CertificateDer::from(self.cert_der);
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.key_der));

        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;

        Ok(Arc::new(config))
    }
}

/// Create a default TLS config for testing
pub fn default_test_tls_config() -> Result<TlsConfig, Box<dyn std::error::Error + Send + Sync>> {
    TlsConfig::generate_self_signed("localhost")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed_cert() {
        let config = TlsConfig::generate_self_signed("test.example.com").unwrap();
        assert!(!config.cert_der.is_empty());
        assert!(!config.key_der.is_empty());
    }

    #[test]
    fn test_generate_localhost_cert() {
        let config = TlsConfig::generate_self_signed("localhost").unwrap();
        assert!(!config.cert_der.is_empty());
        assert!(!config.key_der.is_empty());
    }

    #[test]
    fn test_tls_config_into_server_config() {
        let config = TlsConfig::generate_self_signed("localhost").unwrap();
        let server_config = config.into_server_config();
        assert!(server_config.is_ok());
    }

    #[test]
    fn test_default_test_tls_config() {
        let config = default_test_tls_config();
        assert!(config.is_ok());
        let config = config.unwrap();
        assert!(!config.cert_der.is_empty());
        assert!(!config.key_der.is_empty());
    }

    #[test]
    fn test_cert_and_key_different() {
        let config1 = TlsConfig::generate_self_signed("domain1.example.com").unwrap();
        let config2 = TlsConfig::generate_self_signed("domain2.example.com").unwrap();
        assert_ne!(config1.cert_der, config2.cert_der);
        assert_ne!(config1.key_der, config2.key_der);
    }

    #[test]
    fn test_tls_config_clone() {
        let config = TlsConfig::generate_self_signed("test.com").unwrap();
        let cloned = config.clone();
        assert_eq!(cloned.cert_der, config.cert_der);
        assert_eq!(cloned.key_der, config.key_der);
    }
}
