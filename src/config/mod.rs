//! Configuration module for the TURN server
//!
//! This module provides configuration structures and functionality for:
//! - Transport settings (UDP/TCP/TLS)
//! - Authentication and rate limiting
//! - TURN protocol settings
//! - Timeout configurations
//! - TCP-specific settings

use crate::auth::AuthManager;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_with::serde_as;
use serde_with::DurationSeconds;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Configuration for network transport settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// Network interface to listen on
    pub listen_address: IpAddr,

    /// UDP/TCP port for STUN/TURN
    pub port: u16,

    /// Port for TLS connections
    pub tls_port: u16,

    /// Maximum concurrent connections
    pub max_connections: usize,

    /// Size of network buffers
    pub buffer_size: usize,

    /// Enable TCP transport
    pub enable_tcp: bool,

    /// Enable TLS transport
    pub enable_tls: bool,
}

/// Configuration for rate limiting
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum authentication attempts before rate limiting
    pub max_auth_attempts: usize,

    /// Time window for rate limiting
    #[serde_as(as = "DurationSeconds<u64>")]
    pub rate_limit_window: Duration,

    /// Duration to blacklist IPs that exceed rate limits
    #[serde_as(as = "DurationSeconds<u64>")]
    pub blacklist_duration: Duration,

    /// IPs exempt from rate limiting
    pub whitelist: Vec<String>,

    /// Enable strict rate limiting mode
    pub strict_mode: bool,
}

/// Configuration for authentication
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Authentication realm
    pub realm: String,

    /// Shared secret for auth tokens
    pub shared_secret: String,

    /// Nonce timeout duration
    #[serde_as(as = "DurationSeconds<u64>")]
    pub nonce_timeout: Duration,

    /// How long credentials remain valid
    #[serde_as(as = "DurationSeconds<u64>")]
    pub credential_lifetime: Duration,

    /// Allow long-term credentials
    pub allow_long_term_credentials: bool,

    /// Allow short-term credentials
    pub allow_short_term_credentials: bool,

    /// Max auth attempts before rate limiting
    pub max_auth_attempts: usize,

    /// Rate limit window duration
    #[serde_as(as = "DurationSeconds<u64>")]
    pub rate_limit_window: Duration,

    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
}

/// Configuration for TURN protocol settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnConfig {
    /// Maximum concurrent allocations
    pub max_allocations: usize,

    /// Maximum bandwidth per allocation
    pub max_bandwidth: Option<u64>,

    /// Allowed peer domains
    pub allowed_peer_domains: Vec<String>,

    /// IP range for relay addresses
    pub relay_address_range: String,
}

/// Configuration for various timeouts
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// How long allocations remain valid
    #[serde_as(as = "DurationSeconds<u64>")]
    pub allocation_lifetime: Duration,

    /// How long permissions remain valid
    #[serde_as(as = "DurationSeconds<u64>")]
    pub permission_lifetime: Duration,

    /// How long channel bindings remain valid
    #[serde_as(as = "DurationSeconds<u64>")]
    pub channel_lifetime: Duration,

    /// How long nonces remain valid
    #[serde_as(as = "DurationSeconds<u64>")]
    pub nonce_timeout: Duration,

    /// TCP connection timeout
    #[serde_as(as = "DurationSeconds<u64>")]
    pub tcp_connect_timeout: Duration,

    /// How often to run cleanup tasks
    #[serde_as(as = "DurationSeconds<u64>")]
    pub cleanup_interval: Duration,
}

/// Configuration for TCP-specific settings
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpConfig {
    /// Enable TCP support
    pub enabled: bool,

    /// TCP connection timeout
    #[serde_as(as = "DurationSeconds<u64>")]
    pub connect_timeout: Duration,

    /// TCP idle timeout
    #[serde_as(as = "DurationSeconds<u64>")]
    pub idle_timeout: Duration,

    /// TCP keepalive interval
    #[serde_as(as = "Option<DurationSeconds<u64>>")]
    pub keepalive_interval: Option<Duration>,

    /// Maximum TCP connections
    pub max_connections: usize,
}

/// Main server configuration struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Transport configuration
    pub transport: TransportConfig,

    /// Authentication configuration  
    pub auth: AuthConfig,

    /// TURN protocol configuration
    pub turn: TurnConfig,

    /// Timeout configuration
    pub timeouts: TimeoutConfig,

    /// TCP configuration
    pub tcp: TcpConfig,
}

impl ServerConfig {
    /// Get the bind address for UDP/TCP
    pub fn get_bind_address(&self) -> SocketAddr {
        SocketAddr::new(self.transport.listen_address, self.transport.port)
    }

    /// Get the bind address for TLS
    pub fn get_tls_bind_address(&self) -> SocketAddr {
        SocketAddr::new(self.transport.listen_address, self.transport.tls_port)
    }

    /// Get the authentication realm
    pub fn get_realm(&self) -> String {
        self.auth.realm.clone()
    }

    /// Get maximum allowed allocations
    pub fn get_max_allocations(&self) -> usize {
        self.turn.max_allocations
    }

    /// Get maximum bandwidth per allocation
    pub fn get_max_bandwidth(&self) -> Option<u64> {
        self.turn.max_bandwidth
    }

    /// Get permission lifetime duration
    pub fn get_permission_lifetime(&self) -> Duration {
        self.timeouts.permission_lifetime
    }

    /// Get allocation lifetime duration
    pub fn get_allocation_lifetime(&self) -> Duration {
        self.timeouts.allocation_lifetime
    }

    /// Get channel binding lifetime duration
    pub fn get_channel_lifetime(&self) -> Duration {
        self.timeouts.channel_lifetime
    }

    /// Get nonce timeout duration
    pub fn get_nonce_timeout(&self) -> Duration {
        self.timeouts.nonce_timeout
    }

    /// Get TCP connect timeout duration
    pub fn get_tcp_connect_timeout(&self) -> Duration {
        self.timeouts.tcp_connect_timeout
    }

    /// Get cleanup interval duration
    pub fn get_cleanup_interval(&self) -> Duration {
        self.timeouts.cleanup_interval
    }

    /// Get maximum connections allowed
    pub fn get_max_connections(&self) -> usize {
        self.transport.max_connections
    }

    /// Get network buffer size
    pub fn get_buffer_size(&self) -> usize {
        self.transport.buffer_size
    }

    /// Check if TCP is enabled
    pub fn is_tcp_enabled(&self) -> bool {
        self.transport.enable_tcp
    }

    /// Check if TLS is enabled
    pub fn is_tls_enabled(&self) -> bool {
        self.transport.enable_tls
    }

    /// Get allowed peer domains
    pub fn get_allowed_peer_domains(&self) -> &[String] {
        &self.turn.allowed_peer_domains
    }

    /// Get relay address range
    pub fn get_relay_address_range(&self) -> &str {
        &self.turn.relay_address_range
    }

    /// Create an auth manager from config
    pub fn create_auth_manager(&self) -> AuthManager {
        AuthManager::new(self.auth.realm.clone(), self.auth.shared_secret.clone())
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate transport config
        if self.transport.max_connections == 0 {
            return Err("max_connections must be greater than 0".into());
        }
        if self.transport.port == 0 {
            return Err("port must be greater than 0".into());
        }

        // Validate rate limit config
        if self.auth.rate_limit.max_auth_attempts == 0 {
            return Err("max_auth_attempts must be greater than 0".into());
        }
        if self.auth.rate_limit.rate_limit_window.as_secs() == 0 {
            return Err("rate_limit_window must be greater than 0".into());
        }
        if self.auth.rate_limit.blacklist_duration.as_secs() == 0 {
            return Err("blacklist_duration must be greater than 0".into());
        }

        // Validate TCP config
        if self.tcp.enabled && self.tcp.max_connections == 0 {
            return Err("TCP max_connections must be greater than 0 when TCP is enabled".into());
        }

        Ok(())
    }

    /// Load configuration from a JSON file
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        // Read file contents
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config file: {}", e))?;

        // Parse JSON
        let config: ServerConfig = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse config file: {}", e))?;

        // Validate the loaded config
        config.validate()?;

        Ok(config)
    }
}

// Default implementation provides reasonable defaults for all settings
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            transport: TransportConfig {
                listen_address: "0.0.0.0".parse().unwrap(),
                port: 3478,
                tls_port: 5349,
                max_connections: 1000,
                buffer_size: 65535,
                enable_tcp: true,
                enable_tls: false,
            },
            auth: AuthConfig {
                realm: "turn.example.com".to_string(),
                shared_secret: "default_secret".to_string(),
                nonce_timeout: Duration::from_secs(3600),
                credential_lifetime: Duration::from_secs(86400),
                allow_long_term_credentials: true,
                allow_short_term_credentials: false,
                max_auth_attempts: 5,
                rate_limit_window: Duration::from_secs(60),
                rate_limit: RateLimitConfig {
                    max_auth_attempts: 5,
                    rate_limit_window: Duration::from_secs(60),
                    blacklist_duration: Duration::from_secs(3600),
                    whitelist: vec![],
                    strict_mode: false,
                },
            },
            turn: TurnConfig {
                max_allocations: 10000,
                max_bandwidth: Some(1024 * 1024),
                allowed_peer_domains: vec![],
                relay_address_range: "0.0.0.0/0".to_string(),
            },
            timeouts: TimeoutConfig {
                allocation_lifetime: Duration::from_secs(600),
                permission_lifetime: Duration::from_secs(300),
                channel_lifetime: Duration::from_secs(600),
                nonce_timeout: Duration::from_secs(3600),
                tcp_connect_timeout: Duration::from_secs(30),
                cleanup_interval: Duration::from_secs(60),
            },
            tcp: TcpConfig {
                enabled: true,
                connect_timeout: Duration::from_secs(30),
                idle_timeout: Duration::from_secs(60),
                keepalive_interval: Some(Duration::from_secs(15)),
                max_connections: 1000,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_default_config() {
        let config = ServerConfig::default();

        // Test transport defaults
        assert_eq!(config.transport.port, 3478);
        assert_eq!(config.transport.tls_port, 5349);
        assert_eq!(config.transport.max_connections, 1000);
        assert!(config.transport.enable_tcp);
        assert!(!config.transport.enable_tls);

        // Test auth defaults
        assert_eq!(config.auth.realm, "turn.example.com");
        assert_eq!(config.auth.shared_secret, "default_secret");
        assert_eq!(config.auth.nonce_timeout, Duration::from_secs(3600));
        assert_eq!(config.auth.credential_lifetime, Duration::from_secs(86400));
        assert!(config.auth.allow_long_term_credentials);
        assert!(!config.auth.allow_short_term_credentials);

        // Test rate limit defaults
        assert_eq!(config.auth.rate_limit.max_auth_attempts, 5);
        assert_eq!(
            config.auth.rate_limit.rate_limit_window,
            Duration::from_secs(60)
        );
        assert_eq!(
            config.auth.rate_limit.blacklist_duration,
            Duration::from_secs(3600)
        );
        assert!(config.auth.rate_limit.whitelist.is_empty());
        assert!(!config.auth.rate_limit.strict_mode);
    }

    #[test]
    fn test_bind_address() {
        let mut config = ServerConfig::default();
        config.transport.listen_address = "127.0.0.1".parse().unwrap();
        config.transport.port = 3478;

        let bind_addr = config.get_bind_address();
        assert_eq!(bind_addr.to_string(), "127.0.0.1:3478");

        let tls_addr = config.get_tls_bind_address();
        assert_eq!(tls_addr.to_string(), "127.0.0.1:5349");
    }

    #[test]
    fn test_duration_conversions() {
        let config = ServerConfig::default();

        // Test all duration getters
        assert_eq!(config.get_allocation_lifetime(), Duration::from_secs(600));
        assert_eq!(config.get_permission_lifetime(), Duration::from_secs(300));
        assert_eq!(config.get_channel_lifetime(), Duration::from_secs(600));
        assert_eq!(config.get_nonce_timeout(), Duration::from_secs(3600));
        assert_eq!(config.get_tcp_connect_timeout(), Duration::from_secs(30));
        assert_eq!(config.get_cleanup_interval(), Duration::from_secs(60));
    }

    #[test]
    fn test_rate_limit_config() {
        let mut config = ServerConfig::default();

        // Modify rate limit settings
        config.auth.rate_limit.max_auth_attempts = 10;
        config.auth.rate_limit.rate_limit_window = Duration::from_secs(120);
        config.auth.rate_limit.blacklist_duration = Duration::from_secs(7200);
        config.auth.rate_limit.whitelist = vec!["192.168.1.1".to_string()];
        config.auth.rate_limit.strict_mode = true;

        // Verify changes
        assert_eq!(config.auth.rate_limit.max_auth_attempts, 10);
        assert_eq!(
            config.auth.rate_limit.rate_limit_window,
            Duration::from_secs(120)
        );
        assert_eq!(
            config.auth.rate_limit.blacklist_duration,
            Duration::from_secs(7200)
        );
        assert_eq!(config.auth.rate_limit.whitelist.len(), 1);
        assert!(config
            .auth
            .rate_limit
            .whitelist
            .contains(&"192.168.1.1".to_string()));
        assert!(config.auth.rate_limit.strict_mode);
    }

    #[test]
    fn test_config_validation() {
        let mut config = ServerConfig::default();

        // Test invalid max connections
        config.transport.max_connections = 0;
        assert!(config.validate().is_err());

        // Test invalid port
        config.transport.max_connections = 1000;
        config.transport.port = 0;
        assert!(config.validate().is_err());

        // Test invalid rate limit window
        config.transport.port = 3478;
        config.auth.rate_limit.rate_limit_window = Duration::from_secs(0);
        assert!(config.validate().is_err());

        // Test valid config
        config.auth.rate_limit.rate_limit_window = Duration::from_secs(60);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_file_loading() {
        // Create a temporary config file with all required fields
        let config_str = r#"
        {
            "transport": {
                "listen_address": "0.0.0.0",
                "port": 3478,
                "tls_port": 5349,
                "max_connections": 2000,
                "buffer_size": 65535,
                "enable_tcp": true,
                "enable_tls": false
            },
            "auth": {
                "realm": "custom.realm",
                "shared_secret": "test_secret",
                "nonce_timeout": 3600,
                "credential_lifetime": 86400,
                "allow_long_term_credentials": true,
                "allow_short_term_credentials": false,
                "max_auth_attempts": 5,
                "rate_limit_window": 60,
                "rate_limit": {
                    "max_auth_attempts": 10,
                    "rate_limit_window": 120,
                    "blacklist_duration": 7200,
                    "whitelist": ["192.168.1.1"],
                    "strict_mode": true
                }
            },
            "turn": {
                "max_allocations": 10000,
                "max_bandwidth": 1048576,
                "allowed_peer_domains": [],
                "relay_address_range": "0.0.0.0/0"
            },
            "timeouts": {
                "allocation_lifetime": 600,
                "permission_lifetime": 300,
                "channel_lifetime": 600,
                "nonce_timeout": 3600,
                "tcp_connect_timeout": 30,
                "cleanup_interval": 60
            },
            "tcp": {
                "enabled": true,
                "connect_timeout": 30,
                "idle_timeout": 60,
                "keepalive_interval": 15,
                "max_connections": 1000
            }
        }"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join("config.json");
        std::fs::write(&config_path, config_str).unwrap();

        // Load and verify config
        let config = ServerConfig::from_file(&config_path).unwrap();

        // Test transport config
        assert_eq!(config.transport.max_connections, 2000);
        assert_eq!(config.transport.buffer_size, 65535);
        assert!(config.transport.enable_tcp);
        assert!(!config.transport.enable_tls);

        // Test auth config
        assert_eq!(config.auth.realm, "custom.realm");
        assert_eq!(config.auth.shared_secret, "test_secret");
        assert_eq!(config.auth.rate_limit.max_auth_attempts, 10);
        assert_eq!(
            config.auth.rate_limit.rate_limit_window,
            Duration::from_secs(120)
        );
        assert!(config
            .auth
            .rate_limit
            .whitelist
            .contains(&"192.168.1.1".to_string()));

        // Test turn config
        assert_eq!(config.turn.max_allocations, 10000);
        assert_eq!(config.turn.max_bandwidth, Some(1048576));
        assert_eq!(config.turn.relay_address_range, "0.0.0.0/0");

        // Test timeout config
        assert_eq!(
            config.timeouts.allocation_lifetime,
            Duration::from_secs(600)
        );
        assert_eq!(
            config.timeouts.permission_lifetime,
            Duration::from_secs(300)
        );
        assert_eq!(config.timeouts.channel_lifetime, Duration::from_secs(600));

        // Test TCP config
        assert!(config.tcp.enabled);
        assert_eq!(config.tcp.max_connections, 1000);
    }
}
