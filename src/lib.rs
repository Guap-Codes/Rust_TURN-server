//! A TURN server implementation in Rust
//!
//! This crate provides a TURN (Traversal Using Relays around NAT) server
//! implementation following RFC 5766.

mod auth;
mod config;
mod error;
mod rate_limit;
mod transport;
mod turn;
mod types;

// Re-export primary types
pub use config::ServerConfig;
pub use error::Error;
pub use turn::TurnServer;

// Re-export the types
pub use types::*;

// Re-export configuration types that users might need to construct ServerConfig
pub use config::{AuthConfig, TimeoutConfig, TransportConfig};

// Re-export error types for error handling
pub use auth::AuthError;
pub use error::TransportError;

// Re-export rate limiter if needed externally
pub use rate_limit::RateLimiter;

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the logger for the TURN server
pub fn init_logger() {
    env_logger::init();
}

// Re-export stats
pub use rate_limit::RateLimitStats;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_creation() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let config = ServerConfig::default();
            let server = TurnServer::new(&config).await;
            assert!(matches!(server, Ok(_)));
        });
    }
}
