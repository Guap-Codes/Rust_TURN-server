//! Permission Management Module for TURN Server
//!
//! This module implements permission handling as specified in RFC 5766 Section 9.
//! Permissions authorize peers to send data through the TURN server to a client.
//! Without a permission, the TURN server will drop any data from that peer.
//!
//! Key features:
//! - Permission creation and validation
//! - Permission lifetime management
//! - Automatic cleanup of expired permissions
//! - Thread-safe permission state management

use crate::config::ServerConfig;
use crate::error::Result;
use crate::types::{Expiration, PeerAddress};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Represents a permission for a peer to send data to a client
pub struct Permission {
    /// The peer's address that has permission
    peer_address: PeerAddress,
    /// When this permission expires
    expiration: Expiration,
}

/// Manages permissions for the TURN server
pub struct PermissionManager {
    /// Maps client addresses to their peer permissions
    permissions: HashMap<SocketAddr, Vec<Permission>>,
    /// Server configuration
    config: Arc<ServerConfig>,
}

impl Permission {
    /// Creates a new permission
    ///
    /// # Arguments
    /// * `peer_address` - The peer's address to grant permission to
    /// * `lifetime` - How long the permission should last
    pub fn new(peer_address: PeerAddress, lifetime: Duration) -> Self {
        Self {
            peer_address,
            expiration: Expiration::new(lifetime),
        }
    }

    /// Checks if this permission has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expiration.0
    }

    /// Gets the peer's socket address
    pub fn socket_address(&self) -> SocketAddr {
        self.peer_address.0
    }

    /// Refreshes the permission with a new lifetime
    pub fn refresh(&mut self, lifetime: Duration) {
        self.expiration.refresh(lifetime);
    }

    /// Checks if this permission matches a peer address
    pub fn matches_peer(&self, addr: &PeerAddress) -> bool {
        &self.peer_address == addr
    }
}

impl PermissionManager {
    /// Creates a new permission manager
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            permissions: HashMap::new(),
            config,
        }
    }

    /// Creates a new permission for a client-peer pair
    ///
    /// # Arguments
    /// * `client_addr` - The client's socket address
    /// * `peer_addr` - The peer's socket address to grant permission to
    ///
    /// # Returns
    /// * `Ok(())` - If permission was created successfully
    /// * `Err(Error)` - If permission creation failed
    pub fn create_permission(
        &mut self,
        client_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let permission = Permission::new(
            PeerAddress(peer_addr),
            self.config.get_permission_lifetime(),
        );

        self.permissions
            .entry(client_addr)
            .or_insert_with(Vec::new)
            .push(permission);

        Ok(())
    }

    /// Removes expired permissions
    pub fn cleanup_expired(&mut self) {
        // Remove expired permissions from each client's list
        for permissions in self.permissions.values_mut() {
            permissions.retain(|permission| !permission.is_expired());
        }

        // Remove clients with no remaining permissions
        self.permissions
            .retain(|_, permissions| !permissions.is_empty());
    }

    /// Checks if a permission exists for a client-peer pair
    ///
    /// # Arguments
    /// * `client` - The client's socket address
    /// * `peer` - The peer's socket address to check permission for
    ///
    /// # Returns
    /// `true` if a valid permission exists, `false` otherwise
    pub fn check_permission(&self, client: SocketAddr, peer: SocketAddr) -> bool {
        if let Some(client_permissions) = self.permissions.get(&client) {
            client_permissions
                .iter()
                .any(|perm| perm.matches_peer(&PeerAddress(peer)))
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_expiration() {
        let peer_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let permission = Permission::new(PeerAddress(peer_addr), Duration::from_secs(300));

        assert!(!permission.is_expired());
    }

    #[test]
    fn test_permission_manager() {
        let client_addr: SocketAddr = "127.0.0.1:4321".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        let mut manager = PermissionManager::new(Arc::new(ServerConfig::default()));

        // Test permission creation
        manager
            .create_permission(client_addr, peer_addr)
            .expect("Failed to create permission");
        assert!(manager.check_permission(client_addr, peer_addr));
    }
}
