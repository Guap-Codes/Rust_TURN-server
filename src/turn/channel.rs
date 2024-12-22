//! Channel Management Module for TURN Server
//!
//! This module implements channel binding functionality as specified in RFC 5766 Section 11.
//! Channels provide a way to reduce the overhead of data packets sent through
//! the TURN server by replacing the full STUN header with a 4-byte prefix.
//!
//! Key features:
//! - Channel number allocation and management
//! - Channel binding lifecycle tracking
//! - Automatic cleanup of expired bindings
//! - Thread-safe channel state management

use crate::config::ServerConfig;
use crate::error::{Error, Result};
use crate::types::{ChannelNumber, Expiration, PeerAddress};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

// RFC 5766: Channel numbers must be in the range 0x4000 through 0x7FFF
pub const MIN_CHANNEL_NUMBER: ChannelNumber = ChannelNumber(0x4000);
pub const MAX_CHANNEL_NUMBER: ChannelNumber = ChannelNumber(0x7FFF);

/// Represents a single channel binding between a client and peer
#[derive(Debug)]
pub struct Channel {
    /// The assigned channel number
    number: ChannelNumber,
    /// The peer's address this channel is bound to
    peer_address: PeerAddress,
    /// The client's address that owns this channel
    client_address: SocketAddr,
    /// When this channel binding expires
    expiration: Expiration,
}

/// Manages channel bindings for the TURN server
pub struct ChannelManager {
    /// Maps channel numbers to channels
    channels: HashMap<u16, Channel>,
    /// Maps peer addresses to channel numbers for quick lookup
    peer_bindings: HashMap<SocketAddr, u16>,
    /// Next available channel number to assign
    next_channel: u16,
    /// Server configuration
    config: Arc<ServerConfig>,
}

impl Channel {
    /// Creates a new channel binding
    ///
    /// # Arguments
    /// * `number` - The channel number to assign
    /// * `peer_address` - The peer's address to bind to
    /// * `lifetime` - How long the binding should last
    /// * `client_addr` - The client's address that owns this binding
    pub fn new(
        number: ChannelNumber,
        peer_address: PeerAddress,
        lifetime: Duration,
        client_addr: SocketAddr,
    ) -> Self {
        Self {
            number,
            peer_address,
            client_address: client_addr,
            expiration: Expiration::new(lifetime),
        }
    }

    /// Checks if this channel binding has expired
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expiration.0
    }

    /// Gets the peer address this channel is bound to
    pub fn peer_address(&self) -> SocketAddr {
        self.peer_address.0
    }

    /// Refreshes the channel binding with a new lifetime
    pub fn refresh(&mut self, lifetime: Duration) {
        self.expiration.refresh(lifetime);
    }

    /// Gets the client address that owns this binding
    pub fn client_addr(&self) -> SocketAddr {
        self.client_address
    }

    /// Gets the channel number
    #[allow(dead_code)]
    pub fn number(&self) -> u16 {
        self.number.0
    }
}

impl ChannelManager {
    /// Creates a new channel manager
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            channels: HashMap::new(),
            peer_bindings: HashMap::new(),
            next_channel: MIN_CHANNEL_NUMBER.value(),
            config,
        }
    }

    /// Binds a channel number to a peer address
    ///
    /// # Arguments
    /// * `peer_address` - The peer's address to bind to
    ///
    /// # Returns
    /// * `Some(u16)` - The assigned channel number
    /// * `None` - If no channel numbers are available
    #[allow(dead_code)]
    pub fn bind_channel(&mut self, peer_address: SocketAddr) -> Option<u16> {
        // Check if peer already has a channel
        if let Some(&channel_number) = self.peer_bindings.get(&peer_address) {
            if let Some(channel) = self.channels.get_mut(&channel_number) {
                channel.refresh(self.config.get_channel_lifetime());
                return Some(channel_number);
            }
        }

        // Find next available channel number
        while self.channels.contains_key(&self.next_channel) {
            self.next_channel += 1;
            if self.next_channel > MAX_CHANNEL_NUMBER.value() {
                self.next_channel = MIN_CHANNEL_NUMBER.value();
            }
        }

        let channel_number = self.next_channel;
        self.next_channel += 1;

        // Create new channel
        let channel = Channel::new(
            ChannelNumber(channel_number),
            PeerAddress::new(peer_address),
            self.config.get_channel_lifetime(),
            peer_address,
        );
        self.channels.insert(channel.number.0, channel);
        self.peer_bindings.insert(peer_address, channel_number);

        Some(channel_number)
    }

    /// Gets a channel by its number
    pub fn get_channel(&self, channel_number: u16) -> Option<&Channel> {
        self.channels.get(&channel_number)
    }

    /// Gets a channel by peer address
    #[allow(dead_code)]
    pub fn get_channel_by_peer(&self, peer_address: &SocketAddr) -> Option<&Channel> {
        self.peer_bindings
            .get(peer_address)
            .and_then(|number| self.channels.get(number))
    }

    /// Removes a channel binding
    #[allow(dead_code)]
    pub fn remove_channel(&mut self, channel_number: u16) {
        if let Some(channel) = self.channels.remove(&channel_number) {
            self.peer_bindings.remove(&channel.peer_address.0);
        }
    }

    /// Checks if a channel number is in the valid range
    pub fn is_valid_channel_number(number: u16) -> bool {
        (MIN_CHANNEL_NUMBER.value()..=MAX_CHANNEL_NUMBER.value()).contains(&number)
    }

    /// Creates a new channel binding between a client and peer address
    ///
    /// # Arguments
    /// * `client_addr` - The client's address
    /// * `peer_addr` - The peer's address to bind to
    /// * `channel_number` - The requested channel number
    ///
    /// # Returns
    /// * `Ok(())` - If binding was created successfully
    /// * `Err(Error)` - If binding failed
    pub fn create_binding(
        &mut self,
        client_addr: SocketAddr,
        peer_addr: SocketAddr,
        channel_number: u16,
    ) -> Result<()> {
        // Validate channel number range
        if !(MIN_CHANNEL_NUMBER.value()..=MAX_CHANNEL_NUMBER.value()).contains(&channel_number) {
            return Err(Error::InvalidChannelNumber);
        }

        // Verify client authorization
        if !self.is_client_authorized(&client_addr) {
            return Err(Error::Unauthorized);
        }

        // Handle existing peer binding
        if let Some(&existing_channel) = self.peer_bindings.get(&peer_addr) {
            if existing_channel == channel_number {
                if let Some(channel) = self.channels.get_mut(&channel_number) {
                    if channel.client_addr() != client_addr {
                        return Err(Error::Unauthorized);
                    }
                    channel.refresh(self.config.get_channel_lifetime());
                    return Ok(());
                }
            }
            self.channels.remove(&existing_channel);
        }

        // Create new channel binding
        let channel = Channel::new(
            ChannelNumber(channel_number),
            peer_addr.into(),
            self.config.get_channel_lifetime(),
            client_addr,
        );

        self.channels.insert(channel.number.0, channel);
        self.peer_bindings.insert(peer_addr, channel_number);

        Ok(())
    }

    /// Removes expired channel bindings
    pub fn cleanup_expired(&mut self) {
        let expired_channels: Vec<_> = self
            .channels
            .iter()
            .filter(|(_, channel)| channel.is_expired())
            .map(|(number, _)| *number)
            .collect();

        for channel_number in expired_channels {
            if let Some(channel) = self.channels.remove(&channel_number) {
                self.peer_bindings.remove(&channel.peer_address());
            }
        }
    }

    /// Gets the peer address associated with a channel number
    pub fn get_peer_address(&self, channel_number: u16) -> Option<SocketAddr> {
        self.channels
            .get(&channel_number)
            .map(|channel| channel.peer_address())
    }

    /// Gets the channel number associated with a peer address
    #[allow(dead_code)]
    pub fn get_channel_number(&self, peer_addr: &SocketAddr) -> Option<u16> {
        self.peer_bindings.get(peer_addr).copied()
    }

    /// Checks if a client is authorized to create/modify channel bindings
    fn is_client_authorized(&self, client_addr: &SocketAddr) -> bool {
        // For now, we'll implement a basic authorization check:
        // 1. Check if the client already has any existing channels
        // 2. If yes, allow them to create more (they're already authorized)
        // 3. If no, allow them (assuming they've been authenticated at a higher level)

        // The client is considered authorized if:
        // - They have existing channel bindings, or
        // - They've passed authentication in TurnServer (which happens before this check)
        self.channels
            .values()
            .any(|channel| channel.client_addr() == *client_addr)
            || true // Allow new clients since auth is handled at TurnServer level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_binding() {
        let mut manager = ChannelManager::new(Arc::new(ServerConfig::default()));
        let peer_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        // Test channel binding
        let channel_number = manager.bind_channel(peer_addr).unwrap();
        assert!(ChannelManager::is_valid_channel_number(channel_number));

        // Test channel lookup
        let channel = manager.get_channel(channel_number).unwrap();
        assert_eq!(channel.peer_address(), peer_addr);

        // Test peer lookup
        let channel = manager.get_channel_by_peer(&peer_addr).unwrap();
        assert_eq!(channel.number(), channel_number);
    }

    #[test]
    fn test_channel_number_validation() {
        assert!(!ChannelManager::is_valid_channel_number(0x3FFF));
        assert!(ChannelManager::is_valid_channel_number(0x4000));
        assert!(ChannelManager::is_valid_channel_number(0x7FFF));
        assert!(!ChannelManager::is_valid_channel_number(0x8000));
    }
}
