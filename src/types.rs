//! Core type definitions for the TURN server
//!
//! This module provides fundamental types used throughout the TURN server:
//! - Channel numbers and identifiers
//! - Authentication credentials and tokens
//! - Network address types
//! - Timing and expiration handling
//! - Type conversions and validation

use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Channel number for TURN channel bindings (0x4000 through 0x7FFF)
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ChannelNumber(pub u16);

/// Username for authentication
#[derive(Debug, Clone)]
pub struct Username(pub String);

/// Authentication nonce value
#[derive(Debug, Clone)]
pub struct Nonce(pub String);

/// Authentication realm (domain)
#[derive(Debug, Clone)]
pub struct Realm(pub String);

/// Authentication password
#[derive(Debug, Clone)]
pub struct Password(pub String);

/// Peer address for TURN allocations
#[derive(Debug, Clone, PartialEq)]
pub struct PeerAddress(pub SocketAddr);

/// Relay address assigned by TURN server
#[derive(Debug, Clone)]
pub struct RelayAddress(pub SocketAddr);

/// Duration for which a resource is valid
#[derive(Debug, Clone, Copy)]
pub struct Lifetime(pub Duration);

/// Point in time when a resource expires
#[derive(Debug, Clone, Copy)]
pub struct Expiration(pub Instant);

impl ChannelNumber {
    /// Creates a new channel number if within valid range
    ///
    /// # Arguments
    /// * `value` - The channel number value (must be 0x4000-0x7FFF)
    ///
    /// # Returns
    /// * `Some(ChannelNumber)` if value is valid
    /// * `None` if value is outside valid range
    pub fn new(value: u16) -> Option<Self> {
        const MIN: u16 = 0x4000;
        const MAX: u16 = 0x7FFF;
        if (MIN..=MAX).contains(&value) {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Gets the raw channel number value
    pub fn value(&self) -> u16 {
        self.0
    }
}

impl Lifetime {
    /// Creates a new lifetime duration
    pub fn new(duration: Duration) -> Self {
        Self(duration)
    }

    /// Gets the lifetime in seconds
    pub fn get(&self) -> u32 {
        self.0.as_secs() as u32
    }
}

impl Expiration {
    /// Creates a new expiration time from a duration
    ///
    /// # Arguments
    /// * `duration` - How long until expiration
    pub fn new(duration: Duration) -> Self {
        Self(Instant::now() + duration)
    }

    /// Checks if the expiration time has passed
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.0
    }

    /// Refreshes the expiration with a new duration
    ///
    /// # Arguments
    /// * `duration` - New duration from now until expiration
    pub fn refresh(&mut self, duration: Duration) {
        self.0 = Instant::now() + duration;
    }
}

impl PeerAddress {
    /// Creates a new peer address
    pub fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }
}

impl RelayAddress {
    /// Creates a new relay address
    pub fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }
}

impl From<SocketAddr> for PeerAddress {
    fn from(addr: SocketAddr) -> Self {
        PeerAddress(addr)
    }
}
