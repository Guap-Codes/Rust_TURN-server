//! TURN Allocation Management Module
//!
//! This module implements allocation management for a TURN server as specified in RFC 5766.
//! It handles:
//! - Creating and managing client allocations
//! - Relay address generation and management
//! - Permission and channel binding tracking
//! - Allocation lifecycle and cleanup

use crate::config::ServerConfig;
use crate::error::{Error, Result};
use crate::turn::permission::Permission;
use crate::turn::TransportManager;
use crate::types::{ChannelNumber, Lifetime, PeerAddress, RelayAddress};
use ipnetwork::IpNetwork;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Manages TURN allocations for the server
pub struct AllocationManager {
    /// Maps client addresses to their allocations
    allocations: HashMap<SocketAddr, Allocation>,
    /// Server configuration
    config: Arc<ServerConfig>,
    /// Transport manager for network I/O
    transport_manager: Arc<TransportManager>,
}

/// Represents a single TURN allocation
#[allow(dead_code)]
pub struct Allocation {
    /// Client's address (5-tuple)
    client_addr: PeerAddress,

    /// Server-assigned relay address
    relay_addr: RelayAddress,

    /// When this allocation was created
    created_at: Instant,

    /// How long this allocation is valid for
    lifetime: Lifetime,

    /// Transport protocol (UDP/TCP)
    transport: TransportProtocol,

    /// Active channel bindings
    channel_bindings: Vec<(ChannelNumber, PeerAddress)>,

    /// Active permissions
    permissions: Vec<Permission>,

    /// Transport manager reference
    transport_manager: Arc<TransportManager>,
}

impl AllocationManager {
    /// Creates a new allocation manager
    pub fn new(config: Arc<ServerConfig>, transport_manager: Arc<TransportManager>) -> Self {
        Self {
            allocations: HashMap::new(),
            config,
            transport_manager,
        }
    }

    /// Creates a new allocation for a client
    ///
    /// # Arguments
    /// * `client_addr` - The client's socket address
    /// * `requested_lifetime` - Optional requested lifetime duration
    ///
    /// # Returns
    /// * `Ok(RelayAddress)` - The allocated relay address
    /// * `Err(Error)` - If allocation fails
    pub fn create_allocation(
        &mut self,
        client_addr: SocketAddr,
        requested_lifetime: Option<Duration>,
    ) -> Result<RelayAddress> {
        // Check if client already has an allocation
        if self.allocations.contains_key(&client_addr) {
            return Err(Error::Turn("Client already has an allocation".into()));
        }

        // Generate relay address
        let relay_addr = self.generate_relay_address()?;

        // Create new allocation with configured or requested lifetime
        let lifetime = requested_lifetime.unwrap_or(self.config.get_allocation_lifetime());

        let allocation = Allocation::new(
            PeerAddress(client_addr),
            relay_addr.clone(),
            Lifetime(lifetime),
            TransportProtocol::UDP,
            Arc::clone(&self.transport_manager),
        );

        self.allocations.insert(client_addr, allocation);
        Ok(relay_addr)
    }

    /// Refreshes an existing allocation
    ///
    /// # Arguments
    /// * `client_addr` - The client's socket address
    /// * `lifetime` - Optional new lifetime duration
    ///
    /// # Returns
    /// * `Ok(())` - If refresh succeeds
    /// * `Err(Error)` - If allocation not found
    #[allow(dead_code)]
    pub fn refresh_allocation(
        &mut self,
        client_addr: &SocketAddr,
        lifetime: Option<Duration>,
    ) -> Result<()> {
        if let Some(allocation) = self.allocations.get_mut(client_addr) {
            let new_lifetime = lifetime.unwrap_or(self.config.get_allocation_lifetime());
            allocation.refresh(Lifetime(new_lifetime));
            Ok(())
        } else {
            Err(Error::Turn("No allocation found for client".into()))
        }
    }

    /// Removes expired allocations
    pub fn cleanup_expired(&mut self) {
        self.allocations
            .retain(|_, allocation| !allocation.is_expired());
    }

    /// Generates a new relay address from the configured address range
    fn generate_relay_address(&self) -> Result<RelayAddress> {
        let mut rng = rand::thread_rng();
        let used_ports = self.get_used_ports();

        // Parse the configured relay address range
        let network = self
            .config
            .get_relay_address_range()
            .parse::<IpNetwork>()
            .map_err(|e| Error::Config(format!("Invalid relay address range: {}", e)))?;

        // Try up to 100 times to find an available address
        for _ in 0..100 {
            let ip = match network {
                IpNetwork::V4(net) => {
                    let mut ip_bytes = net.network().octets();
                    for i in net.network().octets().len() - net.prefix() as usize / 8..4 {
                        ip_bytes[i] = rng.gen();
                    }
                    IpAddr::V4(Ipv4Addr::from(ip_bytes))
                }
                IpNetwork::V6(net) => {
                    let mut ip_bytes = net.network().octets();
                    for i in net.network().octets().len() - net.prefix() as usize / 8..16 {
                        ip_bytes[i] = rng.gen();
                    }
                    IpAddr::V6(Ipv6Addr::from(ip_bytes))
                }
            };

            // Verify the generated IP is within the network range
            if !network.contains(ip) {
                continue;
            }

            // Generate a port in the IANA dynamic range (49152-65535)
            let port = loop {
                let p = rng.gen_range(49152..65535);
                if !used_ports.contains(&p) {
                    break p;
                }
            };

            let relay_addr = SocketAddr::new(ip, port);

            // Final verification that the address isn't in use
            if !self.is_address_in_use(&relay_addr) {
                return Ok(RelayAddress(relay_addr));
            }
        }

        Err(Error::ResourceLimit(
            "Failed to allocate relay address after 100 attempts".into(),
        ))
    }

    // Helper methods
    fn get_used_ports(&self) -> HashSet<u16> {
        self.allocations
            .values()
            .map(|alloc| alloc.relay_addr.0.port())
            .collect()
    }

    fn is_address_in_use(&self, addr: &SocketAddr) -> bool {
        self.allocations
            .values()
            .any(|alloc| alloc.relay_addr.0 == *addr)
    }

    #[allow(dead_code)]
    // Add this to track address pool usage
    fn get_address_pool_usage(&self) -> (usize, usize) {
        let network = self
            .config
            .get_relay_address_range()
            .parse::<IpNetwork>()
            .unwrap_or_else(|_| match self.config.get_bind_address().ip() {
                IpAddr::V4(_) => "0.0.0.0/0".parse().unwrap(),
                IpAddr::V6(_) => "::/0".parse().unwrap(),
            });

        let total_addresses = match network {
            IpNetwork::V4(net) => 2u128.pow(32 - net.prefix() as u32),
            IpNetwork::V6(net) => 2u128.pow(128 - net.prefix() as u32),
        };

        let used_addresses = self.allocations.len() as u128;
        (used_addresses as usize, total_addresses as usize)
    }

    pub fn get_allocation_mut(&mut self, addr: &SocketAddr) -> Option<&mut Allocation> {
        self.allocations.get_mut(addr)
    }

    pub fn create_tcp_allocation(
        &mut self,
        client_addr: SocketAddr,
        requested_lifetime: Option<Duration>,
    ) -> Result<RelayAddress> {
        let relay_addr = self.generate_relay_address()?;
        let lifetime = requested_lifetime.unwrap_or(self.config.get_allocation_lifetime());

        let allocation = Allocation::new_tcp(
            PeerAddress(client_addr),
            relay_addr.clone(),
            Lifetime(lifetime),
            Arc::clone(&self.transport_manager),
        );

        self.allocations.insert(client_addr, allocation);
        Ok(relay_addr)
    }

    pub fn contains_key(&self, addr: &SocketAddr) -> bool {
        self.allocations.contains_key(addr)
    }
}

/// Transport protocol for allocations
#[derive(Debug, Clone, Copy)]
pub enum TransportProtocol {
    /// UDP transport
    UDP,
    /// TCP transport
    TCP,
}

impl Allocation {
    /// Creates a new allocation
    pub fn new(
        client_addr: PeerAddress,
        relay_addr: RelayAddress,
        lifetime: Lifetime,
        transport: TransportProtocol,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self {
            client_addr,
            relay_addr,
            created_at: Instant::now(),
            lifetime,
            transport,
            channel_bindings: Vec::new(),
            permissions: Vec::new(),
            transport_manager,
        }
    }

    /// Checks if this allocation has expired
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.lifetime.0
    }

    /// Adds a permission for a peer address
    #[allow(dead_code)]
    pub fn add_permission(&mut self, peer_addr: PeerAddress) {
        // Permissions last for 5 minutes (300 seconds) as per RFC 5766
        self.permissions
            .push(Permission::new(peer_addr, Duration::from_secs(300)));
    }

    /// Checks if a permission exists for a peer address
    #[allow(dead_code)]
    pub fn has_permission(&self, peer_addr: &SocketAddr) -> bool {
        self.permissions
            .iter()
            .any(|permission| permission.socket_address() == *peer_addr && !permission.is_expired())
    }

    #[allow(dead_code)]
    pub fn bind_channel(&mut self, channel_number: ChannelNumber, peer_addr: PeerAddress) {
        // Remove any existing binding for this channel number
        self.channel_bindings
            .retain(|(num, _)| *num != channel_number);
        self.channel_bindings.push((channel_number, peer_addr));
    }

    #[allow(dead_code)]
    pub fn get_channel(&self, peer_addr: &PeerAddress) -> Option<ChannelNumber> {
        self.channel_bindings
            .iter()
            .find(|(_, addr)| addr == peer_addr)
            .map(|(num, _)| *num)
    }

    pub fn refresh(&mut self, lifetime: Lifetime) {
        self.created_at = Instant::now();
        self.lifetime = lifetime;
    }

    #[allow(dead_code)]
    pub fn cleanup_expired_permissions(&mut self) {
        self.permissions
            .retain(|permission| !permission.is_expired());
    }

    /// Get the current lifetime of the allocation
    pub fn get_lifetime(&self) -> Duration {
        self.lifetime.0
    }

    pub fn refresh_permission(&mut self, peer_addr: &SocketAddr) -> bool {
        if let Some(permission) = self
            .permissions
            .iter_mut()
            .find(|p| p.socket_address() == *peer_addr)
        {
            permission.refresh(self.lifetime.0);
            true
        } else {
            false
        }
    }

    pub fn new_tcp(
        client_addr: PeerAddress,
        relay_addr: RelayAddress,
        lifetime: Lifetime,
        transport_manager: Arc<TransportManager>,
    ) -> Self {
        Self::new(
            client_addr,
            relay_addr,
            lifetime,
            TransportProtocol::TCP,
            transport_manager,
        )
    }

    pub async fn handle_tcp_data(&mut self, data: &[u8], peer_addr: &SocketAddr) -> Result<()> {
        if !self.has_permission(peer_addr) {
            return Err(Error::Turn("No permission exists for peer".into()));
        }

        match self.transport {
            TransportProtocol::TCP => {
                // RFC 6062 Channel Data framing
                let data = if let Some(channel_num) = self.get_channel(&PeerAddress(*peer_addr)) {
                    // Channel Data Format:
                    // 0                   1                   2                   3
                    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    // |         Channel Number          |            Length             |
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    // |                                                                 |
                    // /                       Application Data                          /
                    // /                                                                /
                    // |                                                                 |
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    let mut channel_data = Vec::with_capacity(data.len() + 4);
                    channel_data.extend_from_slice(&channel_num.value().to_be_bytes());
                    channel_data.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    channel_data.extend_from_slice(data);
                    channel_data
                } else {
                    data.to_vec()
                };

                // Send using transport manager
                self.transport_manager
                    .send_tcp(&data, self.client_addr.0)
                    .await?;
                Ok(())
            }
            TransportProtocol::UDP => Err(Error::Turn(
                "Cannot handle TCP data on UDP allocation".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocation_expiration() {
        let client_addr = "127.0.0.1:1234".parse().unwrap();
        let relay_addr = "127.0.0.1:5678".parse().unwrap();
        let bind_addr = "127.0.0.1:3478".parse().unwrap(); // Standard TURN port

        // Create a runtime for async TransportManager
        let rt = tokio::runtime::Runtime::new().unwrap();
        let transport_manager =
            rt.block_on(async { Arc::new(TransportManager::new(bind_addr).await.unwrap()) });

        let allocation = Allocation::new(
            PeerAddress::new(client_addr),
            RelayAddress::new(relay_addr),
            Lifetime::new(Duration::from_secs(10)),
            TransportProtocol::UDP,
            transport_manager,
        );

        assert!(!allocation.is_expired());
    }
}
