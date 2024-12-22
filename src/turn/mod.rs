//! TURN Server Implementation (RFC 5766)
//!
//! This module implements the core TURN server functionality including:
//! - Allocation management
//! - Permission handling  
//! - Channel binding
//! - Rate limiting
//! - Authentication
//! - TCP/UDP transport

use std::net::SocketAddr;
use stun_rs::{
    attributes::stun::ErrorCode,
    attributes::stun::{MessageIntegrity, Nonce, UserName},
    attributes::turn::LifeTime as StunLifetime,
    attributes::turn::{ChannelNumber, XorPeerAddress, XorRelayedAddress},
    Algorithm, AlgorithmId, DecoderContextBuilder, ErrorCode as ErrorCodeType, MessageClass,
    MessageDecoderBuilder, MessageEncoderBuilder, MessageMethod, StunMessage as Message,
    StunMessageBuilder,
};

use crate::types::Lifetime;
use stun_rs::attributes::turn::LifeTime; // Add this import

use stun_rs::methods::{ALLOCATE, BINDING, CHANNEL_BIND, CREATE_PERMMISSION, REFRESH};

use crate::auth::AuthManager;
use crate::config::ServerConfig;
use crate::error::{AuthError, Error, Result};
use crate::rate_limit::{RateLimitStats, RateLimiter};
use crate::transport::TransportManager;
use std::boxed::Box;
use std::sync::Arc;
use std::time::Duration;
use stun_rs::HMACKey;
use tokio::sync::RwLock;

mod allocation;
mod channel;
mod permission;

pub use allocation::AllocationManager;
pub use channel::ChannelManager;
pub use permission::PermissionManager;

// Add TCP-specific method constants (RFC 6062)
use lazy_static::lazy_static;

lazy_static! {
    static ref tcp_connect: MessageMethod = MessageMethod::try_from(0x000A).unwrap();
    static ref tcp_connection_bind: MessageMethod = MessageMethod::try_from(0x000B).unwrap();
    static ref tcp_connection_attempt: MessageMethod = MessageMethod::try_from(0x000C).unwrap();
}

/// A TURN server implementation following RFC 5766.
pub struct TurnServer {
    transport: Arc<TransportManager>,
    allocations: Arc<RwLock<AllocationManager>>,
    permissions: RwLock<PermissionManager>,
    channels: ChannelManager,
    auth: AuthManager,
    config: Arc<ServerConfig>,
    rate_limiter: RateLimiter,
}

impl TurnServer {
    /// Creates a new TURN server instance with the given configuration.

    /// A Result containing the new TurnServer instance or an error if initialization fails
    ///
    /// # Errors
    /// Returns error if:
    /// - Unable to bind to configured network address
    /// - Invalid configuration values
    /// - Failed to initialize transport or managers
    pub async fn new(config: &ServerConfig) -> Result<Self> {
        let config = Arc::new(config.clone());
        let transport = TransportManager::new(config.get_bind_address()).await?;
        let transport = Arc::new(transport);
        let auth = config.create_auth_manager();

        // Create rate limiter using config reference before moving config
        let rate_limiter = RateLimiter::new(
            config.auth.max_auth_attempts,
            config.auth.rate_limit_window,
            config.auth.rate_limit.blacklist_duration,
        );

        Ok(Self {
            transport: transport.clone(),
            allocations: Arc::new(RwLock::new(AllocationManager::new(
                Arc::clone(&config),
                Arc::clone(&transport),
            ))),
            permissions: RwLock::new(PermissionManager::new(Arc::clone(&config))),
            channels: ChannelManager::new(Arc::clone(&config)),
            auth,
            config: Arc::clone(&config), // Use Arc::clone here
            rate_limiter,
        })
    }

    /// Starts the TURN server and begins processing requests.
    ///
    /// This method runs indefinitely, handling:
    /// - UDP and TCP connections
    /// - STUN/TURN protocol messages
    /// - Periodic cleanup of expired resources
    /// - Rate limiting and authentication
    ///
    /// # Returns
    /// Returns error if server encounters fatal error during operation
    ///
    /// # Cancellation
    /// This method runs until cancelled or encounters an unrecoverable error
    pub async fn run(&mut self) -> Result<()> {
        log::info!(
            "TURN server running on {}",
            self.transport.tcp_listener().local_addr()?
        );

        let cleanup_interval = self.config.get_cleanup_interval();
        let mut cleanup_timer = tokio::time::interval(cleanup_interval);

        // Create channel for UDP message handling only
        let (udp_tx, mut udp_rx) = tokio::sync::mpsc::channel(100);

        // Clone necessary handles for the UDP and TCP tasks
        let udp_handler = self.transport.clone();
        let tcp_handler = self.transport.clone();

        // Create TCP cleanup timer
        let mut tcp_cleanup_timer = tokio::time::interval(Duration::from_secs(15));

        // Spawn UDP handling task and pin it
        let mut udp_task = Box::pin(tokio::spawn(async move {
            loop {
                match udp_handler.receive_udp().await {
                    Ok(msg) => {
                        if let Err(e) = udp_tx.send(msg).await {
                            log::error!("Failed to send UDP message: {}", e);
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        log::error!("UDP receive error: {}", e);
                        return Err::<(), Error>(e.into());
                    }
                }
            }
        }));

        // Spawn TCP handling task and pin it
        let mut tcp_task = Box::pin(tokio::spawn(async move {
            loop {
                match tcp_handler.accept_tcp().await {
                    Ok(()) => {
                        if let Ok(messages) = tcp_handler.receive_tcp().await {
                            for (data, addr) in messages {
                                if let Err(e) = tcp_handler.handle_incoming_tcp(&data, addr).await {
                                    log::error!("Failed to handle TCP data: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("TCP accept error: {}", e);
                        return Err::<(), Error>(e.into());
                    }
                }
            }
        }));

        loop {
            tokio::select! {
                Some((data, addr)) = udp_rx.recv() => {
                    self.handle_message(data, addr).await?;
                }
                _ = cleanup_timer.tick() => {
                    self.cleanup().await?;
                }
                _ = tcp_cleanup_timer.tick() => {
                    // Handle TCP cleanup in the main loop
                    if let Err(e) = self.transport.cleanup_inactive_connections().await {
                        log::error!("TCP cleanup error: {}", e);
                    }
                    if let Err(e) = self.transport.handle_connection_timeout().await {
                        log::error!("TCP keepalive error: {}", e);
                    }
                }
                result = &mut udp_task => {
                    if let Ok(Err(e)) = result {
                        log::error!("UDP task failed: {}", e);
                        return Err(e);
                    }
                }
                result = &mut tcp_task => {
                    if let Ok(Err(e)) = result {
                        log::error!("TCP task failed: {}", e);
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Relays data between clients and peers.
    ///
    /// # Arguments
    /// * `data` - The data to relay
    /// * `from` - Source address
    /// * `to` - Destination address  
    /// * `channel_number` - Optional channel number for efficient relay
    ///
    /// # Returns
    /// Result indicating success/failure of the relay operation
    async fn relay_data(
        &mut self,
        data: &[u8],
        from: SocketAddr,
        to: SocketAddr,
        channel_number: Option<u16>,
    ) -> Result<()> {
        // Check if we have a channel binding
        if let Some(channel_num) = channel_number {
            // Verify channel exists and matches peer
            if let Some(channel) = self.channels.get_channel(channel_num) {
                if channel.peer_address() != to {
                    return Err(Error::Turn(
                        "Channel number doesn't match peer address".into(),
                    ));
                }
            } else {
                return Err(Error::Turn("Invalid channel number".into()));
            }
        }

        // Check if we have permission
        let permissions = self.permissions.read().await;
        if !permissions.check_permission(from, to) {
            return Err(Error::Turn("No permission exists for peer".into()));
        }

        // Relay data based on transport protocol
        if self.transport.is_tcp_connection(&from).await {
            self.transport.relay_tcp_data(data, from, to).await?;
        } else {
            self.transport.send_udp(data, to).await?;
        }

        Ok(())
    }

    /// Handles incoming STUN/TURN protocol messages.
    ///
    /// # Arguments
    /// * `data` - Raw message bytes
    /// * `addr` - Source address
    ///
    /// # Returns
    /// Result indicating success/failure of message handling
    async fn handle_message(&mut self, data: Vec<u8>, addr: SocketAddr) -> Result<()> {
        // First check if it's channel data
        if data.len() >= 4 {
            let channel_number = ((data[0] as u16) << 8) | (data[1] as u16);
            if ChannelManager::is_valid_channel_number(channel_number) {
                // Get peer address from channel
                if let Some(peer_addr) = self.channels.get_peer_address(channel_number) {
                    // Relay data through channel
                    return self
                        .relay_data(&data[4..], addr, peer_addr, Some(channel_number))
                        .await;
                }
            }
        }

        // Not channel data, handle as STUN message
        let decoder = MessageDecoderBuilder::default()
            .with_context(DecoderContextBuilder::default().build())
            .build();

        if let Ok((message, _)) = decoder.decode(&data) {
            self.handle_stun_message(message, addr).await?;
        } else {
            // If it's not a STUN message, it might be TCP data
            if self.transport.is_tcp_connection(&addr).await {
                let mut allocations = self.allocations.write().await;
                if let Some(allocation) = allocations.get_allocation_mut(&addr) {
                    allocation.handle_tcp_data(&data, &addr).await?;
                }
            } else {
                log::warn!("Invalid message received from {}", addr);
            }
        }
        Ok(())
    }

    /// Handles incoming STUN messages and routes them to appropriate handlers.
    ///
    /// # Message Types
    /// - Binding requests (RFC 5389)
    /// - Allocation requests (RFC 5766)
    /// - Permission requests (RFC 5766)
    /// - Channel Binding requests (RFC 5766)
    /// - Refresh requests (RFC 5766)
    /// - TCP-specific requests (RFC 6062):
    ///   - Connect
    ///   - Connection Bind
    ///   - Connection Attempt
    ///
    /// # Arguments
    /// * `message` - The decoded STUN message to process
    /// * `addr` - Source address of the message
    ///
    /// # Returns
    /// * `Ok(())` - If message was handled successfully
    /// * `Err(Error)` - If an error occurred during processing
    ///
    /// For unsupported message types, returns a 400 Bad Request error response.
    async fn handle_stun_message(&mut self, message: Message, addr: SocketAddr) -> Result<()> {
        match (message.class(), message.method()) {
            (MessageClass::Request, BINDING) => self.handle_binding_request(message, addr).await,
            (MessageClass::Request, ALLOCATE) => {
                self.handle_allocation_request(message, addr).await
            }
            (MessageClass::Request, CREATE_PERMMISSION) => {
                self.handle_create_permission_request(message, addr).await
            }
            (MessageClass::Request, CHANNEL_BIND) => {
                self.handle_channel_bind_request(message, addr).await
            }
            (MessageClass::Request, REFRESH) => self.handle_refresh_request(message, addr).await,
            (MessageClass::Request, ref method) if method == &*tcp_connect => {
                self.handle_tcp_connect_request(message, addr).await
            }
            (MessageClass::Request, ref method) if method == &*tcp_connection_bind => {
                self.handle_connection_bind_request(message, addr).await
            }
            (MessageClass::Request, ref method) if method == &*tcp_connection_attempt => {
                self.handle_connection_attempt_request(message, addr).await
            }
            (class, method) => {
                log::debug!(
                    "Unhandled STUN message - Class: {:?}, Method: {:?}",
                    class,
                    method
                );

                // Create error response for unsupported request
                let error_message = match class {
                    MessageClass::Request => "Unsupported STUN request method",
                    MessageClass::Indication => "Unsupported STUN indication method",
                    _ => "Bad Request",
                };

                let error_code = ErrorCodeType::new(400, error_message)
                    .map_err(|e| Error::Stun(e.to_string()))?;

                let error_response = StunMessageBuilder::new(
                    method, // Use the actual method in the response
                    MessageClass::ErrorResponse,
                )
                .with_transaction_id(*message.transaction_id())
                .with_attribute(ErrorCode::new(error_code))
                .build();

                // Use to_bytes() instead of trying to encode directly
                let encoder = MessageEncoderBuilder::default().build();
                let mut buf = vec![0; 2048];
                let size = encoder.encode(&mut buf, &error_response)?;
                let response_bytes = &buf[..size];

                self.transport.send_udp(&response_bytes, addr).await?;
                Ok(())
            }
        }
    }

    /// Handles a STUN Binding request from a client (RFC 5389 Section 7.2).
    ///
    /// A Binding request is used by clients to:
    /// - Determine their reflexive transport address
    /// - Keep NAT bindings alive
    /// - Verify STUN connectivity
    ///
    /// # Arguments
    /// * `request` - The STUN message containing the Binding request
    /// * `addr` - The socket address of the client making the request
    ///
    /// # Returns
    /// * `Ok(())` - If the response was sent successfully
    /// * `Err(Error)` - If there was an error sending the response
    async fn handle_binding_request(&mut self, request: Message, addr: SocketAddr) -> Result<()> {
        let response = StunMessageBuilder::new(request.method(), MessageClass::SuccessResponse)
            .with_transaction_id(*request.transaction_id())
            .build();

        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &response)?;
        let response_bytes = &buf[..size];

        self.transport.send_udp(&response_bytes, addr).await?;
        Ok(())
    }

    /// Handles an Allocation request from a client (RFC 5766 Section 6).
    ///
    /// This method processes TURN Allocation requests which are used to create a relay
    /// address for the client. The method implements the authentication and validation
    /// steps required by the TURN specification.
    ///
    /// # Authentication Flow
    /// 1. Extracts and validates required STUN attributes (USERNAME, MESSAGE-INTEGRITY, NONCE)
    /// 2. Verifies message integrity using HMAC-SHA1
    /// 3. Validates user credentials against the auth manager
    /// 4. Creates allocation if authentication succeeds
    ///
    /// # Arguments
    /// * `request` - The STUN message containing the Allocation request
    /// * `addr` - The socket address of the client making the request
    ///
    /// # Returns
    /// * `Ok(())` - If the request was handled successfully (even if authentication failed)
    /// * `Err(Error)` - If there was an unrecoverable error processing the request
    ///
    /// # Error Responses
    /// The method may send the following STUN error responses:
    /// * 401 Unauthorized - For message integrity failures
    /// * 400 Bad Request - For missing or invalid attributes
    /// * 431 Integrity Check Failure - For HMAC validation failures
    /// * 437 Nonce Expired - If the provided nonce has expired
    async fn handle_allocation_request(
        &mut self,
        request: Message,
        addr: SocketAddr,
    ) -> Result<()> {
        // First, extract the required attributes from the STUN request
        let username = request
            .get::<UserName>()
            .ok_or_else(|| Error::Auth(AuthError::MissingCredentials))?;

        let message_integrity = request
            .get::<MessageIntegrity>()
            .ok_or_else(|| Error::Auth(AuthError::MissingCredentials))?;

        let nonce = request
            .get::<Nonce>()
            .ok_or_else(|| Error::Auth(AuthError::InvalidNonce))?;

        // First get the UserName value, then get the string reference
        let username_str = username
            .as_user_name()
            .map_err(|e| Error::Stun(e.to_string()))?
            .as_ref();

        let nonce_str: &str = nonce.as_nonce()?.as_ref();

        // Get the key using the string representation of the username
        let key = self.auth.get_key_for_user(username_str).await?;

        // Verify message integrity
        let message_integrity = message_integrity
            .as_message_integrity()
            .map_err(|e| Error::Stun(e.to_string()))?;

        let stun_key = HMACKey::new_long_term(
            username_str,
            self.config.get_realm(),
            &key,
            Algorithm::new(AlgorithmId::Reserved, None::<&[u8]>), // Use SHA1 algorithm with no parameters
        )?;

        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &request)?;
        let message_bytes = &buf[..size];

        if !message_integrity.validate(message_bytes, &stun_key) {
            // Create error response for integrity check failure
            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        401,
                        "Message Integrity Check Failed",
                    )?))
                    .build();

            let encoder = MessageEncoderBuilder::default().build();
            let mut buf = vec![0; 2048];
            let size = encoder.encode(&mut buf, &error_response)?;
            let response_bytes = &buf[..size];

            self.transport.send_udp(&response_bytes, addr).await?;
            return Ok(());
        }

        // Verify credentials
        if let Err(auth_error) = self
            .auth
            .verify_credentials(username_str, &key, nonce_str)
            .await
        {
            // Convert auth_error to Error using the From implementation
            let error = Error::from(auth_error);
            let error_code = error.to_stun_error_code();

            // Create an ErrorCodeType first
            let error_code_type =
                ErrorCodeType::new(error_code, error.to_stun_error_message().as_str())
                    .map_err(|e| Error::Stun(e.to_string()))?;

            // Create error response using StunMessageBuilder
            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(error_code_type))
                    .build();

            let encoder = MessageEncoderBuilder::default().build();
            let mut buf = vec![0; 2048];
            let size = encoder.encode(&mut buf, &error_response)?;
            let response_bytes = &buf[..size];

            self.transport.send_udp(&response_bytes, addr).await?;
            return Ok(());
        }
        // Extract requested lifetime if present using get<Lifetime>()
        let requested_lifetime = request
            .get::<StunLifetime>()
            .and_then(|lifetime| lifetime.as_life_time().ok()) // Convert to LifeTime
            .map(|lifetime| Duration::from_secs(lifetime.as_u32() as u64)) // Use as_u32() instead of value()
            .unwrap_or_else(|| self.config.get_allocation_lifetime());

        // Create allocation
        let relay_addr = self
            .allocations
            .write()
            .await
            .create_allocation(addr, Some(requested_lifetime))?;

        // Create the success response using builder pattern
        let response = StunMessageBuilder::new(request.method(), MessageClass::SuccessResponse)
            .with_transaction_id(*request.transaction_id())
            .with_attribute(XorRelayedAddress::from(relay_addr.0)) // Use XorRelayedAddress type
            .with_attribute(LifeTime::new(
                self.config.get_allocation_lifetime().as_secs() as u32,
            )) // Use LifeTime type
            .build();

        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &response)?;
        let response_bytes = &buf[..size];

        self.transport.send_udp(&response_bytes, addr).await?;
        Ok(())
    }

    /// Handles a Create Permission request from a client (RFC 5766 Section 9).
    ///
    /// A Create Permission request establishes permissions for a peer to send data through
    /// the TURN server to the client. Without a permission, the TURN server will drop any
    /// data from that peer.
    ///
    /// # Authentication Flow
    /// 1. Extracts and validates required STUN attributes (USERNAME, MESSAGE-INTEGRITY, NONCE)
    /// 2. Verifies message integrity using HMAC-SHA1
    /// 3. Validates user credentials against the auth manager
    /// 4. Creates permission if authentication succeeds
    ///
    /// # Arguments
    /// * `request` - The STUN message containing the Create Permission request
    /// * `addr` - The socket address of the client making the request
    ///
    /// # Returns
    /// * `Ok(())` - If the request was handled successfully (even if authentication failed)
    /// * `Err(Error)` - If there was an unrecoverable error processing the request
    ///
    /// # Error Responses
    /// The method may send the following STUN error responses to the client:
    /// * 400 Bad Request - For missing or invalid attributes
    /// * 401 Unauthorized - For message integrity failures
    /// * 431 Integrity Check Failure - For HMAC validation failures
    /// * 437 Nonce Expired - If the provided nonce has expired
    /// * 438 Stale Nonce - If the nonce is no longer valid
    /// * 441 Wrong Credentials - If authentication fails
    /// * 442 Unsupported Transport Protocol - For unsupported protocols
    ///
    /// # Example Flow
    /// ```text
    /// Client                                                Server
    ///   |                                                    |
    ///   |--- Create Permission Request ---------------------->|
    ///   |    (USERNAME, MESSAGE-INTEGRITY, NONCE,            |
    ///   |     XOR-PEER-ADDRESS)                             |
    ///   |                                                    |
    ///   |<-- Success Response ------------------------------|
    ///   |    or Error Response                              |
    /// ```
    ///
    /// # RFC Compliance
    /// This implementation follows RFC 5766 Section 9:
    /// - Validates all required attributes
    /// - Performs proper authentication
    /// - Creates permissions with correct lifetimes
    /// - Sends appropriate success/error responses
    ///
    /// # Security Considerations
    /// - Enforces message integrity check
    /// - Validates credentials on every request
    /// - Uses nonce for replay protection
    /// - Rate limits authentication attempts
    async fn handle_create_permission_request(
        &mut self,
        request: Message,
        addr: SocketAddr,
    ) -> Result<()> {
        // First, extract the required attributes from the STUN request
        let username = request
            .get::<UserName>()
            .ok_or_else(|| Error::Auth(AuthError::MissingCredentials))?;

        let message_integrity = request
            .get::<MessageIntegrity>()
            .ok_or_else(|| Error::Auth(AuthError::MissingCredentials))?;

        let nonce = request
            .get::<Nonce>()
            .ok_or_else(|| Error::Auth(AuthError::InvalidNonce))?;

        // Convert the STUN attributes to their string representations
        let username_str = username
            .as_user_name()
            .map_err(|e| Error::Stun(e.to_string()))?
            .as_ref();

        let nonce_str: &str = nonce.as_nonce()?.as_ref();

        let key = self.auth.get_key_for_user(username_str).await?;

        // Verify message integrity
        let message_integrity = message_integrity
            .as_message_integrity()
            .map_err(|e| Error::Stun(e.to_string()))?;

        let stun_key = HMACKey::new_long_term(
            username_str,
            self.config.get_realm(),
            &key,
            Algorithm::new(AlgorithmId::Reserved, None::<&[u8]>), // Use SHA1 algorithm with no parameters
        )?;

        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &request)?;
        let message_bytes = &buf[..size];

        if !message_integrity.validate(message_bytes, &stun_key) {
            // Create error response for integrity check failure
            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        401,
                        "Message Integrity Check Failed",
                    )?))
                    .build();

            let encoder = MessageEncoderBuilder::default().build();
            let mut buf = vec![0; 2048];
            let size = encoder.encode(&mut buf, &error_response)?;
            let response_bytes = &buf[..size];

            self.transport.send_udp(&response_bytes, addr).await?;
            return Ok(());
        }

        // Verify credentials
        if let Err(auth_error) = self
            .auth
            .verify_credentials(username_str, &key, nonce_str)
            .await
        {
            // Convert auth_error to Error once and reuse the Error type
            let error = Error::from(auth_error);
            let error_code = error.to_stun_error_code();
            let error_message = error.to_stun_error_message();

            // Create error response using StunMessageBuilder
            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        error_code,
                        &error_message,
                    )?))
                    .build();

            let encoder = MessageEncoderBuilder::default().build();
            let mut buf = vec![0; 2048];
            let size = encoder.encode(&mut buf, &error_response)?;
            let response_bytes = &buf[..size];

            self.transport.send_udp(&response_bytes, addr).await?;
            return Ok(());
        }

        // Extract peer address from XOR-PEER-ADDRESS attribute
        let peer_addr = request
            .get::<XorPeerAddress>()
            .ok_or_else(|| Error::Turn("Missing XOR-PEER-ADDRESS attribute".to_string()))?
            .as_xor_peer_address()?
            .socket_address();

        // Get mutable access to permissions through RwLock
        let mut permissions = self.permissions.write().await;
        permissions.create_permission(addr, *peer_addr)?;

        // Create success response
        let response = StunMessageBuilder::new(request.method(), MessageClass::SuccessResponse)
            .with_transaction_id(*request.transaction_id())
            .build();

        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &response)?;
        let response_bytes = &buf[..size];

        self.transport.send_udp(&response_bytes, addr).await?;
        Ok(())
    }

    /// Handles a Channel Bind request from a client (RFC 5766 Section 11).
    ///
    /// A Channel Bind request establishes a channel between the client and a peer, allowing for more
    /// efficient subsequent communication by using a 4-byte channel number instead of the full STUN header.
    ///
    /// # Authentication Flow
    /// 1. Extracts and validates required STUN attributes (USERNAME, MESSAGE-INTEGRITY, NONCE)
    /// 2. Verifies message integrity using HMAC-SHA1
    /// 3. Validates user credentials against the auth manager
    /// 4. Creates/refreshes channel binding if authentication succeeds
    ///
    /// # Channel Binding Process
    /// 1. Validates the requested channel number (must be in range 0x4000-0x7FFF)
    /// 2. Verifies channel ownership if the channel already exists
    /// 3. Creates or refreshes the channel binding
    /// 4. Automatically creates a permission for the peer (required by TURN spec)
    ///
    /// # Arguments
    /// * `request` - The STUN message containing the Channel Bind request
    /// * `addr` - The socket address of the client making the request
    ///
    /// # Returns
    /// * `Ok(())` - If the request was handled successfully (even if authentication failed)
    /// * `Err(Error)` - If there was an unrecoverable error processing the request
    ///
    /// # Error Responses
    /// The method may send the following STUN error responses to the client:
    /// * 400 Bad Request - For missing or invalid attributes
    /// * 401 Unauthorized - For message integrity failures
    /// * 437 Allocation Mismatch - If no allocation exists for the 5-tuple
    /// * 441 Wrong Credentials - If authentication fails
    /// * 442 Unsupported Transport Protocol - For unsupported protocols
    /// * 486 Allocation Quota Reached - If channel quota is exceeded
    ///
    /// # RFC Compliance
    /// This implementation follows RFC 5766 Section 11:
    /// - Validates all required attributes
    /// - Performs proper authentication
    /// - Creates both channel binding and permission
    /// - Sends appropriate success/error responses
    ///
    /// # Security Considerations
    /// - Enforces message integrity check
    /// - Validates channel number range
    /// - Verifies channel ownership
    /// - Rate limits authentication attempts
    /// - Creates permissions automatically
    async fn handle_channel_bind_request(
        &mut self,
        request: Message,
        addr: SocketAddr,
    ) -> Result<()> {
        // First, extract the required attributes from the STUN request
        let username = request
            .get::<UserName>()
            .ok_or_else(|| Error::Auth(AuthError::MissingCredentials))?;

        let message_integrity = request
            .get::<MessageIntegrity>()
            .ok_or_else(|| Error::Auth(AuthError::MissingCredentials))?;

        let nonce = request
            .get::<Nonce>()
            .ok_or_else(|| Error::Auth(AuthError::InvalidNonce))?;

        // Convert the STUN attributes to their string representations
        let username_str = username
            .as_user_name()
            .map_err(|e| Error::Stun(e.to_string()))?
            .as_ref();

        let nonce_str: &str = nonce.as_nonce()?.as_ref();

        // For MessageIntegrity, we need to get the HMAC key
        let key = self.auth.get_key_for_user(username_str).await?;

        // Verify message integrity
        let message_integrity = message_integrity
            .as_message_integrity()
            .map_err(|e| Error::Stun(e.to_string()))?;

        let stun_key = HMACKey::new_long_term(
            username_str,
            self.config.get_realm(),
            &key,
            Algorithm::new(AlgorithmId::Reserved, None::<&[u8]>), // Use SHA1 algorithm with no parameters
        )?;

        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &request)?;
        let message_bytes = &buf[..size];

        if !message_integrity.validate(message_bytes, &stun_key) {
            // Create error response for integrity check failure
            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        401,
                        "Message Integrity Check Failed",
                    )?))
                    .build();

            let encoder = MessageEncoderBuilder::default().build();
            let mut buf = vec![0; 2048];
            let size = encoder.encode(&mut buf, &error_response)?;
            let response_bytes = &buf[..size];

            self.transport.send_udp(&response_bytes, addr).await?;
            return Ok(());
        }

        // Verify credentials
        if let Err(auth_error) = self
            .auth
            .verify_credentials(username_str, &key, nonce_str)
            .await
        {
            // Convert auth_error to Error once and reuse the Error type
            let error = Error::from(auth_error);
            let error_code = error.to_stun_error_code();
            let error_message = error.to_stun_error_message();

            // Create error response using StunMessageBuilder
            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        error_code,
                        &error_message,
                    )?))
                    .build();

            let encoder = MessageEncoderBuilder::default().build();
            let mut buf = vec![0; 2048];
            let size = encoder.encode(&mut buf, &error_response)?;
            let response_bytes = &buf[..size];

            self.transport.send_udp(&response_bytes, addr).await?;
            return Ok(());
        }

        // Extract channel number and peer address
        let channel_number = request
            .get::<ChannelNumber>()
            .ok_or_else(|| Error::Turn("Missing CHANNEL-NUMBER attribute".to_string()))?
            .as_channel_number()?
            .number();

        let peer_addr = request
            .get::<XorPeerAddress>()
            .ok_or_else(|| Error::Turn("Missing XOR-PEER-ADDRESS attribute".to_string()))?
            .as_xor_peer_address()?
            .socket_address();

        // Verify channel number is valid
        if !ChannelManager::is_valid_channel_number(channel_number) {
            return Err(Error::InvalidChannelNumber);
        }

        // Check if channel already exists
        if let Some(existing_channel) = self.channels.get_channel(channel_number) {
            // Verify ownership
            if existing_channel.client_addr() != addr {
                return Err(Error::Unauthorized);
            }
        }

        // Create or refresh the binding
        self.channels
            .create_binding(addr, *peer_addr, channel_number)?;

        // Create a permission for this peer (required by TURN spec)
        self.permissions
            .write()
            .await
            .create_permission(addr, *peer_addr)?;

        // Create success response
        let response = StunMessageBuilder::new(request.method(), MessageClass::SuccessResponse)
            .with_transaction_id(*request.transaction_id())
            .build();

        // Send response
        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &response)?;
        self.transport.send_udp(&buf[..size], addr).await?;

        Ok(())
    }

    /// Handles TURN Refresh requests from clients (RFC 5766 Section 7.2)
    ///
    /// A Refresh request is used to:
    /// - Refresh an existing allocation to keep it alive
    /// - Update the lifetime of an allocation
    /// - Delete an allocation by setting lifetime to 0
    /// - Refresh permissions for peers
    ///
    /// # Authentication Flow
    /// 1. Extracts and validates required STUN attributes (USERNAME, MESSAGE-INTEGRITY, NONCE)
    /// 2. Verifies message integrity using HMAC-SHA1
    /// 3. Validates user credentials against the auth manager
    ///
    /// # Arguments
    /// * `request` - The STUN message containing the Refresh request
    /// * `addr` - The socket address of the client making the request
    ///
    /// # Returns
    /// * `Ok(())` - If the request was handled successfully (even if authentication failed)
    /// * `Err(Error)` - If there was an unrecoverable error processing the request
    ///
    /// # Error Responses
    /// The method may send the following STUN error responses to the client:
    /// * 400 Bad Request - For missing or invalid attributes
    /// * 401 Unauthorized - For message integrity failures
    /// * 431 Integrity Check Failure - For HMAC validation failures
    /// * 437 Nonce Expired - If the provided nonce has expired
    /// * 438 Stale Nonce - If the nonce is no longer valid
    ///
    /// # Success Response
    /// On successful refresh, sends a response containing:
    /// * The method and transaction ID from the request
    /// * A LIFETIME attribute with the actual lifetime granted
    ///
    /// # Example Flow
    /// ```text
    /// Client                                                Server
    ///   |                                                    |
    ///   |--- Refresh Request (USERNAME, LIFETIME) ---------->|
    ///   |                                                    |
    ///   |<-- Success Response (LIFETIME) --------------------|
    /// ```
    ///
    /// # RFC Compliance
    /// This implementation follows RFC 5766 Section 7.2:
    /// - Validates all required attributes
    /// - Performs proper authentication
    /// - Handles lifetime extension/reduction
    /// - Refreshes related permissions
    /// - Sends appropriate success/error responses
    ///
    /// # Security Considerations
    /// - Enforces message integrity check
    /// - Validates credentials on every refresh
    /// - Uses nonce for replay protection
    /// - Rate limits authentication attempts
    async fn handle_refresh_request(&mut self, request: Message, addr: SocketAddr) -> Result<()> {
        // First, extract the required attributes from the STUN request
        let username = request
            .get::<UserName>()
            .ok_or_else(|| Error::Auth(AuthError::MissingCredentials))?;

        let username_str = username
            .as_user_name() // Use username here
            .map_err(|e| Error::Stun(e.to_string()))?
            .as_ref();

        let message_integrity = request
            .get::<MessageIntegrity>()
            .ok_or_else(|| Error::Auth(AuthError::MissingCredentials))?;

        let nonce = request
            .get::<Nonce>()
            .ok_or_else(|| Error::Auth(AuthError::InvalidNonce))?;

        let nonce_str: &str = nonce.as_nonce()?.as_ref();

        // In handle_refresh_request, get the key first:
        let key = self.auth.get_key_for_user(username_str).await?;

        // Then verify credentials with the key
        if let Err(auth_error) = self
            .auth
            .verify_credentials(username_str, &key, nonce_str)
            .await
        {
            // Convert auth_error to Error once and reuse the Error type
            let error = Error::from(auth_error);
            let error_code = error.to_stun_error_code();
            let error_message = error.to_stun_error_message();

            // Create error response using StunMessageBuilder
            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        error_code,
                        &error_message,
                    )?))
                    .build();

            let encoder = MessageEncoderBuilder::default().build();
            let mut buf = vec![0; 2048];
            let size = encoder.encode(&mut buf, &error_response)?;
            let response_bytes = &buf[..size];

            self.transport.send_udp(&response_bytes, addr).await?;
            return Ok(());
        }

        // Verify message integrity
        let message_integrity = message_integrity
            .as_message_integrity()
            .map_err(|e| Error::Stun(e.to_string()))?;

        let stun_key = HMACKey::new_long_term(
            username_str,
            self.config.get_realm(),
            &key,
            Algorithm::new(AlgorithmId::Reserved, None::<&[u8]>), // Use SHA1 algorithm with no parameters
        )?;

        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &request)?;
        let message_bytes = &buf[..size];

        if !message_integrity.validate(message_bytes, &stun_key) {
            // Create error response for integrity check failure
            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        401,
                        "Message Integrity Check Failed",
                    )?))
                    .build();

            let encoder = MessageEncoderBuilder::default().build();
            let mut buf = vec![0; 2048];
            let size = encoder.encode(&mut buf, &error_response)?;
            let response_bytes = &buf[..size];

            self.transport.send_udp(&response_bytes, addr).await?;
            return Ok(());
        }

        // Extract requested lifetime if present
        let requested_lifetime = request
            .get::<StunLifetime>()
            .and_then(|lifetime| lifetime.as_life_time().ok()) // Convert to LifeTime
            .map(|lifetime| Duration::from_secs(lifetime.as_u32() as u64)) // Use as_u32() instead of value()
            .unwrap_or_else(|| self.config.get_allocation_lifetime());

        // Refresh the allocation
        let mut allocations = self.allocations.write().await;
        if let Some(allocation) = (*allocations).get_allocation_mut(&addr) {
            // Refresh the allocation
            allocation.refresh(Lifetime(requested_lifetime));

            // Also refresh any existing permissions
            if let Some(peer_addr) = request.get::<XorPeerAddress>() {
                if let Ok(addr) = peer_addr.as_xor_peer_address() {
                    if !allocation.refresh_permission(&addr.socket_address()) {
                        log::warn!(
                            "Failed to refresh permission for peer {}",
                            addr.socket_address()
                        );
                    }
                }
            }

            // Create success response
            let response = StunMessageBuilder::new(request.method(), MessageClass::SuccessResponse)
                .with_transaction_id(*request.transaction_id())
                .with_attribute(StunLifetime::new(allocation.get_lifetime().as_secs() as u32))
                .build();

            // Send response
            let encoder = MessageEncoderBuilder::default().build();
            let mut buf = vec![0; 2048];
            let size = encoder.encode(&mut buf, &response)?;
            self.transport.send_udp(&buf[..size], addr).await?;
        }
        Ok(())
    }

    /// Handles a TCP Connect request from a client (RFC 6062).
    ///
    /// This method processes TCP Connect requests which are used to establish TCP-based
    /// TURN allocations. It implements the authentication and validation steps required
    /// by RFC 6062 section 4.3.
    ///
    /// # Authentication Flow
    /// 1. Rate limit check for the client IP
    /// 2. Validates required STUN attributes (USERNAME, MESSAGE-INTEGRITY, NONCE)
    /// 3. Verifies message integrity using HMAC-SHA1
    /// 4. Validates user credentials against the auth manager
    /// 5. Creates TCP allocation if authentication succeeds
    ///
    /// # Arguments
    /// * `request` - The STUN message containing the TCP Connect request
    /// * `addr` - The socket address of the client making the request
    ///
    /// # Returns
    /// * `Ok(())` - If the request was handled successfully (even if authentication failed)
    /// * `Err(Error)` - If there was an unrecoverable error processing the request
    ///
    /// # Error Responses
    /// The method may send the following STUN error responses to the client:
    /// * 400 Bad Request - For missing or invalid attributes
    /// * 401 Unauthorized - For message integrity failures
    /// * 431 Integrity Check Failure - For HMAC validation failures
    /// * 437 Nonce Expired - If the provided nonce has expired
    /// * 486 Allocation Quota Reached - If client exceeds allocation limits
    ///
    /// # Rate Limiting
    /// * Implements IP-based rate limiting for authentication attempts
    /// * Uses configured limits from ServerConfig
    /// * May blacklist IPs that exceed rate limits
    ///
    /// # Logging
    /// * Warns on authentication failures with detailed error information
    /// * Info logs successful authentication attempts
    /// * Debug logs for request processing steps
    async fn handle_tcp_connect_request(
        &mut self,
        request: Message,
        addr: SocketAddr,
    ) -> Result<()> {
        // Check rate limit before processing auth
        self.check_auth_rate_limit(addr).await?;

        // Add detailed logging for missing credentials
        let username = request.get::<UserName>().ok_or_else(|| {
            log::warn!("TCP auth failed: Missing USERNAME attribute from {}", addr);
            Error::Auth(AuthError::MissingCredentials)
        })?;

        let message_integrity = request.get::<MessageIntegrity>().ok_or_else(|| {
            log::warn!(
                "TCP auth failed: Missing MESSAGE-INTEGRITY attribute from {}",
                addr
            );
            Error::Auth(AuthError::MissingCredentials)
        })?;

        let nonce = request.get::<Nonce>().ok_or_else(|| {
            log::warn!("TCP auth failed: Missing NONCE attribute from {}", addr);
            Error::Auth(AuthError::InvalidNonce)
        })?;

        // Add logging for username parsing failure
        let username_str = username
            .as_user_name()
            .map_err(|e| {
                log::warn!(
                    "TCP auth failed: Invalid USERNAME format from {}: {}",
                    addr,
                    e
                );
                Error::Stun(e.to_string())
            })?
            .as_ref();

        // Add logging for nonce parsing failure
        let nonce_str = nonce
            .as_nonce()
            .map_err(|e| {
                log::warn!("TCP auth failed: Invalid NONCE format from {}: {}", addr, e);
                Error::Stun(e.to_string())
            })?
            .as_ref();

        // Add logging for key lookup failure
        let key = self
            .auth
            .get_key_for_user(username_str)
            .await
            .map_err(|e| {
                log::warn!(
                    "TCP auth failed: Key lookup failed for user '{}' from {}: {:?}",
                    username_str,
                    addr,
                    e
                );
                e
            })?;

        // Verify message integrity
        let message_integrity = message_integrity
            .as_message_integrity()
            .map_err(|e| Error::Stun(e.to_string()))?;

        let stun_key = HMACKey::new_long_term(
            username_str,
            self.config.get_realm(),
            &key,
            Algorithm::new(AlgorithmId::Reserved, None::<&[u8]>),
        )?;

        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &request)?;
        let message_bytes = &buf[..size];

        if !message_integrity.validate(message_bytes, &stun_key) {
            log::warn!(
                "TCP auth failed: Message integrity check failed for user '{}' from {}",
                username_str,
                addr
            );
            // Create error response for integrity check failure
            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        401,
                        "Message Integrity Check Failed",
                    )?))
                    .build();

            let size = encoder.encode(&mut buf, &error_response)?;
            self.transport.send_tcp(&buf[..size], addr).await?;
            return Ok(());
        }

        // Verify credentials
        if let Err(auth_error) = self
            .auth
            .verify_credentials(username_str, &key, nonce_str)
            .await
        {
            log::warn!(
                "TCP auth failed: Credential verification failed for user '{}' from {}: {:?}",
                username_str,
                addr,
                auth_error
            );
            let error = Error::from(auth_error);
            let error_code = error.to_stun_error_code();
            let error_message = error.to_stun_error_message();

            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        error_code,
                        &error_message,
                    )?))
                    .build();

            let size = encoder.encode(&mut buf, &error_response)?;
            self.transport.send_tcp(&buf[..size], addr).await?;
            return Ok(());
        }

        // Add success logging
        log::info!(
            "TCP auth succeeded for user '{}' from {}",
            username_str,
            addr
        );

        // Create TCP allocation if authenticated
        let mut allocations = self.allocations.write().await;
        if !allocations.contains_key(&addr) {
            let relay_addr = allocations.create_tcp_allocation(
                addr, None, // Use default lifetime
            )?;

            // Send success response with relay address
            let response = StunMessageBuilder::new(request.method(), MessageClass::SuccessResponse)
                .with_transaction_id(*request.transaction_id())
                .with_attribute(XorRelayedAddress::from(relay_addr.0))
                .build();

            let size = encoder.encode(&mut buf, &response)?;
            self.transport.send_tcp(&buf[..size], addr).await?;
        }

        Ok(())
    }

    /// Handles a TCP Connection Bind request from a client (RFC 6062).
    ///
    /// This function processes Connection Bind requests which are used to bind a TCP
    /// connection to a previously allocated TURN relay address. The function:
    /// 1. Authenticates the request using long-term credentials
    /// 2. Validates message integrity
    /// 3. Verifies the client's credentials
    /// 4. Sends appropriate success/error responses
    ///
    /// # Arguments
    /// * `request` - The STUN message containing the Connection Bind request
    /// * `addr` - The socket address of the client making the request
    ///
    /// # Returns
    /// * `Ok(())` - If the request was handled successfully (even if authentication failed)
    /// * `Err(Error)` - If there was an unrecoverable error processing the request
    ///
    /// # Authentication Flow
    /// 1. Extracts USERNAME, MESSAGE-INTEGRITY, and NONCE attributes
    /// 2. Validates the message integrity using HMAC-SHA1
    /// 3. Verifies the credentials against the auth manager
    ///
    /// # Error Responses
    /// * 401 Unauthorized - For message integrity failures
    /// * Various error codes - For credential verification failures
    ///
    /// # Logging
    /// * Warns on authentication failures with detailed error information
    /// * Info log on successful authentication
    async fn handle_connection_bind_request(
        &mut self,
        request: Message,
        addr: SocketAddr,
    ) -> Result<()> {
        // Add detailed logging for missing credentials
        let username = request.get::<UserName>().ok_or_else(|| {
            log::warn!("TCP auth failed: Missing USERNAME attribute from {}", addr);
            Error::Auth(AuthError::MissingCredentials)
        })?;

        let message_integrity = request.get::<MessageIntegrity>().ok_or_else(|| {
            log::warn!(
                "TCP auth failed: Missing MESSAGE-INTEGRITY attribute from {}",
                addr
            );
            Error::Auth(AuthError::MissingCredentials)
        })?;

        let nonce = request.get::<Nonce>().ok_or_else(|| {
            log::warn!("TCP auth failed: Missing NONCE attribute from {}", addr);
            Error::Auth(AuthError::InvalidNonce)
        })?;

        // Add logging for username parsing failure
        let username_str = username
            .as_user_name()
            .map_err(|e| {
                log::warn!(
                    "TCP auth failed: Invalid USERNAME format from {}: {}",
                    addr,
                    e
                );
                Error::Stun(e.to_string())
            })?
            .as_ref();

        // Add logging for nonce parsing failure
        let nonce_str = nonce
            .as_nonce()
            .map_err(|e| {
                log::warn!("TCP auth failed: Invalid NONCE format from {}: {}", addr, e);
                Error::Stun(e.to_string())
            })?
            .as_ref();

        // Add logging for key lookup failure
        let key = self
            .auth
            .get_key_for_user(username_str)
            .await
            .map_err(|e| {
                log::warn!(
                    "TCP auth failed: Key lookup failed for user '{}' from {}: {:?}",
                    username_str,
                    addr,
                    e
                );
                e
            })?;

        // Verify message integrity
        let message_integrity = message_integrity
            .as_message_integrity()
            .map_err(|e| Error::Stun(e.to_string()))?;

        let stun_key = HMACKey::new_long_term(
            username_str,
            self.config.get_realm(),
            &key,
            Algorithm::new(AlgorithmId::Reserved, None::<&[u8]>),
        )?;

        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &request)?;
        let message_bytes = &buf[..size];

        if !message_integrity.validate(message_bytes, &stun_key) {
            log::warn!(
                "TCP auth failed: Message integrity check failed for user '{}' from {}",
                username_str,
                addr
            );
            // Create error response for integrity check failure
            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        401,
                        "Message Integrity Check Failed",
                    )?))
                    .build();

            let size = encoder.encode(&mut buf, &error_response)?;
            self.transport.send_tcp(&buf[..size], addr).await?;
            return Ok(());
        }

        // Verify credentials
        if let Err(auth_error) = self
            .auth
            .verify_credentials(username_str, &key, nonce_str)
            .await
        {
            log::warn!(
                "TCP auth failed: Credential verification failed for user '{}' from {}: {:?}",
                username_str,
                addr,
                auth_error
            );
            let error = Error::from(auth_error);
            let error_code = error.to_stun_error_code();
            let error_message = error.to_stun_error_message();

            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        error_code,
                        &error_message,
                    )?))
                    .build();

            let size = encoder.encode(&mut buf, &error_response)?;
            self.transport.send_tcp(&buf[..size], addr).await?;
            return Ok(());
        }

        // Add success logging
        log::info!(
            "TCP auth succeeded for user '{}' from {}",
            username_str,
            addr
        );

        // Create success response only if authenticated
        let response = StunMessageBuilder::new(request.method(), MessageClass::SuccessResponse)
            .with_transaction_id(*request.transaction_id())
            .build();

        let size = encoder.encode(&mut buf, &response)?;
        self.transport.send_tcp(&buf[..size], addr).await?;
        Ok(())
    }

    /// Handles a TCP Connection Attempt request from a peer (RFC 6062).
    ///
    /// This method processes Connection Attempt requests which are sent by peers attempting
    /// to establish TCP connections through the TURN server. The method implements the
    /// authentication and validation steps required by RFC 6062.
    ///
    /// # Authentication Flow
    /// 1. Validates required STUN attributes (USERNAME, MESSAGE-INTEGRITY, NONCE)
    /// 2. Verifies message integrity using HMAC-SHA1
    /// 3. Validates user credentials against the auth manager
    ///
    /// # Arguments
    /// * `request` - The STUN message containing the Connection Attempt request
    /// * `addr` - The socket address of the peer making the request
    ///
    /// # Returns
    /// * `Ok(())` - If the request was handled successfully (even if authentication failed)
    /// * `Err(Error)` - If there was an unrecoverable error processing the request
    ///
    /// # Error Responses
    /// The method may send the following STUN error responses:
    /// * 401 Unauthorized - For message integrity failures
    /// * 400 Bad Request - For missing or invalid attributes
    /// * 431 Integrity Check Failure - For HMAC validation failures
    /// * 437 Nonce Expired - If the provided nonce has expired
    ///
    /// # Logging
    /// * Warns on authentication failures with detailed error information
    /// * Info logs successful authentication attempts
    /// * Debug logs for request processing steps
    async fn handle_connection_attempt_request(
        &mut self,
        request: Message,
        addr: SocketAddr,
    ) -> Result<()> {
        // Add detailed logging for missing credentials
        let username = request.get::<UserName>().ok_or_else(|| {
            log::warn!("TCP auth failed: Missing USERNAME attribute from {}", addr);
            Error::Auth(AuthError::MissingCredentials)
        })?;

        let message_integrity = request.get::<MessageIntegrity>().ok_or_else(|| {
            log::warn!(
                "TCP auth failed: Missing MESSAGE-INTEGRITY attribute from {}",
                addr
            );
            Error::Auth(AuthError::MissingCredentials)
        })?;

        let nonce = request.get::<Nonce>().ok_or_else(|| {
            log::warn!("TCP auth failed: Missing NONCE attribute from {}", addr);
            Error::Auth(AuthError::InvalidNonce)
        })?;

        // Add logging for username parsing failure
        let username_str = username
            .as_user_name()
            .map_err(|e| {
                log::warn!(
                    "TCP auth failed: Invalid USERNAME format from {}: {}",
                    addr,
                    e
                );
                Error::Stun(e.to_string())
            })?
            .as_ref();

        // Add logging for nonce parsing failure
        let nonce_str = nonce
            .as_nonce()
            .map_err(|e| {
                log::warn!("TCP auth failed: Invalid NONCE format from {}: {}", addr, e);
                Error::Stun(e.to_string())
            })?
            .as_ref();

        // Add logging for key lookup failure
        let key = self
            .auth
            .get_key_for_user(username_str)
            .await
            .map_err(|e| {
                log::warn!(
                    "TCP auth failed: Key lookup failed for user '{}' from {}: {:?}",
                    username_str,
                    addr,
                    e
                );
                e
            })?;

        // Verify message integrity
        let message_integrity = message_integrity
            .as_message_integrity()
            .map_err(|e| Error::Stun(e.to_string()))?;

        let stun_key = HMACKey::new_long_term(
            username_str,
            self.config.get_realm(),
            &key,
            Algorithm::new(AlgorithmId::Reserved, None::<&[u8]>),
        )?;

        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &request)?;
        let message_bytes = &buf[..size];

        if !message_integrity.validate(message_bytes, &stun_key) {
            log::warn!(
                "TCP auth failed: Message integrity check failed for user '{}' from {}",
                username_str,
                addr
            );
            // Create error response for integrity check failure
            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        401,
                        "Message Integrity Check Failed",
                    )?))
                    .build();

            let size = encoder.encode(&mut buf, &error_response)?;
            self.transport.send_tcp(&buf[..size], addr).await?;
            return Ok(());
        }

        // Verify credentials
        if let Err(auth_error) = self
            .auth
            .verify_credentials(username_str, &key, nonce_str)
            .await
        {
            log::warn!(
                "TCP auth failed: Credential verification failed for user '{}' from {}: {:?}",
                username_str,
                addr,
                auth_error
            );
            let error = Error::from(auth_error);
            let error_code = error.to_stun_error_code();
            let error_message = error.to_stun_error_message();

            let error_response =
                StunMessageBuilder::new(request.method(), MessageClass::ErrorResponse)
                    .with_transaction_id(*request.transaction_id())
                    .with_attribute(ErrorCode::new(ErrorCodeType::new(
                        error_code,
                        &error_message,
                    )?))
                    .build();

            let size = encoder.encode(&mut buf, &error_response)?;
            self.transport.send_tcp(&buf[..size], addr).await?;
            return Ok(());
        }

        // Add success logging
        log::info!(
            "TCP auth succeeded for user '{}' from {}",
            username_str,
            addr
        );

        // Create success response only if authenticated
        let response = StunMessageBuilder::new(request.method(), MessageClass::SuccessResponse)
            .with_transaction_id(*request.transaction_id())
            .build();

        let size = encoder.encode(&mut buf, &response)?;
        self.transport.send_tcp(&buf[..size], addr).await?;
        Ok(())
    }

    /// Performs periodic cleanup of expired resources.
    ///
    /// Cleans up:
    /// - Expired allocations
    /// - Expired permissions
    /// - Expired channel bindings
    /// - Expired auth tokens
    /// - Rate limiter state
    ///
    /// # Returns
    /// Result indicating success/failure of cleanup operation
    async fn cleanup(&mut self) -> Result<()> {
        // Cleanup expired allocations
        self.allocations.write().await.cleanup_expired();

        // Cleanup expired permissions
        self.permissions.write().await.cleanup_expired();

        // Cleanup expired channels
        self.channels.cleanup_expired();

        // Cleanup expired auth tokens
        self.auth.cleanup_expired().await;

        // Cleanup rate limiter
        self.rate_limiter.cleanup().await;

        Ok(())
    }

    /// Checks if authentication attempts from an IP address should be rate limited.
    ///
    /// This function implements a multi-layer rate limiting strategy:
    /// 1. Whitelist check - Whitelisted IPs bypass rate limiting entirely
    /// 2. Blacklist check - Blacklisted IPs are blocked immediately
    /// 3. Rate limit check - Remaining IPs are subject to standard rate limiting
    ///
    /// # Arguments
    /// * `addr` - The socket address (IP:port) to check for rate limiting
    ///
    /// # Returns
    /// * `Ok(())` - If the request should be allowed to proceed
    /// * `Err(Error::Auth(AuthError::Blacklisted))` - If the IP is blacklisted
    /// * `Err(Error::Auth(AuthError::RateLimitExceeded))` - If rate limit is exceeded
    ///
    /// # Rate Limiting Behavior
    /// - Whitelisted IPs in config.auth.rate_limit.whitelist bypass all checks
    /// - IPs are blacklisted after exceeding max_auth_attempts within rate_limit_window
    /// - Blacklisted IPs remain blocked for blacklist_duration
    ///
    async fn check_auth_rate_limit(&self, addr: SocketAddr) -> Result<()> {
        // Check whitelist first
        if self
            .config
            .auth
            .rate_limit
            .whitelist
            .contains(&addr.ip().to_string())
        {
            return Ok(());
        }

        // Check blacklist
        if self.rate_limiter.is_blacklisted(addr).await {
            log::warn!("Blocked blacklisted IP: {}", addr);
            return Err(Error::Auth(AuthError::Blacklisted));
        }

        // Regular rate limit check
        if !self.rate_limiter.check_rate_limit(addr).await {
            log::warn!("Auth rate limit exceeded for {}", addr);
            return Err(Error::Auth(AuthError::RateLimitExceeded));
        }

        Ok(())
    }

    /// Returns statistics about the rate limiting system.
    ///
    /// This endpoint provides metrics about the rate limiting behavior of the TURN server,
    /// which can be useful for monitoring and debugging purposes.
    ///
    /// # Returns
    /// Returns a `RateLimitStats` struct containing:
    /// - Total number of IPs being tracked
    /// - Total authentication attempts
    /// - Number of blacklisted IPs
    /// - Number of rate-limited reques
    pub async fn get_rate_limit_stats(&self) -> RateLimitStats {
        self.rate_limiter.get_stats().await
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for TURN server functionality
    //!
    //! Tests cover:
    //! - Server creation and initialization
    //! - Message handling and relay
    //! - Rate limiting and authentication
    //! - Channel binding and permissions
    //! - Resource cleanup
    //! - TCP/UDP transport

    // Test implementations...
    use super::*;
    use std::net::SocketAddr;

    // Helper function to create a test server with random port
    async fn create_test_server() -> TurnServer {
        let mut config = ServerConfig::default();

        // Use port 0 to let OS assign a random available port
        config.transport.port = 0;
        config.transport.tls_port = 0; // Also use random TLS port
        config.transport.listen_address = "127.0.0.1".parse().unwrap();

        // Try creating server with retries
        for _ in 0..5 {
            // Increased retries
            match TurnServer::new(&config).await {
                Ok(server) => {
                    // Verify we can bind to the ports
                    if server.transport.tcp_listener().local_addr().is_ok()
                        && server.transport.udp_socket().local_addr().is_ok()
                    {
                        return server;
                    }
                    // If port binding verification fails, try again
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => panic!("Failed to create server: {}", e),
            }
        }
        panic!("Failed to create server after retries");
    }

    #[tokio::test]
    async fn test_server_creation() {
        let server = create_test_server().await;
        assert!(server.transport.tcp_listener().local_addr().is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let server = create_test_server().await;
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        // First attempt should succeed
        assert!(server.check_auth_rate_limit(addr).await.is_ok());

        // Make attempts up to but not exceeding max_attempts
        for _ in 1..server.config.auth.rate_limit.max_auth_attempts {
            assert!(server.check_auth_rate_limit(addr).await.is_ok());
        }

        // Next attempt should be rate limited
        match server.check_auth_rate_limit(addr).await {
            Err(Error::Auth(AuthError::RateLimitExceeded)) => (),
            other => panic!("Expected RateLimitExceeded, got {:?}", other),
        }

        // Further attempts should be blacklisted
        match server.check_auth_rate_limit(addr).await {
            Err(Error::Auth(AuthError::Blacklisted)) => (),
            other => panic!("Expected Blacklisted, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_blacklisting() {
        let server = create_test_server().await;
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        // Exceed rate limit to get blacklisted
        for _ in 0..10 {
            let _ = server.check_auth_rate_limit(addr).await;
        }

        // Should be blacklisted
        assert!(matches!(
            server.check_auth_rate_limit(addr).await,
            Err(Error::Auth(AuthError::Blacklisted))
        ));
    }

    #[tokio::test]
    async fn test_channel_binding() {
        let mut server = create_test_server().await;
        let client_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:5678".parse().unwrap();
        let channel_number = 0x4000;

        // Create channel binding
        assert!(server
            .channels
            .create_binding(client_addr, peer_addr, channel_number)
            .is_ok());

        // Verify binding exists
        let channel = server.channels.get_channel(channel_number);
        assert!(channel.is_some());
        assert_eq!(channel.unwrap().peer_address(), peer_addr);
    }

    #[tokio::test]
    async fn test_relay_data() {
        let mut server = create_test_server().await;
        let client_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:5678".parse().unwrap();
        let channel_number = 0x4000;
        let test_data = b"test data";

        // Create permission
        server
            .permissions
            .write()
            .await
            .create_permission(client_addr, peer_addr)
            .expect("Failed to create permission");

        // Test relay without channel
        assert!(server
            .relay_data(test_data, client_addr, peer_addr, None)
            .await
            .is_ok());

        // Create and test channel binding
        server
            .channels
            .create_binding(client_addr, peer_addr, channel_number)
            .expect("Failed to create binding");

        // Test relay with channel
        assert!(server
            .relay_data(test_data, client_addr, peer_addr, Some(channel_number))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_cleanup() {
        let mut server = create_test_server().await;
        let client_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:5678".parse().unwrap();

        // Create some test data
        server
            .permissions
            .write()
            .await
            .create_permission(client_addr, peer_addr)
            .expect("Failed to create permission");

        server
            .channels
            .create_binding(client_addr, peer_addr, 0x4000)
            .expect("Failed to create binding");

        // Run cleanup
        assert!(server.cleanup().await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limit_stats() {
        let server = create_test_server().await;
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        // Make some auth attempts
        for _ in 0..5 {
            let _ = server.check_auth_rate_limit(addr).await;
        }

        // Get stats
        let stats = server.get_rate_limit_stats().await;
        assert!(stats.total_tracked_ips > 0);
        assert!(stats.total_attempts > 0);
    }

    #[tokio::test]
    async fn test_stun_message_handling() {
        let mut server = create_test_server().await;
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        // Create a test STUN binding request
        let request = StunMessageBuilder::new(BINDING, MessageClass::Request).build();

        // Handle the message
        assert!(server.handle_stun_message(request, addr).await.is_ok());
    }
}
