use crate::error::{Error, Result, TransportError};
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use std::io;
/// Transport module for handling UDP and TCP connections in a STUN/TURN server
///
/// This module provides functionality for:
/// - Managing UDP and TCP connections
/// - Handling STUN message framing
/// - Connection lifecycle management
/// - Message relay capabilities
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use stun_rs::methods::BINDING;
use stun_rs::{
    MessageClass, MessageDecoderBuilder, MessageEncoderBuilder, StunMessage, StunMessageBuilder,
    MAGIC_COOKIE,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

// Constants for TCP connection management
#[allow(dead_code)]
/// Timeout duration for idle TCP connections (60 seconds)
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
#[allow(dead_code)]
/// Maximum time to wait for TCP connection establishment (30 seconds)
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
#[allow(dead_code)]
/// Interval for sending TCP keepalive messages (15 seconds)
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
#[allow(dead_code)]
/// Maximum number of concurrent TCP connections allowed
const MAX_TCP_CONNECTIONS: usize = 1000;

// Maximum size for STUN/TURN messages
const MAX_MESSAGE_SIZE: usize = 65535;

/// Main transport manager handling both UDP and TCP connections
#[derive(Clone)]
pub struct TransportManager {
    /// Shared UDP socket for datagram communication
    udp_socket: Arc<UdpSocket>,
    /// TCP listener for accepting new connections
    tcp_listener: Arc<TcpListener>,
    /// Thread-safe collection of active TCP connections
    tcp_connections: Arc<Mutex<Vec<TcpConnection>>>,
}

/// Represents a single TCP connection with its associated state
struct TcpConnection {
    /// The TCP stream for this connection
    stream: TcpStream,
    /// Remote peer's address
    peer_addr: SocketAddr,
    /// Buffer for incoming data
    buffer: BytesMut,
    /// Timestamp of last activity on this connection
    last_activity: Instant,
}

impl TransportManager {
    /// Creates a new TransportManager bound to the specified address
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let udp_socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let tcp_listener = Arc::new(TcpListener::bind(bind_addr).await?);

        Ok(Self {
            udp_socket,
            tcp_listener,
            tcp_connections: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Sends UDP data to the specified target address
    pub async fn send_udp(&self, data: &[u8], target: SocketAddr) -> Result<usize> {
        if data.len() > MAX_MESSAGE_SIZE {
            return Err(Error::Transport(TransportError::MessageTooLarge {
                max_size: MAX_MESSAGE_SIZE,
            }));
        }
        Ok(self.udp_socket.send_to(data, target).await?)
    }

    /// Receives UDP data and returns the data along with sender's address
    pub async fn receive_udp(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
        let (len, addr) = self.udp_socket.recv_from(&mut buf).await?;
        buf.truncate(len);
        Ok((buf, addr))
    }

    /// Accepts a new TCP connection
    pub async fn accept_tcp(&self) -> Result<()> {
        let (stream, peer_addr) = self.tcp_listener.accept().await?;
        stream.set_nodelay(true)?; // Optimize TCP performance

        let connection = TcpConnection {
            stream,
            peer_addr,
            buffer: BytesMut::with_capacity(MAX_MESSAGE_SIZE),
            last_activity: Instant::now(),
        };

        let mut connections = self.tcp_connections.lock().await;
        connections.push(connection);
        Ok(())
    }

    /// Sends data over TCP to the specified target
    pub async fn send_tcp(&self, data: &[u8], target: SocketAddr) -> Result<()> {
        let mut connections = self.tcp_connections.lock().await;
        if let Some(conn) = connections.iter_mut().find(|c| c.peer_addr == target) {
            conn.stream.write_all(data).await?;
            conn.stream.flush().await?;
            Ok(())
        } else {
            // Try to establish new connection if none exists
            let stream = TcpStream::connect(target).await?;
            stream.set_nodelay(true)?;

            let mut connection = TcpConnection {
                stream,
                peer_addr: target,
                buffer: BytesMut::with_capacity(MAX_MESSAGE_SIZE),
                last_activity: Instant::now(),
            };

            connection.stream.write_all(data).await?;
            connection.stream.flush().await?;
            connections.push(connection);
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn udp_socket(&self) -> &UdpSocket {
        &self.udp_socket
    }

    pub fn tcp_listener(&self) -> &TcpListener {
        &self.tcp_listener
    }

    /// Receives data from all active TCP connections
    pub async fn receive_tcp(&self) -> Result<Vec<(Vec<u8>, SocketAddr)>> {
        let mut messages = Vec::new();
        let mut connections = self.tcp_connections.lock().await;

        for conn in connections.iter_mut() {
            let mut buf = vec![0u8; MAX_MESSAGE_SIZE];
            match conn.stream.try_read(&mut buf) {
                Ok(0) => continue, // Connection closed
                Ok(n) => {
                    conn.buffer.put_slice(&buf[..n]);
                    // Process complete messages
                    while conn.buffer.len() >= 2 {
                        // STUN/TURN message length is in bytes 2-3
                        let msg_len = ((conn.buffer[2] as usize) << 8) | (conn.buffer[3] as usize);
                        let total_len = msg_len + 20; // 20-byte header

                        if conn.buffer.len() >= total_len {
                            let message = conn.buffer.split_to(total_len).freeze();
                            messages.push((message.to_vec(), conn.peer_addr));
                        } else {
                            break;
                        }
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    return Err(Error::Transport(TransportError::ConnectionError(
                        e.to_string(),
                    )))
                }
            }
        }

        // Remove closed connections
        connections.retain(|conn| !conn.buffer.is_empty());

        Ok(messages)
    }

    /// Removes inactive TCP connections that have exceeded the idle timeout
    pub async fn cleanup_inactive_connections(&self) -> Result<()> {
        let mut connections = self.tcp_connections.lock().await;
        let now = Instant::now();

        connections.retain(|conn| {
            if now.duration_since(conn.last_activity) > TCP_IDLE_TIMEOUT {
                false
            } else {
                true
            }
        });
        Ok(())
    }

    /// Sends keepalive messages to connections that are near timeout
    pub async fn handle_connection_timeout(&self) -> Result<()> {
        let mut connections = self.tcp_connections.lock().await;
        let now = Instant::now();

        for conn in connections.iter_mut() {
            if now.duration_since(conn.last_activity) > TCP_CONNECT_TIMEOUT {
                conn.send_keepalive().await?;
            }
        }
        Ok(())
    }

    /// Checks if there's an active TCP connection to the specified address
    pub async fn is_tcp_connection(&self, addr: &SocketAddr) -> bool {
        let connections = self.tcp_connections.lock().await;
        connections.iter().any(|conn| &conn.peer_addr == addr)
    }

    /// Relays TCP data from one peer to another
    pub async fn relay_tcp_data(
        &self,
        data: &[u8],
        _from: SocketAddr,
        to: SocketAddr,
    ) -> Result<()> {
        // First check if we have an active connection to the target
        let mut connections = self.tcp_connections.lock().await;

        // Try to find existing connection
        if let Some(conn) = connections.iter_mut().find(|c| c.peer_addr == to) {
            // Update last activity time
            conn.last_activity = Instant::now();

            // Send data through existing connection
            conn.stream.write_all(data).await?;
            conn.stream.flush().await?;
            return Ok(());
        }

        // No existing connection, try to establish new one
        let stream = TcpStream::connect(to).await?;
        stream.set_nodelay(true)?;

        let mut connection = TcpConnection {
            stream,
            peer_addr: to,
            buffer: BytesMut::with_capacity(MAX_MESSAGE_SIZE),
            last_activity: Instant::now(),
        };

        // Send data through new connection
        connection.stream.write_all(data).await?;
        connection.stream.flush().await?;

        // Store connection for future use
        connections.push(connection);
        Ok(())
    }

    /// Processes incoming TCP data and handles STUN messages
    pub async fn handle_incoming_tcp(&self, data: &[u8], from: SocketAddr) -> Result<()> {
        // Find the allocation for this client
        let mut connections = self.tcp_connections.lock().await;
        if let Some(conn) = connections.iter_mut().find(|c| c.peer_addr == from) {
            // Update last activity
            conn.last_activity = Instant::now();

            // Process data through connection
            conn.buffer.extend_from_slice(data);

            // Handle any complete messages
            while let Some(msg) = conn.parse_stun_message()? {
                // Process STUN message
                conn.handle_message(msg)?;
            }
        }
        Ok(())
    }
}

#[allow(dead_code)]
impl TcpConnection {
    /// Reads a message from the TCP stream
    async fn read_message(&mut self) -> Result<Option<Bytes>> {
        let mut tmp_buf = [0u8; 1024];

        match self.stream.try_read(&mut tmp_buf) {
            Ok(0) => Ok(None), // Connection closed
            Ok(n) => {
                self.buffer.put_slice(&tmp_buf[..n]);
                // Here you would implement message framing logic
                // For now, we'll just return the whole buffer
                let bytes = self.buffer.split().freeze();
                Ok(Some(bytes))
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(Error::Transport(TransportError::Io(e))),
        }
    }

    /// Parses a STUN message from the buffer
    fn parse_stun_message(&mut self) -> Result<Option<StunMessage>> {
        // STUN message structure:
        // 0                   1                   2                   3
        // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |0 0|     STUN Message Type     |         Message Length          |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                         Magic Cookie                             |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |                                                                 |
        // |                     Transaction ID (96 bits)                    |
        // |                                                                 |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        if self.buffer.len() < 20 {
            return Ok(None); // Need more data
        }

        // Check magic cookie
        let magic_cookie = &self.buffer[4..8];
        let expected_cookie = MAGIC_COOKIE.as_u32().to_be_bytes();
        if magic_cookie != expected_cookie {
            return Err(Error::Transport(TransportError::InvalidMessage(
                "Invalid magic cookie".into(),
            )));
        }

        // Get message length
        let length = BigEndian::read_u16(&self.buffer[2..4]) as usize;
        let total_length = 20 + length; // Header + body

        if self.buffer.len() < total_length {
            return Ok(None); // Need more data
        }

        // Extract and parse message
        let message_data = self.buffer.split_to(total_length);
        let decoder = MessageDecoderBuilder::default().build();
        let (message, _) = decoder.decode(&message_data)?;

        Ok(Some(message))
    }

    /// Handles message fragmentation and reassembly
    fn handle_fragmentation(&mut self) -> Result<()> {
        while let Some(msg) = self.parse_stun_message()? {
            // Process complete message
            self.handle_message(msg)?;
        }
        Ok(())
    }

    /// Sends a keepalive STUN binding indication
    async fn send_keepalive(&mut self) -> Result<()> {
        // Send STUN binding indication as keepalive
        let message = StunMessageBuilder::new(BINDING, MessageClass::Indication).build();

        let encoder = MessageEncoderBuilder::default().build();
        let mut buf = vec![0; 2048];
        let size = encoder.encode(&mut buf, &message)?;

        self.stream.write_all(&buf[..size]).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Processes a complete STUN message
    fn handle_message(&mut self, msg: StunMessage) -> Result<()> {
        // Update last activity time
        self.last_activity = Instant::now();

        // For now, just log the message type
        log::debug!(
            "Received STUN message: {:?} from {}",
            msg.class(),
            self.peer_addr
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    // Helper function to create test transport manager with random ports
    async fn create_test_transport() -> TransportManager {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap(); // Port 0 for random assignment

        // Try creating transport with retries
        for _ in 0..3 {
            match TransportManager::new(addr).await {
                Ok(transport) => return transport,
                Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Err(e) => panic!("Failed to create transport: {}", e),
            }
        }
        panic!("Failed to create transport after retries");
    }

    #[tokio::test]
    async fn test_transport_creation() {
        let transport = create_test_transport().await;
        assert!(transport.udp_socket().local_addr().is_ok());
        assert!(transport.tcp_listener().local_addr().is_ok());
    }

    #[tokio::test]
    async fn test_udp_send_receive() {
        let transport = create_test_transport().await;
        let test_data = b"test message";

        // Create a test UDP client
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = transport.udp_socket().local_addr().unwrap();

        // Send data to server
        client.send_to(test_data, server_addr).await.unwrap();

        // Server should receive the data
        let (data, addr) = transport.receive_udp().await.unwrap();
        assert_eq!(&data, test_data);
        assert_eq!(addr, client.local_addr().unwrap());

        // Server sends response
        transport.send_udp(test_data, addr).await.unwrap();

        // Client should receive response
        let mut buf = vec![0u8; 1024];
        let (len, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], test_data);
    }

    #[tokio::test]
    async fn test_tcp_connection() {
        let transport = create_test_transport().await;
        let server_addr = transport.tcp_listener().local_addr().unwrap();

        // Accept connections in background
        let transport_clone = transport.clone();
        let accept_handle = tokio::spawn(async move {
            transport_clone.accept_tcp().await.unwrap();
        });

        // Give time for server to start accepting
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connect client
        let mut client = TcpStream::connect(server_addr).await.unwrap();

        // Give time for connection to be established
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Send data from client with proper STUN message framing
        let test_data = b"test message";
        let mut framed_data = Vec::new();

        // Add STUN message header (20 bytes)
        framed_data.extend_from_slice(&[0x00, 0x01]); // Message Type
        framed_data.extend_from_slice(&[(test_data.len() >> 8) as u8, test_data.len() as u8]); // Message Length
        framed_data.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // Magic Cookie
        framed_data.extend_from_slice(&[0; 12]); // Transaction ID

        // Add message body
        framed_data.extend_from_slice(test_data);

        client.write_all(&framed_data).await.unwrap();
        client.flush().await.unwrap();

        // Give time for data to be received and processed
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Server should receive data
        let messages = transport.receive_tcp().await.unwrap();
        assert!(!messages.is_empty(), "No messages received");
        assert_eq!(
            &messages[0].0, &framed_data,
            "Received data doesn't match sent data"
        );

        // Clean up
        accept_handle.abort();
    }

    #[tokio::test]
    async fn test_tcp_connection_management() {
        let transport = create_test_transport().await;
        let server_addr = transport.tcp_listener().local_addr().unwrap();

        // Accept connections in background
        let transport_clone = transport.clone();
        tokio::spawn(async move {
            transport_clone.accept_tcp().await.unwrap();
        });

        // Connect client and get its address
        let client = TcpStream::connect(server_addr).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Test connection tracking with client's address
        assert!(transport.is_tcp_connection(&client_addr).await);

        // Test cleanup
        assert!(transport.cleanup_inactive_connections().await.is_ok());
        assert!(transport.handle_connection_timeout().await.is_ok());
    }

    #[tokio::test]
    async fn test_message_size_limits() {
        let transport = create_test_transport().await;
        let addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        // Try to send oversized message
        let large_data = vec![0u8; MAX_MESSAGE_SIZE + 1];
        let result = transport.send_udp(&large_data, addr).await;
        assert!(matches!(
            result,
            Err(Error::Transport(TransportError::MessageTooLarge { .. }))
        ));
    }

    #[tokio::test]
    async fn test_tcp_relay() {
        let transport = create_test_transport().await;
        let from_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let to_addr: SocketAddr = "127.0.0.1:5678".parse().unwrap();
        let test_data = b"test relay data";

        // Test relay (should create new connection)
        let result = transport
            .relay_tcp_data(test_data, from_addr, to_addr)
            .await;
        assert!(result.is_err()); // Should fail since no real peer exists

        // Test connection tracking
        assert!(!transport.is_tcp_connection(&to_addr).await);
    }

    #[tokio::test]
    async fn test_handle_incoming_tcp() {
        let transport = create_test_transport().await;
        let client_addr: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let test_data = b"test incoming data";

        // Handle incoming data (should be handled gracefully even without connection)
        let result = transport.handle_incoming_tcp(test_data, client_addr).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_connection_cleanup() {
        let transport = create_test_transport().await;

        // Run cleanup operations
        assert!(transport.cleanup_inactive_connections().await.is_ok());
        assert!(transport.handle_connection_timeout().await.is_ok());

        // Verify no active connections
        let connections = transport.tcp_connections.lock().await;
        assert!(connections.is_empty());
    }
}
