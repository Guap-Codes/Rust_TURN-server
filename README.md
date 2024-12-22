# TURN Server in Rust

A high-performance TURN (Traversal Using Relays around NAT) server implementation in Rust, following RFC 5766.

## Features

- **Full TURN Protocol Support**
  - UDP and TCP relay capabilities
  - Channel binding for efficient data relay
  - Permission-based access control
  - IPv4 and IPv6 support

- **Security**
  - Authentication with long-term and short-term credentials
  - Rate limiting and IP blacklisting
  - Nonce-based replay protection
  - Message integrity validation

- **Performance**
  - Asynchronous I/O with Tokio
  - Efficient memory management
  - Connection pooling
  - Configurable resource limits

- **Monitoring & Management**
  - Detailed logging
  - Rate limiting statistics
  - Resource usage tracking
  - Automatic cleanup of expired resources

## Installation

Add this to your `Cargo.toml`: 

```toml
[dependencies]
turn-server-rs = { git = "https://github.com/guap-codes/rust_turn-server" }
```

## Quick Start

```rust
use turn_server_rs::{ServerConfig, TurnServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    turn_server_rs::init_logger();

    // Create default config or load from file
    let config = ServerConfig::default();
    
    // Create and start server
    let mut server = TurnServer::new(&config).await?;
    server.run().await?;

    Ok(())
}
```

## Configuration

The server can be configured via a JSON configuration file:

```json
{
    "transport": {
        "listen_address": "0.0.0.0",
        "port": 3478,
        "tls_port": 5349,
        "max_connections": 1000
    },
    "auth": {
        "realm": "turn.example.com",
        "shared_secret": "your-secret-key",
        "rate_limit": {
            "max_auth_attempts": 5,
            "rate_limit_window": 60,
            "blacklist_duration": 3600
        }
    }
}
```

## Documentation

For detailed documentation, run:
```bash
cargo doc --open
```

## Testing

Run the test suite:
```bash
cargo test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## References

- [RFC 5766: TURN Protocol](https://datatracker.ietf.org/doc/html/rfc5766)
- [RFC 8656: TURN UDP/TCP/TLS](https://datatracker.ietf.org/doc/html/rfc8656)
- [RFC 6062: TURN TCP](https://datatracker.ietf.org/doc/html/rfc6062)

## Acknowledgments

- Thanks to the Rust community
- Built with [stun-rs](https://crates.io/crates/stun-rs) for STUN protocol support
- Uses [tokio](https://tokio.rs/) for async runtime

## Status

This project is in active development. While it implements the core TURN functionality, some advanced features are still being added.

Current limitations:
- Limited TLS support
- No DTLS support yet
- Basic monitoring capabilities

## Contact

For questions and support:
- Open an issue
