//! Error types and handling for the TURN server
//!
//! This module provides error types and conversion implementations for:
//! - STUN/TURN protocol errors
//! - Transport errors (UDP/TCP)
//! - Authentication errors
//! - Resource limit errors
//! - Configuration errors
//!
//! The error types map to appropriate STUN error codes as defined in RFC 5766.

use crate::auth;
use std::io;
use stun_rs::error::StunDecodeError;
use stun_rs::error::StunEncodeError;
use stun_rs::StunError;
use thiserror::Error;

/// The main error type for the TURN server
#[derive(Error, Debug)]
pub enum Error {
    /// I/O errors from std::io
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Transport-specific errors (UDP/TCP)
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    /// Authentication and authorization errors
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),

    /// STUN protocol errors
    #[error("STUN protocol error: {0}")]
    Stun(String),

    /// TURN protocol errors
    #[error("TURN protocol error: {0}")]
    Turn(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(String),

    /// Resource limit exceeded errors
    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),

    /// Invalid state errors
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Invalid channel number errors
    #[error("Invalid channel number")]
    InvalidChannelNumber,

    /// Unauthorized access errors
    #[error("Unauthorized access")]
    Unauthorized,
}

/// Transport-specific errors
#[derive(Error, Debug)]
pub enum TransportError {
    /// I/O errors from std::io
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Message size exceeds maximum allowed
    #[error("Message too large (max size: {max_size} bytes)")]
    MessageTooLarge { max_size: usize },

    /// Invalid message format
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),

    /// Connection errors
    #[error("Connection error: {0}")]
    ConnectionError(String),

    /// TLS errors
    #[error("TLS error: {0}")]
    TlsError(String),

    /// Connection timeout errors
    #[error("Connection timeout: {0}")]
    ConnectionTimeout(String),

    /// Connection reset errors
    #[error("Connection reset: {0}")]
    ConnectionReset(String),

    /// Invalid message framing errors
    #[error("Invalid message framing: {0}")]
    InvalidFraming(String),

    /// Too many connections error
    #[error("Too many connections")]
    TooManyConnections,
}

/// Authentication-specific errors
#[derive(Error, Debug)]
pub enum AuthError {
    /// Invalid credentials provided
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// Credentials have expired
    #[error("Expired credentials")]
    ExpiredCredentials,

    /// Required credentials missing
    #[error("Missing credentials")]
    MissingCredentials,

    /// Invalid authentication token
    #[error("Invalid authentication token")]
    InvalidToken,

    /// Invalid or expired nonce
    #[error("Invalid or expired nonce")]
    InvalidNonce,

    /// Unauthorized request
    #[error("Unauthorized request")]
    Unauthorized,

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// IP is blacklisted
    #[error("IP is blacklisted")]
    Blacklisted,

    /// IP blocked due to suspicious activity
    #[error("IP blocked due to suspicious activity")]
    SuspiciousActivity,
}

/// Result type alias for TURN server operations
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Convert the error to a STUN error code
    ///
    /// Maps internal errors to appropriate STUN error codes as defined in RFC 5766:
    /// - 400: Bad Request
    /// - 401: Unauthorized
    /// - 430: Stale Credentials
    /// - 438: Stale Nonce
    /// - 486: Allocation Quota Reached
    /// - 487: Role Conflict
    /// - 500: Server Error
    pub fn to_stun_error_code(&self) -> u16 {
        match self {
            Error::Auth(AuthError::InvalidCredentials) => 401, // Unauthorized
            Error::Auth(AuthError::ExpiredCredentials) => 430, // Stale Credentials
            Error::Auth(AuthError::InvalidNonce) => 438,       // Stale Nonce
            Error::Auth(AuthError::Unauthorized) => 401,       // Unauthorized access
            Error::Auth(_) => 400,                             // Bad Request
            Error::ResourceLimit(_) => 486,                    // Allocation Quota Reached
            Error::Transport(_) => 487,                        // Role Conflict
            Error::Turn(_) => 500,                             // Server Error
            Error::Stun(_) => 400,                             // Bad Request
            Error::Config(_) => 500,                           // Server Error
            Error::Io(_) => 500,                               // Server Error
            Error::InvalidState(_) => 500,                     // Server Error
            Error::InvalidChannelNumber => 400,                // Bad Request
            Error::Unauthorized => 401,                        // Unauthorized access
        }
    }

    /// Convert the error to a STUN error message
    pub fn to_stun_error_message(&self) -> String {
        self.to_string()
    }
}

// Error conversion implementations
impl From<StunError> for Error {
    fn from(err: StunError) -> Self {
        Error::Stun(err.to_string())
    }
}

impl From<auth::AuthError> for Error {
    fn from(err: auth::AuthError) -> Self {
        let auth_error = match err {
            auth::AuthError::InvalidCredentials => AuthError::InvalidCredentials,
            auth::AuthError::ExpiredCredentials => AuthError::ExpiredCredentials,
            auth::AuthError::MissingCredentials => AuthError::MissingCredentials,
            auth::AuthError::InvalidToken => AuthError::InvalidToken,
            auth::AuthError::InvalidNonce => AuthError::InvalidNonce,
            auth::AuthError::Unauthorized => AuthError::Unauthorized,
        };
        Error::Auth(auth_error)
    }
}

impl From<StunEncodeError> for Error {
    fn from(err: StunEncodeError) -> Self {
        Error::Stun(err.to_string())
    }
}

impl From<StunDecodeError> for Error {
    fn from(err: StunDecodeError) -> Self {
        Error::Stun(err.to_string())
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_error_conversion() {
        // Test IO error conversion
        let io_err = io::Error::new(io::ErrorKind::Other, "test error");
        let err = Error::from(io_err);
        assert!(matches!(err, Error::Io(_)));

        // Create a new IO error for next test since the first was consumed
        let io_err2 = io::Error::new(io::ErrorKind::Other, "test error");
        let transport_err = TransportError::from(io_err2);
        assert!(matches!(transport_err, TransportError::Io(_)));

        // Test transport error conversion
        let transport_err = TransportError::MessageTooLarge { max_size: 1024 };
        let err = Error::from(transport_err);
        assert!(matches!(err, Error::Transport(_)));

        // Test auth error conversion
        let auth_err = AuthError::InvalidCredentials;
        let err = Error::from(auth_err);
        assert!(matches!(err, Error::Auth(_)));

        // Test STUN error through string conversion
        let err = Error::Stun("buffer too small".into());
        assert!(matches!(err, Error::Stun(_)));
        assert_eq!(err.to_string(), "STUN protocol error: buffer too small");
    }

    #[test]
    fn test_error_codes() {
        // Test auth error codes
        assert_eq!(
            Error::Auth(AuthError::InvalidCredentials).to_stun_error_code(),
            401
        );
        assert_eq!(
            Error::Auth(AuthError::ExpiredCredentials).to_stun_error_code(),
            430
        );
        assert_eq!(
            Error::Auth(AuthError::InvalidNonce).to_stun_error_code(),
            438
        );
        assert_eq!(
            Error::Auth(AuthError::Unauthorized).to_stun_error_code(),
            401
        );

        // Test resource limit error codes
        assert_eq!(
            Error::ResourceLimit("test".into()).to_stun_error_code(),
            486
        );

        // Test transport error codes
        assert_eq!(
            Error::Transport(TransportError::TooManyConnections).to_stun_error_code(),
            487
        );

        // Test other error codes
        assert_eq!(Error::Turn("test".into()).to_stun_error_code(), 500);
        assert_eq!(Error::Stun("test".into()).to_stun_error_code(), 400);
        assert_eq!(Error::Config("test".into()).to_stun_error_code(), 500);
        assert_eq!(Error::InvalidState("test".into()).to_stun_error_code(), 500);
        assert_eq!(Error::InvalidChannelNumber.to_stun_error_code(), 400);
        assert_eq!(Error::Unauthorized.to_stun_error_code(), 401);
    }

    #[test]
    fn test_error_messages() {
        // Test auth error messages
        let err = Error::Auth(AuthError::InvalidCredentials);
        assert_eq!(err.to_string(), "Authentication error: Invalid credentials");

        // Test transport error messages
        let err = Error::Transport(TransportError::MessageTooLarge { max_size: 1024 });
        assert_eq!(
            err.to_string(),
            "Transport error: Message too large (max size: 1024 bytes)"
        );

        // Test connection errors
        let err = Error::Transport(TransportError::ConnectionError("connection reset".into()));
        assert_eq!(
            err.to_string(),
            "Transport error: Connection error: connection reset"
        );

        // Test resource limit errors
        let err = Error::ResourceLimit("max connections reached".into());
        assert_eq!(
            err.to_string(),
            "Resource limit exceeded: max connections reached"
        );

        // Test invalid state errors
        let err = Error::InvalidState("bad state".into());
        assert_eq!(err.to_string(), "Invalid state: bad state");
    }

    #[test]
    fn test_transport_errors() {
        // Test IO error conversion
        let io_err = io::Error::new(io::ErrorKind::Other, "test error");
        let err = TransportError::from(io_err);
        assert!(matches!(err, TransportError::Io(_)));

        // Test message size error
        let err = TransportError::MessageTooLarge { max_size: 1024 };
        assert!(err.to_string().contains("1024"));

        // Test connection errors
        let err = TransportError::ConnectionTimeout("timeout".into());
        assert!(err.to_string().contains("timeout"));

        let err = TransportError::ConnectionReset("reset".into());
        assert!(err.to_string().contains("reset"));

        let err = TransportError::InvalidFraming("bad frame".into());
        assert!(err.to_string().contains("bad frame"));
        assert!(err.to_string().contains("Invalid message framing"));
    }

    #[test]
    fn test_auth_errors() {
        // Test all auth error variants
        let err = AuthError::InvalidCredentials;
        assert_eq!(err.to_string(), "Invalid credentials");

        let err = AuthError::ExpiredCredentials;
        assert_eq!(err.to_string(), "Expired credentials");

        let err = AuthError::MissingCredentials;
        assert_eq!(err.to_string(), "Missing credentials");

        let err = AuthError::InvalidToken;
        assert_eq!(err.to_string(), "Invalid authentication token");

        let err = AuthError::InvalidNonce;
        assert_eq!(err.to_string(), "Invalid or expired nonce");

        let err = AuthError::Unauthorized;
        assert_eq!(err.to_string(), "Unauthorized request");

        let err = AuthError::RateLimitExceeded;
        assert_eq!(err.to_string(), "Rate limit exceeded");

        let err = AuthError::Blacklisted;
        assert_eq!(err.to_string(), "IP is blacklisted");

        let err = AuthError::SuspiciousActivity;
        assert_eq!(err.to_string(), "IP blocked due to suspicious activity");
    }

    #[test]
    fn test_error_display() {
        // Test Display implementation for Error
        let err = Error::Turn("test error".into());
        assert_eq!(format!("{}", err), "TURN protocol error: test error");

        // Test Debug implementation
        assert_eq!(format!("{:?}", err), "Turn(\"test error\")");

        // Test Display for TransportError
        let err = TransportError::TooManyConnections;
        assert_eq!(format!("{}", err), "Too many connections");

        // Test Display for AuthError
        let err = AuthError::InvalidCredentials;
        assert_eq!(format!("{}", err), "Invalid credentials");
    }
}
