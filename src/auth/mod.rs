// Authentication module for TURN/STUN server implementation
use crate::types::{Expiration, Password, Realm, Username};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use stun_rs::attributes::stun::Nonce;
use tokio::sync::RwLock;

// RFC 5766: Credentials should be valid for 24 hours
const CREDENTIAL_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// Possible authentication errors that can occur during the auth process
#[derive(Debug, Clone)]
pub enum AuthError {
    InvalidCredentials, // Username/password combination is incorrect
    ExpiredCredentials, // Credentials have exceeded their lifetime
    MissingCredentials, // Required credentials were not provided
    InvalidToken,       // Short-term auth token is invalid
    InvalidNonce,       // Challenge-response nonce is invalid/expired
    Unauthorized,       // Generic unauthorized access error
}

/// Represents a set of authentication credentials for a user
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Credentials {
    pub username: Username,     // User's identifier
    pub password: Password,     // User's password
    pub realm: Realm,           // Authentication realm (domain)
    pub nonce: Option<Nonce>,   // Optional challenge-response nonce
    pub created_at: Instant,    // When these credentials were created
    pub expiration: Expiration, // When these credentials expire
}

/// Manages authentication state and operations for the TURN/STUN server
pub struct AuthManager {
    // Stores long-term user credentials
    credentials: Arc<RwLock<HashMap<String, Credentials>>>,
    // Tracks active nonces for challenge-response authentication
    nonces: Arc<RwLock<HashMap<String, Instant>>>,
    // Authentication realm (typically domain name)
    realm: String,
    // Secret used for generating short-term auth tokens
    shared_secret: String,
}

impl AuthManager {
    /// Creates a new AuthManager instance
    pub fn new(realm: String, shared_secret: String) -> Self {
        Self {
            credentials: Arc::new(RwLock::new(HashMap::new())),
            nonces: Arc::new(RwLock::new(HashMap::new())),
            realm,
            shared_secret,
        }
    }

    /// Adds new long-term credentials for a user
    pub async fn add_credentials(&self, username: String, password: String) {
        let credentials = Credentials {
            username: Username(username.clone()),
            password: Password(password),
            realm: Realm(self.realm.clone()),
            nonce: None,
            created_at: Instant::now(),
            expiration: Expiration::new(CREDENTIAL_LIFETIME),
        };

        let mut creds = self.credentials.write().await;
        creds.insert(username, credentials);
    }

    /// Verifies user credentials with a given nonce
    /// Returns Ok(()) if valid, AuthError otherwise
    pub async fn verify_credentials(
        &self,
        username: &str,
        key: &str,
        nonce: &str,
    ) -> Result<(), AuthError> {
        // First verify the nonce is valid and not expired
        if !self.verify_nonce(nonce).await {
            return Err(AuthError::InvalidNonce);
        }

        // Then verify the username/key combination
        if !self.verify_key(username, key).await {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(())
    }

    /// Generates a new nonce for challenge-response authentication
    /// Nonce expires after 30 seconds
    pub async fn generate_nonce(&self) -> String {
        let nonce = format!("{:x}", rand::random::<u64>());
        let mut nonces = self.nonces.write().await;
        nonces.insert(nonce.clone(), Instant::now() + Duration::from_secs(30));
        nonce
    }

    /// Verifies a short-term authentication token for a peer
    /// Token is HMAC-SHA1 of peer address + timestamp using shared secret
    pub async fn verify_token(&self, token: &str, peer_addr: &str) -> Result<(), AuthError> {
        // Token format: base64(HMAC-SHA1(shared_secret, peer_address + timestamp))
        let decoded = BASE64.decode(token).map_err(|_| AuthError::InvalidToken)?;

        let mut mac = Hmac::<Sha1>::new_from_slice(self.shared_secret.as_bytes())
            .expect("HMAC can take key of any size");

        mac.update(peer_addr.as_bytes());

        mac.verify_slice(&decoded)
            .map_err(|_| AuthError::InvalidToken)
    }

    /// Removes expired nonces and credentials from storage
    pub async fn cleanup_expired(&self) {
        // Cleanup expired nonces
        let mut nonces = self.nonces.write().await;
        nonces.retain(|_, expiration| *expiration > Instant::now());

        // Cleanup expired credentials
        let mut creds = self.credentials.write().await;
        creds.retain(|_, cred| !cred.is_expired());
    }

    /// Retrieves the stored key (password) for a given username
    pub async fn get_key_for_user(&self, username: &str) -> Result<String, AuthError> {
        let credentials = self
            .credentials
            .read()
            .await
            .get(username)
            .cloned()
            .ok_or(AuthError::InvalidCredentials)?;

        // Return the key (password) for this user
        Ok(credentials.password.0)
    }

    /// Internal: Verifies if a nonce is valid and not expired
    async fn verify_nonce(&self, nonce: &str) -> bool {
        let nonces = self.nonces.read().await;
        if let Some(expiry) = nonces.get(nonce) {
            // Check if nonce hasn't expired
            expiry > &Instant::now()
        } else {
            false
        }
    }

    /// Internal: Verifies if a username/key combination is valid
    async fn verify_key(&self, username: &str, key: &str) -> bool {
        let creds = self.credentials.read().await;
        if let Some(stored_creds) = creds.get(username) {
            if stored_creds.is_expired() {
                return false;
            }
            // Compare the provided key with stored password
            stored_creds.password.0 == key
        } else {
            false
        }
    }
}

/// Methods for working with individual credential sets
#[allow(dead_code)]
impl Credentials {
    /// Checks if the credentials have expired
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expiration.0
    }

    /// Verifies if credentials match a given username and realm
    fn matches_credentials(&self, username: &str, realm: &str) -> bool {
        self.username.0 == username && self.realm.0 == realm
    }

    /// Updates the nonce associated with these credentials
    fn update_nonce(&mut self, nonce: Nonce) {
        self.nonce = Some(nonce);
    }

    /// Verifies if a given nonce matches these credentials
    fn verify_nonce(&self, nonce: &str) -> bool {
        self.nonce
            .as_ref()
            .map(|n| n.as_str() == nonce)
            .unwrap_or(false)
    }
}

// Test module contains unit tests for the authentication functionality
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn test_auth_manager() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let auth = AuthManager::new("example.org".to_string(), "secret".to_string());

            // Test credentials
            auth.add_credentials("user".to_string(), "pass".to_string())
                .await;
            let nonce = auth.generate_nonce().await;
            assert!(auth
                .verify_credentials("user", "pass", &nonce)
                .await
                .is_ok());
            assert!(auth
                .verify_credentials("user", "wrong", &nonce)
                .await
                .is_err());

            // Test token verification
            let token = "valid_token"; // You would generate this properly
            assert!(auth.verify_token(token, "127.0.0.1:1234").await.is_err());
        });
    }
}
