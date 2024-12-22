//! Rate limiting module for TURN server
//!
//! This module implements rate limiting functionality to prevent abuse:
//! - Tracks authentication attempts per IP address
//! - Implements sliding window rate limiting
//! - Provides IP blacklisting for repeat offenders
//! - Collects rate limiting statistics
//! - Handles cleanup of expired rate limit data

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Statistics about rate limiting behavior
#[derive(Debug)]
pub struct RateLimitStats {
    /// Total number of IP addresses being tracked
    pub total_tracked_ips: usize,

    /// Number of currently blacklisted IPs
    pub blacklisted_ips: usize,

    /// Number of IPs that have exceeded rate limits
    pub rate_limited_ips: usize,

    /// Total number of authentication attempts
    pub total_attempts: u64,

    /// Number of blocked authentication attempts
    pub blocked_attempts: u64,
}

/// Rate limiter for controlling authentication attempts
pub struct RateLimiter {
    /// Maps IP addresses to their authentication attempts
    attempts: RwLock<HashMap<SocketAddr, Vec<Instant>>>,

    /// Maps blacklisted IPs to their expiration time
    blacklist: RwLock<HashMap<SocketAddr, Instant>>,

    /// Maximum attempts allowed within the time window
    max_attempts: usize,

    /// Time window for rate limiting
    window: Duration,

    /// Duration to blacklist IPs that exceed rate limits
    blacklist_duration: Duration,
}

impl RateLimiter {
    /// Creates a new rate limiter
    ///
    /// # Arguments
    /// * `max_attempts` - Maximum allowed attempts within the time window
    /// * `window` - Time window for rate limiting
    /// * `blacklist_duration` - How long to blacklist IPs that exceed limits
    pub fn new(max_attempts: usize, window: Duration, blacklist_duration: Duration) -> Self {
        Self {
            attempts: RwLock::new(HashMap::new()),
            blacklist: RwLock::new(HashMap::new()),
            max_attempts,
            window,
            blacklist_duration,
        }
    }

    /// Checks if an IP address should be rate limited
    ///
    /// # Arguments
    /// * `addr` - The IP address to check
    ///
    /// # Returns
    /// * `true` if the attempt is allowed
    /// * `false` if the attempt should be blocked
    pub async fn check_rate_limit(&self, addr: SocketAddr) -> bool {
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();

        // Get or create attempt history for this IP
        let history = attempts.entry(addr).or_insert_with(Vec::new);

        // Remove attempts outside the window
        history.retain(|&time| now.duration_since(time) <= self.window);

        // Check if under limit
        if history.len() >= self.max_attempts {
            log::warn!(
                "Rate limit exceeded for {}: {} attempts in {:?}",
                addr,
                history.len(),
                self.window
            );

            // Add to blacklist when rate limit is exceeded
            let mut blacklist = self.blacklist.write().await;
            blacklist.insert(addr, Instant::now() + self.blacklist_duration);

            // Don't add the attempt if we're over limit
            return false;
        }

        // Add new attempt
        history.push(now);
        true
    }

    /// Removes expired rate limit data
    pub async fn cleanup(&self) {
        let mut attempts = self.attempts.write().await;
        let mut blacklist = self.blacklist.write().await;
        let now = Instant::now();

        // Remove expired attempts
        attempts.retain(|_, history| {
            history.retain(|&time| now.duration_since(time) <= self.window);
            !history.is_empty()
        });

        // Remove expired blacklist entries
        blacklist.retain(|_, expiry| now < *expiry);
    }

    /// Checks if an IP address is blacklisted
    ///
    /// # Arguments
    /// * `addr` - The IP address to check
    ///
    /// # Returns
    /// * `true` if the IP is blacklisted
    /// * `false` if the IP is not blacklisted
    pub async fn is_blacklisted(&self, addr: SocketAddr) -> bool {
        let blacklist = self.blacklist.read().await;
        if let Some(expiry) = blacklist.get(&addr) {
            if Instant::now() < *expiry {
                return true;
            }
        }
        false
    }

    /// Gets current rate limiting statistics
    ///
    /// Returns statistics about:
    /// - Total tracked IPs
    /// - Blacklisted IPs
    /// - Rate limited IPs  
    /// - Total attempts
    /// - Blocked attempts
    pub async fn get_stats(&self) -> RateLimitStats {
        let attempts = self.attempts.read().await;
        let blacklist = self.blacklist.read().await;

        // Count all attempts
        let total_attempts: u64 = attempts.values().map(|v| v.len() as u64).sum();

        // Count rate limited IPs and blocked attempts
        let mut rate_limited_ips = 0;
        let mut blocked_attempts = 0;

        for history in attempts.values() {
            if history.len() >= self.max_attempts {
                rate_limited_ips += 1;
                blocked_attempts += 1; // Count one blocked attempt per rate limited IP
            }
        }

        RateLimitStats {
            total_tracked_ips: attempts.len(),
            blacklisted_ips: blacklist.len(),
            rate_limited_ips,
            total_attempts,
            blocked_attempts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_rate_limit_basic() {
        let limiter = RateLimiter::new(
            3,                      // max 3 attempts
            Duration::from_secs(1), // 1 second window
            Duration::from_secs(5), // 5 second blacklist
        );

        let addr = "127.0.0.1:1234".parse().unwrap();

        // First three attempts should succeed
        assert!(limiter.check_rate_limit(addr).await);
        assert!(limiter.check_rate_limit(addr).await);
        assert!(limiter.check_rate_limit(addr).await);

        // Fourth attempt should fail
        assert!(!limiter.check_rate_limit(addr).await);

        // IP should be blacklisted
        assert!(limiter.is_blacklisted(addr).await);
    }

    #[tokio::test]
    async fn test_rate_limit_window() {
        let limiter = RateLimiter::new(
            2,                          // max 2 attempts
            Duration::from_millis(100), // 100ms window
            Duration::from_secs(1),     // 1 second blacklist
        );

        let addr = "127.0.0.1:1234".parse().unwrap();

        // First two attempts succeed
        assert!(limiter.check_rate_limit(addr).await);
        assert!(limiter.check_rate_limit(addr).await);

        // Third attempt fails
        assert!(!limiter.check_rate_limit(addr).await);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be able to attempt again
        assert!(limiter.check_rate_limit(addr).await);
    }

    #[tokio::test]
    async fn test_blacklist_expiry() {
        let limiter = RateLimiter::new(
            2,                          // max 2 attempts
            Duration::from_millis(100), // 100ms window
            Duration::from_millis(200), // 200ms blacklist
        );

        let addr = "127.0.0.1:1234".parse().unwrap();

        // Exceed limit to get blacklisted
        assert!(limiter.check_rate_limit(addr).await);
        assert!(limiter.check_rate_limit(addr).await);
        assert!(!limiter.check_rate_limit(addr).await);

        // Should be blacklisted
        assert!(limiter.is_blacklisted(addr).await);

        // Wait for blacklist to expire
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Should no longer be blacklisted
        assert!(!limiter.is_blacklisted(addr).await);
    }

    #[tokio::test]
    async fn test_cleanup() {
        let limiter = RateLimiter::new(
            2,                          // max 2 attempts
            Duration::from_millis(100), // 100ms window
            Duration::from_millis(200), // 200ms blacklist
        );

        let addr1 = "127.0.0.1:1234".parse().unwrap();
        let addr2 = "127.0.0.1:1235".parse().unwrap();

        // Add some attempts
        limiter.check_rate_limit(addr1).await;
        limiter.check_rate_limit(addr2).await;

        // Get initial stats
        let stats = limiter.get_stats().await;
        assert_eq!(stats.total_tracked_ips, 2);
        assert_eq!(stats.total_attempts, 2);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Cleanup should remove expired entries
        limiter.cleanup().await;

        // Check stats after cleanup
        let stats = limiter.get_stats().await;
        assert_eq!(stats.total_tracked_ips, 0);
        assert_eq!(stats.total_attempts, 0);
    }

    #[tokio::test]
    async fn test_stats() {
        let limiter = RateLimiter::new(
            2,                      // max 2 attempts
            Duration::from_secs(1), // 1 second window
            Duration::from_secs(5), // 5 second blacklist
        );

        let addr1 = "127.0.0.1:1234".parse().unwrap();
        let addr2 = "127.0.0.1:1235".parse().unwrap();

        // Add some attempts
        assert!(limiter.check_rate_limit(addr1).await); // 1st attempt - success
        assert!(limiter.check_rate_limit(addr1).await); // 2nd attempt - success
        assert!(!limiter.check_rate_limit(addr1).await); // 3rd attempt - blocked
        assert!(limiter.check_rate_limit(addr2).await); // 1st attempt for addr2 - success

        let stats = limiter.get_stats().await;
        assert_eq!(stats.total_tracked_ips, 2); // Two IPs tracked
        assert_eq!(stats.blacklisted_ips, 1); // One IP blacklisted
        assert_eq!(stats.rate_limited_ips, 1); // One IP rate limited
        assert_eq!(stats.total_attempts, 3); // Three successful attempts (2 + 1)
        assert_eq!(stats.blocked_attempts, 1); // One blocked attempt
    }
}
