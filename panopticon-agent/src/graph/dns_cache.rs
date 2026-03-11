#![allow(dead_code)]

//! TTL-aware DNS cache populated from observed DNS traffic.
//!
//! The cache maps IP addresses to domain names, enabling the service graph
//! to show human-readable service names instead of raw IPs. Entries expire
//! based on the TTL from the original DNS response.
//!
//! Currently populated only via `insert_observed()` (called by the DNS parser
//! when it lands in Phase 7-9). Until then, the cache starts empty and
//! identity resolution falls back to IP-based names.

use std::time::{Duration, Instant};

use dashmap::DashMap;

/// A cached DNS resolution with TTL-based expiry.
#[derive(Debug, Clone)]
pub struct DnsCacheEntry {
    pub domain: String,
    pub inserted_at: Instant,
    pub ttl: Duration,
}

impl DnsCacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > self.ttl
    }
}

/// Thread-safe DNS cache mapping IPs to observed domain names.
pub struct DnsCache {
    ip_to_domain: DashMap<u32, DnsCacheEntry>,
    domain_to_ip: DashMap<String, u32>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            ip_to_domain: DashMap::new(),
            domain_to_ip: DashMap::new(),
        }
    }

    /// Insert a DNS observation (called by the DNS parser on A/AAAA responses).
    pub fn insert_observed(&self, domain: &str, ip: u32, ttl: Duration) {
        let entry = DnsCacheEntry {
            domain: domain.to_string(),
            inserted_at: Instant::now(),
            ttl,
        };
        self.ip_to_domain.insert(ip, entry);
        self.domain_to_ip.insert(domain.to_string(), ip);
    }

    /// Resolve an IP to a cached domain name. Returns `None` if not found or expired.
    pub fn resolve(&self, ip: u32) -> Option<String> {
        let entry = self.ip_to_domain.get(&ip)?;
        if entry.is_expired() {
            drop(entry);
            self.ip_to_domain.remove(&ip);
            return None;
        }
        Some(entry.domain.clone())
    }

    /// Look up the IP for a known domain.
    pub fn resolve_domain(&self, domain: &str) -> Option<u32> {
        self.domain_to_ip.get(domain).map(|r| *r.value())
    }

    /// Remove all expired entries. Called periodically from the stats task.
    pub fn evict_expired(&self) -> usize {
        let mut evicted = 0;
        self.ip_to_domain.retain(|_ip, entry| {
            if entry.is_expired() {
                evicted += 1;
                false
            } else {
                true
            }
        });
        // Also clean domain_to_ip for evicted domains
        if evicted > 0 {
            self.domain_to_ip
                .retain(|_domain, ip| self.ip_to_domain.contains_key(ip));
        }
        evicted
    }

    /// Number of entries (for stats reporting).
    pub fn len(&self) -> usize {
        self.ip_to_domain.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_and_resolve() {
        let cache = DnsCache::new();
        cache.insert_observed("nginx.default.svc", 0x0A000001, Duration::from_secs(60));

        assert_eq!(
            cache.resolve(0x0A000001),
            Some("nginx.default.svc".to_string())
        );
    }

    #[test]
    fn test_resolve_unknown_ip() {
        let cache = DnsCache::new();
        assert_eq!(cache.resolve(0xDEADBEEF), None);
    }

    #[test]
    fn test_ttl_expiry() {
        let cache = DnsCache::new();
        // Insert with zero TTL — immediately expired
        cache.insert_observed("expired.svc", 0x0A000002, Duration::ZERO);

        // Give a tiny bit of time to ensure expiry
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(cache.resolve(0x0A000002), None);
    }

    #[test]
    fn test_evict_expired() {
        let cache = DnsCache::new();
        cache.insert_observed("alive.svc", 0x0A000001, Duration::from_secs(300));
        cache.insert_observed("dead.svc", 0x0A000002, Duration::ZERO);

        std::thread::sleep(Duration::from_millis(1));
        let evicted = cache.evict_expired();

        assert_eq!(evicted, 1);
        assert_eq!(cache.len(), 1);
        assert!(cache.resolve(0x0A000001).is_some());
        assert!(cache.resolve(0x0A000002).is_none());
    }

    #[test]
    fn test_domain_to_ip() {
        let cache = DnsCache::new();
        cache.insert_observed("postgres.svc", 0x0A000003, Duration::from_secs(60));

        assert_eq!(cache.resolve_domain("postgres.svc"), Some(0x0A000003));
        assert_eq!(cache.resolve_domain("unknown.svc"), None);
    }

    #[test]
    fn test_overwrite_entry() {
        let cache = DnsCache::new();
        cache.insert_observed("old.svc", 0x0A000001, Duration::from_secs(60));
        cache.insert_observed("new.svc", 0x0A000001, Duration::from_secs(120));

        // IP should now resolve to the newer domain
        assert_eq!(cache.resolve(0x0A000001), Some("new.svc".to_string()));
    }
}
