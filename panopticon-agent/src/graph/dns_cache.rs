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

/// Longest TTL an observed answer is kept for. DNS answers come from the
/// traffic: a forged one with a TTL of years must not name an address for
/// good.
pub const MAX_DNS_TTL: Duration = Duration::from_secs(3600);

/// Whether `name` may name a service: a hostname (letters, digits, `-`,
/// `_`, labels of 1-63 bytes, at most 253 bytes) whose last label is not
/// all digits. That excludes everything that imitates the agent's other
/// identity formats: `svc:ns/name`, `node:name`, `ns/workload` (`:` and
/// `/`), and addresses (`10.0.0.5`, `10.0.0.5:80`).
pub fn is_service_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    name.len() <= 253
        && name.split('.').all(label_ok)
        && !name
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
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

    /// Insert a DNS observation (an A record answering a query seen on the
    /// same flow). Names that are not plain hostnames are refused (see
    /// [`is_service_name`]) and the TTL is capped at [`MAX_DNS_TTL`].
    /// Returns whether the name was cached.
    pub fn insert_observed(&self, domain: &str, ip: u32, ttl: Duration) -> bool {
        if !is_service_name(domain) {
            return false;
        }
        let entry = DnsCacheEntry {
            domain: domain.to_string(),
            inserted_at: Instant::now(),
            ttl: ttl.min(MAX_DNS_TTL),
        };
        self.ip_to_domain.insert(ip, entry);
        self.domain_to_ip.insert(domain.to_string(), ip);
        true
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
    fn test_names_imitating_identities_or_carrying_junk_are_refused() {
        let cache = DnsCache::new();
        for bad in [
            "svc:payments/checkout",
            "node:worker-1",
            "payments/checkout",
            "10.0.0.5",
            "10.0.0.5:443",
            "api stripe.com",
            "a..b",
            "",
            "evil.com\n{\"x\":1}",
            &format!("{}.com", "a".repeat(64)),
        ] {
            assert!(
                !cache.insert_observed(bad, 0x0A000001, Duration::from_secs(60)),
                "{bad:?}"
            );
        }
        assert_eq!(cache.resolve(0x0A000001), None);
        assert!(cache.insert_observed("api.stripe.com.", 1, Duration::from_secs(60)));
        assert!(cache.insert_observed("_grpc._tcp.svc-1.local", 2, Duration::from_secs(60)));
    }

    #[test]
    fn test_ttl_is_capped() {
        let cache = DnsCache::new();
        // ~68 years, the largest TTL a forged answer can carry.
        assert!(cache.insert_observed("api.stripe.com", 1, Duration::from_secs(u32::MAX as u64)));
        assert_eq!(cache.ip_to_domain.get(&1).unwrap().ttl, MAX_DNS_TTL);
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
