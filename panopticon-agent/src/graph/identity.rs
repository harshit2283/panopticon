#![allow(dead_code)]

//! IP-based service identity resolution.
//!
//! Maps raw IP addresses to human-readable service names using the DNS cache
//! as the primary source. Falls back to IP:port strings for unknown addresses.
//! K8s-based resolution (Pod IP -> Service name) is deferred to Phase 7.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use super::dns_cache::DnsCache;
use crate::util::format_ipv4;

/// Resolved identity for a network endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceIdentity {
    pub name: String,
    pub kind: ServiceKind,
}

/// How the identity was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    /// Resolved via DNS cache to a known service name.
    Service,
    /// Raw IP fallback — no DNS entry found.
    External,
}

/// Cached identity resolution with TTL.
struct CachedIdentity {
    identity: ServiceIdentity,
    resolved_at: Instant,
}

/// Resolves IP addresses to service identities.
///
/// Resolution chain: DNS cache hit -> port-hinted name -> raw IP fallback.
/// Results are memoized in a DashMap with configurable TTL.
pub struct IdentityResolver {
    dns_cache: Arc<DnsCache>,
    cache: DashMap<(u32, u16), CachedIdentity>,
    cache_ttl: Duration,
}

impl IdentityResolver {
    pub fn new(dns_cache: Arc<DnsCache>, cache_ttl: Duration) -> Self {
        Self {
            dns_cache,
            cache: DashMap::new(),
            cache_ttl,
        }
    }

    /// Resolve an IP:port to a service identity.
    pub fn resolve(&self, ip: u32, port: u16) -> ServiceIdentity {
        let key = (ip, port);

        // Check memoized cache first
        if let Some(entry) = self.cache.get(&key)
            && entry.resolved_at.elapsed() < self.cache_ttl
        {
            return entry.identity.clone();
        }

        // Resolve and cache
        let identity = self.do_resolve(ip, port);
        self.cache.insert(
            key,
            CachedIdentity {
                identity: identity.clone(),
                resolved_at: Instant::now(),
            },
        );
        identity
    }

    fn do_resolve(&self, ip: u32, port: u16) -> ServiceIdentity {
        // 1. Check DNS cache
        if let Some(domain) = self.dns_cache.resolve(ip) {
            return ServiceIdentity {
                name: domain,
                kind: ServiceKind::Service,
            };
        }

        // 2. Format as IP string with port hint
        let ip_str = format_ipv4(ip);
        let name = format!("{}:{}", ip_str, port);
        ServiceIdentity {
            name,
            kind: ServiceKind::External,
        }
    }

    /// Number of cached resolutions (for stats).
    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Evict entries older than `cache_ttl`.
    pub fn evict_expired(&self) -> usize {
        let mut evicted = 0usize;
        self.cache.retain(|_, entry| {
            let keep = entry.resolved_at.elapsed() < self.cache_ttl;
            if !keep {
                evicted += 1;
            }
            keep
        });
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_resolver() -> (Arc<DnsCache>, IdentityResolver) {
        let dns = Arc::new(DnsCache::new());
        let resolver = IdentityResolver::new(Arc::clone(&dns), Duration::from_secs(300));
        (dns, resolver)
    }

    #[test]
    fn test_dns_hit() {
        let (dns, resolver) = make_resolver();
        dns.insert_observed("nginx.svc", 0x0A000001, Duration::from_secs(60));

        let id = resolver.resolve(0x0A000001, 80);
        assert_eq!(id.name, "nginx.svc");
        assert_eq!(id.kind, ServiceKind::Service);
    }

    #[test]
    fn test_dns_miss_ip_fallback() {
        let (_dns, resolver) = make_resolver();

        let id = resolver.resolve(0x0A000005, 3306);
        assert_eq!(id.name, "10.0.0.5:3306");
        assert_eq!(id.kind, ServiceKind::External);
    }

    #[test]
    fn test_different_ports_different_identities() {
        let (_dns, resolver) = make_resolver();

        let id1 = resolver.resolve(0x0A000005, 80);
        let id2 = resolver.resolve(0x0A000005, 443);
        assert_ne!(id1.name, id2.name);
    }

    #[test]
    fn test_cache_ttl_expiry() {
        let dns = Arc::new(DnsCache::new());
        let resolver = IdentityResolver::new(Arc::clone(&dns), Duration::ZERO);

        // Resolve once (no DNS entry)
        let id1 = resolver.resolve(0x0A000001, 80);
        assert_eq!(id1.kind, ServiceKind::External);

        // Now add DNS entry — cache TTL is zero so next call should re-resolve
        dns.insert_observed("newly-discovered.svc", 0x0A000001, Duration::from_secs(60));
        std::thread::sleep(Duration::from_millis(1));

        let id2 = resolver.resolve(0x0A000001, 80);
        assert_eq!(id2.name, "newly-discovered.svc");
        assert_eq!(id2.kind, ServiceKind::Service);
    }

    #[test]
    fn test_service_kind_variants() {
        let (dns, resolver) = make_resolver();
        dns.insert_observed("redis.svc", 0x0A000010, Duration::from_secs(60));

        assert_eq!(
            resolver.resolve(0x0A000010, 6379).kind,
            ServiceKind::Service
        );
        assert_eq!(
            resolver.resolve(0xC0A80001, 8080).kind,
            ServiceKind::External
        );
    }

    #[test]
    fn test_evict_expired() {
        let dns = Arc::new(DnsCache::new());
        let resolver = IdentityResolver::new(Arc::clone(&dns), Duration::from_millis(1));
        let _ = resolver.resolve(0x0A000001, 80);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(resolver.evict_expired(), 1);
        assert_eq!(resolver.cache_len(), 0);
    }
}
