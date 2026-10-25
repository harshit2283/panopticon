#![allow(dead_code)]

//! IP-based service identity resolution.
//!
//! Resolution chain:
//! 1. Kubernetes metadata, when enabled: `namespace/workload` for pod IPs,
//!    `svc:namespace/service` for ClusterIPs, `node:name` for node IPs
//!    (see [`crate::k8s`]). Never memoized here: the index is swapped
//!    whenever pods change, so a reused pod IP gets its new owner's name as
//!    soon as the API reports it, regardless of `identity_cache_ttl`.
//! 2. Names observed in DNS answers.
//! 3. The address itself: `ip:port` for servers, `ip` for clients.
//!
//! Results of steps 2–3 are memoized for `identity_cache_ttl`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use super::dns_cache::DnsCache;
use crate::k8s::{EndpointKind, K8sMetadata};
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
    /// A Kubernetes pod, named after its workload.
    Workload,
    /// A Kubernetes Service ClusterIP.
    KubeService,
    /// A Kubernetes node IP (host-network pods, node processes).
    Node,
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
    k8s: Option<Arc<K8sMetadata>>,
    cache: DashMap<(u32, u16), CachedIdentity>,
    cache_ttl: Duration,
}

impl IdentityResolver {
    pub fn new(dns_cache: Arc<DnsCache>, cache_ttl: Duration) -> Self {
        Self {
            dns_cache,
            k8s: None,
            cache: DashMap::new(),
            cache_ttl,
        }
    }

    /// Consult Kubernetes metadata before DNS / IP fallback.
    pub fn with_k8s(mut self, k8s: Option<Arc<K8sMetadata>>) -> Self {
        self.k8s = k8s;
        self
    }

    /// Resolve an IP:port to a service identity.
    pub fn resolve(&self, ip: u32, port: u16) -> ServiceIdentity {
        // Kubernetes first, unmemoized (a lock-free probe of the current
        // index): the index is the source of truth for pod IPs and follows
        // pod churn.
        if let Some(ep) = self.k8s.as_ref().and_then(|k| k.lookup(ip)) {
            return ServiceIdentity {
                name: ep.display.to_string(),
                kind: match ep.kind {
                    EndpointKind::Pod => ServiceKind::Workload,
                    EndpointKind::Service => ServiceKind::KubeService,
                    EndpointKind::Node => ServiceKind::Node,
                },
            };
        }

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

        // 2. Format as IP string, with the port for servers (port 0 = a
        //    client, identified by address only)
        let ip_str = format_ipv4(ip);
        let name = if port == 0 {
            ip_str
        } else {
            format!("{}:{}", ip_str, port)
        };
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

    fn pods(pods: &[(&str, &str, &str)]) -> Vec<crate::k8s::model::Pod> {
        pods.iter()
            .map(|(ns, deploy, ip)| {
                serde_json::from_value(serde_json::json!({
                    "metadata": {"name": format!("{deploy}-6d5c4b3a2-abcde"), "namespace": ns,
                        "labels": {"pod-template-hash": "6d5c4b3a2"},
                        "ownerReferences": [{"kind": "ReplicaSet",
                            "name": format!("{deploy}-6d5c4b3a2"), "controller": true}]},
                    "spec": {"nodeName": "worker-1"},
                    "status": {"phase": "Running", "podIP": ip, "hostIP": "192.168.0.1"}
                }))
                .unwrap()
            })
            .collect()
    }

    fn k8s_with_pods(list: &[(&str, &str, &str)]) -> Arc<K8sMetadata> {
        let meta = K8sMetadata::new("http://test");
        meta.replace_pods(&pods(list));
        meta.publish_if_dirty();
        meta
    }

    #[test]
    fn test_k8s_identity_before_dns_and_ip() {
        let dns = Arc::new(DnsCache::new());
        dns.insert_observed("checkout.example", 0x0AF40105, Duration::from_secs(60));
        let k8s = k8s_with_pods(&[("payments", "checkout", "10.244.1.5")]);
        let resolver =
            IdentityResolver::new(Arc::clone(&dns), Duration::from_secs(300)).with_k8s(Some(k8s));

        let id = resolver.resolve(0x0AF40105, 8080);
        assert_eq!(id.name, "payments/checkout");
        assert_eq!(id.kind, ServiceKind::Workload);
        // Client side (port 0) gets the same workload name.
        assert_eq!(resolver.resolve(0x0AF40105, 0).name, "payments/checkout");
        // Node IP.
        let node = resolver.resolve(0xC0A80001, 0);
        assert_eq!(node.name, "node:worker-1");
        assert_eq!(node.kind, ServiceKind::Node);
        // Unknown to Kubernetes: unchanged fallback.
        assert_eq!(resolver.resolve(0x08080808, 53).name, "8.8.8.8:53");
    }

    #[test]
    fn test_k8s_ip_reuse_not_held_by_identity_cache() {
        let dns = Arc::new(DnsCache::new());
        let k8s = k8s_with_pods(&[("payments", "checkout", "10.244.1.5")]);
        // Cache TTL of an hour: Kubernetes names must not be held by it.
        let resolver = IdentityResolver::new(Arc::clone(&dns), Duration::from_secs(3600))
            .with_k8s(Some(Arc::clone(&k8s)));
        assert_eq!(resolver.resolve(0x0AF40105, 80).name, "payments/checkout");

        // The pod is replaced; its IP goes to a workload in another namespace.
        k8s.replace_pods(&pods(&[("search", "indexer", "10.244.1.5")]));
        k8s.publish_if_dirty();
        assert_eq!(resolver.resolve(0x0AF40105, 80).name, "search/indexer");

        // Gone from Kubernetes: back to the address.
        k8s.replace_pods(&[]);
        k8s.publish_if_dirty();
        assert_eq!(resolver.resolve(0x0AF40105, 80).name, "10.244.1.5:80");
    }
}
