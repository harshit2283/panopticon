//! The object store kept between syncs and the immutable IP index built
//! from it.
//!
//! Workers only ever see [`K8sIndex`] snapshots (swapped in atomically by
//! the sync task), so a lookup is a hash probe on an immutable map: no
//! locks on the per-message path.

use std::collections::HashMap;
use std::sync::Arc;

use fxhash::FxHashMap;

use super::model::{PodRecord, ServiceRecord};

/// Most pods / services kept. Kubernetes' documented scalability limit is
/// 150k pods per cluster; anything beyond these caps is ignored (and
/// counted) so a runaway cluster cannot grow the agent without bound.
pub const MAX_PODS: usize = 200_000;
pub const MAX_SERVICES: usize = 100_000;

/// What an IP belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    /// A pod IP (not hostNetwork).
    Pod,
    /// A Service ClusterIP.
    Service,
    /// A node IP (`status.hostIP`): host-network pods and node processes.
    Node,
}

/// A resolved Kubernetes endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct K8sEndpoint {
    pub kind: EndpointKind,
    /// Empty for nodes.
    pub namespace: Arc<str>,
    /// Workload name (pods), Service name, or node name.
    pub name: Arc<str>,
    /// `Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`,
    /// `ReplicaSet`, `StaticPod`, `Pod`, `Other`; `Service`; `Node`.
    pub workload_kind: &'static str,
    /// The pod name, for pod endpoints.
    pub pod: Option<Arc<str>>,
    /// The node the pod runs on (pods), or the node itself.
    pub node: Option<Arc<str>>,
    /// The identity string used for graph nodes and exports:
    /// `namespace/workload`, `svc:namespace/service` or `node:name`.
    pub display: Arc<str>,
}

impl K8sEndpoint {
    fn for_pod(p: &PodRecord) -> Self {
        Self {
            kind: EndpointKind::Pod,
            display: Arc::from(format!("{}/{}", p.namespace, p.workload_name)),
            namespace: Arc::clone(&p.namespace),
            name: Arc::clone(&p.workload_name),
            workload_kind: p.workload_kind,
            pod: Some(Arc::clone(&p.name)),
            node: p.node.clone(),
        }
    }

    fn for_service(s: &ServiceRecord) -> Self {
        Self {
            kind: EndpointKind::Service,
            display: Arc::from(format!("svc:{}/{}", s.namespace, s.name)),
            namespace: Arc::clone(&s.namespace),
            name: Arc::clone(&s.name),
            workload_kind: "Service",
            pod: None,
            node: None,
        }
    }

    fn for_node(node: &Arc<str>) -> Self {
        Self {
            kind: EndpointKind::Node,
            display: Arc::from(format!("node:{node}")),
            namespace: Arc::from(""),
            name: Arc::clone(node),
            workload_kind: "Node",
            pod: None,
            node: Some(Arc::clone(node)),
        }
    }
}

/// Immutable IP → endpoint snapshot.
#[derive(Debug, Default)]
pub struct K8sIndex {
    by_ip: FxHashMap<u32, Arc<K8sEndpoint>>,
    pub pods: usize,
    pub services: usize,
    pub nodes: usize,
}

impl K8sIndex {
    pub fn lookup(&self, ip: u32) -> Option<&Arc<K8sEndpoint>> {
        self.by_ip.get(&ip)
    }

    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }

    /// Build the index from the current objects.
    ///
    /// Precedence: pod IPs, then ClusterIPs, then node IPs. Host-network pods
    /// are never indexed by IP — their IP is the node's, shared by every
    /// host-network pod and the node itself — and no pod is ever indexed
    /// under an IP that is some node's `hostIP`. Node IPs map to the node.
    /// When two pods claim one IP (a terminating pod whose IP was already
    /// handed to a new pod), the non-terminating, then the newest, wins.
    pub fn build<'a>(
        pods: impl IntoIterator<Item = &'a PodRecord>,
        services: impl IntoIterator<Item = &'a ServiceRecord>,
    ) -> Self {
        let pods: Vec<&PodRecord> = pods.into_iter().collect();

        // Node IPs, learned from every pod's hostIP + nodeName.
        let mut node_ips: FxHashMap<u32, Arc<str>> = FxHashMap::default();
        for p in &pods {
            if let (Some(ip), Some(node)) = (p.host_ip, p.node.as_ref()) {
                node_ips.entry(ip).or_insert_with(|| Arc::clone(node));
            }
        }

        let mut owner: FxHashMap<u32, &PodRecord> = FxHashMap::default();
        let mut pod_count = 0usize;
        for p in &pods {
            if p.host_network {
                continue;
            }
            let mut indexed = false;
            for &ip in &p.ips {
                if node_ips.contains_key(&ip) {
                    continue;
                }
                indexed = true;
                match owner.get(&ip) {
                    Some(cur) if !prefer(p, cur) => {}
                    _ => {
                        owner.insert(ip, p);
                    }
                }
            }
            pod_count += usize::from(indexed);
        }

        let mut by_ip: FxHashMap<u32, Arc<K8sEndpoint>> = FxHashMap::default();
        by_ip.reserve(owner.len() + node_ips.len());
        // Pods of one workload share nothing but strings already Arc'd; one
        // endpoint per pod keeps the pod name available to exports.
        for (ip, p) in owner {
            by_ip.insert(ip, Arc::new(K8sEndpoint::for_pod(p)));
        }
        let mut svc_count = 0usize;
        for s in services {
            if s.cluster_ips.is_empty() {
                continue;
            }
            let ep = Arc::new(K8sEndpoint::for_service(s));
            let mut indexed = false;
            for &ip in &s.cluster_ips {
                if let std::collections::hash_map::Entry::Vacant(v) = by_ip.entry(ip) {
                    v.insert(Arc::clone(&ep));
                    indexed = true;
                }
            }
            svc_count += usize::from(indexed);
        }
        let node_count = node_ips.len();
        let mut node_eps: HashMap<Arc<str>, Arc<K8sEndpoint>> = HashMap::new();
        for (ip, node) in node_ips {
            let ep = node_eps
                .entry(Arc::clone(&node))
                .or_insert_with(|| Arc::new(K8sEndpoint::for_node(&node)));
            by_ip.entry(ip).or_insert_with(|| Arc::clone(ep));
        }

        Self {
            by_ip,
            pods: pod_count,
            services: svc_count,
            nodes: node_count,
        }
    }
}

/// Whether `a` should own a contested IP over `b`.
fn prefer(a: &PodRecord, b: &PodRecord) -> bool {
    if a.terminating != b.terminating {
        return !a.terminating;
    }
    a.created > b.created
}

/// Pods and services as last seen, keyed `namespace/name`.
#[derive(Debug, Default)]
pub struct Store {
    pub pods: HashMap<String, PodRecord>,
    pub services: HashMap<String, ServiceRecord>,
    /// Objects ignored because a cap was reached.
    pub dropped: u64,
}

impl Store {
    pub fn upsert_pod(&mut self, key: String, rec: PodRecord) -> bool {
        if self.pods.len() >= MAX_PODS && !self.pods.contains_key(&key) {
            self.dropped += 1;
            return false;
        }
        self.pods.insert(key, rec);
        true
    }

    pub fn upsert_service(&mut self, key: String, rec: ServiceRecord) -> bool {
        if self.services.len() >= MAX_SERVICES && !self.services.contains_key(&key) {
            self.dropped += 1;
            return false;
        }
        self.services.insert(key, rec);
        true
    }

    pub fn build_index(&self) -> K8sIndex {
        K8sIndex::build(self.pods.values(), self.services.values())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from(Ipv4Addr::new(a, b, c, d))
    }

    fn pod(ns: &str, name: &str, workload: &str, ips: &[u32]) -> PodRecord {
        PodRecord {
            namespace: Arc::from(ns),
            name: Arc::from(name),
            workload_kind: "Deployment",
            workload_name: Arc::from(workload),
            node: Some(Arc::from("node-1")),
            ips: ips.to_vec(),
            host_ip: Some(ip(192, 168, 0, 10)),
            host_network: false,
            terminating: false,
            created: Some("2026-10-01T00:00:00Z".to_string()),
        }
    }

    #[test]
    fn test_pod_service_node_lookup() {
        let pods = [pod(
            "payments",
            "checkout-abc-1",
            "checkout",
            &[ip(10, 244, 1, 5)],
        )];
        let svcs = [ServiceRecord {
            namespace: Arc::from("payments"),
            name: Arc::from("checkout"),
            cluster_ips: vec![ip(10, 96, 0, 20)],
        }];
        let idx = K8sIndex::build(&pods, &svcs);
        assert_eq!(
            &*idx.lookup(ip(10, 244, 1, 5)).unwrap().display,
            "payments/checkout"
        );
        assert_eq!(
            &*idx.lookup(ip(10, 96, 0, 20)).unwrap().display,
            "svc:payments/checkout"
        );
        assert_eq!(
            &*idx.lookup(ip(192, 168, 0, 10)).unwrap().display,
            "node:node-1"
        );
        assert!(idx.lookup(ip(8, 8, 8, 8)).is_none());
        assert_eq!((idx.pods, idx.services, idx.nodes), (1, 1, 1));
    }

    #[test]
    fn test_host_network_pods_never_own_the_node_ip() {
        let mut agent = pod(
            "monitoring",
            "agent-x",
            "panopticon",
            &[ip(192, 168, 0, 10)],
        );
        agent.workload_kind = "DaemonSet";
        agent.host_network = true;
        // A pod that claims the node IP without the hostNetwork flag.
        let odd = pod("kube-system", "odd", "odd", &[ip(192, 168, 0, 10)]);
        let idx = K8sIndex::build(&[agent, odd], &[]);
        let ep = idx.lookup(ip(192, 168, 0, 10)).unwrap();
        assert_eq!(ep.kind, EndpointKind::Node);
        assert_eq!(&*ep.display, "node:node-1");
        assert_eq!(idx.pods, 0);
    }

    #[test]
    fn test_ip_reuse_prefers_live_then_newest_pod() {
        let mut old = pod("a", "old-pod", "old", &[ip(10, 244, 0, 9)]);
        old.terminating = true;
        old.created = Some("2026-10-02T00:00:00Z".to_string());
        let new = pod("b", "new-pod", "new", &[ip(10, 244, 0, 9)]);
        let idx = K8sIndex::build(&[old.clone(), new.clone()], &[]);
        assert_eq!(&*idx.lookup(ip(10, 244, 0, 9)).unwrap().display, "b/new");
        let idx = K8sIndex::build(&[new.clone(), old.clone()], &[]);
        assert_eq!(&*idx.lookup(ip(10, 244, 0, 9)).unwrap().display, "b/new");

        // Both live: newest creation wins.
        let mut older = pod("a", "older", "older", &[ip(10, 244, 0, 9)]);
        older.created = Some("2026-09-01T00:00:00Z".to_string());
        let idx = K8sIndex::build(&[new, older], &[]);
        assert_eq!(&*idx.lookup(ip(10, 244, 0, 9)).unwrap().display, "b/new");
    }

    #[test]
    fn test_store_caps() {
        let mut store = Store::default();
        for i in 0..MAX_SERVICES {
            store.services.insert(
                format!("ns/s{i}"),
                ServiceRecord {
                    namespace: Arc::from("ns"),
                    name: Arc::from("s"),
                    cluster_ips: vec![],
                },
            );
        }
        let rec = ServiceRecord {
            namespace: Arc::from("ns"),
            name: Arc::from("extra"),
            cluster_ips: vec![],
        };
        assert!(!store.upsert_service("ns/extra".into(), rec.clone()));
        assert_eq!(store.dropped, 1);
        // Updating an existing key is always allowed.
        assert!(store.upsert_service("ns/s0".into(), rec));
    }
}
