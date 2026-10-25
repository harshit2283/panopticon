#![allow(dead_code)]

//! Service dependency graph module.
//!
//! Builds a real-time DAG of service-to-service communication from observed
//! L7 traffic. The `GraphBuilder` is the main entry point — it's `Arc`-shared
//! across workers and uses concurrent data structures internally.

pub mod aggregator;
pub mod dag;
pub mod dns_cache;
pub mod identity;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::GraphConfig;
use crate::pii::PiiReport;
use crate::protocol::{L7Message, Protocol};

use self::aggregator::{AggregatedFlow, EdgeAggregator};
use self::dag::ServiceDag;
use self::dns_cache::DnsCache;
use self::identity::IdentityResolver;

/// Connection 4-tuple extracted from a `DataEvent`.
pub struct ConnectionTuple {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub pid: u32,
}

/// Orchestrator that ties together DNS cache, identity resolution,
/// edge aggregation, and the service DAG.
pub struct GraphBuilder {
    pub dns_cache: Arc<DnsCache>,
    identity: IdentityResolver,
    aggregator: Arc<EdgeAggregator>,
    dag: Arc<Mutex<ServiceDag>>,
    stale_edge_timeout: Duration,
}

impl GraphBuilder {
    pub fn new(config: &GraphConfig) -> Self {
        let dns_cache = Arc::new(DnsCache::new());
        Self {
            identity: IdentityResolver::new(Arc::clone(&dns_cache), config.identity_cache_ttl),
            aggregator: Arc::new(EdgeAggregator::new(config.aggregation_window)),
            dag: Arc::new(Mutex::new(ServiceDag::new())),
            dns_cache,
            stale_edge_timeout: config.stale_edge_timeout,
        }
    }

    /// Record an L7 message observation. Called from each worker task.
    ///
    /// Orients the connection client → server (guessing the server from
    /// ports), then records the flow in the aggregator, which deduplicates
    /// via normalized templates.
    pub fn record(&self, conn: &ConnectionTuple, msg: &L7Message, pii_report: Option<&PiiReport>) {
        self.record_with_server(conn, None, msg, pii_report);
    }

    /// Like [`record`](Self::record), with the server side known:
    /// `Some(true)` if `conn.src` is the server (e.g. a response packet),
    /// `Some(false)` if `conn.dst` is.
    ///
    /// The client is identified by address only: its ephemeral port changes
    /// with every connection, and keeping it made every connection a new
    /// graph node and edge, so the graph grew with traffic instead of with
    /// services.
    pub fn record_with_server(
        &self,
        conn: &ConnectionTuple,
        src_is_server: Option<bool>,
        msg: &L7Message,
        pii_report: Option<&PiiReport>,
    ) {
        let (client_addr, server) = orient(conn, src_is_server, msg.protocol);
        let src_id = self.identity.resolve(client_addr, 0);
        let dst_id = self.identity.resolve(server.0, server.1);

        self.aggregator.record(
            &src_id.name,
            &dst_id.name,
            msg.protocol,
            msg.method.as_deref(),
            msg.path.as_deref(),
            msg.status,
            msg.latency_ns,
            msg.request_size_bytes,
            msg.response_size_bytes,
            pii_report.is_some(),
            msg.timestamp_ns,
        );
    }

    /// Name of the server end of a connection, as the graph names it
    /// (Kubernetes workload, DNS name, else `ip:port`).
    pub fn server_identity(
        &self,
        conn: &ConnectionTuple,
        src_is_server: Option<bool>,
        protocol: Protocol,
    ) -> String {
        let (_, (addr, port)) = orient(conn, src_is_server, protocol);
        self.identity.resolve(addr, port).name
    }

    /// Flush the current aggregation window, update the DAG, and return flows.
    /// Called periodically from the stats task (every 10s).
    pub fn flush(&self) -> Vec<AggregatedFlow> {
        let flows = self.aggregator.flush();
        if !flows.is_empty()
            && let Ok(mut dag) = self.dag.lock()
        {
            dag.update_edges(&flows);
        }
        flows
    }

    /// Prune stale edges and evict expired DNS entries.
    pub fn prune(&self, now_ns: u64) {
        if let Ok(mut dag) = self.dag.lock() {
            dag.prune_stale(self.stale_edge_timeout, now_ns);
        }
        self.dns_cache.evict_expired();
        self.identity.evict_expired();
    }

    /// Name endpoints from Kubernetes metadata when available.
    pub fn with_k8s(mut self, k8s: Option<Arc<crate::k8s::K8sMetadata>>) -> Self {
        self.identity = self.identity.with_k8s(k8s);
        self
    }

    pub fn dag(&self) -> &Arc<Mutex<ServiceDag>> {
        &self.dag
    }
}

/// Split a connection into (client address, server endpoint), using
/// `src_is_server` when known and the port heuristic otherwise.
pub fn orient(
    conn: &ConnectionTuple,
    src_is_server: Option<bool>,
    protocol: Protocol,
) -> (u32, (u32, u16)) {
    let src_is_server = src_is_server
        .unwrap_or_else(|| src_is_server_heuristic(conn.src_port, conn.dst_port, protocol));
    if src_is_server {
        (conn.dst_addr, (conn.src_addr, conn.src_port))
    } else {
        (conn.src_addr, (conn.dst_addr, conn.dst_port))
    }
}

/// Guess whether `src` is the server end of a connection, for callers that
/// don't know: a well-known port for the protocol wins, else the lower port.
fn src_is_server_heuristic(src_port: u16, dst_port: u16, protocol: Protocol) -> bool {
    let well_known = match protocol {
        Protocol::Http1 | Protocol::Http2 | Protocol::Grpc => &[80, 443, 8080, 8443][..],
        Protocol::Mysql => &[3306][..],
        Protocol::Postgres => &[5432][..],
        Protocol::Redis => &[6379][..],
        Protocol::Dns => &[53][..],
        Protocol::Kafka => &[9092][..],
        Protocol::Amqp => &[5672][..],
        Protocol::Unknown => &[][..],
    };
    if well_known.contains(&dst_port) {
        return false;
    }
    if well_known.contains(&src_port) {
        return true;
    }
    src_port < dst_port
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GraphConfig;
    use panopticon_common::Direction;

    fn make_builder() -> GraphBuilder {
        GraphBuilder::new(&GraphConfig::default())
    }

    #[test]
    fn test_record_end_to_end() {
        let gb = make_builder();

        let conn = ConnectionTuple {
            src_addr: 0x0A000001,
            dst_addr: 0x0A000002,
            src_port: 54321,
            dst_port: 80,
            pid: 1234,
        };

        let mut msg = L7Message::new(Protocol::Http1, Direction::Egress, 1000);
        msg.method = Some("GET".to_string());
        msg.path = Some("/api/health".to_string());
        msg.status = Some(200);
        msg.latency_ns = Some(5000);

        gb.record(&conn, &msg, None);

        // Flush and verify DAG was updated
        let flows = gb.flush();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].stats.request_count, 1);

        let dag = gb.dag().lock().unwrap();
        assert_eq!(dag.node_count(), 2);
        assert_eq!(dag.edge_count(), 1);
    }

    #[test]
    fn test_connection_tuple_fields() {
        let conn = ConnectionTuple {
            src_addr: 0xC0A80101, // 192.168.1.1
            dst_addr: 0x0A000001, // 10.0.0.1
            src_port: 12345,
            dst_port: 5432,
            pid: 42,
        };
        assert_eq!(conn.src_addr, 0xC0A80101);
        assert_eq!(conn.dst_port, 5432);
        assert_eq!(conn.pid, 42);
    }

    #[test]
    fn test_flush_updates_dag() {
        let gb = make_builder();
        let conn = ConnectionTuple {
            src_addr: 0x0A000001,
            dst_addr: 0x0A000002,
            src_port: 54321,
            dst_port: 3306,
            pid: 1,
        };

        let mut msg = L7Message::new(Protocol::Mysql, Direction::Egress, 1000);
        msg.method = Some("SELECT".to_string());
        msg.path = Some("SELECT * FROM users WHERE id = 1".to_string());

        gb.record(&conn, &msg, None);
        gb.record(&conn, &msg, None);

        let flows = gb.flush();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].stats.request_count, 2);

        let dag = gb.dag().lock().unwrap();
        assert_eq!(dag.edge_count(), 1);
    }

    #[test]
    fn test_server_heuristic() {
        assert!(!src_is_server_heuristic(54321, 80, Protocol::Http1));
        assert!(src_is_server_heuristic(80, 54321, Protocol::Http1));
        // Neither is well-known — prefer lower port as server
        assert!(!src_is_server_heuristic(45000, 8888, Protocol::Unknown));
        assert!(src_is_server_heuristic(8888, 45000, Protocol::Unknown));
    }

    fn edges(gb: &GraphBuilder) -> Vec<(String, String)> {
        gb.flush();
        let dag = gb.dag().lock().unwrap();
        let mut e: Vec<_> = dag
            .to_adjacency_list()
            .into_iter()
            .map(|(s, d, _)| (s, d))
            .collect();
        e.sort();
        e
    }

    #[test]
    fn test_response_packet_keeps_addresses_with_ports() {
        // A response travels server -> client; the edge must still be
        // client -> server with each address next to its own port.
        let gb = make_builder();
        let resp = ConnectionTuple {
            src_addr: 0x0A630001, // 10.99.0.1 (server)
            dst_addr: 0x0A630002, // 10.99.0.2 (client)
            src_port: 18090,
            dst_port: 51000,
            pid: 1,
        };
        let msg = L7Message::new(Protocol::Http1, Direction::Egress, 1000);
        gb.record_with_server(&resp, Some(true), &msg, None);
        assert_eq!(
            edges(&gb),
            vec![("10.99.0.2".to_string(), "10.99.0.1:18090".to_string())]
        );
    }

    #[test]
    fn test_server_identity_names_the_server_end() {
        let gb = make_builder();
        let resp = ConnectionTuple {
            src_addr: 0x0A630001, // 10.99.0.1 (server)
            dst_addr: 0x0A630002,
            src_port: 18090,
            dst_port: 51000,
            pid: 1,
        };
        assert_eq!(
            gb.server_identity(&resp, Some(true), Protocol::Http1),
            "10.99.0.1:18090"
        );
        // Unknown orientation: the port heuristic picks the lower port.
        assert_eq!(
            gb.server_identity(&resp, None, Protocol::Http1),
            "10.99.0.1:18090"
        );
    }

    #[test]
    fn test_client_connections_collapse_to_one_edge() {
        let gb = make_builder();
        let msg = L7Message::new(Protocol::Redis, Direction::Egress, 1000);
        for port in 40000..41000 {
            let conn = ConnectionTuple {
                src_addr: 0x0A000001,
                dst_addr: 0x0A000002,
                src_port: port,
                dst_port: 6379,
                pid: 1,
            };
            gb.record(&conn, &msg, None);
        }
        assert_eq!(edges(&gb).len(), 1, "one client, one server: one edge");
        assert_eq!(gb.dag().lock().unwrap().node_count(), 2);
    }

    #[test]
    fn test_graph_nodes_named_by_kubernetes_workload() {
        let meta = crate::k8s::K8sMetadata::new("http://test");
        let pod = |ns: &str, rs: &str, hash: &str, ip: &str| -> crate::k8s::model::Pod {
            serde_json::from_value(serde_json::json!({
                "metadata": {"name": format!("{rs}-x"), "namespace": ns,
                    "labels": {"pod-template-hash": hash},
                    "ownerReferences": [{"kind": "ReplicaSet", "name": rs, "controller": true}]},
                "spec": {"nodeName": "worker-1"},
                "status": {"phase": "Running", "podIP": ip, "hostIP": "192.168.0.1"}
            }))
            .unwrap()
        };
        meta.replace_pods(&[
            pod("payments", "web-5c6d7e8f9a", "5c6d7e8f9a", "10.0.0.1"),
            pod("payments", "checkout-7d9f8b6c5d", "7d9f8b6c5d", "10.0.0.2"),
        ]);
        meta.publish_if_dirty();
        let gb = make_builder().with_k8s(Some(meta));

        let msg = L7Message::new(Protocol::Http1, Direction::Egress, 1000);
        for port in 40000..40010 {
            let conn = ConnectionTuple {
                src_addr: 0x0A000001,
                dst_addr: 0x0A000002,
                src_port: port,
                dst_port: 8080,
                pid: 1,
            };
            gb.record(&conn, &msg, None);
        }
        // An unknown peer keeps its address.
        let ext = ConnectionTuple {
            src_addr: 0x0A000001,
            dst_addr: 0x08080808,
            src_port: 40100,
            dst_port: 443,
            pid: 1,
        };
        gb.record(&ext, &msg, None);
        assert_eq!(
            edges(&gb),
            vec![
                ("payments/web".to_string(), "8.8.8.8:443".to_string()),
                ("payments/web".to_string(), "payments/checkout".to_string()),
            ]
        );
    }
}
