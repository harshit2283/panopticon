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
    /// Resolves source/destination identities and records the flow in the
    /// aggregator. The aggregator handles deduplication via normalized templates.
    pub fn record(&self, conn: &ConnectionTuple, msg: &L7Message, pii_report: Option<&PiiReport>) {
        // Resolve identities: prefer well-known port side for dst
        let (src_port, dst_port) =
            server_port_heuristic(conn.src_port, conn.dst_port, msg.protocol);
        let src_id = self.identity.resolve(conn.src_addr, src_port);
        let dst_id = self.identity.resolve(conn.dst_addr, dst_port);

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

    pub fn dag(&self) -> &Arc<Mutex<ServiceDag>> {
        &self.dag
    }
}

/// Choose which port to use for identity resolution.
///
/// For requests, we want the server-side (well-known) port to be the dst_port.
/// Ephemeral ports (>= 32768) are useless for identity — they change per connection.
fn server_port_heuristic(src_port: u16, dst_port: u16, protocol: Protocol) -> (u16, u16) {
    // Known server ports by protocol
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

    // If dst_port is a well-known port, use as-is
    if well_known.contains(&dst_port) {
        return (src_port, dst_port);
    }
    // If src_port is well-known, swap — src is actually the server
    if well_known.contains(&src_port) {
        return (dst_port, src_port);
    }
    // Fallback: prefer the lower port (more likely to be server-side)
    if src_port < dst_port {
        (dst_port, src_port)
    } else {
        (src_port, dst_port)
    }
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
    fn test_server_port_heuristic_well_known_dst() {
        let (src, dst) = server_port_heuristic(54321, 80, Protocol::Http1);
        assert_eq!(src, 54321);
        assert_eq!(dst, 80);
    }

    #[test]
    fn test_server_port_heuristic_well_known_src() {
        // Server response: src=80, dst=54321 -> swap
        let (src, dst) = server_port_heuristic(80, 54321, Protocol::Http1);
        assert_eq!(src, 54321);
        assert_eq!(dst, 80);
    }

    #[test]
    fn test_server_port_heuristic_fallback() {
        // Neither is well-known — prefer lower port as server
        let (_src, dst) = server_port_heuristic(45000, 8888, Protocol::Unknown);
        assert_eq!(dst, 8888);
    }
}
