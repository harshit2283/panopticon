#![allow(dead_code)]

//! petgraph-backed service dependency DAG.
//!
//! Nodes are service identities (strings). Edges carry aggregated statistics
//! per (source, destination, protocol) tuple. Updated every aggregation window
//! (10s) from flushed `AggregatedFlow`s.

use std::collections::HashMap;
use std::time::Duration;

use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;

use crate::protocol::Protocol;

use super::aggregator::AggregatedFlow;

/// Statistics stored on each directed edge in the service graph.
#[derive(Debug, Clone)]
pub struct EdgeStats {
    pub protocol: Protocol,
    pub request_count: u64,
    pub error_count: u64,
    pub pii_hit_count: u64,
    pub avg_latency_ns: u64,
    pub max_latency_ns: u64,
    pub last_seen: u64,
}

/// Service dependency graph backed by petgraph `DiGraph`.
pub struct ServiceDag {
    graph: DiGraph<String, EdgeStats>,
    node_index: HashMap<String, NodeIndex>,
}

impl ServiceDag {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_index: HashMap::new(),
        }
    }

    /// Upsert nodes and edges from a batch of aggregated flows.
    pub fn update_edges(&mut self, flows: &[AggregatedFlow]) {
        for flow in flows {
            let src_idx = self.get_or_create_node(&flow.key.src);
            let dst_idx = self.get_or_create_node(&flow.key.dst);

            // Find existing edge with matching protocol
            let existing = self
                .graph
                .edges_connecting(src_idx, dst_idx)
                .find(|e| e.weight().protocol == flow.key.protocol);

            if let Some(edge) = existing {
                let edge_id = edge.id();
                let stats = self.graph.edge_weight_mut(edge_id).unwrap();

                // Merge: accumulate counts, update latency
                stats.request_count += flow.stats.request_count;
                stats.error_count += flow.stats.error_count;
                stats.pii_hit_count += flow.stats.pii_hit_count;

                // Recompute running average latency
                if flow.stats.request_count > 0 && flow.stats.latency_sum_ns > 0 {
                    let new_avg = flow.stats.latency_sum_ns / flow.stats.request_count;
                    stats.avg_latency_ns = (stats.avg_latency_ns + new_avg) / 2;
                }
                if flow.stats.latency_max_ns > stats.max_latency_ns {
                    stats.max_latency_ns = flow.stats.latency_max_ns;
                }
                stats.last_seen = flow.stats.last_seen;
            } else {
                // New edge
                let avg = if flow.stats.request_count > 0 {
                    flow.stats.latency_sum_ns / flow.stats.request_count
                } else {
                    0
                };
                self.graph.add_edge(
                    src_idx,
                    dst_idx,
                    EdgeStats {
                        protocol: flow.key.protocol,
                        request_count: flow.stats.request_count,
                        error_count: flow.stats.error_count,
                        pii_hit_count: flow.stats.pii_hit_count,
                        avg_latency_ns: avg,
                        max_latency_ns: flow.stats.latency_max_ns,
                        last_seen: flow.stats.last_seen,
                    },
                );
            }
        }
    }

    /// Get outgoing dependencies for a service.
    pub fn get_dependencies(&self, service: &str) -> Vec<(String, EdgeStats)> {
        let Some(&idx) = self.node_index.get(service) else {
            return Vec::new();
        };

        self.graph
            .edges_directed(idx, Direction::Outgoing)
            .map(|e| {
                let target = &self.graph[e.target()];
                (target.clone(), e.weight().clone())
            })
            .collect()
    }

    /// Get incoming dependents for a service.
    pub fn get_dependents(&self, service: &str) -> Vec<(String, EdgeStats)> {
        let Some(&idx) = self.node_index.get(service) else {
            return Vec::new();
        };

        self.graph
            .edges_directed(idx, Direction::Incoming)
            .map(|e| {
                let source = &self.graph[e.source()];
                (source.clone(), e.weight().clone())
            })
            .collect()
    }

    /// Remove edges not seen within `max_age` (based on `last_seen` timestamp).
    /// Also removes orphaned nodes with no remaining edges.
    pub fn prune_stale(&mut self, max_age: Duration, now_ns: u64) {
        let cutoff = now_ns.saturating_sub(max_age.as_nanos() as u64);

        // Collect stale edge indices
        let stale: Vec<_> = self
            .graph
            .edge_indices()
            .filter(|&e| self.graph[e].last_seen < cutoff)
            .collect();

        for edge_id in stale {
            self.graph.remove_edge(edge_id);
        }

        // Remove orphaned nodes (no incoming or outgoing edges)
        let orphans: Vec<_> = self
            .graph
            .node_indices()
            .filter(|&n| {
                self.graph
                    .edges_directed(n, Direction::Outgoing)
                    .next()
                    .is_none()
                    && self
                        .graph
                        .edges_directed(n, Direction::Incoming)
                        .next()
                        .is_none()
            })
            .collect();

        // Remove in reverse order to avoid index invalidation
        for idx in orphans.into_iter().rev() {
            let name = self.graph.remove_node(idx).unwrap();
            self.node_index.remove(&name);

            // After removal, the last node's index is swapped to `idx`.
            // We need to update node_index for the node that was moved.
            if let Some(moved_name) = self.graph.node_weight(idx) {
                self.node_index.insert(moved_name.clone(), idx);
            }
        }
    }

    pub fn node_count(&self) -> usize {
        self.graph.node_count()
    }

    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Export as adjacency list for external consumers (e.g., JSON export).
    pub fn to_adjacency_list(&self) -> Vec<(String, String, EdgeStats)> {
        self.graph
            .edge_indices()
            .filter_map(|e| {
                let (src, dst) = self.graph.edge_endpoints(e)?;
                let stats = self.graph[e].clone();
                Some((self.graph[src].clone(), self.graph[dst].clone(), stats))
            })
            .collect()
    }

    fn get_or_create_node(&mut self, name: &str) -> NodeIndex {
        if let Some(&idx) = self.node_index.get(name) {
            idx
        } else {
            let idx = self.graph.add_node(name.to_string());
            self.node_index.insert(name.to_string(), idx);
            idx
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::aggregator::{FlowKey, FlowStats};

    fn make_flow(
        src: &str,
        dst: &str,
        proto: Protocol,
        count: u64,
        last_seen: u64,
    ) -> AggregatedFlow {
        AggregatedFlow {
            key: FlowKey {
                src: src.to_string(),
                dst: dst.to_string(),
                protocol: proto,
                template: "GET /".to_string(),
            },
            stats: FlowStats {
                request_count: count,
                error_count: 0,
                pii_hit_count: 0,
                total_request_bytes: 100,
                total_response_bytes: 200,
                latency_sum_ns: 5000 * count,
                latency_max_ns: 8000,
                first_seen: 1,
                last_seen,
            },
        }
    }

    #[test]
    fn test_add_edge() {
        let mut dag = ServiceDag::new();
        let flows = vec![make_flow("nginx", "api", Protocol::Http1, 10, 100)];
        dag.update_edges(&flows);

        assert_eq!(dag.node_count(), 2);
        assert_eq!(dag.edge_count(), 1);
    }

    #[test]
    fn test_update_existing_edge() {
        let mut dag = ServiceDag::new();
        dag.update_edges(&[make_flow("nginx", "api", Protocol::Http1, 10, 100)]);
        dag.update_edges(&[make_flow("nginx", "api", Protocol::Http1, 5, 200)]);

        assert_eq!(dag.node_count(), 2);
        assert_eq!(dag.edge_count(), 1);

        let deps = dag.get_dependencies("nginx");
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].1.request_count, 15); // 10 + 5
        assert_eq!(deps[0].1.last_seen, 200);
    }

    #[test]
    fn test_get_dependencies() {
        let mut dag = ServiceDag::new();
        dag.update_edges(&[
            make_flow("nginx", "api", Protocol::Http1, 1, 100),
            make_flow("nginx", "postgres", Protocol::Postgres, 1, 100),
        ]);

        let deps = dag.get_dependencies("nginx");
        assert_eq!(deps.len(), 2);

        let names: Vec<_> = deps.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"api"));
        assert!(names.contains(&"postgres"));
    }

    #[test]
    fn test_get_dependents() {
        let mut dag = ServiceDag::new();
        dag.update_edges(&[
            make_flow("nginx", "api", Protocol::Http1, 1, 100),
            make_flow("worker", "api", Protocol::Http1, 1, 100),
        ]);

        let dependents = dag.get_dependents("api");
        assert_eq!(dependents.len(), 2);
    }

    #[test]
    fn test_prune_stale() {
        let mut dag = ServiceDag::new();
        dag.update_edges(&[
            make_flow("nginx", "api", Protocol::Http1, 1, 100),
            make_flow("worker", "redis", Protocol::Redis, 1, 500),
        ]);

        assert_eq!(dag.edge_count(), 2);

        // Prune with cutoff at 300ns — flow with last_seen=100 should be removed
        dag.prune_stale(Duration::from_nanos(200), 500);

        assert_eq!(dag.edge_count(), 1);
        assert!(dag.get_dependencies("nginx").is_empty());
        assert_eq!(dag.get_dependencies("worker").len(), 1);
    }

    #[test]
    fn test_node_edge_counts() {
        let mut dag = ServiceDag::new();
        assert_eq!(dag.node_count(), 0);
        assert_eq!(dag.edge_count(), 0);

        dag.update_edges(&[make_flow("a", "b", Protocol::Http1, 1, 1)]);
        assert_eq!(dag.node_count(), 2);
        assert_eq!(dag.edge_count(), 1);
    }

    #[test]
    fn test_to_adjacency_list() {
        let mut dag = ServiceDag::new();
        dag.update_edges(&[
            make_flow("nginx", "api", Protocol::Http1, 5, 100),
            make_flow("api", "postgres", Protocol::Postgres, 3, 100),
        ]);

        let adj = dag.to_adjacency_list();
        assert_eq!(adj.len(), 2);

        let edge_names: Vec<_> = adj
            .iter()
            .map(|(s, d, _)| (s.as_str(), d.as_str()))
            .collect();
        assert!(edge_names.contains(&("nginx", "api")));
        assert!(edge_names.contains(&("api", "postgres")));
    }
}
