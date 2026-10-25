//! Minimal Kubernetes API object shapes and the pod → workload mapping.
//!
//! Only the fields identity resolution needs are deserialized; serde skips
//! everything else, so a PodList page costs little more than its JSON text
//! while it is parsed and nothing afterwards.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use serde::Deserialize;

// ── Wire types ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ObjectList<T> {
    #[serde(default)]
    pub metadata: ListMeta,
    #[serde(default = "Vec::new")]
    pub items: Vec<T>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListMeta {
    #[serde(rename = "resourceVersion", default)]
    pub resource_version: Option<String>,
    #[serde(rename = "continue", default)]
    pub continue_token: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct ObjectMeta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(rename = "resourceVersion", default)]
    pub resource_version: Option<String>,
    #[serde(rename = "creationTimestamp", default)]
    pub creation_timestamp: Option<String>,
    #[serde(rename = "deletionTimestamp", default)]
    pub deletion_timestamp: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(rename = "ownerReferences", default)]
    pub owner_references: Vec<OwnerReference>,
}

#[derive(Debug, Default, Deserialize)]
pub struct OwnerReference {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub controller: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Pod {
    #[serde(default)]
    pub metadata: ObjectMeta,
    #[serde(default)]
    pub spec: PodSpec,
    #[serde(default)]
    pub status: PodStatus,
}

#[derive(Debug, Default, Deserialize)]
pub struct PodSpec {
    #[serde(rename = "nodeName", default)]
    pub node_name: Option<String>,
    #[serde(rename = "hostNetwork", default)]
    pub host_network: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PodStatus {
    #[serde(default)]
    pub phase: Option<String>,
    #[serde(rename = "podIP", default)]
    pub pod_ip: Option<String>,
    #[serde(rename = "podIPs", default)]
    pub pod_ips: Vec<IpEntry>,
    #[serde(rename = "hostIP", default)]
    pub host_ip: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct IpEntry {
    #[serde(default)]
    pub ip: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct Service {
    #[serde(default)]
    pub metadata: ObjectMeta,
    #[serde(default)]
    pub spec: ServiceSpec,
}

#[derive(Debug, Default, Deserialize)]
pub struct ServiceSpec {
    #[serde(rename = "clusterIP", default)]
    pub cluster_ip: Option<String>,
    #[serde(rename = "clusterIPs", default)]
    pub cluster_ips: Vec<String>,
}

/// One line of a watch stream. `object` is kept as a `Value` because its
/// shape depends on `type` (an object, a bookmark, or a `Status` on ERROR).
#[derive(Debug, Deserialize)]
pub struct WatchEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub object: serde_json::Value,
}

// ── Compact records kept between syncs ───────────────────────────────────

/// What identity resolution keeps about a pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodRecord {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub workload_kind: &'static str,
    pub workload_name: Arc<str>,
    pub node: Option<Arc<str>>,
    pub ips: Vec<u32>,
    pub host_ip: Option<u32>,
    pub host_network: bool,
    pub terminating: bool,
    /// RFC 3339, `Z` suffix: orders lexicographically.
    pub created: Option<String>,
}

/// What identity resolution keeps about a Service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecord {
    pub namespace: Arc<str>,
    pub name: Arc<str>,
    pub cluster_ips: Vec<u32>,
}

/// Parse an IPv4 address; IPv6 and malformed addresses yield `None`
/// (identity resolution is IPv4-only, like the capture path).
pub fn parse_ipv4(s: &str) -> Option<u32> {
    s.parse::<Ipv4Addr>().ok().map(u32::from)
}

impl Pod {
    /// The store key: `namespace/name`.
    pub fn key(&self) -> String {
        format!("{}/{}", self.metadata.namespace, self.metadata.name)
    }

    /// Whether the pod's IP has been released (finished pods).
    pub fn is_finished(&self) -> bool {
        matches!(
            self.status.phase.as_deref(),
            Some("Succeeded") | Some("Failed")
        )
    }

    /// Convert to the compact record, or `None` for pods that cannot own an
    /// IP (finished, or without a name).
    pub fn to_record(&self) -> Option<PodRecord> {
        if self.metadata.name.is_empty() || self.is_finished() {
            return None;
        }
        let mut ips: Vec<u32> = self
            .status
            .pod_ips
            .iter()
            .filter_map(|e| parse_ipv4(&e.ip))
            .collect();
        if let Some(ip) = self.status.pod_ip.as_deref().and_then(parse_ipv4)
            && !ips.contains(&ip)
        {
            ips.push(ip);
        }
        let (workload_kind, workload_name) = workload_of(self);
        Some(PodRecord {
            namespace: Arc::from(self.metadata.namespace.as_str()),
            name: Arc::from(self.metadata.name.as_str()),
            workload_kind,
            workload_name: Arc::from(workload_name.as_str()),
            node: self.spec.node_name.as_deref().map(Arc::from),
            ips,
            host_ip: self.status.host_ip.as_deref().and_then(parse_ipv4),
            host_network: self.spec.host_network.unwrap_or(false),
            terminating: self.metadata.deletion_timestamp.is_some(),
            created: self.metadata.creation_timestamp.clone(),
        })
    }
}

impl Service {
    pub fn key(&self) -> String {
        format!("{}/{}", self.metadata.namespace, self.metadata.name)
    }

    /// Convert to the compact record. Headless (`None`) and ExternalName
    /// services have no cluster IP and yield an empty `cluster_ips`.
    pub fn to_record(&self) -> Option<ServiceRecord> {
        if self.metadata.name.is_empty() {
            return None;
        }
        let mut cluster_ips: Vec<u32> = self
            .spec
            .cluster_ips
            .iter()
            .filter_map(|s| parse_ipv4(s))
            .collect();
        if let Some(ip) = self.spec.cluster_ip.as_deref().and_then(parse_ipv4)
            && !cluster_ips.contains(&ip)
        {
            cluster_ips.push(ip);
        }
        Some(ServiceRecord {
            namespace: Arc::from(self.metadata.namespace.as_str()),
            name: Arc::from(self.metadata.name.as_str()),
            cluster_ips,
        })
    }
}

/// The workload a pod belongs to, from its controller owner reference.
///
/// - ReplicaSet `<deploy>-<pod-template-hash>` → Deployment `<deploy>`
///   (the hash is the pod's `pod-template-hash` label); any other
///   ReplicaSet stays a ReplicaSet.
/// - StatefulSet, DaemonSet → themselves.
/// - Job `<cronjob>-<digits>` (8+ digits: the scheduled time in minutes,
///   which is how the CronJob controller names Jobs) → CronJob `<cronjob>`;
///   other Jobs stay Jobs. This is a naming heuristic: the pod does not
///   reference the CronJob, and listing Jobs would need more API access.
/// - Node (static/mirror pods, named `<name>-<node>`) → StaticPod `<name>`.
/// - Other controllers (operators, Argo Rollouts...) → the owner as-is.
/// - No owner (bare pod) → Pod `<pod name>`.
pub fn workload_of(pod: &Pod) -> (&'static str, String) {
    let meta = &pod.metadata;
    let owner = meta
        .owner_references
        .iter()
        .find(|o| o.controller == Some(true))
        .or_else(|| meta.owner_references.first());
    let Some(owner) = owner else {
        return ("Pod", meta.name.clone());
    };
    match owner.kind.as_str() {
        "ReplicaSet" => {
            if let Some(hash) = meta.labels.get("pod-template-hash")
                && !hash.is_empty()
                && let Some(base) = owner
                    .name
                    .strip_suffix(hash.as_str())
                    .and_then(|s| s.strip_suffix('-'))
                && !base.is_empty()
            {
                return ("Deployment", base.to_string());
            }
            ("ReplicaSet", owner.name.clone())
        }
        "StatefulSet" => ("StatefulSet", owner.name.clone()),
        "DaemonSet" => ("DaemonSet", owner.name.clone()),
        "Job" => match cronjob_base(&owner.name) {
            Some(base) => ("CronJob", base.to_string()),
            None => ("Job", owner.name.clone()),
        },
        "Node" => {
            let base = pod
                .spec
                .node_name
                .as_deref()
                .and_then(|node| meta.name.strip_suffix(node))
                .and_then(|s| s.strip_suffix('-'))
                .filter(|s| !s.is_empty())
                .unwrap_or(&meta.name);
            ("StaticPod", base.to_string())
        }
        "" => ("Pod", meta.name.clone()),
        _ => ("Other", owner.name.clone()),
    }
}

fn cronjob_base(job: &str) -> Option<&str> {
    let (base, suffix) = job.rsplit_once('-')?;
    (suffix.len() >= 8 && suffix.bytes().all(|b| b.is_ascii_digit()) && !base.is_empty())
        .then_some(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod_json(owner_kind: &str, owner_name: &str, labels: &str) -> Pod {
        let json = format!(
            r#"{{
              "metadata": {{
                "name": "p", "namespace": "ns",
                "labels": {labels},
                "ownerReferences": [{{"apiVersion": "apps/v1", "kind": "{owner_kind}",
                  "name": "{owner_name}", "uid": "u", "controller": true,
                  "blockOwnerDeletion": true}}]
              }},
              "spec": {{"nodeName": "node-1"}},
              "status": {{"phase": "Running", "podIP": "10.244.1.5"}}
            }}"#
        );
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn test_replicaset_with_template_hash_is_deployment() {
        let pod = pod_json(
            "ReplicaSet",
            "checkout-7d9f8b6c5d",
            r#"{"app": "checkout", "pod-template-hash": "7d9f8b6c5d"}"#,
        );
        assert_eq!(workload_of(&pod), ("Deployment", "checkout".to_string()));
    }

    #[test]
    fn test_deployment_name_with_dashes() {
        let pod = pod_json(
            "ReplicaSet",
            "payments-api-v2-5f6b7c8d9",
            r#"{"pod-template-hash": "5f6b7c8d9"}"#,
        );
        assert_eq!(
            workload_of(&pod),
            ("Deployment", "payments-api-v2".to_string())
        );
    }

    #[test]
    fn test_replicaset_without_matching_hash_stays_replicaset() {
        let pod = pod_json("ReplicaSet", "standalone-rs", r#"{}"#);
        assert_eq!(
            workload_of(&pod),
            ("ReplicaSet", "standalone-rs".to_string())
        );
        let pod = pod_json("ReplicaSet", "rs-abc", r#"{"pod-template-hash": "zzz"}"#);
        assert_eq!(workload_of(&pod), ("ReplicaSet", "rs-abc".to_string()));
    }

    #[test]
    fn test_statefulset_and_daemonset() {
        let pod = pod_json("StatefulSet", "postgres", r#"{}"#);
        assert_eq!(workload_of(&pod), ("StatefulSet", "postgres".to_string()));
        let pod = pod_json("DaemonSet", "fluent-bit", r#"{}"#);
        assert_eq!(workload_of(&pod), ("DaemonSet", "fluent-bit".to_string()));
    }

    #[test]
    fn test_job_and_cronjob() {
        let pod = pod_json("Job", "db-migrate", r#"{"job-name": "db-migrate"}"#);
        assert_eq!(workload_of(&pod), ("Job", "db-migrate".to_string()));
        let pod = pod_json("Job", "nightly-report-29345678", r#"{}"#);
        assert_eq!(workload_of(&pod), ("CronJob", "nightly-report".to_string()));
        // Short numeric suffixes are not CronJob schedule times.
        let pod = pod_json("Job", "import-42", r#"{}"#);
        assert_eq!(workload_of(&pod), ("Job", "import-42".to_string()));
    }

    #[test]
    fn test_static_pod_strips_node_suffix() {
        let mut pod = pod_json("Node", "node-1", r#"{}"#);
        pod.metadata.name = "kube-apiserver-node-1".to_string();
        assert_eq!(
            workload_of(&pod),
            ("StaticPod", "kube-apiserver".to_string())
        );
    }

    #[test]
    fn test_bare_pod_and_custom_owner() {
        let pod: Pod =
            serde_json::from_str(r#"{"metadata": {"name": "debug", "namespace": "ns"}}"#).unwrap();
        assert_eq!(workload_of(&pod), ("Pod", "debug".to_string()));
        let pod = pod_json("Rollout", "web-rollout", r#"{}"#);
        assert_eq!(workload_of(&pod), ("Other", "web-rollout".to_string()));
    }

    #[test]
    fn test_non_controller_owner_used_only_as_fallback() {
        let json = r#"{"metadata": {"name": "p", "namespace": "ns",
            "ownerReferences": [
              {"kind": "ConfigMap", "name": "cm"},
              {"kind": "StatefulSet", "name": "kafka", "controller": true}
            ]}}"#;
        let pod: Pod = serde_json::from_str(json).unwrap();
        assert_eq!(workload_of(&pod), ("StatefulSet", "kafka".to_string()));
    }

    #[test]
    fn test_pod_record_ips_dual_stack_and_finished() {
        let json = r#"{"metadata": {"name": "p", "namespace": "ns"},
            "spec": {"nodeName": "n1"},
            "status": {"phase": "Running", "hostIP": "192.168.0.10",
              "podIP": "10.244.0.7",
              "podIPs": [{"ip": "10.244.0.7"}, {"ip": "fd00:10:244::7"}]}}"#;
        let pod: Pod = serde_json::from_str(json).unwrap();
        let rec = pod.to_record().unwrap();
        assert_eq!(rec.ips, vec![u32::from(Ipv4Addr::new(10, 244, 0, 7))]);
        assert_eq!(rec.host_ip, Some(u32::from(Ipv4Addr::new(192, 168, 0, 10))));
        assert!(!rec.host_network);

        let done: Pod = serde_json::from_str(
            r#"{"metadata": {"name": "p", "namespace": "ns"},
                "status": {"phase": "Succeeded", "podIP": "10.244.0.8"}}"#,
        )
        .unwrap();
        assert!(done.to_record().is_none());
    }

    #[test]
    fn test_service_record_cluster_ips() {
        let json = r#"{"metadata": {"name": "checkout", "namespace": "payments"},
            "spec": {"type": "ClusterIP", "clusterIP": "10.96.12.34",
              "clusterIPs": ["10.96.12.34", "fd00:10:96::1234"],
              "ports": [{"port": 8080, "protocol": "TCP", "targetPort": 8080}]}}"#;
        let svc: Service = serde_json::from_str(json).unwrap();
        let rec = svc.to_record().unwrap();
        assert_eq!(
            rec.cluster_ips,
            vec![u32::from(Ipv4Addr::new(10, 96, 12, 34))]
        );

        let headless: Service = serde_json::from_str(
            r#"{"metadata": {"name": "db", "namespace": "ns"},
                "spec": {"clusterIP": "None", "clusterIPs": ["None"]}}"#,
        )
        .unwrap();
        assert!(headless.to_record().unwrap().cluster_ips.is_empty());
    }
}
