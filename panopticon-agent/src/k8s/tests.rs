//! Tests against a fake Kubernetes API server (axum, plain HTTP) serving
//! realistic PodList / ServiceList / watch responses.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Value, json};

use super::*;
use crate::config::{KubernetesConfig, KubernetesMode};

fn ip(s: &str) -> u32 {
    u32::from(s.parse::<Ipv4Addr>().unwrap())
}

// ── Realistic object fixtures ────────────────────────────────────────────

struct PodSpecArgs<'a> {
    ns: &'a str,
    name: &'a str,
    owner: Option<(&'a str, &'a str)>,
    labels: Value,
    ips: &'a [&'a str],
    host_ip: &'a str,
    node: &'a str,
    host_network: bool,
    phase: &'a str,
    deleting: bool,
    created: &'a str,
    rv: &'a str,
}

fn pod(a: PodSpecArgs<'_>) -> Value {
    let owner_refs: Vec<Value> = a
        .owner
        .iter()
        .map(|(kind, name)| {
            json!({
                "apiVersion": if *kind == "Job" { "batch/v1" } else if *kind == "Node" { "v1" } else { "apps/v1" },
                "kind": kind, "name": name,
                "uid": "5b8f2c1e-0d6a-4f7e-9a51-3c2b1a0f9e8d",
                "controller": true, "blockOwnerDeletion": true
            })
        })
        .collect();
    let mut metadata = json!({
        "name": a.name,
        "generateName": format!("{}-", a.name),
        "namespace": a.ns,
        "uid": format!("uid-{}-{}", a.ns, a.name),
        "resourceVersion": a.rv,
        "creationTimestamp": a.created,
        "labels": a.labels,
        "annotations": {"kubectl.kubernetes.io/restartedAt": "2026-10-01T10:00:00Z"},
        "ownerReferences": owner_refs,
        "managedFields": [{"manager": "kube-controller-manager", "operation": "Update",
                           "apiVersion": "v1", "time": a.created, "fieldsType": "FieldsV1",
                           "fieldsV1": {"f:metadata": {"f:labels": {}}}}]
    });
    if a.deleting {
        metadata["deletionTimestamp"] = json!("2026-10-25T06:00:00Z");
        metadata["deletionGracePeriodSeconds"] = json!(30);
    }
    let pod_ips: Vec<Value> = a.ips.iter().map(|i| json!({"ip": i})).collect();
    let mut status = json!({
        "phase": a.phase,
        "conditions": [
            {"type": "Initialized", "status": "True", "lastProbeTime": null,
             "lastTransitionTime": a.created},
            {"type": "Ready", "status": "True", "lastProbeTime": null,
             "lastTransitionTime": a.created}
        ],
        "hostIP": a.host_ip,
        "hostIPs": [{"ip": a.host_ip}],
        "podIPs": pod_ips,
        "startTime": a.created,
        "containerStatuses": [{
            "name": "app", "ready": true, "restartCount": 0, "started": true,
            "image": "registry.example.com/app:1.2.3",
            "imageID": "registry.example.com/app@sha256:0123",
            "containerID": "containerd://abcdef",
            "state": {"running": {"startedAt": a.created}}
        }],
        "qosClass": "Burstable"
    });
    if let Some(first) = a.ips.first() {
        status["podIP"] = json!(first);
    }
    json!({
        "kind": "Pod",
        "apiVersion": "v1",
        "metadata": metadata,
        "spec": {
            "volumes": [{"name": "kube-api-access-x", "projected": {"sources": []}}],
            "containers": [{
                "name": "app", "image": "registry.example.com/app:1.2.3",
                "ports": [{"name": "http", "containerPort": 8080, "protocol": "TCP"}],
                "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}},
                "imagePullPolicy": "IfNotPresent"
            }],
            "restartPolicy": "Always",
            "terminationGracePeriodSeconds": 30,
            "dnsPolicy": if a.host_network { "ClusterFirstWithHostNet" } else { "ClusterFirst" },
            "serviceAccountName": "default",
            "nodeName": a.node,
            "hostNetwork": a.host_network,
            "securityContext": {},
            "schedulerName": "default-scheduler",
            "tolerations": [{"key": "node.kubernetes.io/not-ready", "operator": "Exists",
                             "effect": "NoExecute", "tolerationSeconds": 300}],
            "priority": 0,
            "enableServiceLinks": true,
            "preemptionPolicy": "PreemptLowerPriority"
        },
        "status": status
    })
}

fn service(ns: &str, name: &str, cluster_ip: &str) -> Value {
    let ips = if cluster_ip == "None" {
        json!(["None"])
    } else {
        json!([cluster_ip])
    };
    json!({
        "kind": "Service",
        "apiVersion": "v1",
        "metadata": {
            "name": name, "namespace": ns,
            "uid": format!("svc-uid-{ns}-{name}"),
            "resourceVersion": "1001",
            "creationTimestamp": "2026-09-01T00:00:00Z",
            "labels": {"app": name},
            "annotations": {}
        },
        "spec": {
            "ports": [{"name": "http", "protocol": "TCP", "port": 8080,
                       "targetPort": "http"}],
            "selector": {"app": name},
            "clusterIP": cluster_ip,
            "clusterIPs": ips,
            "type": "ClusterIP",
            "sessionAffinity": "None",
            "ipFamilies": ["IPv4"],
            "ipFamilyPolicy": "SingleStack",
            "internalTrafficPolicy": "Cluster"
        },
        "status": {"loadBalancer": {}}
    })
}

fn default_pods() -> Vec<Value> {
    vec![
        pod(PodSpecArgs {
            ns: "payments",
            name: "checkout-7d9f8b6c5d-x2k4p",
            owner: Some(("ReplicaSet", "checkout-7d9f8b6c5d")),
            labels: json!({"app": "checkout", "pod-template-hash": "7d9f8b6c5d"}),
            ips: &["10.244.1.5", "fd00:10:244:1::5"],
            host_ip: "192.168.10.11",
            node: "worker-1",
            host_network: false,
            phase: "Running",
            deleting: false,
            created: "2026-10-20T08:00:00Z",
            rv: "900",
        }),
        pod(PodSpecArgs {
            ns: "payments",
            name: "web-5c6d7e8f9a-abcde",
            owner: Some(("ReplicaSet", "web-5c6d7e8f9a")),
            labels: json!({"app": "web", "pod-template-hash": "5c6d7e8f9a"}),
            ips: &["10.244.2.7"],
            host_ip: "192.168.10.12",
            node: "worker-2",
            host_network: false,
            phase: "Running",
            deleting: false,
            created: "2026-10-20T08:00:00Z",
            rv: "901",
        }),
        pod(PodSpecArgs {
            ns: "data",
            name: "postgres-0",
            owner: Some(("StatefulSet", "postgres")),
            labels: json!({"app": "postgres",
                           "statefulset.kubernetes.io/pod-name": "postgres-0",
                           "controller-revision-hash": "postgres-6b8c9d"}),
            ips: &["10.244.1.9"],
            host_ip: "192.168.10.11",
            node: "worker-1",
            host_network: false,
            phase: "Running",
            deleting: false,
            created: "2026-10-01T00:00:00Z",
            rv: "902",
        }),
        // Host-network DaemonSet pod: its IP is the node's.
        pod(PodSpecArgs {
            ns: "kube-system",
            name: "kube-proxy-7xq2m",
            owner: Some(("DaemonSet", "kube-proxy")),
            labels: json!({"k8s-app": "kube-proxy",
                           "controller-revision-hash": "5d4c3b2a1",
                           "pod-template-generation": "1"}),
            ips: &["192.168.10.11"],
            host_ip: "192.168.10.11",
            node: "worker-1",
            host_network: true,
            phase: "Running",
            deleting: false,
            created: "2026-09-01T00:00:00Z",
            rv: "903",
        }),
        pod(PodSpecArgs {
            ns: "batch",
            name: "nightly-report-29345678-q8w7e",
            owner: Some(("Job", "nightly-report-29345678")),
            labels: json!({"batch.kubernetes.io/job-name": "nightly-report-29345678",
                           "job-name": "nightly-report-29345678"}),
            ips: &["10.244.2.30"],
            host_ip: "192.168.10.12",
            node: "worker-2",
            host_network: false,
            phase: "Running",
            deleting: false,
            created: "2026-10-25T02:00:00Z",
            rv: "904",
        }),
        // Terminating pod whose IP was already reused by a new pod below.
        pod(PodSpecArgs {
            ns: "payments",
            name: "old-worker-1",
            owner: None,
            labels: json!({}),
            ips: &["10.244.1.40"],
            host_ip: "192.168.10.11",
            node: "worker-1",
            host_network: false,
            phase: "Running",
            deleting: true,
            created: "2026-10-24T00:00:00Z",
            rv: "905",
        }),
        pod(PodSpecArgs {
            ns: "shipping",
            name: "tracker-6f7a8b9c0d-zzzzz",
            owner: Some(("ReplicaSet", "tracker-6f7a8b9c0d")),
            labels: json!({"pod-template-hash": "6f7a8b9c0d"}),
            ips: &["10.244.1.40"],
            host_ip: "192.168.10.11",
            node: "worker-1",
            host_network: false,
            phase: "Running",
            deleting: false,
            created: "2026-10-23T00:00:00Z",
            rv: "906",
        }),
        // Pending pod, no IP yet.
        pod(PodSpecArgs {
            ns: "payments",
            name: "pending-1",
            owner: None,
            labels: json!({}),
            ips: &[],
            host_ip: "192.168.10.12",
            node: "worker-2",
            host_network: false,
            phase: "Pending",
            deleting: false,
            created: "2026-10-25T06:00:00Z",
            rv: "907",
        }),
    ]
}

fn default_services() -> Vec<Value> {
    vec![
        service("payments", "checkout", "10.96.12.34"),
        service("data", "postgres-headless", "None"),
        service("default", "kubernetes", "10.96.0.1"),
    ]
}

// ── Fake API server ───────────────────────────────────────────────────────

#[derive(Default)]
struct Fake {
    pods: Vec<Value>,
    services: Vec<Value>,
    page_size: usize,
    list_rv: String,
    /// Respond with this status to every request.
    fail_with: Option<StatusCode>,
    /// Watch bodies for pods, one per watch request (newline-delimited).
    pod_watches: VecDeque<Vec<Value>>,
    requests: Vec<String>,
    auth: Vec<Option<String>>,
}

type Shared = Arc<Mutex<Fake>>;

async fn handle(
    State(state): State<Shared>,
    Path(resource): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let q: HashMap<String, String> = reqwest::Url::parse(&format!("http://fake{uri}"))
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();
    let watching = q.get("watch").is_some_and(|w| w == "1" || w == "true");
    let watch_body = {
        let mut f = state.lock().unwrap();
        let mut keys: Vec<_> = q.iter().map(|(k, v)| format!("{k}={v}")).collect();
        keys.sort();
        f.requests.push(format!("{resource}?{}", keys.join("&")));
        f.auth.push(
            headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
        );
        if let Some(code) = f.fail_with {
            let body = json!({"kind": "Status", "apiVersion": "v1", "status": "Failure",
                "message": format!("{resource} is forbidden: User \"system:serviceaccount:panopticon:panopticon\" cannot list resource \"{resource}\" in API group \"\" at the cluster scope"),
                "reason": "Forbidden", "code": code.as_u16()});
            return (code, axum::Json(body)).into_response();
        }
        if watching {
            Some(if resource == "pods" {
                f.pod_watches.pop_front()
            } else {
                None
            })
        } else {
            None
        }
    };
    if let Some(events) = watch_body {
        return match events {
            Some(events) => {
                let mut body = String::new();
                for e in events {
                    body.push_str(&e.to_string());
                    body.push('\n');
                }
                (StatusCode::OK, body).into_response()
            }
            None => {
                // Quiet watch: hold the stream a little, then end it.
                tokio::time::sleep(Duration::from_millis(300)).await;
                (StatusCode::OK, String::new()).into_response()
            }
        };
    }

    let f = state.lock().unwrap();
    let items = if resource == "pods" {
        &f.pods
    } else {
        &f.services
    };
    let page = f.page_size.max(1);
    let start: usize = q
        .get("continue")
        .and_then(|c| c.strip_prefix("page-"))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    let end = (start + page).min(items.len());
    let mut metadata = json!({"resourceVersion": f.list_rv});
    if end < items.len() {
        metadata["continue"] = json!(format!("page-{end}"));
        metadata["remainingItemCount"] = json!(items.len() - end);
    }
    let kind = if resource == "pods" {
        "PodList"
    } else {
        "ServiceList"
    };
    axum::Json(json!({
        "kind": kind, "apiVersion": "v1",
        "metadata": metadata,
        "items": items[start..end].to_vec(),
    }))
    .into_response()
}

async fn start_fake(fake: Fake) -> (String, Shared) {
    let state: Shared = Arc::new(Mutex::new(fake));
    let app = Router::new()
        .route("/api/v1/{resource}", get(handle))
        .with_state(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), state)
}

fn fake_with_defaults() -> Fake {
    Fake {
        pods: default_pods(),
        services: default_services(),
        page_size: 3,
        list_rv: "12345".to_string(),
        ..Fake::default()
    }
}

fn fast_opts() -> SyncOptions {
    SyncOptions {
        relist_interval: Duration::from_secs(30),
        watch: true,
        max_watch: Duration::from_secs(5),
        publish_interval: Duration::from_millis(20),
        max_backoff: Duration::from_millis(100),
        stale_after: Duration::from_secs(600),
    }
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !cond() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn display(meta: &K8sMetadata, addr: &str) -> Option<String> {
    meta.display(ip(addr)).map(|s| s.to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_list_paginates_and_builds_index() {
    let (base, state) = start_fake(fake_with_defaults()).await;
    let meta = K8sMetadata::new(&base);
    let tasks = meta.spawn_sync(ApiClient::plain_http(&base, Some("tok-123")), fast_opts());
    wait_for("services indexed", || {
        display(&meta, "10.96.12.34").is_some() && display(&meta, "10.244.1.5").is_some()
    })
    .await;

    // Deployment via ReplicaSet + pod-template-hash; dual-stack pod.
    assert_eq!(
        display(&meta, "10.244.1.5").as_deref(),
        Some("payments/checkout")
    );
    let ep = meta.lookup(ip("10.244.1.5")).unwrap();
    assert_eq!(ep.kind, EndpointKind::Pod);
    assert_eq!(ep.workload_kind, "Deployment");
    assert_eq!(ep.pod.as_deref(), Some("checkout-7d9f8b6c5d-x2k4p"));
    assert_eq!(ep.node.as_deref(), Some("worker-1"));
    assert_eq!(
        display(&meta, "10.244.2.7").as_deref(),
        Some("payments/web")
    );
    assert_eq!(
        display(&meta, "10.244.1.9").as_deref(),
        Some("data/postgres")
    );
    assert_eq!(
        display(&meta, "10.244.2.30").as_deref(),
        Some("batch/nightly-report")
    );
    // IP reused: the live pod wins over the terminating one.
    assert_eq!(
        display(&meta, "10.244.1.40").as_deref(),
        Some("shipping/tracker")
    );
    // Host-network pod: the IP names the node, not kube-proxy.
    assert_eq!(
        display(&meta, "192.168.10.11").as_deref(),
        Some("node:worker-1")
    );
    assert_eq!(
        display(&meta, "192.168.10.12").as_deref(),
        Some("node:worker-2")
    );
    // Services; headless has no IP.
    assert_eq!(
        display(&meta, "10.96.12.34").as_deref(),
        Some("svc:payments/checkout")
    );
    assert_eq!(
        display(&meta, "10.96.0.1").as_deref(),
        Some("svc:default/kubernetes")
    );
    assert!(display(&meta, "8.8.8.8").is_none());
    assert!(meta.is_synced());

    let f = state.lock().unwrap();
    let pod_lists: Vec<&String> = f
        .requests
        .iter()
        .filter(|r| r.starts_with("pods?") && !r.contains("watch="))
        .collect();
    // 8 pods, 3 per page: 3 pages, the later ones with continue tokens.
    assert_eq!(pod_lists.len(), 3, "{pod_lists:?}");
    assert!(pod_lists[0].contains("limit=500"));
    assert!(!pod_lists[0].contains("continue="));
    assert!(pod_lists[1].contains("continue=page-3"));
    assert!(pod_lists[2].contains("continue=page-6"));
    assert!(pod_lists[0].contains("fieldSelector=status.phase!=Succeeded,status.phase!=Failed"));
    assert!(
        f.auth
            .iter()
            .all(|a| a.as_deref() == Some("Bearer tok-123")),
        "{:?}",
        f.auth
    );
    drop(f);
    for t in tasks {
        t.abort();
    }
}

#[tokio::test]
async fn test_watch_applies_changes_and_resumes_from_list_rv() {
    let mut fake = fake_with_defaults();
    let mut added = pod(PodSpecArgs {
        ns: "payments",
        name: "fraud-6d5c4b3a2-aaaaa",
        owner: Some(("ReplicaSet", "fraud-6d5c4b3a2")),
        labels: json!({"pod-template-hash": "6d5c4b3a2"}),
        ips: &["10.244.2.50"],
        host_ip: "192.168.10.12",
        node: "worker-2",
        host_network: false,
        phase: "Running",
        deleting: false,
        created: "2026-10-25T07:00:00Z",
        rv: "12346",
    });
    added["metadata"]["resourceVersion"] = json!("12346");
    let mut deleted = default_pods()[1].clone(); // payments/web at 10.244.2.7
    deleted["metadata"]["resourceVersion"] = json!("12347");
    // checkout pod finished: its IP must disappear.
    let mut finished = default_pods()[0].clone();
    finished["status"]["phase"] = json!("Succeeded");
    finished["metadata"]["resourceVersion"] = json!("12348");
    fake.pod_watches.push_back(vec![
        json!({"type": "ADDED", "object": added}),
        json!({"type": "DELETED", "object": deleted}),
        json!({"type": "MODIFIED", "object": finished}),
        json!({"type": "BOOKMARK", "object": {"kind": "Pod", "apiVersion": "v1",
               "metadata": {"resourceVersion": "12350",
                 "annotations": {"k8s.io/initial-events-end": "true"}}}}),
    ]);
    let (base, state) = start_fake(fake).await;
    let meta = K8sMetadata::new(&base);
    let tasks = meta.spawn_sync(ApiClient::plain_http(&base, None), fast_opts());

    wait_for("watch ADDED applied", || {
        display(&meta, "10.244.2.50").as_deref() == Some("payments/fraud")
    })
    .await;
    wait_for("watch DELETED/MODIFIED applied", || {
        display(&meta, "10.244.2.7").is_none() && display(&meta, "10.244.1.5").is_none()
    })
    .await;
    assert_eq!(
        display(&meta, "10.244.1.9").as_deref(),
        Some("data/postgres")
    );

    // The first pod watch starts at the list RV; the next resumes at the
    // bookmark's.
    wait_for("second pod watch", || {
        state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| r.starts_with("pods?") && r.contains("watch=1"))
            .count()
            >= 2
    })
    .await;
    let f = state.lock().unwrap();
    let watches: Vec<&String> = f
        .requests
        .iter()
        .filter(|r| r.starts_with("pods?") && r.contains("watch=1"))
        .collect();
    assert!(watches[0].contains("resourceVersion=12345"), "{watches:?}");
    assert!(watches[0].contains("allowWatchBookmarks=true"));
    assert!(watches[1].contains("resourceVersion=12350"), "{watches:?}");
    drop(f);
    for t in tasks {
        t.abort();
    }
}

#[tokio::test]
async fn test_watch_gone_triggers_relist() {
    let mut fake = fake_with_defaults();
    fake.pod_watches
        .push_back(vec![json!({"type": "ERROR", "object": {
        "kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Failure",
        "message": "too old resource version: 12345 (12999)", "reason": "Expired",
        "code": 410}})]);
    let (base, state) = start_fake(fake).await;
    let meta = K8sMetadata::new(&base);
    let tasks = meta.spawn_sync(ApiClient::plain_http(&base, None), fast_opts());
    wait_for("re-list after 410", || {
        state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| r.starts_with("pods?") && !r.contains("watch=") && !r.contains("continue="))
            .count()
            >= 2
    })
    .await;
    wait_for("synced", || meta.is_synced()).await;
    for t in tasks {
        t.abort();
    }
}

#[tokio::test]
async fn test_forbidden_degrades_then_recovers() {
    let mut fake = fake_with_defaults();
    fake.fail_with = Some(StatusCode::FORBIDDEN);
    let (base, state) = start_fake(fake).await;
    let meta = K8sMetadata::new(&base);
    let tasks = meta.spawn_sync(ApiClient::plain_http(&base, None), fast_opts());
    wait_for("failures counted", || meta.failures() >= 4).await;
    assert!(!meta.is_synced());
    assert!(meta.lookup(ip("10.244.1.5")).is_none());

    // RBAC fixed: the next retry succeeds.
    state.lock().unwrap().fail_with = None;
    wait_for("recovered", || display(&meta, "10.244.1.5").is_some()).await;
    for t in tasks {
        t.abort();
    }
}

#[tokio::test]
async fn test_api_down_never_blocks_or_panics() {
    // Bind then drop a listener: the port refuses connections.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let meta = K8sMetadata::new(&base);
    let tasks = meta.spawn_sync(ApiClient::plain_http(&base, None), fast_opts());
    wait_for("failures counted", || meta.failures() >= 3).await;
    assert!(!meta.is_synced());
    assert!(meta.snapshot().is_empty());
    for t in tasks {
        assert!(!t.is_finished(), "sync tasks keep retrying");
        t.abort();
    }
}

#[tokio::test]
async fn test_stale_metadata_is_dropped() {
    let (base, state) = start_fake(fake_with_defaults()).await;
    let meta = K8sMetadata::new(&base);
    let opts = SyncOptions {
        relist_interval: Duration::from_millis(200),
        watch: false,
        stale_after: Duration::from_millis(500),
        ..fast_opts()
    };
    let tasks = meta.spawn_sync(ApiClient::plain_http(&base, None), opts);
    wait_for("synced", || display(&meta, "10.244.1.5").is_some()).await;
    state.lock().unwrap().fail_with = Some(StatusCode::SERVICE_UNAVAILABLE);
    wait_for("stale index dropped", || meta.snapshot().is_empty()).await;
    for t in tasks {
        t.abort();
    }
}

#[tokio::test]
async fn test_polling_mode_picks_up_ip_reuse() {
    let (base, state) = start_fake(fake_with_defaults()).await;
    let meta = K8sMetadata::new(&base);
    let opts = SyncOptions {
        relist_interval: Duration::from_millis(200),
        watch: false,
        ..fast_opts()
    };
    let tasks = meta.spawn_sync(ApiClient::plain_http(&base, None), opts);
    wait_for("synced", || {
        display(&meta, "10.244.2.7").as_deref() == Some("payments/web")
    })
    .await;
    // web's pod is gone and its IP now belongs to a pod in another namespace.
    {
        let mut f = state.lock().unwrap();
        f.pods.remove(1);
        f.pods.push(pod(PodSpecArgs {
            ns: "search",
            name: "indexer-0",
            owner: Some(("StatefulSet", "indexer")),
            labels: json!({}),
            ips: &["10.244.2.7"],
            host_ip: "192.168.10.12",
            node: "worker-2",
            host_network: false,
            phase: "Running",
            deleting: false,
            created: "2026-10-25T08:00:00Z",
            rv: "2000",
        }));
    }
    wait_for("re-listed", || {
        display(&meta, "10.244.2.7").as_deref() == Some("search/indexer")
    })
    .await;
    assert!(
        state
            .lock()
            .unwrap()
            .requests
            .iter()
            .all(|r| !r.contains("watch=")),
        "watch = false must not watch"
    );
    for t in tasks {
        t.abort();
    }
}

// ── Mode resolution ───────────────────────────────────────────────────────

fn sa_dir(tag: &str, token: bool, ca: bool) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("panopticon-k8s-mode-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    if token {
        std::fs::write(dir.join("token"), "t").unwrap();
    }
    if ca {
        std::fs::write(dir.join("ca.crt"), include_str!("testdata/ca.crt")).unwrap();
    }
    dir
}

fn cfg(mode: KubernetesMode) -> KubernetesConfig {
    KubernetesConfig {
        mode,
        ..KubernetesConfig::default()
    }
}

#[tokio::test]
async fn test_mode_resolution() {
    let no_env = ClusterEnv {
        service_host: None,
        service_port: None,
        service_account_dir: "/nonexistent".into(),
    };
    assert!(K8sMetadata::start_with_env(&cfg(KubernetesMode::Auto), &no_env).is_none());
    assert!(K8sMetadata::start_with_env(&cfg(KubernetesMode::Enabled), &no_env).is_none());

    let dir = sa_dir("full", true, true);
    // Port 1 on loopback: refused immediately, never a real API server.
    let env = ClusterEnv {
        service_host: Some("127.0.0.1".into()),
        service_port: Some("1".into()),
        service_account_dir: dir.clone(),
    };
    assert!(K8sMetadata::start_with_env(&cfg(KubernetesMode::Disabled), &env).is_none());
    let meta = K8sMetadata::start_with_env(&cfg(KubernetesMode::Auto), &env)
        .expect("auto turns on in a pod");
    assert!(!meta.is_synced());
    wait_for("failure recorded", || meta.failures() >= 1).await;
    assert!(meta.lookup(ip("10.244.1.5")).is_none());

    // Token mounted but CA missing: enabled degrades instead of failing.
    let dir2 = sa_dir("noca", true, false);
    let env2 = ClusterEnv {
        service_account_dir: dir2.clone(),
        ..env.clone()
    };
    assert!(K8sMetadata::start_with_env(&cfg(KubernetesMode::Enabled), &env2).is_none());
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(dir2);
}
