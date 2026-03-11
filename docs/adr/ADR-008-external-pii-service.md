# ADR-008: External PII Service Architecture

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-02-19 |
| **Decision Makers** | @panopticon-team |
| **Affected Components** | `panopticon-agent/src/pii/external.rs`, `pii-service/` |
| **Supersedes** | None |
| **Superseded by** | None |

## Context

### The Problem

Some deployments cannot run ML inference in the agent due to:
1. **Resource constraints**: Edge devices, low-memory nodes
2. **Model sharing**: Centralized model reduces total memory footprint
3. **Model updates**: Single service easier to update than 100 agents
4. **Compliance isolation**: PII processing isolated to approved service

### Requirements

| Requirement | Constraint |
|-------------|------------|
| Network latency | < 100ms P99 round-trip |
| Availability | 99.9% uptime target |
| Memory savings | Agent < 50MB (no model) |
| Throughput | 100K requests/sec service capacity |
| Sampling | 1% default (configurable) |

### Deployment Scenarios

| Scenario | Agent Mode | Reason |
|----------|------------|--------|
| Kubernetes DaemonSet | In-Agent ONNX | High throughput, local inference |
| Edge devices | External Service | Insufficient memory for model |
| Multi-tenant clusters | External Service | Model sharing across namespaces |
| Air-gapped environments | In-Agent ONNX | No external network access |

## Decision

Support **both** in-agent ONNX and external HTTP service, selected by configuration.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        DEPLOYMENT MODE A: IN-AGENT                           │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                           AGENT                                      │   │
│   │                                                                      │   │
│   │   L7Message ──► Regex ──► Sampler ──► ONNX ──► Redact ──► Export   │   │
│   │                                │                                     │   │
│   │                                ▼                                     │   │
│   │                         DistilBERT-NER                               │   │
│   │                         (~250MB)                                     │   │
│   │                                                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│   Memory: ~300MB (agent + model)                                            │
│   Latency: < 50ms P99                                                        │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                     DEPLOYMENT MODE B: EXTERNAL SERVICE                      │
│                                                                              │
│   ┌───────────────────────────────────┐    ┌─────────────────────────────┐ │
│   │           AGENT                    │    │     PII SERVICE             │ │
│   │                                    │    │                             │ │
│   │   L7Message ──► Regex ──► Sampler │    │  ┌───────────────────────┐  │ │
│   │               │           │       │    │  │   DistilBERT-NER      │  │ │
│   │               │           │       │    │  │   BERT-large option   │  │ │
│   │               │           ▼       │    │  │   Presidio integration│  │ │
│   │               │    Hash Dedup ────┼───►│  └───────────────────────┘  │ │
│   │               │           │       │    │             │               │ │
│   │               │           ▼       │    │             ▼               │ │
│   │               │    HTTP POST      │    │        Inference            │ │
│   │               │    /scan          │    │             │               │ │
│   │               │           │       │◄───┼─────────────┘               │ │
│   │               │           ▼       │    │                             │ │
│   │               │      Redact      │    │  Memory: ~2GB (shared model) │ │
│   │               │           │       │    │  Latency: < 100ms P99       │ │
│   │               │           ▼       │    │                             │ │
│   │               │        Export     │    └─────────────────────────────┘ │
│   │               │                   │                                     │
│   │   Memory: ~50MB (no model)        │                                     │
│   └───────────────────────────────────┘                                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### API Specification

#### Request

```http
POST /scan HTTP/1.1
Host: pii-service.internal:8080
Content-Type: application/json
X-Request-ID: abc123

{
  "payload": "SELECT * FROM users WHERE email='john@example.com' AND ssn='123-45-6789'",
  "payload_hash": "e3b0c44298fc1c149afbf4c8996fb924",
  "metadata": {
    "protocol": "mysql",
    "timestamp_ns": 1739952000000000000,
    "connection_id": 12345
  },
  "options": {
    "include_context": true,
    "redaction_policy": "hash"
  }
}
```

#### Response

```http
HTTP/1.1 200 OK
Content-Type: application/json
X-Request-ID: abc123
X-Inference-Time-Ms: 23

{
  "has_pii": true,
  "entities": [
    {
      "type": "EMAIL",
      "text": "john@example.com",
      "start": 34,
      "end": 52,
      "confidence": 0.98,
      "detection_method": "regex"
    },
    {
      "type": "SSN",
      "text": "123-45-6789",
      "start": 63,
      "end": 75,
      "confidence": 0.95,
      "detection_method": "regex"
    }
  ],
  "redacted_payload": "SELECT * FROM users WHERE email='[REDACTED:a1b2c3]' AND ssn='[REDACTED:d4e5f6]'",
  "inference_time_ms": 23
}
```

### Agent Configuration

```rust
pub enum PiiMode {
    InAgent {
        model_path: PathBuf,
        tokenizer_path: PathBuf,
        sample_rate: f64,
        max_inferences_per_sec: u64,
    },
    External {
        service_url: String,
        sample_rate: f64,
        timeout_ms: u64,
        retry_count: u32,
        hash_dedup: bool,
    },
}

impl Default for PiiMode {
    fn default() -> Self {
        PiiMode::InAgent {
            model_path: PathBuf::from("models/distilbert-ner/model.onnx"),
            tokenizer_path: PathBuf::from("models/distilbert-ner/tokenizer.json"),
            sample_rate: 0.01,
            max_inferences_per_sec: 1000,
        }
    }
}
```

### Hash-Based Deduplication

Avoid redundant network calls for identical payloads:

```rust
pub struct ExternalPiiClient {
    http_client: reqwest::Client,
    service_url: String,
    seen_hashes: DashMap<u64, PiiReport>,
    hash_ttl: Duration,
}

impl ExternalPiiClient {
    pub async fn scan(&self, payload: &str) -> Result<PiiReport> {
        // Compute hash
        let hash = blake3::hash(payload.as_bytes());
        let hash_u64 = u64::from_be_bytes(hash.as_bytes()[..8].try_into().unwrap());
        
        // Check cache
        if let Some(report) = self.seen_hashes.get(&hash_u64) {
            return Ok(report.clone());
        }
        
        // Network call
        let response = self.http_client
            .post(&format!("{}/scan", self.service_url))
            .json(&ScanRequest {
                payload,
                payload_hash: hex::encode(&hash.as_bytes()[..16]),
                metadata: None,
                options: None,
            })
            .timeout(Duration::from_millis(100))
            .send()
            .await?;
        
        let report: PiiReport = response.json().await?;
        
        // Cache result
        self.seen_hashes.insert(hash_u64, report.clone());
        
        Ok(report)
    }
}
```

### Service Unavailability Handling

```rust
pub struct FallbackPiiClient {
    external: ExternalPiiClient,
    local_regex: RegexPrefilter,
    circuit_breaker: CircuitBreaker,
}

impl FallbackPiiClient {
    pub async fn scan(&self, payload: &str) -> PiiReport {
        // Always run local regex
        let regex_matches = self.local_regex.scan(payload);
        
        // Check circuit breaker
        if self.circuit_breaker.is_open() {
            tracing::warn!("PII service unavailable, using regex-only results");
            return PiiReport::from_regex(regex_matches);
        }
        
        // Try external service
        match self.external.scan(payload).await {
            Ok(report) => {
                self.circuit_breaker.record_success();
                report
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                tracing::warn!(error = %e, "PII service error, falling back to regex");
                PiiReport::from_regex(regex_matches)
            }
        }
    }
}

pub struct CircuitBreaker {
    failure_count: AtomicU32,
    failure_threshold: u32,
    last_failure: AtomicU64,
    cooldown_ms: u64,
}

impl CircuitBreaker {
    pub fn is_open(&self) -> bool {
        let failures = self.failure_count.load(Ordering::Relaxed);
        if failures < self.failure_threshold {
            return false;
        }
        
        let last = self.last_failure.load(Ordering::Relaxed);
        let elapsed = current_time_ms() - last;
        elapsed < self.cooldown_ms
    }
    
    pub fn record_failure(&self) {
        self.failure_count.fetch_add(1, Ordering::Relaxed);
        self.last_failure.store(current_time_ms(), Ordering::Relaxed);
    }
    
    pub fn record_success(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
    }
}
```

## Consequences

### Positive

1. **Lower agent memory**: 50MB vs 300MB without in-agent model
2. **Model sharing**: Single model serves all agents in cluster
3. **Easy model updates**: Update service without restarting agents
4. **Better models**: Service can use larger models (BERT-large, GPT-based)
4. **Compliance isolation**: PII processing in controlled environment

### Negative

1. **Network dependency**: Service unavailability degrades detection
2. **Higher latency**: 50-100ms network vs < 50ms local
3. **Sampling required**: Cannot process 100% of traffic remotely
4. **Single point of failure**: Service must be highly available
5. **Data egress**: Payloads leave agent process (network exposure)

### Neutral

1. **Regex fallback**: Local regex always runs, ensuring baseline detection
2. **Circuit breaker**: Prevents cascade failures when service is down
3. **Hash deduplication**: Reduces network calls by 50-90% for repeated payloads

## Alternatives Considered

### Alternative 1: External Service Only

**Description**: Remove in-agent ONNX entirely, require external service.

**Pros**:
- Simpler agent code
- No model versioning in agent

**Cons**:
- Fails in air-gapped environments
- Mandatory network dependency

**Why rejected**: In-agent mode valuable for air-gapped and high-throughput deployments.

### Alternative 2: gRPC Instead of HTTP

**Description**: Use gRPC for service communication.

**Pros**:
- Lower latency (binary protocol)
- Better streaming support

**Cons**:
- Requires protobuf definitions
- HTTP/JSON more debugging-friendly

**Why rejected**: HTTP/JSON sufficient for request/response pattern, easier debugging.

### Alternative 3: Kafka-Based Processing

**Description**: Send payloads to Kafka, service consumes from topic.

**Pros**:
- Natural buffering
- No synchronous latency

**Cons**:
- Adds Kafka dependency
- Complex error handling
- No immediate feedback

**Why rejected**: Synchronous HTTP simpler for request/response with immediate results.

### Alternative 4: Sidecar Pattern

**Description**: Deploy PII service as sidecar container in same pod.

**Pros**:
- No network hop outside pod
- Shared volume for model

**Cons**:
- No model sharing across pods
- Increases pod memory (model per pod)

**Why rejected**: Defeats purpose of centralized model sharing.

## Implementation Notes

### Service Implementation

```rust
// pii-service/src/main.rs

use axum::{
    extract::Json,
    routing::post,
    Router,
};

async fn scan(payload: Json<ScanRequest>) -> Json<PiiReport> {
    let report = PII_ENGINE.scan(&payload.payload).await;
    Json(report)
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/scan", post(scan))
        .route("/health", get(health));
    
    axum::Server::bind(&"0.0.0.0:8080".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

### Configuration Files

**Agent Config (External Mode)**:
```toml
[pii]
mode = "external"

[pii.external]
service_url = "http://pii-service.default.svc.cluster.local:8080"
sample_rate = 0.01
timeout_ms = 100
retry_count = 2
hash_dedup = true
hash_ttl_seconds = 300
circuit_breaker_threshold = 5
circuit_breaker_cooldown_ms = 30000
```

**Agent Config (In-Agent Mode)**:
```toml
[pii]
mode = "in_agent"

[pii.in_agent]
model_path = "/opt/panopticon/models/distilbert-ner/model.onnx"
tokenizer_path = "/opt/panopticon/models/distilbert-ner/tokenizer.json"
sample_rate = 0.01
max_inferences_per_sec = 1000
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pii-service
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: pii-service
        image: panopticon/pii-service:latest
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: pii-service
spec:
  selector:
    app: pii-service
  ports:
  - port: 8080
```

### Testing Requirements

1. **Service availability**: Circuit breaker opens after threshold failures
2. **Hash deduplication**: Identical payloads return cached result
3. **Timeout handling**: Requests timeout after configured duration
4. **Fallback correctness**: Regex results returned when service unavailable
5. **Load testing**: Service handles 100K requests/sec

### Metrics to Expose

**Agent Side**:
```
# TYPE pii_external_requests_total counter
pii_external_requests_total{status="success"} 990
pii_external_requests_total{status="timeout"} 5
pii_external_requests_total{status="error"} 5

# TYPE pii_external_latency_seconds histogram
pii_external_latency_seconds_bucket{le="0.05"} 500
pii_external_latency_seconds_bucket{le="0.1"} 900
pii_external_latency_seconds_bucket{le="0.2"} 1000

# TYPE pii_circuit_breaker_state gauge
pii_circuit_breaker_state{state="closed"} 1
pii_circuit_breaker_state{state="open"} 0

# TYPE pii_hash_dedup_hits_total counter
pii_hash_dedup_hits_total 50000
```

**Service Side**:
```
# TYPE pii_service_requests_total counter
pii_service_requests_total{status="success"} 1000000

# TYPE pii_service_inference_seconds histogram
pii_service_inference_seconds_bucket{le="0.01"} 100
pii_service_inference_seconds_bucket{le="0.05"} 900
pii_service_inference_seconds_bucket{le="0.1"} 1000
```

## References

- [Circuit Breaker Pattern](https://martinfowler.com/bliki/CircuitBreaker.html)
- [HTTP/1.1 Semantics](https://www.rfc-editor.org/rfc/rfc7231)
- ADR-007: PII Detection Pipeline
- ADR-001: FSM Architecture

---

## Revision History

| Date | Author | Description |
|------|--------|-------------|
| 2026-02-19 | @panopticon-team | Initial proposal and acceptance |
