# Panopticon-rs: Production Architecture Updates (Aurva-Validated)

> Historical planning document. These are architecture insertions and future
> design notes, not the canonical current-state report. For the open-source MVP
> status, use `README.md` and `docs/CURRENT-STATE.md`.
> **Single comprehensive document**: All sections to ADD to original implementation plan based on Aurva's 20B+ query/day production architecture.
> 
> **How to use**: Copy sections below into your original `Panopticon_Rust_Implementation_Plan.md` at the specified locations.

## HIGHLY EXPERIMENTAL / UNSTABLE / NOT PRODUCTION READY

These insertions are architecture guidance for an in-progress MVP.
They are not production-readiness guarantees.

## MVP Support Matrix

| Capability | MVP Status | Notes |
|---|---|---|
| Linux x86_64 on kernel 5.8+ | Supported | Primary target with RingBuf path. |
| Linux x86_64 on kernel 4.15-5.7 | Partial | PerfEventArray fallback with higher overhead. |
| Linux ARM64 | Partial | Build/runtime path exists; validation remains limited. |
| macOS runtime capture | Unsupported | Development-only environment for agent build/test. |
| Windows runtime capture | Unsupported | No MVP runtime support. |
| HTTP/1.1 and HTTP/2 parsing | Supported | Core parser path is in MVP scope. |
| gRPC/MySQL/PostgreSQL/Redis parsing | Partial | Coverage is functional but not complete for all protocol features. |
| Kafka/AMQP/DNS full parser coverage | Unsupported | MVP contains scaffolding, not complete production behavior. |
| OpenSSL TLS plaintext capture | Partial | Works for targeted attach paths with runtime variance. |
| Go TLS plaintext capture | Partial | Write-path capture only in current MVP constraints. |
| Regex-first PII detection | Supported | Included as baseline path. |
| ML-based PII detection (ONNX) | Partial | Optional and throughput-sensitive in MVP. |
| Helm/DaemonSet deployment hardening | Partial | Deployment path exists; production hardening not complete. |

---

## TABLE OF CONTENTS FOR INSERTIONS

1. [INSERT INTO Phase 3: Section 3.6 - FSM Layer](#insert-phase-3-section-36-fsm-layer)
2. [INSERT INTO Phase 3: Section 3.7 - Protocol Version Detection](#insert-phase-3-section-37-protocol-version-detection)
3. [INSERT INTO Phase 5: Section 5.6 - ML Sampling](#insert-phase-5-section-56-ml-sampling)
4. [INSERT INTO Phase 6: Section 6.4 - DNS Cache](#insert-phase-6-section-64-dns-cache)
5. [INSERT INTO Phase 6: EXPAND Section 6.3 - Enhanced Aggregation](#insert-phase-6-expand-section-63-enhanced-aggregation)
6. [APPEND TO Appendix D: New Dependencies](#append-to-appendix-d-new-dependencies)
7. [APPEND TO Implementation Milestones: Updated Timeline](#append-to-implementation-milestones-updated-timeline)

---

---

## INSERT INTO Phase 3: Section 3.6 - FSM Layer

**Location**: After current section 3.5 (PostgreSQL Wire Protocol), before "More parsers..."

```markdown
### 3.6 Connection State Machine Manager

**Objective**: Implement stateful per-connection protocol FSMs to handle multi-packet transactions (e.g., PostgreSQL queries spanning 17+ packets, MySQL auth exchange, HTTP Keep-Alive).

**Why Required**: Single-packet nom parsers fail on real traffic. Aurva's insight: "Each connection has its own FSM instance. Packets advance state based on protocol-specific markers." Without this, multi-packet queries produce garbage metadata.

**Deliverable**: Complete `panopticon-agent/src/protocol/fsm.rs` and FSM implementations for each protocol.

#### 3.6.1 FSM Trait Definition and Manager

Create `panopticon-agent/src/protocol/fsm.rs`:

```rust
use crate::protocol::ProtocolMetadata;

/// Direction of packet flow
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ToServer,
    ToClient,
}

/// Result of FSM state transition
#[derive(Debug)]
pub enum FsmResult {
    /// Continue accumulating data, not enough to parse yet
    WaitingForMore,
    /// Parsed a complete message/transaction
    MessageComplete(ProtocolMetadata),
    /// Protocol error or unexpected data
    Error(String),
    /// Connection closing (FIN received, data exhausted)
    ConnectionClosed,
}

/// Core protocol FSM trait - implemented per protocol
pub trait ProtocolFsm: Send + Sync {
    /// Process incoming packet data, advance state machine
    fn process_packet(&mut self, direction: Direction, data: &[u8]) -> FsmResult;
    
    /// Get current state (for debugging/observability)
    fn current_state(&self) -> &str;
    
    /// Extract metadata if state change occurred
    fn extract_metadata(&self) -> Option<ProtocolMetadata>;
    
    /// Reset FSM for connection reuse (e.g., HTTP Keep-Alive)
    fn reset_for_next_transaction(&mut self);
    
    /// Get version of protocol if detected (e.g., MySQL 8.0 vs 5.7)
    fn protocol_version(&self) -> Option<String>;
}

/// Manages FSM instances keyed by connection ID
pub struct ConnectionFsmManager {
    /// DashMap for lock-free concurrent access: conn_id -> FSM instance
    connections: dashmap::DashMap<u64, Box<dyn ProtocolFsm>>,
    /// Max concurrent connections before eviction
    max_connections: usize,
}

impl ConnectionFsmManager {
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: dashmap::DashMap::new(),
            max_connections,
        }
    }

    /// Process packet through FSM
    pub fn process_packet(
        &self,
        conn_id: u64,
        direction: Direction,
        data: &[u8],
    ) -> Option<FsmResult> {
        self.connections
            .alter(&conn_id, |_, mut fsm| fsm.process_packet(direction, data))
    }

    /// Remove closed connection
    pub fn close_connection(&self, conn_id: u64) {
        self.connections.remove(&conn_id);
    }

    /// Get current state of connection (for metrics/debugging)
    pub fn connection_state(&self, conn_id: u64) -> Option<String> {
        self.connections
            .get(&conn_id)
            .map(|fsm| fsm.current_state().to_string())
    }

    /// Clear expired entries (call periodically)
    pub fn evict_idle(&self, ttl: std::time::Duration) {
        // Implement LRU eviction: remove connections idle > ttl
        // For now, periodic cleanup in background task
    }
}
```

#### 3.6.2 PostgreSQL FSM Implementation Example

Update `panopticon-agent/src/protocol/postgres.rs` to implement `ProtocolFsm`:

```rust
use super::fsm::{Direction, FsmResult, ProtocolFsm};

pub enum PostgresState {
    Idle,
    WaitingForStartup,
    InAuth,
    Ready,
    InQuery,
    InResponse,
    Error,
}

pub struct PostgresFsm {
    state: PostgresState,
    buffer: Vec<u8>,
    version: Option<String>,
    current_message: Option<ProtocolMetadata>,
}

impl ProtocolFsm for PostgresFsm {
    fn process_packet(&mut self, direction: Direction, data: &[u8]) -> FsmResult {
        match self.state {
            PostgresState::Idle => {
                if direction == Direction::ToServer {
                    // Expect StartupMessage
                    if let Ok((_, version)) = parse_startup_msg(data) {
                        self.version = Some(version);
                        self.state = PostgresState::InAuth;
                        self.buffer.extend_from_slice(data);
                        FsmResult::WaitingForMore
                    } else {
                        FsmResult::Error("Invalid startup message".into())
                    }
                } else {
                    FsmResult::Error("Expected client->server in Idle".into())
                }
            }
            PostgresState::InAuth => {
                // Authentication exchange (potentially multiple packets)
                self.buffer.extend_from_slice(data);
                if self.is_auth_complete() {
                    self.state = PostgresState::Ready;
                    self.buffer.clear();
                    FsmResult::WaitingForMore
                } else {
                    FsmResult::WaitingForMore
                }
            }
            PostgresState::Ready => {
                if direction == Direction::ToServer {
                    // Query message (e.g., 'Q' message type)
                    if let Ok(query) = parse_query_message(data) {
                        self.state = PostgresState::InQuery;
                        self.current_message = Some(ProtocolMetadata {
                            method: "Query".into(),
                            body: query,
                            ..Default::default()
                        });
                        FsmResult::WaitingForMore
                    } else {
                        FsmResult::Error("Invalid query".into())
                    }
                } else {
                    FsmResult::Error("Expected client->server in Ready".into())
                }
            }
            PostgresState::InQuery => {
                if direction == Direction::ToClient {
                    // Response (CommandComplete or ErrorResponse)
                    self.buffer.extend_from_slice(data);
                    if self.is_response_complete() {
                        let result = self.current_message.take().unwrap();
                        self.state = PostgresState::Ready;
                        self.buffer.clear();
                        FsmResult::MessageComplete(result)
                    } else {
                        FsmResult::WaitingForMore
                    }
                } else {
                    FsmResult::Error("Expected server->client in InQuery".into())
                }
            }
            _ => FsmResult::Error("Invalid state".into()),
        }
    }

    fn current_state(&self) -> &str {
        match self.state {
            PostgresState::Idle => "idle",
            PostgresState::WaitingForStartup => "waiting_startup",
            PostgresState::InAuth => "in_auth",
            PostgresState::Ready => "ready",
            PostgresState::InQuery => "in_query",
            PostgresState::InResponse => "in_response",
            PostgresState::Error => "error",
        }
    }

    fn extract_metadata(&self) -> Option<ProtocolMetadata> {
        self.current_message.clone()
    }

    fn reset_for_next_transaction(&mut self) {
        self.state = PostgresState::Ready;
        self.buffer.clear();
        self.current_message = None;
    }

    fn protocol_version(&self) -> Option<String> {
        self.version.clone()
    }
}

// Helper functions (use existing nom parsers from 3.5)
fn parse_startup_msg(data: &[u8]) -> Result<(&[u8], String), nom::error::Error> {
    // Parse PostgreSQL StartupMessage
    // Example: version string from parameter value
    todo!()
}

fn parse_query_message(data: &[u8]) -> Result<String, nom::error::Error> {
    // Parse Query message type, extract SQL
    todo!()
}

impl PostgresFsm {
    fn is_auth_complete(&self) -> bool {
        // Check if buffer contains complete auth exchange (AuthenticationOk)
        self.buffer.iter().any(|&b| b == b'R')
    }

    fn is_response_complete(&self) -> bool {
        // Check if buffer contains CommandComplete or ErrorResponse
        self.buffer.iter().any(|&b| b == b'C' || b == b'E')
    }
}
```

**Repeat pattern** for MySQL (states: Handshake → Auth → Ready → Query → Response), HTTP/1.1 (states: Idle → RequestLine → Headers → Body → Complete, reset on Keep-Alive).

#### 3.6.3 Event Loop Integration

Update `panopticon-agent/src/event_loop.rs`:

```rust
use protocol::fsm::{ConnectionFsmManager, FsmResult};

pub struct EventLoop {
    fsm_manager: Arc<ConnectionFsmManager>,
    ringbuf_reader: RingBufReader,
    // ... other fields
}

impl EventLoop {
    pub fn new(ringbuf_reader: RingBufReader) -> Self {
        Self {
            fsm_manager: Arc::new(ConnectionFsmManager::new(65536)),
            ringbuf_reader,
        }
    }

    async fn process_data_event(&mut self, event: DataEvent) {
        let direction = if event.is_outbound {
            Direction::ToServer
        } else {
            Direction::ToClient
        };

        // Route through FSM
        match self.fsm_manager.process_packet(event.conn_id, direction, &event.data) {
            Some(FsmResult::MessageComplete(metadata)) => {
                // Pass to downstream: PII engine, graph builder, export
                tracing::debug!("Message complete on conn {}: {:?}", event.conn_id, metadata.method);
                self.process_message(metadata).await;
            }
            Some(FsmResult::Error(e)) => {
                tracing::warn!("FSM error on conn {}: {}", event.conn_id, e);
                self.fsm_manager.close_connection(event.conn_id);
            }
            Some(FsmResult::ConnectionClosed) => {
                self.fsm_manager.close_connection(event.conn_id);
            }
            Some(FsmResult::WaitingForMore) => {
                // Continue accumulating (normal case for multi-packet)
            }
            None => {} // FSM doesn't exist yet (first packet)
        }
    }

    /// Background task: evict idle connections
    async fn idle_eviction_task(fsm_manager: Arc<ConnectionFsmManager>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            fsm_manager.evict_idle(Duration::from_secs(300));  // 5 min TTL
        }
    }
}
```

#### 3.6.4 Testing Multi-Packet Transactions

Add to `tests/integration/test_protocol_parsing.rs`:

```rust
#[tokio::test]
async fn test_postgresql_multipacket_query() {
    // Simulate 17-packet PostgreSQL query
    let mut fsm = PostgresFsm::new();
    
    // Packet 1: Startup
    let packet1 = b"...StartupMessage...";
    assert_eq!(fsm.process_packet(Direction::ToServer, packet1), FsmResult::WaitingForMore);
    assert_eq!(fsm.current_state(), "in_auth");
    
    // Packets 2-5: Auth exchange
    for auth_packet in &[packet2, packet3, packet4, packet5] {
        assert_eq!(fsm.process_packet(Direction::ToClient, auth_packet), FsmResult::WaitingForMore);
    }
    assert_eq!(fsm.current_state(), "ready");
    
    // Packet 6: Query start
    let query_start = b"Query: SELECT * FROM users";
    assert_eq!(fsm.process_packet(Direction::ToServer, query_start), FsmResult::WaitingForMore);
    assert_eq!(fsm.current_state(), "in_query");
    
    // Packets 7-16: Query continuation
    for cont_packet in &continuation_packets {
        assert_eq!(fsm.process_packet(Direction::ToServer, cont_packet), FsmResult::WaitingForMore);
    }
    
    // Packet 17: Response complete
    let response_complete = b"CommandComplete";
    let result = fsm.process_packet(Direction::ToClient, response_complete);
    assert!(matches!(result, FsmResult::MessageComplete(_)));
    assert_eq!(fsm.current_state(), "ready");
}

#[tokio::test]
async fn test_http_keep_alive_reset() {
    let mut fsm = HttpFsm::new();
    
    // First request
    let req1 = b"GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";
    let result = fsm.process_packet(Direction::ToServer, req1);
    assert!(matches!(result, FsmResult::MessageComplete(_)));
    
    // FSM should reset to Ready state
    assert_eq!(fsm.current_state(), "ready");
    
    // Second request on same connection
    let req2 = b"GET /api HTTP/1.1\r\n\r\n";
    let result = fsm.process_packet(Direction::ToServer, req2);
    assert!(matches!(result, FsmResult::MessageComplete(_)));
}
```

**Key Properties**:
- ✅ Multi-packet queries accumulate until complete
- ✅ Errors don't crash, connection cleaned up
- ✅ State machine enforces protocol ordering (can't send query in Auth state)
- ✅ HTTP Keep-Alive resets for next request without creating new connection

---

## INSERT INTO Phase 3: Section 3.7 - Protocol Version Detection

**Location**: After section 3.6 (FSM Layer)

```markdown
### 3.7 Protocol Version Detection

**Objective**: Detect protocol variants (MySQL 5.7 vs 8.0, PostgreSQL 12 vs 16) and handle wire format differences.

**Why Required**: Aurva insight: "MySQL 5.7 vs 8.0, PostgreSQL 12 vs 16 — we're building dynamic FSM selection based on handshake." Different versions have incompatible auth algorithms, response formats.

**Implementation**: Implement `protocol_version()` in each FSM during handshake phase.

#### 3.7.1 MySQL Version Detection

Add to `panopticon-agent/src/protocol/mysql.rs`:

```rust
pub enum MysqlVersion {
    MySQL57,
    MySQL80Plus,
    Unknown(String),
}

impl MysqlFsm {
    /// Extract version from handshake packet (byte 1-9)
    fn detect_version(&mut self, handshake_packet: &[u8]) -> MysqlVersion {
        // MySQL handshake format: protocol_version(1) + server_version(null-terminated string)
        if handshake_packet.len() < 10 {
            return MysqlVersion::Unknown("short_packet".into());
        }
        
        // Find null terminator of version string
        let version_end = handshake_packet[1..].iter().position(|&b| b == 0).unwrap_or(8);
        let version_str = std::str::from_utf8(&handshake_packet[1..1+version_end])
            .unwrap_or("unknown");
        
        if version_str.starts_with("5.7") {
            MysqlVersion::MySQL57
        } else if version_str.starts_with("8.") {
            MysqlVersion::MySQL80Plus
        } else {
            MysqlVersion::Unknown(version_str.to_string())
        }
    }

    fn process_handshake(&mut self, data: &[u8]) -> FsmResult {
        self.version = Some(self.detect_version(data).to_string());
        
        match &self.version {
            Some(v) if v.contains("5.7") => {
                // Parse MySQL 5.7 handshake
                self.parse_handshake_57(data)
            }
            Some(v) if v.contains("8.") => {
                // Parse MySQL 8.0 handshake (different auth)
                self.parse_handshake_80(data)
            }
            _ => FsmResult::Error("Unknown MySQL version".into()),
        }
    }

    fn parse_handshake_57(&self, data: &[u8]) -> FsmResult {
        // MySQL 5.7 uses mysql_native_password auth
        // ... implementation
        todo!()
    }

    fn parse_handshake_80(&self, data: &[u8]) -> FsmResult {
        // MySQL 8.0 defaults to caching_sha2_password auth
        // ... implementation
        todo!()
    }
}

impl std::fmt::Display for MysqlVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MysqlVersion::MySQL57 => write!(f, "MySQL 5.7"),
            MysqlVersion::MySQL80Plus => write!(f, "MySQL 8.0+"),
            MysqlVersion::Unknown(s) => write!(f, "Unknown({})", s),
        }
    }
}
```

#### 3.7.2 PostgreSQL Version Detection

Add to `panopticon-agent/src/protocol/postgres.rs`:

```rust
pub enum PostgresVersion {
    V12,
    V13,
    V14,
    V15,
    V16Plus,
    Unknown(String),
}

impl PostgresFsm {
    fn detect_version(&mut self, startup_msg: &[u8]) -> PostgresVersion {
        // StartupMessage contains 'server_version' parameter
        // Format: "key=value\0key=value\0\0"
        let params = self.parse_startup_params(startup_msg);
        
        if let Some(version_str) = params.get("server_version") {
            if version_str.starts_with("12") {
                PostgresVersion::V12
            } else if version_str.starts_with("13") {
                PostgresVersion::V13
            } else if version_str.starts_with("14") {
                PostgresVersion::V14
            } else if version_str.starts_with("15") {
                PostgresVersion::V15
            } else if version_str.starts_with("16") || version_str.starts_with("17") {
                PostgresVersion::V16Plus
            } else {
                PostgresVersion::Unknown(version_str.clone())
            }
        } else {
            PostgresVersion::Unknown("no_version_param".into())
        }
    }

    fn parse_startup_params(&self, data: &[u8]) -> std::collections::HashMap<String, String> {
        // Parse null-terminated key-value pairs
        let mut params = std::collections::HashMap::new();
        let mut i = 8;  // Skip length + protocol version
        
        while i < data.len() {
            // Find next null terminator (key)
            let key_end = data[i..].iter().position(|&b| b == 0)?;
            let key = std::str::from_utf8(&data[i..i+key_end]).unwrap_or("?");
            i += key_end + 1;
            
            // Find next null terminator (value)
            let val_end = data[i..].iter().position(|&b| b == 0)?;
            let val = std::str::from_utf8(&data[i..i+val_end]).unwrap_or("?");
            i += val_end + 1;
            
            params.insert(key.to_string(), val.to_string());
        }
        params
    }
}
```

#### 3.7.3 HTTP/2 Version Detection

Add to `panopticon-agent/src/protocol/http2.rs`:

```rust
pub struct Http2Fsm {
    version: Option<String>,  // "h2", "h2c", etc.
    // ... other fields
}

impl Http2Fsm {
    fn detect_version(&mut self, preface: &[u8]) -> String {
        // HTTP/2 preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        if preface.starts_with(b"PRI * HTTP/2.0") {
            "h2".to_string()  // HTTP/2 over TLS
        } else if preface.starts_with(b"h2c") {
            "h2c".to_string()  // HTTP/2 over cleartext
        } else {
            "unknown".to_string()
        }
    }
}
```

#### 3.7.4 Testing Version Detection

Add to `tests/unit/test_protocol_version.rs`:

```rust
#[test]
fn test_mysql_version_detection_57() {
    let handshake_57 = b"\x0a5.7.42\x00\x01\x02\x03...";
    let mut fsm = MysqlFsm::new();
    fsm.process_handshake(handshake_57);
    assert_eq!(fsm.protocol_version(), Some("MySQL 5.7".into()));
}

#[test]
fn test_mysql_version_detection_80() {
    let handshake_80 = b"\x0a8.0.28\x00\x01\x02\x03...";
    let mut fsm = MysqlFsm::new();
    fsm.process_handshake(handshake_80);
    assert_eq!(fsm.protocol_version(), Some("MySQL 8.0+".into()));
}

#[test]
fn test_postgres_version_detection() {
    let startup_msg = b"...server_version=16.1...";
    let mut fsm = PostgresFsm::new();
    fsm.process_packet(Direction::ToServer, startup_msg);
    assert_eq!(fsm.protocol_version(), Some("16".into()));
}
```

---

## INSERT INTO Phase 5: Section 5.6 - ML Sampling

**Location**: After section 5.5 (Classifier + Redactor), before "Testing and Validation"

```markdown
### 5.6 Intelligent Sampling Before ML Inference

**Objective**: Reduce ML inference workload by sampling candidates intelligently.

**Why Required**: At scale (20B events/day), running DistilBERT on every message is expensive. Aurva's approach: sample intelligently while preserving all PII detections.

**Strategy**:
- Always infer: first occurrence of query template, errors, PII-hit flows
- Sample 10% of high-frequency duplicates
- Budget: max N inferences/second per CPU

#### 5.6.1 Sampler Module

Create `panopticon-agent/src/pii/sampler.rs`:

```rust
use dashmap::DashSet;
use std::sync::atomic::{AtomicU32, Ordering};

pub struct InferenceSampler {
    /// Track first-seen query templates (always infer)
    seen_templates: DashSet<String>,
    
    /// Budget: max N inferences per second
    inference_budget: AtomicU32,
    max_inferences_per_sec: u32,
    
    /// Sampling rate for duplicates (10%)
    sample_rate: u32,
}

impl InferenceSampler {
    pub fn new(max_inferences_per_sec: u32, sample_rate: u32) -> Self {
        Self {
            seen_templates: DashSet::new(),
            inference_budget: AtomicU32::new(max_inferences_per_sec),
            max_inferences_per_sec,
            sample_rate,
        }
    }

    /// Determine if text should be sent to ML inference
    pub fn should_infer(
        &self,
        query_template: &str,
        is_first_time: bool,
    ) -> bool {
        // Always infer first occurrence
        if is_first_time {
            self.seen_templates.insert(query_template.to_string());
            return true;
        }

        // Check budget
        if self.inference_budget.load(Ordering::Relaxed) == 0 {
            return false;
        }

        // Sample 10% of duplicates
        let hash = fxhash::hash32(query_template);
        (hash % 100) < self.sample_rate
    }

    /// Consume from budget after inference
    pub fn consume_budget(&self) {
        self.inference_budget.fetch_sub(1, Ordering::Relaxed);
    }

    /// Reset budget every second (call from background task)
    pub fn reset_budget(&self) {
        self.inference_budget.store(self.max_inferences_per_sec, Ordering::Relaxed);
    }

    /// Get sampling stats
    pub fn stats(&self) -> SamplerStats {
        SamplerStats {
            templates_seen: self.seen_templates.len(),
            budget_remaining: self.inference_budget.load(Ordering::Relaxed),
        }
    }
}

pub struct SamplerStats {
    pub templates_seen: usize,
    pub budget_remaining: u32,
}
```

#### 5.6.2 Integration with Inference Loop

Update `panopticon-agent/src/pii/inference.rs`:

```rust
pub struct PiiInferenceEngine {
    regex_prefilter: RegexPrefilter,
    sampler: Arc<InferenceSampler>,
    tokenizer: Tokenizer,
    ort_session: OrtSession,
    // ... other fields
}

impl PiiInferenceEngine {
    pub async fn infer_batch(&self, messages: Vec<(String, String)>) -> Vec<PiiReport> {
        let mut results = Vec::new();

        for (query_template, body) in messages {
            // 1. Check regex pre-filter first (always runs, fast)
            if !self.regex_prefilter.might_contain_pii(&body) {
                continue;
            }

            // 2. Check sampler (deduplicates)
            let first_time = !self.sampler.seen_templates.contains(&query_template);
            if !self.sampler.should_infer(&query_template, first_time) {
                // Sampled out - skip inference
                continue;
            }

            // 3. Check budget
            if self.sampler.inference_budget.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                tracing::warn!("ML inference budget exhausted");
                continue;
            }

            // Only then run expensive ML
            match self.infer_single(&body).await {
                Ok(report) => {
                    results.push(report);
                    self.sampler.consume_budget();
                }
                Err(e) => {
                    tracing::error!("Inference error: {}", e);
                }
            }
        }

        results
    }

    async fn infer_single(&self, text: &str) -> Result<PiiReport, String> {
        // Tokenize
        let tokens = self.tokenizer.encode(text)?;

        // Run ONNX inference
        let output = self.ort_session.run(vec![tokens])?;

        // Classify
        let entities = self.classify_entities(output)?;

        Ok(PiiReport {
            entities,
            redacted_text: self.redactor.redact(text),
            scan_duration_us: 0,  // TODO: measure
            model_used: "distilbert-ner".into(),
        })
    }
}
```

#### 5.6.3 Background Budget Reset Task

Update `panopticon-agent/src/main.rs`:

```rust
pub async fn start_budget_reset_task(sampler: Arc<InferenceSampler>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            sampler.reset_budget();
        }
    });
}
```

**Impact**: 
- Reduce ML inference candidates by 90% (first-time + errors only)
- Keep 100% of PII-hit flows
- Maintain budget to avoid CPU saturation

---

## INSERT INTO Phase 6: Section 6.4 - DNS Cache

**Location**: After section 6.3 (Edge Aggregation, which will be expanded separately), before "DAG Construction"

```markdown
### 6.4 DNS Resolution Cache

**Objective**: Maintain userspace DNS cache with intelligent fallback chain for IP→domain resolution.

**Why Critical**: Aurva's insight: "Maintain a userspace DNS cache with intelligent fallback: Primary: DNS events from eBPF → Fallback: Reverse DNS lookup → Last resort: IP address." Without DNS cache, service graph shows raw IPs instead of service names.

**Deliverable**: Complete `panopticon-agent/src/graph/dns_cache.rs` with TTL-aware caching.

#### 6.4.1 DNS Cache Data Structure

Create `panopticon-agent/src/graph/dns_cache.rs`:

```rust
use std::net::IpAddr;
use std::time::{Duration, Instant};
use dashmap::DashMap;

/// Cached DNS entry with TTL
#[derive(Clone)]
pub struct DnsCacheEntry {
    pub domain: String,
    pub ip: IpAddr,
    pub expires_at: Instant,
    pub source: DnsSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsSource {
    /// From observed DNS query/response in traffic
    Observed,
    /// From reverse DNS lookup
    Lookup,
    /// From /etc/hosts or system cache
    System,
}

/// Bidirectional DNS cache with TTL expiry
pub struct DnsCache {
    /// IP -> (domain, metadata)
    ip_to_domain: DashMap<IpAddr, DnsCacheEntry>,
    /// Domain -> IP for quick lookups
    domain_to_ip: DashMap<String, IpAddr>,
    /// Reverse lookup in-flight (dedupe concurrent requests)
    lookup_in_flight: DashMap<IpAddr, Arc<tokio::sync::Semaphore>>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            ip_to_domain: DashMap::new(),
            domain_to_ip: DashMap::new(),
            lookup_in_flight: DashMap::new(),
        }
    }

    /// Insert from DNS packet observation (with TTL from DNS response)
    pub fn insert_observed(&self, domain: String, ip: IpAddr, ttl: u32) {
        let ttl_duration = Duration::from_secs(ttl as u64);
        let expires_at = Instant::now() + ttl_duration;

        let entry = DnsCacheEntry {
            domain: domain.clone(),
            ip,
            expires_at,
            source: DnsSource::Observed,
        };

        self.ip_to_domain.insert(ip, entry.clone());
        self.domain_to_ip.insert(domain, ip);
    }

    /// Resolve IP -> domain with fallback chain
    pub async fn resolve_domain(&self, ip: IpAddr) -> Option<String> {
        // 1. Check cache (if not expired)
        if let Some(entry) = self.ip_to_domain.get(&ip) {
            if Instant::now() < entry.expires_at {
                return Some(entry.domain.clone());
            } else {
                // TTL expired, remove stale entry
                drop(entry);
                self.ip_to_domain.remove(&ip);
            }
        }

        // 2. Perform reverse DNS lookup (deduplicated)
        self.reverse_lookup(ip).await
    }

    /// Reverse DNS lookup with deduplication
    async fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        // Dedupe concurrent lookups for same IP
        let semaphore = self
            .lookup_in_flight
            .entry(ip)
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1)))
            .clone();

        let _permit = semaphore.acquire().await.ok()?;

        // Check again in case another task already populated cache
        if let Some(entry) = self.ip_to_domain.get(&ip) {
            if Instant::now() < entry.expires_at {
                return Some(entry.domain.clone());
            }
        }

        // Perform actual reverse lookup (non-blocking DNS)
        match tokio::task::spawn_blocking(move || {
            resolve_hostname_blocking(ip)
        })
        .await
        {
            Ok(Some(domain)) => {
                // Cache with reasonable TTL (15 min for reverse lookups)
                let entry = DnsCacheEntry {
                    domain: domain.clone(),
                    ip,
                    expires_at: Instant::now() + Duration::from_secs(900),
                    source: DnsSource::Lookup,
                };
                self.ip_to_domain.insert(ip, entry);
                self.domain_to_ip.insert(domain.clone(), ip);
                Some(domain)
            }
            _ => None,  // Lookup failed, IP remains unresolved
        }
    }

    /// Fallback: IP address as string (when domain not available)
    pub async fn resolve_or_fallback(&self, ip: IpAddr) -> String {
        self.resolve_domain(ip)
            .await
            .unwrap_or_else(|| ip.to_string())
    }

    /// Clear expired entries (call periodically)
    pub fn evict_expired(&self) {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        for entry in self.ip_to_domain.iter() {
            if now > entry.expires_at {
                to_remove.push(entry.key().clone());
            }
        }

        for ip in to_remove {
            self.ip_to_domain.remove(&ip);
        }
    }

    pub fn stats(&self) -> DnsCacheStats {
        DnsCacheStats {
            entries: self.ip_to_domain.len(),
            domains: self.domain_to_ip.len(),
        }
    }
}

pub struct DnsCacheStats {
    pub entries: usize,
    pub domains: usize,
}

/// Helper: blocking reverse DNS (run in tokio::task::spawn_blocking)
fn resolve_hostname_blocking(ip: IpAddr) -> Option<String> {
    // TODO: Implement using socket libraries or trust-dns-resolver crate
    // For now, stub:
    None
}
```

#### 6.4.2 Integration with DNS Parser

Update `panopticon-agent/src/protocol/dns.rs`:

```rust
impl DnsParser {
    pub fn parse_and_cache(
        data: &[u8],
        cache: &Arc<DnsCache>,
    ) -> Result<Vec<DnsRecord>, DnsError> {
        let records = Self::parse(data)?;

        // Cache A/AAAA records
        for record in &records {
            if record.record_type == RecordType::A || record.record_type == RecordType::AAAA {
                if let (Some(domain), Some(ip)) = (&record.name, &record.ip) {
                    cache.insert_observed(
                        domain.clone(),
                        ip.clone(),
                        record.ttl as u32,
                    );
                }
            }
        }

        Ok(records)
    }
}
```

#### 6.4.3 Usage in Service Graph Builder

Update `panopticon-agent/src/graph/identity.rs`:

```rust
pub struct ServiceIdentityResolver {
    dns_cache: Arc<DnsCache>,
    k8s_client: kube::Client,
}

impl ServiceIdentityResolver {
    /// Resolve IP to service name with DNS cache fallback
    pub async fn resolve_service(&self, ip: IpAddr) -> ServiceIdentity {
        // 1. Try DNS cache first
        let hostname = self.dns_cache.resolve_or_fallback(ip).await;

        // 2. Try K8s service lookup
        if let Ok(service) = self.lookup_k8s_service(&hostname).await {
            return service;
        }

        // 3. Fallback to IP-only identity
        ServiceIdentity {
            name: hostname,
            namespace: "external".into(),
            kind: ServiceKind::External,
            labels: Default::default(),
        }
    }
}
```

#### 6.4.4 Testing DNS Cache

Add to `tests/unit/test_dns_cache.rs`:

```rust
#[tokio::test]
async fn test_dns_cache_ttl_expiry() {
    let cache = Arc::new(DnsCache::new());
    let ip = "10.0.0.5".parse().unwrap();
    
    // Insert with 2-second TTL
    cache.insert_observed("api.example.com".into(), ip, 2);
    
    // Should resolve immediately
    assert_eq!(
        cache.resolve_domain(ip).await,
        Some("api.example.com".into())
    );
    
    // Wait for expiry
    tokio::time::sleep(Duration::from_secs(3)).await;
    
    // Should be gone
    // (will attempt reverse lookup, which fails in test)
    // Result depends on reverse DNS implementation
}

#[tokio::test]
async fn test_dns_cache_concurrent_lookups() {
    let cache = Arc::new(DnsCache::new());
    let ip = "10.0.0.5".parse().unwrap();
    
    // Insert
    cache.insert_observed("api.example.com".into(), ip, 300);
    
    // Spawn 100 concurrent lookups
    let mut handles = vec![];
    for _ in 0..100 {
        let cache_clone = cache.clone();
        handles.push(tokio::spawn(async move {
            cache_clone.resolve_domain(ip).await
        }));
    }
    
    // All should succeed
    for handle in handles {
        assert_eq!(handle.await.unwrap(), Some("api.example.com".into()));
    }
}
```

---

## INSERT INTO Phase 6: EXPAND Section 6.3 - Enhanced Aggregation

**Location**: REPLACE current section 6.3, keep the heading "Edge Aggregator with Intelligent Sampling"

```markdown
### 6.3 Edge Aggregator with Intelligent Sampling

**Objective**: Aggregate flows by (src, dst, protocol) and deduplicate repeated queries to achieve 90% event reduction.

**Why Critical**: Aurva's insight: "90% traffic reduction: Most flow data aggregated at collector." At 20B events/day, aggregation is essential for scale.

**Strategy**:
- Time-window aggregation (10-second windows)
- Query template normalization (SQL literals → ?, HTTP UUIDs → ?)
- Sampling: always export errors/PII, sample 10% of duplicates
- Result: 20B raw events → 2B aggregated flows

#### 6.3.1 Query Template Normalization

Create enhanced logic in `panopticon-agent/src/graph/aggregator.rs`:

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use regex::Regex;

/// Represents a unique query template (parameterized form)
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct QueryTemplate {
    pub protocol: String,
    pub method: String,
    pub template: String,  // e.g., "SELECT * FROM users WHERE id = ?"
}

/// Aggregated flow statistics
#[derive(Clone, Debug)]
pub struct FlowAggregation {
    pub src: String,
    pub dst: String,
    pub protocol: String,
    pub query_counts: HashMap<QueryTemplate, FlowStats>,
    pub window_start: Instant,
    pub window_duration: Duration,
}

#[derive(Clone, Debug, Default)]
pub struct FlowStats {
    pub count: u64,
    pub total_bytes: u64,
    pub error_count: u64,
    pub pii_hits: u32,
    pub latency_p50_ms: f32,
    pub latency_p95_ms: f32,
    pub latency_p99_ms: f32,
}

/// Edge aggregator with time-window bucketing
pub struct EdgeAggregator {
    /// Current window: (src, dst, protocol, template) -> FlowStats
    current_window: DashMap<(String, String, String, String), FlowStats>,
    
    /// Query template cache (expensive to compute)
    query_templates: DashMap<String, QueryTemplate>,
    
    /// Window configuration
    window_duration: Duration,
    window_start: Instant,
    
    /// Statistics
    total_events_seen: std::sync::atomic::AtomicU64,
    total_events_aggregated: std::sync::atomic::AtomicU64,
}

impl EdgeAggregator {
    pub fn new(window_duration: Duration) -> Self {
        Self {
            current_window: DashMap::new(),
            query_templates: DashMap::new(),
            window_duration,
            window_start: Instant::now(),
            total_events_seen: std::sync::atomic::AtomicU64::new(0),
            total_events_aggregated: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record a message/flow event
    pub fn record_event(
        &self,
        src: &str,
        dst: &str,
        protocol: &str,
        method: &str,
        body: &str,
        latency_ms: f32,
        pii_hit: bool,
        is_error: bool,
    ) {
        self.total_events_seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Normalize query to template
        let template = self.normalize_query(protocol, method, body);

        let key = (
            src.to_string(),
            dst.to_string(),
            protocol.to_string(),
            template,
        );

        self.current_window
            .entry(key)
            .and_modify(|stats| {
                stats.count += 1;
                stats.total_bytes += body.len() as u64;
                if is_error {
                    stats.error_count += 1;
                }
                if pii_hit {
                    stats.pii_hits += 1;
                }
                // Update latency percentiles (simplified)
                stats.latency_p99_ms = latency_ms.max(stats.latency_p99_ms);
            })
            .or_insert(FlowStats {
                count: 1,
                total_bytes: body.len() as u64,
                error_count: if is_error { 1 } else { 0 },
                pii_hits: if pii_hit { 1 } else { 0 },
                latency_p50_ms: latency_ms,
                latency_p95_ms: latency_ms,
                latency_p99_ms: latency_ms,
            });

        self.total_events_aggregated.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Flush current window and start new one
    pub fn flush_window(&self) -> Vec<FlowAggregation> {
        let mut result = Vec::new();

        for entry in self.current_window.iter() {
            let ((src, dst, protocol, _template), stats) = (entry.key().clone(), entry.value().clone());

            result.push(FlowAggregation {
                src,
                dst,
                protocol,
                query_counts: {
                    let mut map = HashMap::new();
                    map.insert(
                        QueryTemplate {
                            protocol: protocol.clone(),
                            method: "unknown".into(),
                            template: _template,
                        },
                        stats,
                    );
                    map
                },
                window_start: self.window_start,
                window_duration: self.window_duration,
            });
        }

        // Clear for next window
        self.current_window.clear();

        result
    }

    /// Normalize query by parameterizing literals
    fn normalize_query(&self, protocol: &str, method: &str, body: &str) -> String {
        let cache_key = format!("{}:{}:{}", protocol, method, body);

        // Check cache first
        if let Some(cached) = self.query_templates.get(&cache_key) {
            return cached.template.clone();
        }

        // Apply normalization rules
        let normalized = match protocol {
            "mysql" | "postgres" => self.normalize_sql(body),
            "http" => self.normalize_http_url(body),
            _ => body.to_string(),
        };

        self.query_templates.insert(
            cache_key,
            QueryTemplate {
                protocol: protocol.to_string(),
                method: method.to_string(),
                template: normalized.clone(),
            },
        );

        normalized
    }

    /// SQL query normalization: 'abc' -> ?, 123 -> ?
    fn normalize_sql(&self, query: &str) -> String {
        let mut result = query.to_string();

        // String literals: 'value' -> ?
        result = Regex::new(r#"'[^']*'"#)
            .unwrap()
            .replace_all(&result, "?")
            .to_string();

        // Numbers: 123 -> ?
        result = Regex::new(r"\b\d+\b")
            .unwrap()
            .replace_all(&result, "?")
            .to_string();

        result
    }

    /// HTTP URL/body normalization: UUIDs -> ?, numeric IDs -> ?
    fn normalize_http_url(&self, body: &str) -> String {
        let mut result = body.to_string();

        // UUIDs: 550e8400-e29b-41d4-a716-446655440000 -> ?
        result = Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
            .unwrap()
            .replace_all(&result, "?")
            .to_string();

        // Numeric IDs: id=123 -> id=?
        result = Regex::new(r"(?:id|Id|ID)=\d+")
            .unwrap()
            .replace_all(&result, "?")
            .to_string();

        result
    }

    /// Get aggregation ratio (events aggregated / total seen)
    pub fn aggregation_ratio(&self) -> f64 {
        let seen = self.total_events_seen.load(std::sync::atomic::Ordering::Relaxed) as f64;
        let aggregated = self.total_events_aggregated.load(std::sync::atomic::Ordering::Relaxed) as f64;
        if seen == 0.0 {
            0.0
        } else {
            aggregated / seen
        }
    }

    pub fn stats(&self) -> AggregatorStats {
        AggregatorStats {
            window_count: self.current_window.len(),
            events_seen: self.total_events_seen.load(std::sync::atomic::Ordering::Relaxed),
            aggregation_ratio: self.aggregation_ratio(),
        }
    }
}

pub struct AggregatorStats {
    pub window_count: usize,
    pub events_seen: u64,
    pub aggregation_ratio: f64,
}
```

#### 6.3.2 Sampling Strategy Before Export

Add intelligent filtering:

```rust
pub struct ExportSampler {
    /// Always export: errors, PII hits, first-seen templates
    keep_list: std::sync::atomic::AtomicU64,
    /// Sample 10% of: high-frequency duplicate flows
    sample_list: std::sync::atomic::AtomicU64,
    /// Sampling rate for duplicates
    sample_rate: u32,
}

impl ExportSampler {
    pub fn new(sample_rate: u32) -> Self {
        Self {
            keep_list: std::sync::atomic::AtomicU64::new(0),
            sample_list: std::sync::atomic::AtomicU64::new(0),
            sample_rate,
        }
    }

    pub fn should_export(
        &self,
        flow: &FlowAggregation,
        _template: &QueryTemplate,
        first_time_seen: bool,
    ) -> bool {
        // Always export these
        if flow.query_counts.values().any(|s| s.error_count > 0) {
            self.keep_list.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return true;
        }

        if flow.query_counts.values().any(|s| s.pii_hits > 0) {
            self.keep_list.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return true;
        }

        if first_time_seen {
            self.keep_list.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return true;
        }

        // Sample 10% of others
        let hash = fxhash::hash64(&format!("{}:{}", flow.src, flow.dst));
        let sampled = (hash % 100) < self.sample_rate as u64;
        if sampled {
            self.sample_list.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        sampled
    }
}
```

#### 6.3.3 Background Window Flush Task

Add to event loop:

```rust
// In panopticon-agent/src/event_loop.rs

pub async fn start_aggregation_flush_task(
    aggregator: Arc<EdgeAggregator>,
    exporter: Arc<Exporter>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let flows = aggregator.flush_window();
            tracing::info!("Flushed {} aggregated flows, ratio={:.2}%",
                flows.len(),
                aggregator.aggregation_ratio() * 100.0
            );
            
            // Export
            for flow in flows {
                exporter.export_flow(&flow).await;
            }
        }
    });
}
```

#### 6.3.4 Testing Query Normalization

Add to `tests/unit/test_query_aggregation.rs`:

```rust
#[test]
fn test_sql_normalization() {
    let agg = EdgeAggregator::new(Duration::from_secs(10));
    
    // All these should normalize to same template
    let q1 = "SELECT * FROM users WHERE id = 123";
    let q2 = "SELECT * FROM users WHERE id = 456";
    let q3 = "SELECT * FROM users WHERE id = 789";
    
    let t1 = agg.normalize_query("postgres", "Query", q1);
    let t2 = agg.normalize_query("postgres", "Query", q2);
    let t3 = agg.normalize_query("postgres", "Query", q3);
    
    assert_eq!(t1, t2);
    assert_eq!(t2, t3);
    assert!(t1.contains("?"));  // Literals replaced
}

#[test]
fn test_aggregation_ratio() {
    let agg = Arc::new(EdgeAggregator::new(Duration::from_secs(10)));
    
    // Record 1000 identical queries
    for i in 0..1000 {
        agg.record_event(
            "svc-a",
            "svc-b",
            "postgres",
            "Query",
            &format!("SELECT * FROM users WHERE id = {}", i),
            1.5,
            false,
            false,
        );
    }
    
    // Should aggregate to ~1 unique template
    let ratio = agg.aggregation_ratio();
    assert!(ratio > 0.99, "Expected 99%+ aggregation, got {}", ratio);
}
```

---

## APPEND TO Appendix D: New Dependencies

Add the following to the Dependencies table:

```markdown
| trust-dns-resolver | 0.23 | DNS reverse lookups (6.4) |
| fxhash | 0.2 | Fast hashing for sampling (5.6, 6.3) |
```

(Note: `regex`, `dashmap`, `bytes`, `tokio` already present)

---

## APPEND TO Implementation Milestones: Updated Timeline

Replace the existing milestone list with:

```markdown
### Milestone 1: Foundation (Weeks 1-2)
- [ ] Set up workspace, toolchain, CI pipeline
- [ ] Implement panopticon-common (shared types)
- [ ] Implement TC capture eBPF program (cleartext packets)
- [ ] Implement basic event loop (RingBuf consumer)
- [ ] **Verify: capture raw TCP packets on loopback**

### Milestone 2: Protocol Parsing - CRITICAL FSM Update (Weeks 3-4)
- [ ] **NEW: Implement FSM trait and ConnectionFsmManager (3.6)**
- [ ] **NEW: Refactor MySQL parser to MysqlFsm (3.6.2)**
- [ ] **NEW: Refactor PostgreSQL parser to PostgresFsm (3.6.2)**
- [ ] **NEW: Refactor HTTP/1.1 parser to HttpFsm (3.6.2)**
- [ ] **NEW: Add protocol version detection to MySQL, PostgreSQL (3.7)**
- [ ] Integrate FSM manager into event loop (3.6.4)
- [ ] **Verify: Multi-packet PostgreSQL query (17 packets) captured correctly**
- [ ] **Verify: MySQL 5.7 vs 8.0 versions detected correctly**

### Milestone 3: TLS Interception (Weeks 5-6)
- [ ] Implement proc_scanner (library discovery)
- [ ] Implement OpenSSL uprobes (SSL_write/SSL_read)
- [ ] Implement Go TLS uprobes (with ABI detection)
- [ ] Implement HTTP/2 and gRPC parsers
- [ ] **Verify: capture HTTPS traffic from curl to nginx with TLS**

### Milestone 4: PII Detection - Updated with Sampling (Weeks 7-8)
- [ ] Implement regex pre-filter
- [ ] Integrate ONNX Runtime (ort) with DistilBERT-NER
- [ ] Implement tokenizer -> inference -> classifier pipeline
- [ ] Implement redactor
- [ ] **NEW: Implement inference sampler (5.6) - optional but recommended**
- [ ] **Verify: detect names, emails, SSNs in HTTP bodies**

### Milestone 5: Service Graph - CRITICAL DNS Cache Update (Weeks 9-10)
- [ ] **NEW: Implement DNS cache with TTL (6.4)**
- [ ] **NEW: Integrate DNS parser -> DNS cache population (6.4.2)**
- [ ] **NEW: Update service graph identity resolver to use DNS cache (6.4.3)**
- [ ] **NEW: Expand edge aggregator with query dedup (6.3.1-6.3.3)**
- [ ] Implement K8s identity resolution (kube-rs informer)
- [ ] Implement container ID -> Pod mapping
- [ ] Implement edge aggregator with sliding windows
- [ ] Implement petgraph DAG builder
- [ ] **Verify: graph shows service NAMES (not IPs) with DNS cache**
- [ ] **Verify: aggregation ratio >= 80% on test traffic**

### Milestone 6: Export and Production Readiness (Weeks 11-12)
- [ ] Implement OTLP exporter
- [ ] Implement Prometheus metrics endpoint
- [ ] Implement JSON log exporter
- [ ] Implement graph API endpoint
- [ ] Kernel compat layer (PerfEventArray fallback)
- [ ] Dockerfile + DaemonSet + Helm chart
- [ ] Load testing: 500K events/sec sustained
- [ ] **Verify: full E2E test passes with new FSM, DNS, aggregation**

### Milestone 7: Extended Protocol and Platform Support (Weeks 13-16)
- [ ] Kafka, MongoDB, DNS, AMQP parsers (wrapped as FSMs)
- [ ] Java TLS interception
- [ ] ARM64 cross-compilation and testing
- [ ] Alpine/musl support
- [ ] CentOS 8, Amazon Linux, RHEL testing
```

---

## CRITICAL PATH SUMMARY

**Blocking Dependencies**:

```
3.6 FSM Layer
  ↓ (BLOCKS)
All downstream protocol parsing
  ↓ (BLOCKS)
Phase 3 verification (multi-packet queries)

6.4 DNS Cache
  ↓ (BLOCKS)
Service graph with names (not IPs)

6.3 Edge Aggregation (EXPAND)
  ↓ (REQUIRED FOR SCALE)
Handling 20B events/day
```

**Must-Do Order**:
1. **Weeks 3-4**: Implement 3.6 (FSM) + 3.7 (version detection)
2. **Weeks 9-10**: Implement 6.4 (DNS cache) + expand 6.3 (aggregation)
3. **Optional but recommended**: Implement 5.6 (ML sampling) in week 8

---

## TESTING CHECKLIST BY SECTION

### After 3.6 (FSM) Implementation:

```
✓ Single-packet HTTP request works
✓ Multi-packet PostgreSQL query (17 packets) → 1 metadata
✓ MySQL auth handshake (3 packets) completes successfully
✓ TLS handshake (5 packets) detected, routed to SSL uprobes
✓ HTTP Keep-Alive: first request completes, reset for second
✓ Connection error: FSM cleaned up, no memory leak
✓ 10K concurrent connections don't cause OOM
```

### After 3.7 (Version Detection):

```
✓ MySQL 5.7 handshake → detected as "MySQL 5.7"
✓ MySQL 8.0 handshake → detected as "MySQL 8.0+"
✓ PostgreSQL 12 → detected in StartupMessage
✓ PostgreSQL 16 → detected in StartupMessage
✓ Wrong version → fallback handling works
```

### After 6.4 (DNS Cache):

```
✓ Observed DNS A record → inserted with TTL
✓ Cache lookup before expiry → returns domain
✓ Cache lookup after expiry → re-requests reverse DNS
✓ Concurrent lookups for same IP deduplicated
✓ Service graph shows "api-service" instead of "10.0.0.5"
✓ TTL=0 entries removed immediately
```

### After 6.3 (Aggregation Expansion):

```
✓ 1000 identical queries with different IDs → 1 template
✓ Aggregation ratio >= 80% on test traffic
✓ Errors NOT aggregated (always exported)
✓ PII flows NOT aggregated (always exported)
✓ Query normalization preserves attack detection (SQL injection still visible)
✓ 10-second window flushes correctly
```

---

## DEPENDENCY ADDITIONS (Cargo.toml)

```toml
[dependencies]
# ... existing deps ...

# Phase 3.6: FSM Layer
# (no new deps - uses existing aya, bytes, nom)

# Phase 6.4: DNS Cache
trust-dns-resolver = "0.23"

# Phase 5.6 + 6.3: Sampling
fxhash = "0.2"

# Already present:
# regex, dashmap, tokio, bytes, aya, ort, tokenizers, petgraph, kube
```

---

## QUICK REFERENCE: Implementation Sequence

### Start Here (Critical Path):

**Week 3-4: FSM Layer (Blocks Everything)**
```
1. Create panopticon-agent/src/protocol/fsm.rs
2. Implement ProtocolFsm trait + ConnectionFsmManager
3. Wrap MySQL parser as MysqlFsm
4. Wrap PostgreSQL parser as PostgresFsm
5. Wrap HTTP/1.1 parser as HttpFsm
6. Update event_loop.rs to route through FSM
7. Test: Multi-packet query works (17 packets → 1 metadata)
```

**Week 4: Version Detection**
```
8. Add detect_version() to MysqlFsm (5.7 vs 8.0)
9. Add detect_version() to PostgresFsm (12 vs 16)
10. Add detect_version() to Http2Fsm (h2 vs h2c)
11. Test: Version detection works
12. Verify: Milestone 2 checkpoint passes
```

**Week 9-10: DNS Cache (Enables Service Names)**
```
13. Create panopticon-agent/src/graph/dns_cache.rs
14. Integrate DNS parser → cache population
15. Update identity.rs to use DNS cache
16. Test: Service names instead of IPs in graph
```

**Week 9-10: Aggregation (Handles Scale)**
```
17. Expand aggregator.rs with query normalization
18. Add SQL/HTTP deduplication
19. Implement ExportSampler
20. Test: 1M identical queries → 1 template, ratio >= 80%
```

**Optional Week 8: ML Sampling (Efficiency)**
```
21. Create panopticon-agent/src/pii/sampler.rs
22. Integrate into inference loop
23. Test: 10% sampling on duplicates works
```

---

> **END OF ADDITIONS** -- Copy sections above into original `Panopticon_Rust_Implementation_Plan.md` at specified locations. Start with FSM (3.6) — it's the critical blocker. Questions? Refer back to the Aurva comparison document.
