# ADR-002: Protocol Parser Lifecycle Management

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Proposed |
| **Date** | 2026-02-18 |
| **Decision Makers** | @panopticon-team |
| **Affected Components** | `panopticon-agent/src/protocol/fsm.rs`, `panopticon-agent/src/protocol/detect.rs`, `panopticon-agent/src/event_loop.rs` |
| **Supersedes** | - |
| **Superseded by** | - |

## Context

### Problem Statement

Panopticon intercepts network traffic at the kernel level and needs to parse application-layer protocols (HTTP/1.1, HTTP/2, gRPC, MySQL, PostgreSQL, Redis, etc.) for observability and PII detection. Each TCP connection may use a different protocol, and connections have varying lifecycles:

1. **Unknown Protocol on Arrival**: Connections arrive without protocol metadata—we must detect the protocol from traffic patterns.

2. **Long-Lived Connections**: HTTP Keep-Alive, database connection pools, and persistent messaging connections can remain open for hours or days.

3. **Idle Connections**: Connections may sit idle between transactions (e.g., connection pool waiting for work), consuming memory if FSM state is retained indefinitely.

4. **Abrupt Termination**: Connections can close via FIN (graceful), RST (abrupt), or simply timeout without explicit signals.

5. **Memory Constraints**: With 100K+ concurrent connections possible, unbounded FSM state growth would exhaust memory.

6. **Protocol Version Differences**: MySQL 5.7 vs 8.0, PostgreSQL 12-16 have different wire formats; detecting version during handshake is required.

### Current Implementation

The codebase uses `ConnectionFsmManager` to manage FSM instances keyed by `socket_cookie` (u64):

```rust
pub struct ConnectionFsmManager {
    connections: DashMap<u64, Box<dyn ProtocolFsm>>,
    last_seen: DashMap<u64, Instant>,
    max_connections: usize,
}
```

Each connection gets its own `ProtocolFsm` instance that maintains parsing state across packets.

## Decision

We will implement a **lazy protocol detection with explicit lifecycle management**:

1. **Lazy Detection**: Detect protocol on first non-empty payload via `detect_protocol()` in `detect.rs`. This avoids wasting resources on connections that never transmit data.

2. **FSM Lifecycle Tied to Connection Cookie**: Each connection's FSM is keyed by the kernel's `socket_cookie` (guaranteed unique for the connection's lifetime).

3. **Idle Eviction via Timestamp Tracking**: `last_seen` DashMap tracks activity; `evict_idle(ttl)` removes connections idle beyond TTL.

4. **Explicit Cleanup on Close**: `close_connection()` called on FIN/RST events from eBPF or on parser `ConnectionClosed` result.

5. **Keep-Alive Support**: `reset_for_next_transaction()` clears transaction state while preserving connection-level state (e.g., protocol version detected during handshake).

## Lifecycle State Machine

```
                    ┌──────────────┐
                    │   Created    │
                    └──────┬───────┘
                           │ first packet
                           ▼
                    ┌──────────────┐
         ┌─────────│   Detected   │◄────────┐
         │         └──────┬───────┘         │
         │                │                 │
         │                ▼                 │
         │         ┌──────────────┐        │
         │         │    Active    │────────┤ reset_for_next_transaction
         │         └──────┬───────┘        │ (HTTP Keep-Alive)
         │                │                 │
         │         ┌──────┴───────┐        │
         │         ▼              ▼        │
         │   ┌──────────┐  ┌──────────┐   │
         │   │   Idle   │  │   Error  │───┘
         │   └────┬─────┘  └────┬─────┘
         │        │             │
         │   evict_idle()   close_connection()
         │        │             │
         └────────┴─────────────┘
                  │
                  ▼
           ┌──────────────┐
           │   Destroyed  │
           └──────────────┘
```

### State Descriptions

| State | Entry Condition | Exit Condition | Memory Held |
|-------|-----------------|----------------|-------------|
| **Created** | `get_or_create()` called | First packet with data | FSM instance (minimal) |
| **Detected** | `detect_protocol()` returns Some | FSM processes first message | FSM + protocol-specific state |
| **Active** | FSM returns `MessageComplete` | No activity for TTL, or close | Full FSM state + buffers |
| **Idle** | No packets for extended period | New packet (→Active), eviction | Same as Active |
| **Error** | FSM returns `FsmResult::Error` | `close_connection()` called | Preserved for debugging |
| **Destroyed** | `close_connection()` or `evict_idle()` | N/A | None |

## Implementation

### Core API

```rust
impl ConnectionFsmManager {
    /// Create FSM for new connection, or return existing.
    /// Returns true if FSM exists (created or already present).
    pub fn get_or_create(&self, conn_id: u64, protocol: Protocol) -> bool;

    /// Process a packet through the connection's FSM.
    /// Returns None if connection doesn't exist.
    pub fn process_packet(
        &self,
        conn_id: u64,
        direction: Direction,
        data: &[u8],
        timestamp_ns: u64,
    ) -> Option<FsmResult>;

    /// Close connection and free all state.
    /// Safe to call multiple times.
    pub fn close_connection(&self, conn_id: u64);

    /// Remove all connections idle longer than TTL.
    /// Should be called periodically (e.g., every 30s).
    pub fn evict_idle(&self, ttl: Duration);

    /// Get current state name for debugging/metrics.
    pub fn connection_state(&self, conn_id: u64) -> Option<&'static str>;
}
```

### FsmResult Enum

```rust
#[derive(Debug)]
pub enum FsmResult {
    /// Need more data to complete message
    WaitingForMore,
    /// Single message parsed successfully
    MessageComplete(L7Message),
    /// Multiple messages (e.g., pipelined requests)
    Messages(Vec<L7Message>),
    /// Parse error - connection should be closed
    Error(String),
    /// Protocol-specific close signal (PostgreSQL 'X' message, etc.)
    ConnectionClosed,
}
```

### Event Loop Integration

```rust
// In event_loop.rs (conceptual)

fn handle_data_event(&self, event: DataEvent) {
    let conn_id = event.socket_cookie;

    // 1. Get or create FSM
    if !self.fsm_manager.contains(conn_id) {
        let protocol = detect_protocol(
            &event.data,
            event.src_port,
            event.dst_port,
            event.direction,
        );

        match protocol {
            Some(p) => self.fsm_manager.get_or_create(conn_id, p),
            None => return, // Unknown protocol, skip parsing
        };
    }

    // 2. Process packet
    if let Some(result) = self.fsm_manager.process_packet(
        conn_id,
        event.direction,
        &event.data,
        event.timestamp_ns,
    ) {
        match result {
            FsmResult::MessageComplete(msg) => self.handle_message(msg),
            FsmResult::Messages(msgs) => msgs.into_iter().for_each(|m| self.handle_message(m)),
            FsmResult::Error(e) => {
                tracing::warn!(conn_id, error = %e, "parse error, closing");
                self.fsm_manager.close_connection(conn_id);
            }
            FsmResult::ConnectionClosed => self.fsm_manager.close_connection(conn_id),
            FsmResult::WaitingForMore => {}
        }
    }
}

fn handle_close_event(&self, conn_id: u64) {
    self.fsm_manager.close_connection(conn_id);
}

// Periodic task (spawned separately)
async fn eviction_task(fsm_manager: Arc<ConnectionFsmManager>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        fsm_manager.evict_idle(Duration::from_secs(300)); // 5 min TTL
    }
}
```

### Keep-Alive Handling

For HTTP Keep-Alive and database connection pools:

```rust
impl ProtocolFsm for ProtocolFsmAdapter {
    fn reset_for_next_transaction(&mut self) {
        // Clear request/response buffers but preserve:
        // - Protocol version (detected during handshake)
        // - Connection-level state (e.g., authenticated user)
        self.parser.reset_transaction_state();
    }
}

// In HTTP/1.1 parser (conceptual):
fn on_message_complete(&mut self) {
    if self.headers.connection == "keep-alive" {
        self.reset_for_next_transaction();
        // Stay in Active state, ready for next request
    }
}
```

### Memory Protection

Two-level protection prevents OOM:

1. **Hard Limit**: `max_connections` (default 100K) triggers LRU eviction on new connections:
   ```rust
   if self.connections.len() >= self.max_connections {
       let oldest_id = self.last_seen.iter()
           .min_by_key(|e| *e.value())
           .map(|e| *e.key());
       if let Some(id) = oldest_id {
           self.connections.remove(&id);
           self.last_seen.remove(&id);
       }
   }
   ```

2. **Soft Limit**: `evict_idle()` called periodically removes truly idle connections, freeing memory proactively.

## Consequences

### Positive

1. **Memory Efficiency**: Idle connections don't hold FSM state indefinitely; eviction reclaims memory.

2. **Correctness**: FSM state matches actual connection state—no stale parsing of closed connections.

3. **Keep-Alive Support**: Connections can process multiple transactions without re-detecting protocol.

4. **Observability**: `connection_state()` and metrics (connection count, eviction rate) aid debugging.

5. **Graceful Degradation**: On memory pressure, LRU eviction drops oldest connections first.

### Negative

1. **Idle Eviction Race**: Connection evicted while packets in flight will be re-detected, potentially with wrong protocol if first post-eviction packet is ambiguous. Mitigation: set TTL longer than expected idle periods.

2. **DashMap Overhead**: Two DashMaps (`connections` + `last_seen`) have memory overhead; combined structure would be more efficient but more complex.

3. **Detection Cost**: First-packet detection runs regex/magic byte checks on every new connection; mitigated by early returns and port hints.

### Neutral

1. **No Protocol Re-detection**: Once detected, protocol is fixed for connection lifetime. Protocol switching (HTTP upgrade) requires connection close + reconnect.

## Alternatives Considered

### Alternative 1: Eager Detection on SYN

**Description**: Detect protocol when TCP SYN is observed.

**Pros**:
- FSM created before first data packet

**Cons**:
- No protocol information in SYN
- Port hints unreliable (services on non-standard ports)
- Wastes FSM slots for connections that never transmit

**Why rejected**: Protocol cannot be determined from SYN; would require guesswork.

### Alternative 2: Per-Packet Detection

**Description**: Run detection on every packet.

**Pros**:
- Handles protocol switching

**Cons**:
- CPU overhead on every packet
- Detection ambiguous mid-stream
- HTTP/2 multiplexing makes packet-level detection meaningless

**Why rejected**: Protocols like HTTP/2 multiplex multiple streams; per-packet detection is semantically wrong.

### Alternative 3: Single Global Parser

**Description**: One parser instance reused for all connections.

**Pros**:
- Minimal memory

**Cons**:
- Cannot handle concurrent connections
- State management nightmare
- Doesn't match real-world model

**Why rejected**: Fundamentally incompatible with connection-oriented protocols.

## Implementation Notes

### Files to Modify

1. **`panopticon-agent/src/protocol/fsm.rs`**: Already contains `ConnectionFsmManager`. Ensure `reset_for_next_transaction()` is wired to parsers.

2. **`panopticon-agent/src/event_loop.rs`**: Wire up `close_connection()` on FIN/RST events; spawn eviction task.

3. **`panopticon-agent/src/protocol/mod.rs`**: Ensure `ProtocolParser` trait has `reset_transaction_state()` method.

4. **`panopticon-common/src/lib.rs`**: Add `ConnectionClosed` event type if not present.

### Testing Requirements

1. **Unit Tests** (in `fsm.rs`): Already present for `StreamBuffer`, `FsmResult`, and `ConnectionFsmManager` operations.

2. **Integration Tests**: 
   - Test Keep-Alive: send multiple HTTP requests on same connection
   - Test idle eviction: verify FSM removed after TTL
   - Test close on error: send malformed data, verify cleanup

3. **Performance Tests**:
   - 100K concurrent connections
   - Eviction rate under load
   - Memory usage over time

### Metrics to Expose

```rust
// Prometheus metrics
pub static CONNECTIONS_ACTIVE: Lazy<Counter> = ...;
pub static CONNECTIONS_EVICTED_IDLE: Lazy<Counter> = ...;
pub static CONNECTIONS_EVICTED_LRU: Lazy<Counter> = ...;
pub static CONNECTIONS_CLOSED: Lazy<Counter> = ...;
```

## References

- [ADR-001: FSM Architecture](ADR-001-fsm-architecture.md) (when created)
- [PostgreSQL Frontend/Backend Protocol](https://www.postgresql.org/docs/current/protocol.html)
- [MySQL Client/Server Protocol](https://dev.mysql.com/doc/internals/en/client-server-protocol.html)
- [HTTP/2 Connection Preface](https://httpwg.org/specs/rfc7540.html#ConnectionHeader)

---

## Revision History

| Date | Author | Description |
|------|--------|-------------|
| 2026-02-18 | @panopticon-team | Initial proposal |
