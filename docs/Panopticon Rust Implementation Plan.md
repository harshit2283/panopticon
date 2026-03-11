# Panopticon-rs: Complete Implementation Plan

> Historical planning document. This file records the original implementation
> plan and contains future-state design material. For the current open-source
> MVP status, use `README.md` and `docs/CURRENT-STATE.md`.
> **Purpose**: This document is a detailed, actionable implementation plan for Claude Code (or any AI coding agent) to build Panopticon-rs — a universal eBPF-based observability and privacy engine written in Rust. Follow this plan sequentially. Each phase produces a working, testable artifact before proceeding to the next.

## HIGHLY EXPERIMENTAL / UNSTABLE / NOT PRODUCTION READY

This plan describes an MVP and hardening-in-progress implementation target.
Do **not** treat features listed here as production guarantees.

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
| Kafka/AMQP/DNS/MongoDB full parser coverage | Unsupported | MVP contains scaffolding, not complete production behavior. |
| OpenSSL TLS plaintext capture | Partial | Works for targeted attach paths with runtime variance. |
| Go TLS plaintext capture | Partial | Write-path capture only in current MVP constraints. |
| Regex-first PII detection | Supported | Included as baseline path. |
| ML-based PII detection (ONNX) | Partial | Optional and throughput-sensitive in MVP. |
| Helm/DaemonSet deployment hardening | Partial | Deployment path exists; production hardening not complete. |

---

## Table of Contents

1. [Project Overview and Goals](#1-project-overview-and-goals)
2. [Repository Structure](#2-repository-structure)
3. [Development Environment and Toolchain Setup](#3-development-environment-and-toolchain-setup)
4. [Phase 1: Core eBPF Kernel Probes](#4-phase-1-core-ebpf-kernel-probes)
5. [Phase 2: User-Space Event Loop and Transport](#5-phase-2-user-space-event-loop-and-transport)
6. [Phase 3: Universal Protocol Parsing Engine](#6-phase-3-universal-protocol-parsing-engine)
7. [Phase 4: Cross-Language TLS Interception](#7-phase-4-cross-language-tls-interception)
8. [Phase 5: ML/SLM PII Detection Engine](#8-phase-5-mlslm-pii-detection-engine)
9. [Phase 6: Service Graph and Data Flow Builder](#9-phase-6-service-graph-and-data-flow-builder)
10. [Phase 7: Cross-Kernel and Cross-Platform Compatibility](#10-phase-7-cross-kernel-and-cross-platform-compatibility)
11. [Phase 8: API, Export and Integration Layer](#11-phase-8-api-export-and-integration-layer)
12. [Phase 9: Deployment and Packaging](#12-phase-9-deployment-and-packaging)
13. [Phase 10: Testing Strategy](#13-phase-10-testing-strategy)
14. [Appendices](#appendices)

---

## 1. Project Overview and Goals

### What We Are Building

Panopticon-rs is a **single-binary** observability agent that:

1. **Intercepts network traffic** (cleartext and encrypted) at the kernel level using eBPF, with protocol depth bounded by MVP scope (see Support Matrix): HTTP/1.1, HTTP/2, gRPC, MySQL, PostgreSQL, Redis, Kafka, MongoDB, DNS, and AMQP.
2. **Builds a real-time service dependency graph** (DAG) across all services in a cluster, resolving ephemeral IPs to Kubernetes service identities.
3. **Runs embedded ML-based PII detection** (Named Entity Recognition via DistilBERT/TinyBERT in ONNX) on intercepted payloads to flag and redact sensitive data in real time.
4. **Targets Linux kernel compatibility** (4.15+ via fallback, 5.8+ native), with **full support on x86_64** and **partial/validation-in-progress support on ARM64**, and language coverage via syscall and crypto-library hooks for Go, Java, Python, Node.js, Rust, C/C++, Ruby, and .NET.

### Non-Goals (v1)

- Full APM replacement (no flame graphs, CPU profiling)
- Windows/macOS kernel support (Linux only, but Darwin for dev builds)
- Real-time dashboarding UI (export to Grafana/OpenTelemetry instead)
- Replacing service meshes (observing, not proxying)

### Architecture Summary

```
+-------------------------------------------------------------+
|                     KERNEL SPACE                            |
|                                                             |
|  +--------------+  +--------------+  +------------------+   |
|  | TC Ingress/  |  | TLS Uprobes  |  | Tracepoints      |  |
|  | Egress       |  | (OpenSSL,    |  | (sched_process,  |  |
|  | (L3/L4 cap)  |  |  Go, Java)   |  |  sock events)    |  |
|  +------+-------+  +------+-------+  +--------+---------+  |
|         |                 |                    |            |
|         +--------+--------+--------------------+            |
|                  |                                          |
|          +-------v-------+                                  |
|          |   RingBuf     |  (shared, ordered, zero-copy)    |
|          +-------+-------+                                  |
|                  |                                          |
+------------------+------------------------------------------+
|                  |       USER SPACE                         |
|          +-------v-------+                                  |
|          |  Tokio Event  |                                  |
|          |  Loop         |                                  |
|          +-------+-------+                                  |
|                  |                                          |
|    +-------------+-------------+                            |
|    |             |             |                            |
|  +-v------+  +--v-------+  +-v----------+                  |
|  |Protocol|  |ML/PII    |  |Graph       |                  |
|  |Engine  |  |Engine    |  |Builder     |                  |
|  |(nom)   |  |(ort/ONNX)|  |(petgraph)  |                  |
|  +--------+  +----------+  +------------+                  |
|                  |                                          |
|          +-------v-------+                                  |
|          |  Export Layer  |  (OTLP, Prometheus, JSON, gRPC) |
|          +---------------+                                  |
+-------------------------------------------------------------+
```

---

## 2. Repository Structure

Create this exact directory layout. Every file listed below will be implemented.

```
panopticon-rs/
├── Cargo.toml                          # Workspace root
├── rust-toolchain.toml                 # Pin nightly for eBPF
├── .cargo/
│   └── config.toml                     # Cross-compilation targets
├── xtask/
│   ├── Cargo.toml                      # Build orchestration tool
│   └── src/
│       └── main.rs                     # cargo xtask build/run/test
├── panopticon-ebpf/                    # eBPF programs (kernel space)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                     # eBPF program entry (dispatcher)
│       ├── tc_capture.rs               # TC ingress/egress packet capture
│       ├── tls_probes.rs               # Uprobe hooks for OpenSSL/Go/Java
│       ├── process_monitor.rs          # Tracepoints for PID lifecycle
│       ├── sock_monitor.rs             # Socket event tracing
│       └── maps.rs                     # All eBPF map definitions
├── panopticon-common/                  # Shared types (kernel <-> user)
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs                      # Event structs, constants, enums
├── panopticon-agent/                   # User-space agent (main binary)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                     # Entry point, CLI, Tokio bootstrap
│       ├── loader.rs                   # eBPF program loader & attach logic
│       ├── event_loop.rs              # RingBuf consumer, dispatcher
│       ├── config.rs                   # Configuration (YAML/TOML)
│       ├── protocol/
│       │   ├── mod.rs                  # Protocol trait + dispatcher
│       │   ├── http1.rs                # HTTP/1.1 parser (httparse)
│       │   ├── http2.rs                # HTTP/2 frame parser + demux
│       │   ├── grpc.rs                 # gRPC over HTTP/2 + protobuf decode
│       │   ├── mysql.rs                # MySQL wire protocol parser
│       │   ├── postgres.rs             # PostgreSQL wire protocol parser
│       │   ├── redis.rs                # RESP protocol parser
│       │   ├── kafka.rs                # Kafka wire protocol parser
│       │   ├── dns.rs                  # DNS query/response parser
│       │   ├── mongodb.rs              # MongoDB wire protocol parser
│       │   ├── amqp.rs                 # AMQP 0-9-1 parser
│       │   └── detect.rs              # Auto-detection / multiplexing
│       ├── pii/
│       │   ├── mod.rs                  # PII engine orchestrator
│       │   ├── tokenizer.rs            # HuggingFace tokenizer wrapper
│       │   ├── inference.rs            # ONNX Runtime (ort) session
│       │   ├── classifier.rs           # NER label -> PII category mapping
│       │   ├── redactor.rs             # Text redaction engine
│       │   └── regex_prefilter.rs     # Fast pre-filter before ML
│       ├── graph/
│       │   ├── mod.rs                  # Graph builder orchestrator
│       │   ├── identity.rs             # IP -> K8s Service resolution
│       │   ├── aggregator.rs           # Sliding window edge aggregation
│       │   └── dag.rs                  # petgraph DAG operations
│       ├── export/
│       │   ├── mod.rs                  # Export dispatcher
│       │   ├── otlp.rs                 # OpenTelemetry Protocol export
│       │   ├── prometheus.rs           # Prometheus metrics endpoint
│       │   └── json.rs                 # JSON log export
│       └── platform/
│           ├── mod.rs                  # Platform abstraction
│           ├── kernel_compat.rs        # Kernel version detection & fallback
│           ├── container.rs            # Container ID -> Pod resolution
│           └── proc_scanner.rs         # /proc scanning for library paths
├── models/                             # ML model assets
│   ├── download_models.sh             # Script to download ONNX models
│   └── README.md                       # Model provenance documentation
├── deploy/
│   ├── Dockerfile                      # Multi-stage build
│   ├── Dockerfile.builder             # Build environment image
│   ├── daemonset.yaml                 # Kubernetes DaemonSet manifest
│   ├── rbac.yaml                       # ServiceAccount + ClusterRole
│   ├── configmap.yaml                 # Agent configuration
│   └── helm/                           # Helm chart
│       ├── Chart.yaml
│       ├── values.yaml
│       └── templates/
│           ├── daemonset.yaml
│           ├── rbac.yaml
│           └── configmap.yaml
├── tests/
│   ├── integration/
│   │   ├── test_http_capture.rs
│   │   ├── test_tls_capture.rs
│   │   ├── test_mysql_capture.rs
│   │   ├── test_pii_detection.rs
│   │   ├── test_graph_building.rs
│   │   └── test_kernel_compat.rs
│   ├── e2e/
│   │   ├── docker-compose.yaml        # Multi-service test environment
│   │   ├── test_microservices.py       # End-to-end validation
│   │   └── services/                   # Test microservices (Go, Python, Java, Node)
│   │       ├── go-service/
│   │       ├── python-service/
│   │       ├── java-service/
│   │       └── node-service/
│   └── benchmarks/
│       ├── bench_protocol_parsing.rs
│       ├── bench_pii_inference.rs
│       └── bench_ringbuf_throughput.rs
├── scripts/
│   ├── setup_dev.sh                    # Developer environment setup
│   ├── check_kernel.sh                # Kernel capability checker
│   └── generate_go_offsets.py          # Go ABI offset table generator
└── docs/
    ├── ARCHITECTURE.md
    ├── KERNEL_COMPAT.md
    └── ADDING_PROTOCOLS.md
```

### Cargo Workspace Configuration

**File: `Cargo.toml` (workspace root)**

```toml
[workspace]
resolver = "2"
members = [
    "panopticon-ebpf",
    "panopticon-common",
    "panopticon-agent",
    "xtask",
]

[workspace.dependencies]
aya = "0.13"
aya-ebpf = "0.1"
aya-log = "0.2"
aya-log-ebpf = "0.1"
tokio = { version = "1", features = ["full"] }
nom = "7"
httparse = "1"
ort = "2"
tokenizers = "0.20"
petgraph = "0.6"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = "0.3"
anyhow = "1"
thiserror = "1"
bytes = "1"
dashmap = "6"
kube = { version = "0.97", features = ["runtime", "derive"] }
k8s-openapi = { version = "0.23", features = ["latest"] }
opentelemetry = "0.27"
opentelemetry-otlp = "0.27"
prometheus-client = "0.23"
```

**File: `rust-toolchain.toml`**

```toml
[toolchain]
channel = "nightly"
components = ["rust-src", "clippy", "rustfmt", "llvm-tools"]
```

---

## 3. Development Environment and Toolchain Setup

### Prerequisites Script

**File: `scripts/setup_dev.sh`**

This script MUST be run first. It installs all required system dependencies.

```bash
#!/usr/bin/env bash
set -euo pipefail

echo "=== Panopticon-rs Development Environment Setup ==="

# 1. System packages
sudo apt-get update && sudo apt-get install -y \
    build-essential pkg-config libssl-dev libelf-dev \
    llvm-18 clang-18 linux-headers-$(uname -r) \
    linux-tools-$(uname -r) linux-tools-common \
    bpftool iproute2 libclang-dev protobuf-compiler cmake curl git

# 2. Rust nightly (required for aya-ebpf)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
source "$HOME/.cargo/env"
rustup component add rust-src clippy rustfmt llvm-tools

# 3. BPF linker (required for eBPF compilation)
cargo install bpf-linker

# 4. Cross-compilation targets
rustup target add x86_64-unknown-linux-gnu
rustup target add aarch64-unknown-linux-gnu
rustup target add x86_64-unknown-linux-musl

# 5. ONNX Runtime (for ML inference)
ONNXRUNTIME_VERSION="1.19.2"
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then ORT_ARCH="x64";
elif [ "$ARCH" = "aarch64" ]; then ORT_ARCH="aarch64"; fi
curl -L "https://github.com/microsoft/onnxruntime/releases/download/v${ONNXRUNTIME_VERSION}/onnxruntime-linux-${ORT_ARCH}-${ONNXRUNTIME_VERSION}.tgz" \
    -o /tmp/onnxruntime.tgz
sudo mkdir -p /opt/onnxruntime
sudo tar -xzf /tmp/onnxruntime.tgz -C /opt/onnxruntime --strip-components=1
echo 'export ORT_LIB_LOCATION=/opt/onnxruntime/lib' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/opt/onnxruntime/lib:${LD_LIBRARY_PATH:-}' >> ~/.bashrc

# 6. Download PII detection model
mkdir -p models/distilbert-ner
python3 -c "
from transformers import AutoTokenizer, AutoModelForTokenClassification
import torch
model_name = 'dslim/distilbert-NER'
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForTokenClassification.from_pretrained(model_name)
dummy_input = tokenizer('Hello World', return_tensors='pt')
torch.onnx.export(model, (dummy_input['input_ids'], dummy_input['attention_mask']),
    'models/distilbert-ner/model.onnx',
    input_names=['input_ids', 'attention_mask'], output_names=['logits'],
    dynamic_axes={'input_ids': {0: 'batch', 1: 'sequence'},
        'attention_mask': {0: 'batch', 1: 'sequence'},
        'logits': {0: 'batch', 1: 'sequence'}},
    opset_version=14)
tokenizer.save_pretrained('models/distilbert-ner/')
print('Model exported successfully')
" 2>/dev/null || echo "WARNING: Python model export failed. Install transformers+torch."

# 7. Kernel capability check
echo ""
echo "=== Kernel Capability Check ==="
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
echo "Kernel: $(uname -r)"
if awk "BEGIN {exit !($KERNEL_VERSION >= 5.8)}"; then echo "OK: RingBuf support (5.8+)";
else echo "WARN: No RingBuf. Will fall back to PerfEventArray."; fi
if awk "BEGIN {exit !($KERNEL_VERSION >= 5.5)}"; then echo "OK: BTF support (5.5+)";
else echo "WARN: No BTF. Will use manual struct definitions."; fi
if awk "BEGIN {exit !($KERNEL_VERSION >= 4.15)}"; then echo "OK: BPF TC hook support (4.15+)";
else echo "ERROR: Kernel too old. Minimum 4.15 required."; fi
echo "=== Setup Complete ==="
```

### Cargo Cross-Compilation Config

**File: `.cargo/config.toml`**

```toml
[build]
target-dir = "target"

[target.bpfel-unknown-none]
linker = "bpf-linker"
rustflags = ["-C", "link-arg=--target=bpfel"]

[alias]
xtask = "run --package xtask --"
```

---

## 4. Phase 1: Core eBPF Kernel Probes

### 4.1 Shared Types (panopticon-common)

**File: `panopticon-common/src/lib.rs`**

This file defines ALL data structures shared between kernel and user space. These must be `#[repr(C)]` for cross-boundary compatibility.

```rust
#![no_std]

pub const MAX_PAYLOAD_SIZE: usize = 4096;
pub const MAX_CONNECTIONS: u32 = 65536;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum EventType {
    TcPacket = 0,      // Raw packet from TC hook (cleartext)
    TlsData = 1,       // Decrypted payload from TLS uprobe
    ProcessExec = 2,   // New process/thread created
    ProcessExit = 3,   // Process/thread exited
    SockConnect = 4,   // Socket connect event
    SockAccept = 5,    // Socket accept event
    SockClose = 6,     // Socket close event
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Direction { Ingress = 0, Egress = 1 }

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TlsLibrary {
    OpenSsl = 0, GoTls = 1, JavaSsl = 2,
    // Future: BoringSSL, GnuTLS, NSS, rustls
}

/// Primary event structure sent from kernel to user space via RingBuf.
/// IMPORTANT: Must remain <= 8KB to fit in a single RingBuf slot.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DataEvent {
    pub timestamp_ns: u64,       // bpf_ktime_get_ns
    pub event_type: EventType,
    pub direction: Direction,
    pub socket_cookie: u64,      // bpf_get_socket_cookie
    pub pid: u32,
    pub tgid: u32,
    pub src_addr: u32,           // Network byte order, IPv4
    pub dst_addr: u32,
    pub src_port: u16,           // Host byte order
    pub dst_port: u16,
    pub ip_proto: u8,            // 6=TCP, 17=UDP
    pub tls_library: TlsLibrary,
    pub payload_len: u32,
    pub payload: [u8; MAX_PAYLOAD_SIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessEvent {
    pub timestamp_ns: u64,
    pub event_type: EventType,
    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],          // Task name, 16 bytes max in Linux
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnInfo {
    pub pid: u32,
    pub tgid: u32,
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub socket_cookie: u64,
    pub connect_ts: u64,
}
```

### 4.2 eBPF Maps

**File: `panopticon-ebpf/src/maps.rs`**

```rust
use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, RingBuf, PerfEventArray, Array};
use panopticon_common::{DataEvent, ProcessEvent, ConnInfo, MAX_CONNECTIONS};

// Primary data channel: kernel -> user space
#[map]
pub static DATA_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Fallback for kernels < 5.8
#[map]
pub static DATA_EVENTS_PERF: PerfEventArray<DataEvent> =
    PerfEventArray::with_max_entries(1024, 0);

#[map]
pub static PROCESS_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// Active connection tracking: socket_cookie -> ConnInfo
#[map]
pub static CONN_MAP: HashMap<u64, ConnInfo> =
    HashMap::with_max_entries(MAX_CONNECTIONS, 0);

// PID -> container cgroup ID mapping
#[map]
pub static PID_CGROUP_MAP: HashMap<u32, u64> =
    HashMap::with_max_entries(MAX_CONNECTIONS, 0);

// Config flags: [0]=capture_enabled, [1]=max_payload, [2]=use_ringbuf, [3]=pid_filter_on
#[map]
pub static CONFIG: Array<u64> = Array::with_max_entries(16, 0);

// PID allowlist filter
#[map]
pub static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);

// Scratch map for SSL_read buf pointer storage (per PID/TID)
#[map]
pub static TLS_SCRATCH: HashMap<u64, u64> = HashMap::with_max_entries(8192, 0);

// Per-binary Go ABI register mapping
#[map]
pub static GO_ABI_MAP: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);
```

### 4.3 TC Capture eBPF Program

**File: `panopticon-ebpf/src/tc_capture.rs`**

Implementation specification for the TC (Traffic Control) classifier:

```
HOOK: tc ingress + egress on all pod interfaces
KERNEL COMPAT: Linux 4.15+

PSEUDO-CODE FLOW:
  1. Read CONFIG[0] -- if 0, return TC_ACT_OK immediately (passthrough).
  2. Parse ethernet header (14 bytes). Check ethertype == IPv4 (0x0800).
     - For IPv6 (0x86DD): parse IPv6 header (40 bytes), extract next_header.
     - Skip non-IP traffic (ARP, etc.).
  3. Parse IP header. Extract: src_ip, dst_ip, protocol, total_length, IHL.
  4. If protocol == TCP (6):
     a. Parse TCP header (variable length via data_offset).
     b. Extract: src_port, dst_port, flags, seq, ack.
     c. Calculate payload offset = eth_hdr + ip_hdr + tcp_hdr.
     d. Calculate payload length = ip_total_length - ip_hdr - tcp_hdr.
  5. If protocol == UDP (17):
     a. Parse UDP header (8 bytes fixed).
     b. Extract: src_port, dst_port.
     c. Payload offset = eth_hdr + ip_hdr + 8.
     d. Payload length = udp_length - 8.
  6. If payload_length > 0:
     a. Reserve space in RingBuf via bpf_ringbuf_reserve (NOT stack -- too big).
     b. Fill metadata (timestamp, 5-tuple, direction, pid via socket_cookie).
     c. Copy min(payload_length, MAX_PAYLOAD_SIZE) bytes via bpf_skb_load_bytes.
     d. Submit to RingBuf.
  7. Return TC_ACT_OK always (never drop packets -- passive observer).

VERIFIER CONSTRAINTS:
  - All buffer accesses bounded with explicit checks.
  - No unbounded loops. Use #[inline(always)] for all helper functions.
  - Stack limit: 512 bytes. DataEvent is ~4.2KB -- MUST use RingBuf reserve.
  - If RingBuf reserve fails (full), drop event silently.
```

### 4.4 TLS Probes eBPF Program

**File: `panopticon-ebpf/src/tls_probes.rs`**

Specification for TLS interception via Uprobes:

```
STRATEGY: Hook plaintext side of TLS -- capture data BEFORE encryption
(on write) and AFTER decryption (on read). Immune to TLS version changes.

TARGET FUNCTIONS:
  OpenSSL:  SSL_write(ssl, buf, num) / SSL_read(ssl, buf, num)
  Go TLS:   crypto/tls.(*Conn).Write([]byte) / Read([]byte)
  Java:     Via JNI/USDT probes on Conscrypt or JSSE

OPENSSL (covers C, C++, Python, Ruby, Node.js, PHP):
  SSL_write entry uprobe:
    1. Read buf pointer from RDI (x86_64 SysV ABI) or X0 (ARM64).
    2. Read num from RSI / X1.
    3. Copy min(num, MAX_PAYLOAD_SIZE) bytes via bpf_probe_read_user.
    4. Submit DataEvent{event_type=TlsData, direction=Egress}.

  SSL_read entry uprobe:
    1. Store buf pointer in TLS_SCRATCH map keyed by (pid << 32 | tid).
  SSL_read return uretprobe:
    1. Read return value (bytes read) from RAX / X0.
    2. Lookup buf pointer from TLS_SCRATCH.
    3. Copy min(retval, MAX_PAYLOAD_SIZE) bytes.
    4. Submit DataEvent{event_type=TlsData, direction=Ingress}.

GO TLS (Go 1.17+ register-based ABI):
  crypto/tls.(*Conn).Write:
    Registers: RAX=receiver, RBX=buf.ptr, RCX=buf.len, RDI=buf.cap
    1. Read RBX (buf_ptr) and RCX (buf_len) from pt_regs.
    2. Validate non-zero.
    3. Copy min(buf_len, MAX_PAYLOAD_SIZE) via bpf_probe_read_user.
    4. Submit DataEvent.

  crypto/tls.(*Conn).Read:
    PROBLEM: uretprobe CRASHES Go binaries (goroutine stack relocation).
    SOLUTION (v1): Only hook Write (egress). For Read:
      Option A: Use Go USDT probes if available (go >= 1.22)
      Option B: Hook internal readFromReader or readRecordLocked
      Option C: Accept egress-only for Go TLS in v1

GO VERSION DETECTION (done by user-space loader):
  1. Read ELF .note.go.buildinfo section -> parse Go version.
  2. If go < 1.17: args on stack. If go >= 1.17: register ABI.
  3. Use DWARF debug info or symbol table for function offsets.
  4. Fall back to version-matrix lookup table.

LIBRARY DISCOVERY (done by user-space proc_scanner):
  Scan /proc/<pid>/maps for:
    - libssl.so*     -> attach OpenSSL probes
    - libgnutls.so*  -> attach GnuTLS probes  
    - Static Go bin  -> readelf -s | grep crypto/tls -> attach Go probes
    - java in cmdline -> attach Java probes
```

### 4.5 Process Monitor

**File: `panopticon-ebpf/src/process_monitor.rs`**

```
HOOK POINTS:
  1. tracepoint/sched/sched_process_exec (Linux 2.6+)
     Captures: pid, tgid, comm, ppid.
     Also captures cgroup ID via bpf_get_current_cgroup_id() (kernel 4.18+).
     Stores in PID_CGROUP_MAP. Emits ProcessEvent.

  2. tracepoint/sched/sched_process_exit (Linux 2.6+)
     Cleans up CONN_MAP and PID_CGROUP_MAP entries.
     Emits ProcessEvent.

  3. tracepoint/sock/inet_sock_set_state (Linux 4.16+)
     TCP state transitions. Captures full 5-tuple at connection time.
     Fallback: kprobe/tcp_set_state for older kernels.
```

### 4.6 Socket Monitor

**File: `panopticon-ebpf/src/sock_monitor.rs`**

```
HOOK POINTS:
  1. kprobe/tcp_connect -> SYN_SENT, capture 5-tuple, store in CONN_MAP
  2. kprobe/inet_csk_accept (ret) -> accepted connections (server side)
  3. kprobe/tcp_close -> remove from CONN_MAP, emit SockClose event
  4. kprobe/udp_sendmsg / udp_recvmsg -> individual UDP packet tracking
```

---

## 5. Phase 2: User-Space Event Loop and Transport

### 5.1 eBPF Program Loader

**File: `panopticon-agent/src/loader.rs`**

```
RESPONSIBILITIES:
  1. Detect kernel version and capabilities.
  2. Load appropriate eBPF programs (embedded .o files via include_bytes!).
  3. Attach to correct hook points.
  4. Discover TLS libraries and attach uprobes dynamically.
  5. Watch for new processes and attach uprobes on the fly.

KERNEL VERSION DETECTION:
  Read /proc/version_signature or uname(). Build KernelCapabilities:
    has_ringbuf: kernel >= 5.8
    has_btf: kernel >= 5.5 AND /sys/kernel/btf/vmlinux exists
    has_cgroup_id: kernel >= 4.18
    has_inet_sock_set_state: kernel >= 4.16
    has_tc_ebpf: kernel >= 4.15
    has_bpf_link: kernel >= 5.7

LOADING STRATEGY:
  If has_btf: Use Aya BpfLoader with BTF (CO-RE).
  Else: Load with manually defined struct layouts.
  Embed TWO eBPF binaries:
    panopticon-ebpf-ringbuf.o  (kernel 5.8+)
    panopticon-ebpf-perf.o     (kernel 4.15-5.7)
  Select at runtime.

TC ATTACHMENT:
  For each interface in /sys/class/net/*/:
    Skip lo, br-*, docker0.
    Create clsact qdisc if not present.
    Attach tc_ingress + tc_egress programs.
    Watch for new interfaces via inotify/netlink.

TLS UPROBE ATTACHMENT:
  1. Scan /proc/*/maps for all running processes.
  2. Identify loaded libraries -> attach appropriate probes.
  3. Track attached probes in HashSet<(pid, library, function)>.
  4. Re-scan every 5s to catch new processes.
  5. On process exit, remove probes.

CLEANUP ON SHUTDOWN:
  Detach all TC programs, uprobes. Remove clsact qdiscs. Close maps.

ERROR HANDLING:
  If program fails to load: log error, continue with remaining programs.
  If uprobe fails to attach: log and skip. Never crash the agent.
```

### 5.2 Asynchronous Event Loop

**File: `panopticon-agent/src/event_loop.rs`**

```
ARCHITECTURE:

  RingBuf --> Reader Task --> mpsc channels --> Worker Tasks
                 |                                |
                 | (routes by socket_cookie)      |
                 |                                v
                 |                          +-------------+
                 |                          | Protocol    |
                 |                          | Parser      |
                 |                          +-------------+
                 |                          | PII Engine  |
                 |                          +-------------+
                 |                          | Graph Update|
                 |                          +-------------+
                 |
                 +--> Process Events --> Identity Resolver

IMPLEMENTATION:

1. RingBuf Reader (single task):
   - Uses aya::maps::RingBuf with AsyncFd for tokio integration.
   - On readable: drain ALL available events in tight loop.
   - For each DataEvent:
     a. Look up socket_cookie in DashMap<u64, mpsc::Sender>.
     b. If found: send to existing worker. If not: spawn new worker.
   - For each ProcessEvent: send to identity resolver channel.

2. Connection Worker (one per active connection):
   - Maintains StreamBuffer (Vec<u8>) for TCP reassembly.
   - On new event: append payload, attempt protocol detection,
     parse complete L7 messages, send to PII + graph + export.
   - Idle timeout: 30s -> close worker and remove channel.

3. Channel Sizing:
   - Reader -> Worker: bounded mpsc, capacity 1024.
   - Worker -> PII: bounded mpsc, capacity 256.
   - Worker -> Graph: bounded mpsc, capacity 4096.
   - Backpressure: if full, DROP event + increment counter. Never block.

4. Fallback (PerfEventArray for kernel < 5.8):
   - One reader task per CPU.
   - Events may arrive out of order.
   - Add reorder buffer keyed on (socket_cookie, sequence_number).
   - Adds ~2ms latency but ensures correct protocol parsing.

PERFORMANCE TARGETS:
  - 500K events/sec sustained on 16-core node.
  - P99 latency kernel capture -> user-space processing: < 5ms.
  - Memory: < 200MB RSS (excluding ML model).
```

---

## 6. Phase 3: Universal Protocol Parsing Engine

### 6.1 Protocol Detection

**File: `panopticon-agent/src/protocol/detect.rs`**

Detection uses magic bytes first (most reliable), then falls back to port hints.

```
MAGIC BYTE SIGNATURES:
  HTTP/1.x:    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/1."
  HTTP/2:      "PRI * HTTP/2.0\r\n" (connection preface)
  MySQL:       packet[4] == 0x0a (protocol version 10 greeting)
  PostgreSQL:  first byte 'R' (auth) or length-prefixed with protocol 3.0
  Redis:       starts with +, -, :, $, or *
  Kafka:       API key + version in first 4 bytes
  MongoDB:     bytes 12-15 are opcode (1=OP_REPLY, 2013=OP_MSG)
  DNS:         UDP + specific header structure (QR bit, opcode, qdcount)
  AMQP:        "AMQP\x00\x00\x09\x01"
  TLS:         ContentType=0x16, Version=0x0301-0x0303

UNKNOWN PROTOCOL HANDLING:
  - Still build flow graph edge (we know src->dst).
  - Run PII regex pre-filter on raw bytes.
  - Log as "unknown" with hex dump of first 64 bytes.
```

### 6.2 Protocol Parser Trait

**File: `panopticon-agent/src/protocol/mod.rs`**

```rust
pub trait ProtocolParser: Send + 'static {
    /// Feed new bytes. Returns complete L7 messages extracted.
    fn feed(&mut self, data: &[u8], direction: Direction) -> Vec<L7Message>;
    fn reset(&mut self);
    fn protocol(&self) -> Protocol;
}

pub struct L7Message {
    pub protocol: Protocol,
    pub direction: Direction,
    pub timestamp_ns: u64,
    pub latency_ns: Option<u64>,       // request->response delta
    pub method: Option<String>,         // HTTP method, SQL command, etc.
    pub path: Option<String>,           // HTTP URI, SQL table, Redis key
    pub status: Option<u32>,            // HTTP status, error code
    pub content_type: Option<String>,
    pub payload_text: Option<String>,   // For PII scanning
    pub headers: Vec<(String, String)>,
    pub request_size_bytes: u64,
    pub response_size_bytes: u64,
}
```

### 6.3 Individual Parser Specifications

**HTTP/1.1** (`protocol/http1.rs`):
- Use `httparse` crate for zero-copy header parsing.
- Track request/response pairs (HTTP/1.1 is sequential per connection).
- Handle chunked transfer encoding (parse chunk sizes, reassemble body).
- Handle Content-Length body reads and `100 Continue` responses.
- Handle HTTP pipelining.

**HTTP/2** (`protocol/http2.rs`):
- Parse 9-byte frame header: Length(3) + Type(1) + Flags(1) + StreamID(4).
- Handle frames: DATA(0), HEADERS(1), SETTINGS(4), PING(6), GOAWAY(7), WINDOW_UPDATE(8).
- Per-stream state: `HashMap<u32, StreamState>` for accumulated HEADERS and DATA.
- HPACK header decompression via `hpack` crate.
- Detect gRPC via Content-Type containing "application/grpc".

**gRPC** (`protocol/grpc.rs`):
- Built on HTTP/2 parser.
- Parse gRPC frame: Compressed(1) + MessageLength(4) + Message(N).
- Schema-less Protobuf decoding: scan wire format for Length-Delimited fields (Wire Type 2), attempt UTF-8 decode on all, recursively decode nested messages.
- Output flat list of `(field_path, string_value)` pairs for PII scanning.

**MySQL** (`protocol/mysql.rs`):
- Packet: length(3) + sequence_id(1) + payload.
- Server greeting, COM_QUERY (0x03), COM_STMT_PREPARE (0x16), error packet (0xFF).
- Track request/response by sequence_id.

**PostgreSQL** (`protocol/postgres.rs`):
- Message: type(1) + length(4) + payload.
- Frontend: 'Q' (Simple Query), 'P' (Parse), 'B' (Bind), 'E' (Execute).
- Backend: 'T' (RowDescription), 'D' (DataRow), 'C' (CommandComplete), 'E' (ErrorResponse).
- Track extended query protocol flow.

**Redis** (`protocol/redis.rs`):
- RESP: type prefix (+, -, :, $, *) + data + \r\n.
- Parse array of bulk strings for commands. Track request/response pairing.

**Kafka** (`protocol/kafka.rs`):
- Request: length(4) + api_key(2) + api_version(2) + correlation_id(4) + client_id + payload.
- Track by correlation_id. Key APIs: Produce(0), Fetch(1), Metadata(3).

**DNS** (`protocol/dns.rs`):
- UDP. Header + question section. Parse domain names with compression pointers.

**MongoDB** (`protocol/mongodb.rs`):
- MsgHeader + OP_MSG (2013) sections. BSON field name/value extraction.

**AMQP** (`protocol/amqp.rs`):
- Frame: type(1) + channel(2) + size(4) + payload + frame_end(1).
- Extract exchange, routing_key, queue names, message payload.

---

## 7. Phase 4: Cross-Language TLS Interception

**File: `panopticon-agent/src/platform/proc_scanner.rs`**

```
SCAN ALGORITHM:
  For each PID:
    1. Read /proc/<pid>/maps, identify loaded TLS libraries:
       - libssl.so*    -> OpenSSL (covers C, C++, Python, Ruby, Node.js, PHP)
       - libgnutls.so* -> GnuTLS
       - libnss*.so    -> NSS
    2. Check if ELF binary is a static Go binary:
       - readelf -s | grep crypto/tls -> Go TLS
       - Detect Go version from .note.go.buildinfo
       - Select register mapping (stack for <1.17, register for >=1.17)
    3. Check for Java: cmdline contains "java"
       - Hook JNI SSL if Conscrypt is used
       - Or use JVM USDT probes (hotspot_jni_*)
       - Or fall back to TC capture (encrypted, but still get L3/L4)
    4. .NET: Hook SslStream via CoreCLR or underlying OpenSSL

SYMBOL RESOLUTION:
  Use `object` crate to parse ELF:
    - .dynsym for shared libraries
    - .symtab for Go binaries
    - DWARF .debug_info for function signatures

NAMESPACE AWARENESS (in Kubernetes):
  Running as DaemonSet with hostPID=true:
    - /proc shows HOST process namespace
    - Use /proc/<pid>/root/ for process filesystem access
    - Resolve library paths relative to process mount namespace
    - Handle overlay filesystems (Docker/containerd layers)

CONTINUOUS SCANNING:
  - Full scan on startup
  - Watch ProcessEvent from eBPF for new processes
  - Periodic full re-scan every 60s
```

---

## 8. Phase 5: ML/SLM PII Detection Engine

### 8.1 Pipeline Architecture

**File: `panopticon-agent/src/pii/mod.rs`**

```
PIPELINE:

  L7Message.payload_text
      |
      v
  1. Regex Pre-Filter (regex_prefilter.rs)
     Fast scan: skip if no patterns match. Filters ~90% of traffic.
     Cost: ~1us per payload.
      |  (suspicious payloads only)
      v
  2. Tokenizer (tokenizer.rs)
     HuggingFace WordPiece tokenizer -> input_ids + attention_mask.
     Truncate at 512 tokens (model max).
      |
      v
  3. ONNX Inference (inference.rs)
     DistilBERT-NER or TinyBERT-NER via ort crate.
     Outputs: logits per token per entity class.
      |
      v
  4. Classifier (classifier.rs)
     Softmax -> argmax per token.
     Map BIO labels: B-PER/I-PER -> PERSON_NAME, B-LOC -> LOCATION, etc.
      |
      v
  5. Redactor (redactor.rs)
     Replace spans: "John Smith" -> "<PERSON_NAME>"
     Return redacted text + PII report.
```

### 8.2 Regex Pre-Filter Patterns

**File: `panopticon-agent/src/pii/regex_prefilter.rs`**

```
PATTERNS (compiled once via RegexSet for O(n) matching):

  EMAIL:       [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
  PHONE_US:    \b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b
  PHONE_INTL:  \b\+\d{1,3}[-.\s]?\d{4,14}\b
  SSN:         \b\d{3}-\d{2}-\d{4}\b
  CREDIT_CARD: \b(?:\d{4}[-\s]?){3}\d{4}\b
  IP_V4:       \b(?:\d{1,3}\.){3}\d{1,3}\b
  JWT:         \beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b
  API_KEY:     \b(?:sk|pk|api|key|token|secret|password)[-_]?[A-Za-z0-9]{20,}\b
  AWS_KEY:     \bAKIA[0-9A-Z]{16}\b
  AADHAAR:     \b\d{4}\s?\d{4}\s?\d{4}\b    (Indian Aadhaar)
  PAN:         \b[A-Z]{5}\d{4}[A-Z]\b       (Indian PAN card)
```

### 8.3 Performance Optimization

```
1. Regex pre-filter runs BEFORE ML. No regex match -> skip ML entirely.
2. Sampling: configurable per endpoint.
     pii.default_sample_rate: 0.01   (1% of all traffic)
     pii.endpoint_overrides:
       "/api/users/*": 1.0           (100% for user endpoints)
       "/health": 0.0                (0% for health checks)
3. Batching: accumulate up to 8 texts, run inference in single batch.
   DistilBERT on CPU: ~3ms for batch of 8 vs ~2ms for batch of 1.
   Use 5ms timeout to flush partial batches.
4. Dedicated thread pool for ML (spawn_blocking or rayon).
   Pool size: num_cpus / 4, cap at 4 threads.

MODEL LOADING:
  Load ONNX from embedded binary (include_bytes!) or configurable path.
  Load tokenizer vocabulary from tokenizer.json.
  Initialize ort::Session with:
    ExecutionProviders: CPU (default), CUDA (if available)
    IntraOpNumThreads: 2
    GraphOptimizationLevel: Level3
  Warm up: run dummy inference to trigger JIT.

CONFIDENCE THRESHOLD:
  Default: 0.90. Configurable per deployment.
  Start at 0.90, tune down based on false negative rate.
```

---

## 9. Phase 6: Service Graph and Data Flow Builder

**File: `panopticon-agent/src/graph/`**

### 9.1 Identity Resolution (`identity.rs`)

```
Resolution chain (IP -> Service):
  1. Check local cache: DashMap<IpAddr, ServiceIdentity> with TTL=5min.
  2. If miss: PID -> Container ID -> Pod Name -> Service.
  3. Container ID from: /proc/<pid>/cgroup (v1) or /proc/<pid>/mountinfo (v2).
  4. Pod lookup via kube::Api<Pod>::list (cached with kube::runtime::watcher).
  5. Service lookup: Pod labels -> Service selector match.
  6. If not in K8s: use hostname or "external:<ip>" as identity.
```

### 9.2 Edge Aggregation (`aggregator.rs`)

```rust
struct EdgeStats {
    source: ServiceIdentity,
    destination: ServiceIdentity,
    protocol: Protocol,
    request_count: u64,
    error_count: u64,
    pii_detected_count: u64,
    total_request_bytes: u64,
    total_response_bytes: u64,
    latency_histogram: HdrHistogram,   // P50, P90, P99, P999
    first_seen: Instant,
    last_seen: Instant,
    sample_requests: VecDeque<L7MessageSummary>,  // last 10
}

// Aggregation window: 30 seconds. At end:
// 1. Snapshot all EdgeStats.
// 2. Reset counters (keep cumulative histograms).
// 3. Send snapshot to export layer.
```

### 9.3 DAG Construction (`dag.rs`)

```
Use petgraph::DiGraph<ServiceIdentity, EdgeStats>.

Operations:
  add_or_update_edge(src, dst, protocol, stats)
  get_dependencies(service) -> downstream services
  get_dependents(service) -> upstream services
  detect_cycles() -> should be empty in healthy systems
  topological_sort() -> service execution order
  find_critical_path(entry, exit) -> highest latency path
  prune_stale(max_age: Duration) -> remove old edges
```

---

## 10. Phase 7: Cross-Kernel and Cross-Platform Compatibility

**File: `panopticon-agent/src/platform/kernel_compat.rs`**

### Kernel Feature Matrix

| Kernel Version | Features Available | Strategy |
|---|---|---|
| 4.15 - 4.17 | TC eBPF, kprobes, basic maps | PerfEventArray, no cgroup ID, manual structs |
| 4.18 - 5.4 | + cgroup ID, raw tracepoints, sock_ops | PerfEventArray, cgroup-based PID mapping |
| 5.5 - 5.7 | + BTF (CO-RE), global data | BTF-enabled loading, PerfEventArray |
| 5.8 - 5.12 | + RingBuf, bpf_ringbuf_reserve | RingBuf, BTF, full feature set |
| 5.13+ | + typed globals, bpf_loop, kfuncs | Everything + optimized loops |
| 6.0+ | + bpf_dynptr, arena maps | Everything + dynamic buffers |

### Build Strategy

```
Compile TWO eBPF binaries:
  1. panopticon-ebpf-ringbuf.o   (kernel 5.8+)
  2. panopticon-ebpf-perf.o      (kernel 4.15-5.7)
Both embedded in agent binary via include_bytes!.
Runtime selection based on kernel version detection.

For kernels WITH BTF (5.5+): use CO-RE.
For kernels WITHOUT BTF:
  - Ship pre-generated vmlinux.h for common distros
    (Ubuntu 18.04/20.04/22.04, CentOS 7/8, Amazon Linux 2, RHEL 8/9)
  - Match /etc/os-release and kernel version at runtime.
  - Last resort: most common struct layout + warning log.
```

### Architecture Support

```
x86_64: Primary target. Full support.
aarch64 (ARM64): Partial support in MVP. Arch-specific register names for uprobes are implemented, but validation coverage remains limited.

Abstraction trait:
  trait ArchRegisters {
      fn arg0(regs: &PtRegs) -> u64;  // x86: rdi, arm64: x0
      fn arg1(regs: &PtRegs) -> u64;  // x86: rsi, arm64: x1
      fn ret_val(regs: &PtRegs) -> u64;
      fn stack_ptr(regs: &PtRegs) -> u64;
  }
```

### Distribution Support

```
TESTED AND SUPPORTED:
  Ubuntu 18.04+, Debian 10+, CentOS 8/Rocky 8/Alma 8,
  RHEL 9/Rocky 9, Amazon Linux 2023, Fedora (latest),
  Alpine Linux (musl target), Bottlerocket, Flatcar, Talos Linux

PARTIAL SUPPORT:
  Amazon Linux 2 (kernel 4.14 -- some features missing)

NOT SUPPORTED:
  CentOS 7 (kernel 3.10 -- below minimum 4.15)

REQUIRED CAPABILITIES:
  CAP_BPF (or CAP_SYS_ADMIN on older kernels)
  CAP_NET_ADMIN (TC hooks)
  CAP_SYS_PTRACE (uprobe attachment)
  CAP_PERFMON (perf events, kernel 5.8+)
  Access to /sys/kernel/debug (debugfs)
  Access to host /proc (hostPID: true in K8s)
```

---

## 11. Phase 8: API, Export and Integration Layer

**File: `panopticon-agent/src/export/`**

### Export Targets

**1. OpenTelemetry (OTLP)** (`otlp.rs`):
- Traces: Each L7 request becomes a span with parent/child linking.
- Metrics: RED metrics per service edge (request_total, duration, pii_detected).
- Export via gRPC to Jaeger, Tempo, Datadog, New Relic, etc.

**2. Prometheus** (`prometheus.rs`):
- /metrics endpoint on port 9090.
- panopticon_events_total, events_dropped, ringbuf_usage, connections_active,
  pii_scan_duration, ml_inference_duration, plus all RED metrics.

**3. JSON Log** (`json.rs`):
- Structured JSON per L7 message to stdout or file.
- Includes: timestamp, src/dst service, protocol, method, path, status,
  latency, pii_detected, redacted_payload.

**4. Graph API**:
- GET /api/v1/graph -> full DAG as JSON adjacency list.
- WebSocket /api/v1/graph/stream -> real-time updates.

---

## 12. Phase 9: Deployment and Packaging

### Dockerfile

```dockerfile
# Stage 1: Build eBPF
FROM rust:nightly-bookworm AS ebpf-builder
RUN apt-get update && apt-get install -y clang-18 llvm-18 libelf-dev linux-headers-generic pkg-config cmake protobuf-compiler
RUN cargo install bpf-linker
WORKDIR /build
COPY . .
RUN cargo xtask build-ebpf --release

# Stage 2: Build agent
FROM rust:nightly-bookworm AS agent-builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev libelf-dev protobuf-compiler cmake
ARG ONNXRUNTIME_VERSION=1.19.2
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "amd64" ]; then ORT_ARCH="x64"; elif [ "$TARGETARCH" = "arm64" ]; then ORT_ARCH="aarch64"; fi && \
    curl -L "https://github.com/microsoft/onnxruntime/releases/download/v${ONNXRUNTIME_VERSION}/onnxruntime-linux-${ORT_ARCH}-${ONNXRUNTIME_VERSION}.tgz" -o /tmp/ort.tgz && \
    mkdir -p /opt/onnxruntime && tar -xzf /tmp/ort.tgz -C /opt/onnxruntime --strip-components=1
ENV ORT_LIB_LOCATION=/opt/onnxruntime/lib
WORKDIR /build
COPY . .
COPY --from=ebpf-builder /build/target/bpfel-unknown-none/release/ target/bpfel-unknown-none/release/
RUN cargo build --package panopticon-agent --release

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libelf1 libssl3 iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=agent-builder /opt/onnxruntime/lib/ /usr/lib/
COPY --from=agent-builder /build/target/release/panopticon-agent /usr/local/bin/
COPY models/ /opt/panopticon/models/
ENV LD_LIBRARY_PATH=/usr/lib
ENTRYPOINT ["/usr/local/bin/panopticon-agent"]
```

### Kubernetes DaemonSet

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: panopticon
  namespace: panopticon-system
spec:
  selector:
    matchLabels:
      app: panopticon
  template:
    metadata:
      labels:
        app: panopticon
    spec:
      hostPID: true
      hostNetwork: true
      serviceAccountName: panopticon
      containers:
      - name: agent
        image: panopticon-rs:latest
        securityContext:
          privileged: false
          capabilities:
            add: [BPF, SYS_ADMIN, NET_ADMIN, SYS_PTRACE, PERFMON, SYS_RESOURCE]
        volumeMounts:
        - { name: proc, mountPath: /host/proc, readOnly: true }
        - { name: sys, mountPath: /sys, readOnly: true }
        - { name: debugfs, mountPath: /sys/kernel/debug }
        - { name: config, mountPath: /etc/panopticon }
        resources:
          requests: { cpu: 200m, memory: 256Mi }
          limits: { cpu: "2", memory: 1Gi }
        ports:
        - { containerPort: 9090, name: metrics }
        - { containerPort: 8080, name: api }
      volumes:
      - { name: proc, hostPath: { path: /proc } }
      - { name: sys, hostPath: { path: /sys } }
      - { name: debugfs, hostPath: { path: /sys/kernel/debug } }
      - { name: config, configMap: { name: panopticon-config } }
      tolerations:
      - operator: Exists
```

### Agent Configuration (ConfigMap)

```yaml
agent:
  log_level: info

capture:
  interfaces: []           # empty = all non-loopback
  max_payload_size: 4096
  use_ringbuf: auto        # auto-detected

tls:
  enabled: true
  openssl: true
  go_tls: true
  java_tls: false          # experimental
  scan_interval_seconds: 10

protocols:
  http1: true
  http2: true
  grpc: true
  mysql: true
  postgres: true
  redis: true
  kafka: true
  dns: true
  mongodb: true
  amqp: true

pii:
  enabled: true
  model: distilbert-ner
  confidence_threshold: 0.90
  default_sample_rate: 0.01
  endpoint_overrides:
    "/api/users/*": 1.0
    "/api/payments/*": 1.0
    "/api/auth/*": 1.0
    "/health": 0.0
    "/metrics": 0.0
  max_inference_threads: 4
  batch_size: 8
  batch_timeout_ms: 5

graph:
  window_seconds: 30
  stale_edge_timeout_seconds: 300

export:
  otlp:
    enabled: true
    endpoint: "http://otel-collector.observability:4317"
    protocol: grpc
  prometheus:
    enabled: true
    port: 9090
  json:
    enabled: false
    output: stdout
  api:
    enabled: true
    port: 8080
```

---

## 13. Phase 10: Testing Strategy

### Unit Tests

```
Every module must have unit tests. Key areas:

protocol/http1.rs:
  - Parse valid GET, POST, PUT, DELETE requests.
  - Parse chunked transfer encoding.
  - Parse responses with Content-Length.
  - Handle incomplete data (streaming).
  - Handle malformed requests (no panic).

protocol/http2.rs:
  - Parse connection preface.
  - Parse HEADERS, DATA, SETTINGS frames.
  - De-multiplex multiple streams.
  - HPACK decompression.

pii/regex_prefilter.rs:
  - Match emails, phones, SSNs, credit cards, Aadhaar, PAN.
  - Reject non-PII text.
  - Edge cases (partial matches, overlapping).

pii/classifier.rs:
  - Map BIO labels correctly.
  - Handle multi-token entities (B-PER, I-PER, I-PER).
  - Respect confidence threshold.

graph/identity.rs:
  - Resolve Pod IP to Service name.
  - Handle missing K8s metadata.
  - Cache expiration.
```

### Integration Tests

```
test_http_capture.rs:
  Start agent with eBPF. Send curl -> nginx.
  Verify: captures request/response, correct parsing, PII detection on body,
  graph edge created between curl PID and nginx PID.

test_tls_capture.rs:
  Start agent. Send curl -> nginx with TLS.
  Verify: captures decrypted traffic via OpenSSL uprobe.

test_mysql_capture.rs:
  Start agent + MySQL. Execute queries with PII.
  Verify: SQL captured, PII detected and redacted.
```

### End-to-End Test Environment

```yaml
# tests/e2e/docker-compose.yaml
# Deploy multi-language microservices:
  go-service:     Go HTTP server with TLS (crypto/tls)
  python-service: Flask with requests to go-service
  java-service:   Spring Boot with MySQL queries
  node-service:   Express.js with Redis and Kafka
  mysql:          MySQL 8.0
  redis:          Redis 7
  kafka:          Kafka + Zookeeper
  nginx:          Reverse proxy (cleartext + TLS)

# Test scenarios:
  1. HTTP/1.1 cleartext: python -> nginx -> go-service
  2. HTTP/2 + TLS: python -> go-service (direct)
  3. MySQL: java-service -> mysql (COM_QUERY with PII)
  4. Redis: node-service -> redis (SET with PII value)
  5. Kafka: node-service -> kafka -> python-service
  6. gRPC: go-service -> java-service (protobuf)
  7. DNS: all services -> coredns

# Validation: All flows captured, graph complete, PII detected, no crashes.
```

### Performance Benchmarks

```
bench_protocol_parsing.rs:
  10K HTTP/1.1 requests: < 50ms
  10K HTTP/2 frames: < 100ms
  10K MySQL packets: < 30ms

bench_pii_inference.rs:
  Regex pre-filter on 10K texts: < 10ms
  DistilBERT batch of 8: < 10ms
  Full pipeline on 1K texts: < 500ms

bench_ringbuf_throughput.rs:
  Sustained event rate: > 500K events/sec
  Event processing latency P99: < 5ms
```

---

## Appendices

### Appendix A: Key Data Structures

```rust
pub struct ServiceIdentity {
    pub name: String,
    pub namespace: String,
    pub kind: ServiceKind,  // Pod, Service, External
    pub labels: HashMap<String, String>,
}

pub struct PiiReport {
    pub entities: Vec<PiiEntity>,
    pub redacted_text: String,
    pub scan_duration_us: u64,
    pub model_used: String,
}

pub struct PiiEntity {
    pub entity_type: PiiType,
    pub text: String,
    pub start_offset: usize,
    pub end_offset: usize,
    pub confidence: f32,
    pub source: DetectionSource,  // Regex or ML
}

pub enum PiiType {
    PersonName, Email, Phone, Ssn, CreditCard,
    Location, Organization, Date, IpAddress,
    Jwt, ApiKey, AwsKey, Aadhaar, Pan, Other(String),
}
```

### Appendix B: eBPF Map Definitions

| Map Name | Type | Key | Value | Max Entries | Purpose |
|---|---|---|---|---|---|
| DATA_EVENTS | RingBuf | -- | DataEvent | 256KB | Kernel->user data channel |
| DATA_EVENTS_PERF | PerfEventArray | -- | DataEvent | 1024 | Fallback for kernel <5.8 |
| PROCESS_EVENTS | RingBuf | -- | ProcessEvent | 64KB | Process lifecycle events |
| CONN_MAP | HashMap | u64 (cookie) | ConnInfo | 65536 | Active connection tracking |
| PID_CGROUP_MAP | HashMap | u32 (pid) | u64 (cgroup) | 65536 | PID->container mapping |
| CONFIG | Array | u32 (index) | u64 (value) | 16 | Runtime config flags |
| PID_FILTER | HashMap | u32 (pid) | u8 | 4096 | Optional PID allowlist |
| TLS_SCRATCH | PerCpuHashMap | u64 (pid_tid) | u64 (buf_ptr) | 8192 | SSL_read buf ptr storage |
| GO_ABI_MAP | HashMap | u32 (pid) | GoAbiInfo | 1024 | Per-binary Go ABI mapping |

### Appendix C: Kernel Compatibility Matrix

| Feature | Min Kernel | Fallback Strategy |
|---|---|---|
| eBPF TC classifier | 4.15 | None (hard requirement) |
| bpf_get_socket_cookie (TC) | 4.12 | Synthetic cookie from 5-tuple hash |
| Uprobes | 4.1 | None (hard requirement for TLS) |
| BPF_MAP_TYPE_RINGBUF | 5.8 | PerfEventArray + reorder buffer |
| BTF (CO-RE) | 5.5 | Ship pre-compiled variants per distro |
| bpf_get_current_cgroup_id | 4.18 | Read from /proc/pid/cgroup in user space |
| inet_sock_set_state tracepoint | 4.16 | kprobe on tcp_set_state |
| CAP_BPF (fine-grained) | 5.8 | Require CAP_SYS_ADMIN |
| bpf_probe_read_user | 5.5 | bpf_probe_read (works for user memory) |

### Appendix D: Key Dependencies

| Crate | Version | Purpose |
|---|---|---|
| aya | 0.13 | eBPF loader, map access, program attachment |
| aya-ebpf | 0.1 | eBPF program writing (kernel space) |
| tokio | 1.x | Async runtime |
| nom | 7.x | Parser combinators |
| httparse | 1.x | Zero-copy HTTP/1.1 parsing |
| ort | 2.x | ONNX Runtime bindings (ML inference) |
| tokenizers | 0.20 | HuggingFace tokenizer |
| petgraph | 0.6 | Graph data structure |
| kube | 0.97 | Kubernetes API client |
| k8s-openapi | 0.23 | K8s type definitions |
| dashmap | 6.x | Concurrent hash map |
| bytes | 1.x | Efficient byte buffer |
| clap | 4.x | CLI argument parsing |
| tracing | 0.1 | Structured logging |
| object | 0.36 | ELF/DWARF parsing |
| hdrhistogram | 7.x | Latency histograms |
| prometheus-client | 0.23 | Prometheus metrics |
| opentelemetry | 0.27 | OTLP export |
| regex | 1.x | PII regex patterns |
| hpack | 0.3 | HTTP/2 HPACK decompression |

---

## Implementation Order and Milestones

### Milestone 1: Foundation (Weeks 1-2)
- [ ] Set up workspace, toolchain, CI pipeline
- [ ] Implement panopticon-common (shared types)
- [ ] Implement TC capture eBPF program (cleartext packets)
- [ ] Implement basic event loop (RingBuf consumer)
- [ ] **Verify: capture raw TCP packets on loopback**

### Milestone 2: Protocol Parsing (Weeks 3-4)
- [ ] Implement protocol detection engine
- [ ] Implement HTTP/1.1 parser
- [ ] Implement MySQL parser
- [ ] Implement PostgreSQL parser
- [ ] Implement Redis parser
- [ ] **Verify: parse real HTTP requests from curl to nginx**

### Milestone 3: TLS Interception (Weeks 5-6)
- [ ] Implement proc_scanner (library discovery)
- [ ] Implement OpenSSL uprobes (SSL_write/SSL_read)
- [ ] Implement Go TLS uprobes (with ABI detection)
- [ ] Implement HTTP/2 and gRPC parsers
- [ ] **Verify: capture HTTPS traffic from curl to nginx with TLS**

### Milestone 4: PII Detection (Weeks 7-8)
- [ ] Implement regex pre-filter
- [ ] Integrate ONNX Runtime (ort) with DistilBERT-NER
- [ ] Implement tokenizer -> inference -> classifier pipeline
- [ ] Implement redactor
- [ ] **Verify: detect names, emails, SSNs in HTTP bodies**

### Milestone 5: Service Graph (Weeks 9-10)
- [ ] Implement K8s identity resolution (kube-rs informer)
- [ ] Implement container ID -> Pod mapping
- [ ] Implement edge aggregator with sliding windows
- [ ] Implement petgraph DAG builder
- [ ] **Verify: graph shows service-to-service edges in test cluster**

### Milestone 6: Export and Production Readiness (Weeks 11-12)
- [ ] Implement OTLP exporter
- [ ] Implement Prometheus metrics endpoint
- [ ] Implement JSON log exporter
- [ ] Implement graph API endpoint
- [ ] Kernel compat layer (PerfEventArray fallback)
- [ ] Dockerfile + DaemonSet + Helm chart
- [ ] Load testing: 500K events/sec sustained
- [ ] **Verify: full E2E test passes**

### Milestone 7: Extended Protocol and Platform Support (Weeks 13-16)
- [ ] Kafka, MongoDB, DNS, AMQP parsers
- [ ] Java TLS interception
- [ ] ARM64 cross-compilation and testing
- [ ] Alpine/musl support
- [ ] CentOS 8, Amazon Linux, RHEL testing

---

> **END OF PLAN** -- This document is designed to be fed directly to Claude Code or any AI coding agent. Each phase is self-contained and produces testable artifacts. Start with Phase 1 and proceed sequentially. When in doubt about implementation details, refer back to the research document for architectural rationale.
