# Panopticon-rs

Engineering notes for working in this repository. The canonical, user-facing
descriptions are `README.md`, `docs/CURRENT-STATE.md` (what is validated,
partial and not done), `docs/USER-GUIDE.md` (configuration, privacy modes,
metrics) and `docs/adr/` (design decisions; ADR-014 is the capture and scope
design). When this file and those disagree, they win; fix this file.

eBPF-based observability and privacy engine in Rust: captures traffic at
every socket on a Linux node (`cgroup_skb`, scoped in the kernel by process,
cgroup or pod) and TLS plaintext (OpenSSL and Go uprobes), parses nine L7
protocols, detects PII, builds a service graph, and exports what the
privacy mode allows (`full`, `redacted` default, `metrics_only`).

## Workspace

| Crate | Role | Environment |
|---|---|---|
| `panopticon-common` | Types and pure decision logic shared by kernel and user space (`#[repr(C)]` events, `scope.rs` verdict/hold rules, map constants) | `#![no_std]` |
| `panopticon-ebpf` | eBPF programs | `#![no_std]`, `bpfel-unknown-none` |
| `panopticon-agent` | User-space agent: loader, event loop, parsers, PII, graph, export | std, Tokio |
| `xtask` | Build orchestration (`cargo xtask build-ebpf`) | std |

**eBPF programs** (`panopticon-ebpf/src/`):
- `sock_capture.rs`: `cgroup_skb` ingress/egress capture on the cgroup v2
  root, socket state (`SOCK_STATE` sk_storage) written by `cgroup/sock_create`,
  `sockops` and fexit `inet_csk_accept`; the in-kernel scope verdict; the
  pre-accept hold (`PENDING`, tail-called `scope_skb_hold`, per-listener
  budget shares); kTLS markers; per-connection packet cap (`CONN_CAP`).
- `tls_probes.rs`: OpenSSL `SSL_read/SSL_write(_ex)` and Go `crypto/tls` uprobes.
- `process_monitor.rs`: `sched_process_exit` (PID reuse, TLS call slots).
- `maps.rs`: maps and the sharded ring buffers.

**Agent** (`panopticon-agent/src/`): `scope_loader.rs` (load-check, attach,
arm), `loader.rs`, `event_loop.rs` (ring consumer, per-connection workers),
`reorder.rs`, `conn_cap.rs`, `protocol/` (FSM parsers, `detect.rs`,
`secrets.rs` credential masking), `pii/`, `graph/`, `export/`, `platform/`
(process scanner, Go symbol resolution), `config.rs` (TOML, SIGHUP reload),
`replay.rs`.

## Build and test

```bash
cargo xtask build-ebpf --release      # eBPF object (Linux toolchain: nightly, rust-src, bpf-linker)
cargo build -p panopticon-agent --release
cargo test -p panopticon-agent        # unit tests (run targeted filters while iterating)
cargo test -p panopticon-common
cargo clippy -p panopticon-agent -p panopticon-common -p xtask --all-targets
cargo fmt --all -- --check
```

- macOS builds the agent without the eBPF object and runs the unit tests;
  eBPF programs load only on Linux.
- Kernel behaviour is tested on real kernels: `panopticon-agent/tests/scope_attach.rs`
  (every program through the verifier, the scope and hold rules on loopback;
  needs root) and the oracle suites in `tests/oracle/` (`run.sh`,
  `run_modes.sh`, `run_tls.sh`, `run_protocols.sh`, `run_messaging.sh`,
  `run_sampling.sh`, `run_overlay.sh`, `run_scope.sh`, `scope_lab.py`), each
  scoring the agent's export against ground truth. Supported: x86-64 on
  upstream 5.8+, and RHEL 8 (4.18) and 9 (5.14) with their BPF backports
  (README.md); the lab gate runs 7.0, 6.8, 5.15, RHEL 9 and RHEL 8.
- Verifier headroom is tight on 4.18 and 5.15 for `scope_skb_ingress` /
  `scope_skb_egress` (about 850K and 750K of the 1M-instruction limit):
  measure any change to the capture path on those kernels
  (docs/BENCHMARKS.md records the counts).

## Invariants that must not regress

- **Scope is decided in the kernel before any byte leaves it.** Attribution
  is by the socket's stamped owner/acceptor, never the current task.
- **What leaves the node is the privacy mode's contract**, checked against
  planted PII in every output. Any change to what is exported or withheld is
  a product decision: state it plainly in the PR.
- **Unproven framing exports closed-set values only**: a parser that joined
  late, lost bytes or is unsynced never exports free text.
- **Passive observer**: the capture never drops or alters a packet.
- **Bounded everything**: channels, maps, budgets; a full queue drops and
  counts, it never blocks the event loop.
- `#[repr(C)]` shared types; eBPF helpers `#[inline(always)]`; every buffer
  access bounded for the verifier; records built in ring reservations or
  map values, never on the 512-byte stack.
