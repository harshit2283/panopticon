# ADR-006: TLS Interception Architecture

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-02-19 |
| **Decision Makers** | @panopticon-team |
| **Affected Components** | `panopticon-ebpf/tls_probes.rs`, `panopticon-agent/src/loader.rs`, `panopticon-agent/src/platform/proc_scanner.rs` |
| **Supersedes** | None |
| **Superseded by** | None |

## Context

### The Problem

Panopticon must capture application-layer data from TLS-encrypted connections for PII detection and service graph building. Traditional network-level packet capture only sees ciphertext, making L7 protocol parsing impossible.

### Options Available

| Approach | Mechanism | Pros | Cons |
|----------|-----------|------|------|
| **eBPF uprobes** | Hook SSL_write/SSL_read in userspace | No MITM, no certs, transparent | Library-specific, ABI complexity |
| **LD_PRELOAD** | Inject library to intercept calls | Simple, widely compatible | Easy to detect, container issues |
| **Proxy MITM** | Intercept and re-encrypt traffic | Universal coverage | Cert management, breaking changes |
| **Key logging** | SSLKEYLOGFILE environment variable | Clean separation | Requires app cooperation |

### TLS Library Landscape

| Library | Usage | Uprobe Feasibility |
|---------|-------|-------------------|
| OpenSSL | ~70% of servers | ✅ Stable symbol tables |
| BoringSSL | Google ecosystem | ❌ Symbol names differ |
| GnuTLS | Some Linux apps | ❌ Not implemented |
| Go crypto/tls | Microservices | ⚠️ Register ABI only |
| Rust native | Growing adoption | ❌ Not implemented |
| Node.js (OpenSSL) | V8-based | ✅ Via OpenSSL hooks |
| Python (OpenSSL) | CPython/PyPy | ✅ Via OpenSSL hooks |

### Go TLS ABI Complexity

Go's calling convention changed in 1.17:
- **Go < 1.17**: Stack-based ABI (arguments on stack)
- **Go ≥ 1.17**: Register-based ABI (arguments in registers)

Uprobe attachment must detect Go version and use correct argument extraction. Additionally, uretprobes on Go functions cause crashes due to goroutine stack relocation—Go runtime can move stacks during execution, invalidating return probe addresses.

## Decision

We will use **eBPF uprobes** on OpenSSL and Go TLS (register ABI only) with explicit coverage gaps.

### Supported Libraries

| Library | Read | Write | Notes |
|---------|------|-------|-------|
| OpenSSL 1.1.x | ✅ | ✅ | SSL_read/SSL_write |
| OpenSSL 3.x | ✅ | ✅ | SSL_read/SSL_write |
| Go ≥ 1.17 | ❌ | ✅ | crypto/tls.(*Conn).Write |
| Go < 1.17 | ❌ | ❌ | Stack ABI incompatible |
| BoringSSL | ❌ | ❌ | Not implemented |
| GnuTLS | ❌ | ❌ | Not implemented |
| Rust rustls | ❌ | ❌ | Not implemented |

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER SPACE                                   │
│                                                                      │
│   ┌──────────────┐     ┌──────────────┐                             │
│   │   OpenSSL    │     │   Go Runtime │                             │
│   │   libssl.so  │     │   (≥1.17)    │                             │
│   └──────┬───────┘     └──────┬───────┘                             │
│          │                    │                                      │
│   SSL_read()            Write() method                               │
│   SSL_write()           (register ABI)                               │
│          │                    │                                      │
│          ▼                    ▼                                      │
│   ┌─────────────────────────────────────────┐                       │
│   │           eBPF UPROBES                   │                       │
│   │  • uprobe_ssl_read (entry)               │                       │
│   │  • uprobe_ssl_write (entry)              │                       │
│   │  • uretprobe_ssl_read (return)           │  ◄── Data captured    │
│   │  • uretprobe_ssl_write (return)          │                       │
│   └─────────────────────────────────────────┘                       │
│                      │                                               │
└──────────────────────┼───────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        RINGBUF                                       │
│   TlsKeyEvent { pid, fd, direction, data, timestamp }               │
└─────────────────────────────────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     EVENT LOOP                                       │
│   • Correlate with connection metadata                               │
│   • Feed to protocol FSMs                                            │
│   • PII pipeline processing                                          │
└─────────────────────────────────────────────────────────────────────┘
```

### OpenSSL Uprobe Implementation

```c
// In panopticon-ebpf/tls_probes.rs

SEC("uprobe/ssl_read")
fn uprobe_ssl_read(ctx: *mut c_void) -> i64 {
    let ssl = unsafe { (*ctx).arg(0) };
    let buf = unsafe { (*ctx).arg(1) };
    let num = unsafe { (*ctx).arg(2) };
    
    // Store buf pointer for uretprobe
    ssl_read_args.insert(&get_pid_tgid(), &SslArgs { buf, ssl });
    0
}

SEC("uretprobe/ssl_read")
fn uretprobe_ssl_read(ctx: *mut c_void) -> i64 {
    let ret = unsafe { (*ctx).ret() };
    if ret <= 0 { return 0; }
    
    let args = ssl_read_args.get(&get_pid_tgid());
    let buf = args.buf;
    
    // Read decrypted data
    let event = TlsKeyEvent {
        pid: get_pid(),
        fd: get_fd_from_ssl(args.ssl),
        direction: Direction::Ingress,
        data_len: ret as u32,
        timestamp_ns: ktime_get_ns(),
        ..
    };
    
    // Copy data and submit to ringbuf
    tls_events.output(&ctx, &event, 0);
    0
}
```

### Go Uprobe Implementation

```c
// In panopticon-ebpf/tls_probes.rs

SEC("uprobe/go_tls_write")
fn uprobe_go_tls_write(ctx: *mut c_void) -> i64 {
    // Go 1.17+ register ABI:
    // R0 = *tls.Conn (receiver)
    // R1 = []byte (data slice: ptr, len, cap)
    
    let conn = unsafe { (*ctx).arg(0) };
    let data_ptr = unsafe { (*ctx).arg(1) };
    let data_len = unsafe { (*ctx).arg(2) };
    
    if data_len == 0 || data_len > MAX_DATA_SIZE {
        return 0;
    }
    
    let event = TlsKeyEvent {
        pid: get_pid(),
        fd: get_fd_from_go_conn(conn),
        direction: Direction::Egress,
        data_len: data_len as u32,
        timestamp_ns: ktime_get_ns(),
        ..
    };
    
    tls_events.output(&ctx, &event, 0);
    0
}
```

### Go Version Detection

```rust
// In panopticon-agent/src/platform/proc_scanner.rs

pub fn detect_go_version(binary_path: &Path) -> Option<GoVersion> {
    let data = std::fs::read(binary_path).ok()?;
    
    // Look for build info in ELF .go.buildinfo section
    // or parse from runtime.buildVersion symbol
    
    let version_str = extract_go_buildinfo(&data)?;
    parse_go_version(&version_str)
}

pub struct GoVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl GoVersion {
    pub fn supports_register_abi(&self) -> bool {
        self.major > 1 || (self.major == 1 && self.minor >= 17)
    }
}
```

### Attachment Logic

```rust
// In panopticon-agent/src/loader.rs

pub fn attach_tls_probes(&mut self, program: &mut TlsProbes) -> Result<()> {
    for (pid, proc_info) in self.process_scanner.scan_processes()? {
        // OpenSSL attachment
        if let Some(libssl_path) = &proc_info.libssl_path {
            self.attach_openssl_probes(program, pid, libssl_path)?;
        }
        
        // Go TLS attachment
        if let Some(go_version) = &proc_info.go_version {
            if go_version.supports_register_abi() {
                self.attach_go_tls_probes(program, pid, &proc_info.binary_path)?;
            } else {
                tracing::warn!(
                    pid = pid,
                    version = format!("{}.{}.{}", go_version.major, go_version.minor, go_version.patch),
                    "Go version too old for TLS interception (need ≥1.17)"
                );
            }
        }
    }
    Ok(())
}
```

## Consequences

### Positive

1. **No MITM required**: Captures plaintext without certificate injection or proxy configuration
2. **Transparent to applications**: No environment variables or config changes needed
3. **Low overhead**: Uprobe overhead ~100-500ns per call
4. **No key management**: Keys never leave application process
5. **Works with mutual TLS**: No interference with client certificates

### Negative

1. **Limited library coverage**: Only OpenSSL and Go ≥1.17 supported at launch
2. **No Go TLS Read**: Goroutine stack relocation makes uretprobes unsafe
3. **Version detection required**: Go ABI changes require binary analysis
4. **Process attachment latency**: New processes must be detected and attached
5. **Container complexity**: Must resolve library paths inside container mount namespaces

### Neutral

1. **Write-only for Go**: Captures outbound traffic but not inbound for Go services
2. **Runtime attachment**: uprobes attach to running processes without restart

## Alternatives Considered

### Alternative 1: Proxy MITM with Custom CA

**Description**: Configure proxy with custom CA certificate, intercept and re-encrypt all TLS.

**Pros**:
- Universal coverage (all libraries)
- Captures both directions
- No version detection needed

**Cons**:
- Requires CA certificate deployment to all trust stores
- Breaks certificate pinning
- Client applications must be configured to use proxy
- MITM detection triggers security alerts

**Why rejected**: Operational complexity and security concerns outweigh universal coverage.

### Alternative 2: LD_PRELOAD Library Injection

**Description**: Inject shared library that interposes SSL functions.

**Pros**:
- Simple implementation
- Works with any dynamically linked library

**Cons**:
- Requires restart of target processes
- Container environments need special handling
- Easily detected by security tools
- Doesn't work with statically linked binaries

**Why rejected**: Less transparent than eBPF, requires process restart.

### Alternative 3: SSLKEYLOGFILE Key Extraction

**Description**: Use SSLKEYLOGFILE environment variable to extract session keys.

**Pros**:
- Standard mechanism
- No code injection

**Cons**:
- Requires application cooperation
- Security risk (keys written to disk)
- Must restart applications with env var set
- Not supported by all libraries

**Why rejected**: Requires application changes and creates security exposure.

### Alternative 4: Extended Berkeley Packet Filter (XDP) with Key Exchange Hooks

**Description**: Hook TLS key exchange at kernel level during handshake.

**Pros**:
- Completely transparent
- No userspace dependencies

**Cons**:
- Extremely complex implementation
- Only works for RSA key exchange (not PFS)
- Modern TLS 1.3 uses ephemeral keys (DHE/ECDHE)
- Would require kernel modifications

**Why rejected**: Infeasible for TLS 1.3 and modern cipher suites.

## Implementation Notes

### OpenSSL Symbol Resolution

```bash
# Verify SSL_write/SSL_read symbols exist
nm -D /usr/lib/x86_64-linux-gnu/libssl.so | grep -E 'SSL_(read|write)'
# Output:
# 00000000000aa340 T SSL_read
# 00000000000aa4a0 T SSL_write
```

### Go Binary Analysis

```bash
# Check Go version
strings /path/to/binary | grep -E '^go1\.[0-9]+' | head -1

# Check for crypto/tls symbols
objdump -t /path/to/binary | grep -E 'crypto/tls.*Write'
```

### Mount Namespace Handling

```rust
// Resolve library path inside container
fn resolve_container_path(pid: u32, lib_path: &str) -> Result<PathBuf> {
    let root = PathBuf::from("/proc").join(pid.to_string()).join("root");
    let resolved = root.join(lib_path.strip_prefix('/').unwrap_or(lib_path));
    
    if resolved.exists() {
        Ok(resolved)
    } else {
        Err(anyhow!("Library not found in container mount namespace"))
    }
}
```

### Testing Requirements

1. **OpenSSL 1.1.x** and **3.x** compatibility tests
2. **Go 1.17, 1.18, 1.19, 1.20, 1.21, 1.22** compatibility tests
3. **Go < 1.17** rejection tests (verify no attachment)
4. **Container namespace** resolution tests
5. **High connection churn** stress test (attach/detach cycles)

### Metrics to Expose

```
# TYPE tls_interception_attached_total counter
tls_interception_attached_total{library="openssl"} 42
tls_interception_attached_total{library="go"} 15

# TYPE tls_interception_skipped_total counter
tls_interception_skipped_total{library="go",reason="old_version"} 3
tls_interception_skipped_total{library="boringssl"} 1

# TYPE tls_events_captured_total counter
tls_events_captured_total{direction="ingress",library="openssl"} 1000000
tls_events_captured_total{direction="egress",library="openssl"} 950000
tls_events_captured_total{direction="egress",library="go"} 500000
```

## References

- [OpenSSL SSL_read/write documentation](https://www.openssl.org/docs/man3.0/man3/SSL_read.html)
- [Go 1.17 Release Notes - Register ABI](https://go.dev/doc/go1.17#compiler)
- [eBPF uprobes documentation](https://www.kernel.org/doc/html/latest/trace/uprobetracer.html)
- [Aya uprobe examples](https://github.com/aya-rs/aya/tree/main/test/integration-ebpf/uprobe)
- ADR-001: FSM Architecture (event processing)

---

## Revision History

| Date | Author | Description |
|------|--------|-------------|
| 2026-02-19 | @panopticon-team | Initial proposal and acceptance |
