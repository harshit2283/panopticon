# ADR-005: gRPC Compression Handling

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Proposed |
| **Date** | 2026-02-18 |
| **Decision Makers** | @panopticon-team |
| **Affected Components** | protocol/grpc.rs, compression/mod.rs, pii/ |
| **Supersedes** | None |

## Context

gRPC supports per-message compression to reduce bandwidth. The agent must handle compressed gRPC messages for PII detection while balancing CPU overhead.

### Problem Statement

- gRPC messages can be compressed with gzip, snappy, or zstd
- PII detection requires decompressed text
- Decompression adds CPU overhead (especially at 500K events/sec)
- zstd uses C library (libzstd) which could panic on malformed input
- Production systems may prefer decompression in external PII service

### Compression Ecosystem

| Algorithm | Official gRPC | Usage | Rust Crate |
|-----------|--------------|-------|------------|
| gzip | ✅ Built-in | Universal | `flate2` |
| snappy | ⚠️ Optional | Google ecosystem | `snap` |
| zstd | ⚠️ Optional | Growing adoption | `zstd` |

## Decision

Support configurable decompression with two deployment modes:

1. **In-Agent Decompression** (default): Decompress in agent, sample for PII
2. **External PII Service**: Store compression metadata, decompress downstream

### Configuration

```rust
pub struct DecompressionConfig {
    /// Enable decompression in agent (vs external PII service)
    pub enabled: bool,
    /// Maximum decompressed size (prevent zip bombs)
    pub max_decompressed_size: usize,
    /// Compression types to decompress
    pub enabled_types: Vec<CompressionType>,
    /// PII sampling rate (1% = 0.01)
    pub pii_sample_rate: f64,
}

impl Default for DecompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_decompressed_size: 10 * 1024 * 1024, // 10MB
            enabled_types: vec![CompressionType::Gzip, CompressionType::Snappy, CompressionType::Zstd],
            pii_sample_rate: 0.01, // 1%
        }
    }
}
```

### Two Deployment Modes

#### Mode A: In-Agent Decompression

```
┌─────────────────────────────────────────────────────────────────┐
│                           AGENT                                  │
│                                                                  │
│  eBPF → RingBuf → Parser → Decompress → PII Engine (sampled)   │
│                              │           │                       │
│                              │           ▼                       │
│                              │    Regex Prefilter               │
│                              │           │                       │
│                              │           ▼                       │
│                              │    Sampler (1%)                   │
│                              │           │                       │
│                              │           ▼                       │
│                              │    DistilBERT ONNX                │
│                              ▼           ▼                       │
│                        L7Message ◄──── PiiReport                 │
└─────────────────────────────────────────────────────────────────┘
```

**CPU cost**: Decompress 100% → regex 100% → sample 1% → ML 1%

#### Mode B: External PII Service

```
┌──────────────────────────────────┐    ┌─────────────────────────┐
│           AGENT                   │    │    PII SERVICE          │
│                                   │    │                         │
│  eBPF → RingBuf → Parser          │    │  Decompress ◄──┐        │
│                    │              │    │       │        │        │
│                    ▼              │    │       ▼        │        │
│             L7Message ─────────► Kafka    │        │        │
│             (compressed_bytes)    │    │  Regex         │        │
│             (compression_type)    │    │  Sampler       │        │
│                                   │    │       ▼        │        │
│                                   │    │  DistilBERT ───┘        │
└──────────────────────────────────┘    └─────────────────────────┘
```

**CPU cost in agent**: 0% decompression overhead

### Panic Safety

zstd uses C library (libzstd) which could panic on malformed input. All decompression is wrapped in `catch_unwind`:

```rust
use std::panic::{catch_unwind, AssertUnwindSafe};

pub fn decompress(
    data: &[u8],
    compression: CompressionType,
    config: &DecompressionConfig,
) -> DecompressionResult {
    let result = catch_unwind(AssertUnwindSafe(|| {
        decompress_inner(data, compression, config)
    }));
    
    match result {
        Ok(r) => r,
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic in decompression".to_string()
            };
            DecompressionResult::Failed(format!("Decompression panic: {}", msg))
        }
    }
}
```

### Size Limits

Prevent zip bomb attacks:

1. Check compressed size first
2. Streaming decompression with early termination
3. Reject if decompressed > `max_decompressed_size`

```rust
fn decompress_gzip(data: &[u8], config: &DecompressionConfig) -> DecompressionResult {
    let mut decoder = GzDecoder::new(data);
    let mut output = Vec::with_capacity(4096);
    
    loop {
        let mut chunk = vec![0u8; 8192];
        match decoder.read(&mut chunk) {
            Ok(0) => break, // EOF
            Ok(n) => {
                output.extend_from_slice(&chunk[..n]);
                if output.len() > config.max_decompressed_size {
                    return DecompressionResult::SizeLimitExceeded {
                        actual: output.len(),
                        limit: config.max_decompressed_size,
                    };
                }
            }
            Err(e) => return DecompressionResult::Failed(e.to_string()),
        }
    }
    
    DecompressionResult::Success(output)
}
```

## Consequences

### Positive

- ✅ Flexibility: in-agent or external decompression
- ✅ Panic-safe: C library crashes don't take down agent
- ✅ Zip bomb protection: configurable size limits
- ✅ Configurable sampling: balance accuracy vs CPU
- ✅ All major compression algorithms supported

### Negative

- ⚠️ Additional dependencies: flate2, snap, zstd
- ⚠️ ~500KB binary size increase with all compression libs
- ⚠️ In-agent decompression adds CPU at high event rates

### Neutral

- Default configuration enables in-agent decompression with 1% PII sampling
- zstd crate requires libzstd system library (or static linking)

## Alternatives Considered

### Alternative 1: Decompress All In-Agent

**Pros**: Simple, no external service needed

**Cons**: High CPU overhead at scale

**Why rejected**: Not suitable for 500K events/sec targets

### Alternative 2: Never Decompress In-Agent

**Pros**: Zero decompression overhead in agent

**Cons**: PII detection impossible on compressed messages

**Why rejected**: Need PII detection capability in agent for many deployments

### Alternative 3: Decompress Only on Regex Match

**Pros**: Skip decompression on obvious non-PII

**Cons**: Compressed bytes rarely match text regexes

**Why rejected**: Ineffective - regex matches almost never on compressed data

## Implementation Notes

### Adding New Compression Types

1. Add variant to `CompressionType` enum
2. Implement decompress function with size checking
3. Add to `enabled_types` default
4. Add optional dependency to Cargo.toml

### Testing Requirements

- Unit test each compression algorithm (roundtrip)
- Test panic handling with malformed input
- Test size limit enforcement
- Test configuration options

### Metrics to Expose

- `decompression_requests_total` by algorithm
- `decompression_success_total`
- `decompression_failed_total` (by error type)
- `decompression_size_exceeded_total`
- `decompression_panic_total`

## References

- [gRPC Compression Spec](https://grpc.io/docs/guides/compression/)
- [Zstandard RFC 8878](https://datatracker.ietf.org/doc/html/rfc8878)
- [Snappy Format](https://github.com/google/snappy/blob/main/format_description.txt)
- ADR-001: FSM Architecture
- ADR-004: HTTP/2 Stream Multiplexing

---

## Revision History

| Date | Author | Description |
|------|--------|-------------|
| 2026-02-18 | @panopticon-team | Initial proposal |
