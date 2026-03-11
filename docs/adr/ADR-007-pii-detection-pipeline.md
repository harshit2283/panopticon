# ADR-007: PII Detection Pipeline Architecture

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Accepted |
| **Date** | 2026-02-19 |
| **Decision Makers** | @panopticon-team |
| **Affected Components** | `panopticon-agent/src/pii/` |
| **Supersedes** | None |
| **Superseded by** | None |

## Context

### The Problem

Panopticon must detect personally identifiable information (PII) in captured network traffic for compliance (GDPR, CCPA, HIPAA) and privacy protection. The detection must balance accuracy against performance constraints.

### Requirements

| Requirement | Constraint |
|-------------|------------|
| Throughput | 500K events/sec sustained |
| Detection latency | < 50ms P99 |
| Memory overhead | < 250MB (including model) |
| Precision | > 95% (minimize false positives) |
| Recall | > 85% (minimize false negatives) |
| PII types | 11 categories |

### PII Categories

| Category | Examples | Detection Method |
|----------|----------|------------------|
| Email | user@example.com | Regex |
| Phone (US) | +1-555-123-4567 | Regex |
| SSN (US) | 123-45-6789 | Regex |
| Credit Card | 4532-1234-5678-9010 | Regex + Luhn |
| JWT | eyJhbGciOiJIUzI1NiI... | Regex |
| API Key | sk-xxx, api_key=xxx | Regex |
| Aadhaar (IN) | 1234-5678-9012 | Regex + Verhoeff |
| PAN (IN) | ABCDE1234F | Regex |
| IP Address | 192.168.1.1, 2001:db8::1 | Regex |
| Date of Birth | 1990-01-15 | ML (context) |
| Person Name | John Smith | ML (NER) |

### Detection Methods Comparison

| Method | Speed | Precision | Recall | Cost |
|--------|-------|-----------|--------|------|
| **Regex** | ~1µs | 80% | 60% | Minimal |
| **ML (NER)** | ~30ms | 95% | 85% | High |
| **Hybrid** | Variable | 90% | 80% | Medium |

## Decision

We will use a **3-stage pipeline**: Regex prefilter → ML inference → Redaction, with budget-based sampling for ML.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PII DETECTION PIPELINE                             │
│                                                                              │
│   L7Message                                                                  │
│       │                                                                      │
│       ▼                                                                      │
│   ┌─────────────────────────────────────────────────┐                       │
│   │  STAGE 1: REGEX PREFILTER                       │                       │
│   │  • RegexSet (11 patterns, ~1µs)                 │                       │
│   │  • Output: Vec<PatternMatch>                    │                       │
│   │  • ~90% of traffic rejected here (no match)     │                       │
│   └──────────────────────┬──────────────────────────┘                       │
│                          │                                                   │
│           ┌──────────────┴──────────────┐                                   │
│           │                             │                                   │
│           ▼                             ▼                                   │
│   ┌───────────────┐           ┌─────────────────┐                          │
│   │ NO MATCH      │           │ MATCHES FOUND   │                          │
│   │ Skip ML       │           │                 │                          │
│   └───────────────┘           └────────┬────────┘                          │
│                                        │                                    │
│                                        ▼                                    │
│                          ┌─────────────────────────────┐                   │
│                          │  STAGE 2: ML SAMPLER        │                   │
│                          │  • Template deduplication   │                   │
│                          │  • Budget check             │                   │
│                          │  • 1% default sample rate   │                   │
│                          └────────────┬────────────────┘                   │
│                                       │                                     │
│                        ┌──────────────┴──────────────┐                     │
│                        │                             │                     │
│                        ▼                             ▼                     │
│                ┌───────────────┐           ┌─────────────────┐            │
│                │ SAMPLED OUT   │           │ SAMPLED IN      │            │
│                │ Return regex  │           │                 │            │
│                │ results only  │           └────────┬────────┘            │
│                └───────────────┘                    │                     │
│                                                     ▼                     │
│                              ┌─────────────────────────────────┐          │
│                              │  STAGE 3: ML INFERENCE          │          │
│                              │  • Tokenizer (WordPiece)        │          │
│                              │  • DistilBERT-NER ONNX          │          │
│                              │  • Entity classifier            │          │
│                              │  • ~10-50ms latency             │          │
│                              └────────────┬────────────────────┘          │
│                                           │                               │
│                                           ▼                               │
│                              ┌─────────────────────────────────┐          │
│                              │  STAGE 4: REDACTION             │          │
│                              │  • Merge regex + ML results     │          │
│                              │  • Apply redaction policy       │          │
│                              │  • Output: PiiReport            │          │
│                              └─────────────────────────────────┘          │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Stage 1: Regex Prefilter

Uses `regex::RegexSet` for efficient multi-pattern matching:

```rust
pub struct RegexPrefilter {
    patterns: RegexSet,
    pattern_names: Vec<&'static str>,
}

impl RegexPrefilter {
    pub fn scan(&self, text: &str) -> Vec<PatternMatch> {
        let matches: Vec<usize> = self.patterns.matches(text).into_iter().collect();
        
        matches.into_iter().map(|idx| {
            // Extract matched region for validation
            let pattern = &self.patterns[idx];
            let matched_text = extract_match(text, pattern);
            
            PatternMatch {
                pattern_name: self.pattern_names[idx],
                matched_text,
                start: 0,  // Position extracted separately
                end: 0,
                confidence: 0.8,  // Regex baseline confidence
            }
        }).collect()
    }
}
```

### Stage 2: ML Sampler

Budget-based sampling with template deduplication:

```rust
pub struct InferenceSampler {
    budget: Arc<AtomicU64>,
    max_per_second: u64,
    seen_templates: DashMap<u64, Instant>,
    template_ttl: Duration,
}

impl InferenceSampler {
    pub fn should_sample(&self, payload: &[u8]) -> SamplingDecision {
        // Step 1: Template deduplication
        let template_hash = compute_template_hash(payload);
        if self.seen_templates.contains_key(&template_hash) {
            return SamplingDecision::Skip(SkipReason::DuplicateTemplate);
        }
        self.seen_templates.insert(template_hash, Instant::now());
        
        // Step 2: Budget check
        let current = self.budget.load(Ordering::Relaxed);
        if current >= self.max_per_second {
            return SamplingDecision::Skip(SkipReason::BudgetExhausted);
        }
        
        // Step 3: Probabilistic sampling (1% default)
        if rand::random::<f64>() > 0.01 {
            return SamplingDecision::Skip(SkipReason::SampledOut);
        }
        
        // Step 4: Reserve budget
        self.budget.fetch_add(1, Ordering::Relaxed);
        SamplingDecision::Proceed
    }
    
    pub fn reset_budget(&self) {
        self.budget.store(0, Ordering::Relaxed);
        // Also clean up old templates
        let now = Instant::now();
        self.seen_templates.retain(|_, &seen| {
            now.duration_since(seen) < self.template_ttl
        });
    }
}
```

### Stage 3: ML Inference

DistilBERT-NER via ONNX Runtime:

```rust
pub struct MlInferenceEngine {
    session: ort::Session,
    tokenizer: Tokenizer,
    label_map: Vec<String>,
}

impl MlInferenceEngine {
    pub fn infer(&self, text: &str) -> Result<Vec<Entity>> {
        // Step 1: Tokenize
        let encoding = self.tokenizer.encode(text, true)?;
        let input_ids = encoding.get_ids();
        let attention_mask = encoding.get_attention_mask();
        
        // Step 2: ONNX inference
        let outputs = self.session.run(ort::inputs![
            "input_ids" => Tensor::from_array(input_ids),
            "attention_mask" => Tensor::from_array(attention_mask),
        ]?)?;
        
        // Step 3: Extract entities from logits
        let logits = outputs["logits"].extract_tensor::<f32>()?;
        let entities = self.decode_entities(logits, &encoding)?;
        
        Ok(entities)
    }
    
    fn decode_entities(&self, logits: &[f32], encoding: &Encoding) -> Vec<Entity> {
        // BIO tag decoding with confidence scores
        // ...
    }
}
```

### Stage 4: Redaction

```rust
pub struct Redactor {
    policy: RedactionPolicy,
}

#[derive(Clone, Copy)]
pub enum RedactionPolicy {
    Mask,       // Replace with ****
    Hash,       // Replace with SHA256 prefix
    Remove,     // Delete entirely
    None,       // Keep original (for audit mode)
}

impl Redactor {
    pub fn redact(&self, text: &str, entities: &[PiiEntity]) -> RedactedText {
        let mut result = text.to_string();
        
        // Sort entities by position (reverse order to maintain offsets)
        let mut sorted = entities.to_vec();
        sorted.sort_by(|a, b| b.start.cmp(&a.start));
        
        for entity in sorted {
            let replacement = match self.policy {
                RedactionPolicy::Mask => "*".repeat(entity.end - entity.start),
                RedactionPolicy::Hash => {
                    format!("[REDACTED:{}]", &sha256(&entity.text)[..8])
                }
                RedactionPolicy::Remove => String::new(),
                RedactionPolicy::None => entity.text.clone(),
            };
            
            result.replace_range(entity.start..entity.end, &replacement);
        }
        
        RedactedText {
            original_length: text.len(),
            redacted: result,
            entities_redacted: entities.len(),
        }
    }
}
```

### Pipeline Orchestration

```rust
pub struct PiiPipeline {
    prefilter: RegexPrefilter,
    sampler: InferenceSampler,
    ml_engine: Option<MlInferenceEngine>,
    redactor: Redactor,
    config: PiiConfig,
}

impl PiiPipeline {
    pub async fn scan(&self, message: &L7Message) -> PiiReport {
        let payload = message.payload.as_str();
        
        // Stage 1: Regex prefilter
        let regex_matches = self.prefilter.scan(payload);
        
        if regex_matches.is_empty() {
            // ~90% of traffic exits here
            return PiiReport {
                has_pii: false,
                entities: vec![],
                detection_method: DetectionMethod::None,
                latency_us: 1,  // ~1µs for RegexSet
            };
        }
        
        // Stage 2: Sampling decision
        match self.sampler.should_sample(payload.as_bytes()) {
            SamplingDecision::Skip(reason) => {
                // Return regex-only results
                return PiiReport {
                    has_pii: true,
                    entities: regex_matches.into_iter().map(|m| m.into()).collect(),
                    detection_method: DetectionMethod::Regex,
                    latency_us: 2,
                    skip_reason: Some(reason),
                };
            }
            SamplingDecision::Proceed => {}
        }
        
        // Stage 3: ML inference
        let start = Instant::now();
        let ml_entities = if let Some(engine) = &self.ml_engine {
            engine.infer(payload).unwrap_or_default()
        } else {
            vec![]
        };
        
        // Stage 4: Merge and redact
        let all_entities = self.merge_entities(regex_matches, ml_entities);
        let redacted = self.redactor.redact(payload, &all_entities);
        
        PiiReport {
            has_pii: !all_entities.is_empty(),
            entities: all_entities,
            detection_method: DetectionMethod::Hybrid,
            latency_us: start.elapsed().as_micros() as u64,
            redacted_text: Some(redacted),
        }
    }
}
```

## Consequences

### Positive

1. **High throughput**: ~90% of traffic filtered by regex in ~1µs
2. **Accurate detection**: ML adds 15-25% recall improvement over regex alone
3. **Bounded latency**: Budget sampler prevents ML from causing tail latency
4. **Configurable**: Sample rate adjustable for accuracy vs performance tradeoff
5. **Template deduplication**: Avoids redundant ML calls on identical query structures

### Negative

1. **Memory overhead**: ~250MB for ONNX model + tokenizer
2. **ML latency**: 10-50ms per inference affects sampled payloads
3. **Sampling reduces accuracy**: 1% sample rate means 99% of PII relies on regex only
4. **Cold start**: Model loading takes ~2 seconds at startup
5. **GPU unavailable**: ONNX Runtime CPU-only in agent (no GPU in DaemonSet)

### Neutral

1. **Hybrid approach**: Regex catches structured PII, ML catches unstructured (names)
2. **Budget resets per second**: Allows burst handling while maintaining average rate

## Alternatives Considered

### Alternative 1: Regex Only

**Description**: Skip ML entirely, rely on regex patterns for all detection.

**Pros**:
- Minimal latency (~1µs)
- No memory overhead for model
- Deterministic performance

**Cons**:
- 25% lower recall (misses names, contextual PII)
- High false positive rate on patterns like phone numbers

**Why rejected**: Insufficient accuracy for compliance requirements.

### Alternative 2: ML Only

**Description**: Run all payloads through DistilBERT-NER, skip regex.

**Pros**:
- Higher accuracy
- Simpler pipeline

**Cons**:
- 30ms per event at 500K/sec = impossible
- Would need 15,000 parallel inference threads

**Why rejected**: Cannot meet throughput requirements.

### Alternative 3: External PII Service (Always)

**Description**: Send all payloads to external service for detection.

**Pros**:
- No in-agent model memory
- Can use larger models (BERT-large, GPT)

**Cons**:
- Network latency unacceptable (10-50ms becomes 50-200ms)
- External dependency for core functionality

**Why rejected**: Latency requirements preclude network calls for all traffic. See ADR-008 for hybrid approach.

### Alternative 4: Presidio Integration

**Description**: Use Microsoft Presidio for PII detection.

**Pros**:
- Mature, well-tested
- Multiple analyzers built-in

**Cons**:
- Python-based (heavyweight for Rust agent)
- Requires gRPC/REST integration
- Adds 50MB+ dependency

**Why rejected**: Not suitable for embedded Rust agent; better suited for external service.

## Implementation Notes

### Model Files Required

```
models/
└── distilbert-ner/
    ├── model.onnx          # ~250MB quantized
    ├── tokenizer.json      # Vocabulary
    └── config.json         # Label mappings
```

### Configuration

```toml
[pii]
enabled = true
sample_rate = 0.01  # 1%
max_inferences_per_sec = 1000
redaction_policy = "hash"

[pii.regex]
patterns = ["email", "phone", "ssn", "credit_card", "jwt", "api_key", "aadhaar", "pan", "ip_address"]

[pii.ml]
model_path = "models/distilbert-ner/model.onnx"
tokenizer_path = "models/distilbert-ner/tokenizer.json"
batch_size = 8
```

### Template Normalization

```rust
fn compute_template_hash(payload: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    let normalized = normalize_template(payload);
    hasher.write(normalized.as_bytes());
    hasher.finish()
}

fn normalize_template(payload: &[u8]) -> String {
    let s = String::from_utf8_lossy(payload);
    
    // Replace literals with placeholders
    // "SELECT * FROM users WHERE id = 123" -> "SELECT * FROM users WHERE id = ?"
    // "email=john@example.com" -> "email=?"
    
    let mut result = s.to_string();
    
    // UUIDs
    result = UUID_REGEX.replace_all(&result, "?").into();
    
    // Numbers
    result = NUMBER_REGEX.replace_all(&result, "?").into();
    
    // Emails
    result = EMAIL_REGEX.replace_all(&result, "?").into();
    
    result
}
```

### Testing Requirements

1. **Regex accuracy**: Unit tests for all 11 patterns
2. **ML model loading**: Integration test with ONNX Runtime
3. **Sampler budget enforcement**: Verify max_inferences_per_sec respected
4. **Template deduplication**: Verify identical templates deduplicated
5. **Redaction correctness**: Verify all policies applied correctly
6. **End-to-end latency**: Verify < 50ms P99 for sampled payloads

### Metrics to Expose

```
# TYPE pii_scan_total counter
pii_scan_total{result="clean"} 900000
pii_scan_total{result="pii_found"} 100000

# TYPE pii_detection_method counter
pii_detection_method{method="regex"} 99000
pii_detection_method{method="ml"} 1000

# TYPE pii_ml_inference_seconds histogram
pii_ml_inference_seconds_bucket{le="0.01"} 500
pii_ml_inference_seconds_bucket{le="0.05"} 950
pii_ml_inference_seconds_bucket{le="0.1"} 1000

# TYPE pii_sampler_skip_total counter
pii_sampler_skip_total{reason="budget_exhausted"} 100
pii_sampler_skip_total{reason="duplicate_template"} 50000
pii_sampler_skip_total{reason="sampled_out"} 49400
```

## References

- [DistilBERT-NER model](https://huggingface.co/dslim/distilbert-NER)
- [ONNX Runtime Rust bindings](https://docs.rs/ort/latest/ort/)
- [HuggingFace Tokenizers](https://docs.rs/tokenizers/latest/tokenizers/)
- [Microsoft Presidio](https://github.com/microsoft/presidio)
- ADR-001: FSM Architecture
- ADR-008: External PII Service

---

## Revision History

| Date | Author | Description |
|------|--------|-------------|
| 2026-02-19 | @panopticon-team | Initial proposal and acceptance |
