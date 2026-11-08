//! Every process-global in the agent crate, reviewed (DESIGN §3): no
//! `static`, `OnceLock`, `LazyLock`, `thread_local!` or `lazy_static!` may
//! hold anything derived from captured data, which must live in the
//! disposable capture pipeline instead. A `OnceLock` / `LazyLock` is only
//! process-global as a `static`, and `thread_local!` / `lazy_static!`
//! bodies declare `static` items, so scanning `static NAME:` declarations
//! covers all five. A new one fails this test until it is reviewed and
//! listed here with its reason.

/// (file under `src/`, static name, why it holds nothing captured-derived).
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "test_hooks.rs",
        "HOOKS",
        "armed test pause points (unit tests and scope-test-hooks builds only)",
    ),
    ("main.rs", "GLOBAL", "the global allocator"),
    (
        "event_loop.rs",
        "TLS_KEY",
        "a random hash key drawn at start, never derived from traffic",
    ),
    (
        "capture_gate.rs",
        "KEY",
        "a random hash key drawn at start, never derived from traffic",
    ),
    ("scope_loader.rs", "LOCK", "the agent's lock file handle"),
    (
        "platform/proc_scanner.rs",
        "VERDICTS",
        "per-binary TLS verdicts from ELF files on disk, not from traffic",
    ),
    (
        "export/otlp.rs",
        "OFFSET",
        "the monotonic-to-wall clock offset",
    ),
    (
        "protocol/mod.rs",
        "SECRET_CLAUSE",
        "a compiled regex from a literal",
    ),
    (
        "protocol/mod.rs",
        "SECRET_CLAUSE_LOCAL",
        "a per-thread clone of a compiled regex",
    ),
    (
        "protocol/mod.rs",
        "MASK_CREDENTIALS",
        "the [privacy] mask_credentials config flag",
    ),
    (
        "graph/aggregator.rs",
        "UUID_RE_SHARED",
        "a compiled regex from a literal",
    ),
    (
        "graph/aggregator.rs",
        "UUID_RE",
        "a per-thread clone of a compiled regex",
    ),
    (
        "pii/regex_prefilter.rs",
        "COMPILED",
        "compiled PII regexes from literals",
    ),
    (
        "pii/regex_prefilter.rs",
        "LOCAL",
        "a per-thread clone of the compiled PII regexes",
    ),
];

/// `static NAME:` declarations in `text` (comments and `'static` skipped).
fn statics_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let code = line.split("//").next().unwrap_or_default();
        let mut words = code
            .split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '\''))
            .filter(|w| !w.is_empty());
        while let Some(w) = words.next() {
            if w != "static" {
                continue;
            }
            let mut name = words.next();
            if matches!(name, Some("ref" | "mut")) {
                name = words.next();
            }
            if let Some(name) = name
                && code.contains(&format!("{name}:"))
            {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn walk(dir: &std::path::Path, root: &std::path::Path, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().collect();
    entries.sort_by_key(|e| e.path());
    for e in entries {
        let path = e.path();
        if path.is_dir() {
            walk(&path, root, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            let rel = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if rel == "statics_check.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            out.extend(statics_in(&text).into_iter().map(|n| (rel.clone(), n)));
        }
    }
}

#[test]
fn every_static_is_reviewed() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    walk(&root, &root, &mut found);
    let unreviewed: Vec<_> = found
        .iter()
        .filter(|(f, n)| !ALLOWED.iter().any(|(af, an, _)| af == f && an == n))
        .collect();
    assert!(
        unreviewed.is_empty(),
        "statics not in the allowlist (statics_check.rs): {unreviewed:?}; a static must \
         never hold captured-derived data (DESIGN §3)"
    );
    let stale: Vec<_> = ALLOWED
        .iter()
        .filter(|(af, an, _)| !found.iter().any(|(f, n)| af == f && an == n))
        .collect();
    assert!(
        stale.is_empty(),
        "allowlisted statics that are gone: {stale:?}"
    );
}

#[test]
fn scanner_finds_each_form() {
    let src = "static A: u8 = 0;\npub static mut B: u8 = 0;\nthread_local! {\n    static C: Cell<u8> = Cell::new(0);\n}\nlazy_static! { static ref D: X = x(); }\n\
               fn f(s: &'static str) {} // static E: u8\nconst F: &'static str = \"\";\n";
    assert_eq!(statics_in(src), ["A", "B", "C", "D"]);
}
