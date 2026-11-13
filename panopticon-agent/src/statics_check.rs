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
    (
        "test_hooks.rs",
        "TAPS",
        "tests and scope-test-hooks builds only: the test oracle of socket writes, \
         what revoked gates refused, and OTLP exports",
    ),
    ("main.rs", "GLOBAL", "the global allocator"),
    (
        "narrowing_tests.rs",
        "GLOBAL_LOG",
        "tests only: the test binary's process-wide log, the oracle itself",
    ),
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
        "MASK_CREDENTIALS",
        "the [privacy] mask_credentials config flag",
    ),
    (
        "protocol/secrets.rs",
        "HINT_SEARCH",
        "a regex compiled from a constant word list",
    ),
    (
        "protocol/credential_rules.rs",
        "RULES",
        "the compiled [credentials] config (operator patterns, builtin level)",
    ),
    (
        "protocol/credential_rules.rs",
        "USER_MATCHES",
        "a counter of user-pattern matches (a number, never a value)",
    ),
    (
        "protocol/credential_rules.rs",
        "BUILTIN_MATCHES",
        "a counter of fields the built-in rules changed (a number, never a value)",
    ),
    (
        "protocol/credential_rules.rs",
        "LOADS",
        "test-only count of rule-set loads on this thread (a number, never a value)",
    ),
    (
        "protocol/http2.rs",
        "SCANNED",
        "test-only count of content-type bytes classified (a number, never a value)",
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

/// `static NAME:` declarations in `text`, read from its tokens: comments
/// and string contents are not code, `r#NAME` is `NAME`, a declaration may
/// span lines or carry a comment anywhere, `'static` is a lifetime, and
/// macro bodies (`thread_local!`, `lazy_static!`) are searched too.
fn statics_in(text: &str) -> Vec<String> {
    use proc_macro2::{TokenStream, TokenTree};
    fn scan(ts: TokenStream, out: &mut Vec<String>) {
        let tts: Vec<TokenTree> = ts.into_iter().collect();
        let punct = |t: Option<&TokenTree>, c: char| matches!(t, Some(TokenTree::Punct(p)) if p.as_char() == c);
        for (i, tt) in tts.iter().enumerate() {
            match tt {
                TokenTree::Group(g) => scan(g.stream(), out),
                TokenTree::Ident(id) if id == "static" => {
                    if i > 0 && punct(tts.get(i - 1), '\'') {
                        continue; // 'static
                    }
                    let mut j = i + 1;
                    if matches!(tts.get(j), Some(TokenTree::Ident(w)) if w == "ref" || w == "mut") {
                        j += 1;
                    }
                    if let Some(TokenTree::Ident(name)) = tts.get(j)
                        && punct(tts.get(j + 1), ':')
                    {
                        let name = name.to_string();
                        out.push(name.strip_prefix("r#").unwrap_or(&name).to_string());
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    scan(text.parse().expect("source file does not lex"), &mut out);
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

/// Forms a line-based scan missed (statics_check review).
#[test]
fn scanner_reads_tokens_not_lines() {
    let src = r##"
        static r#TYPE: u8 = 0;
        static G /* why */ : u8 = 0;
        pub(crate) static
            H
            : std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());
        mod m { fn f() { static I: u8 = 0; } }
        /// static J: u8 (a doc comment)
        const K: &str = "static L: u8";
        const M: &str = r#"static N: u8"#;
        /* static O: u8 */
        fn g<'a>(_: &'a str) -> &'static str { "" }
        static P: &'static str = "";
    "##;
    assert_eq!(statics_in(src), ["TYPE", "G", "H", "I", "P"]);
}
