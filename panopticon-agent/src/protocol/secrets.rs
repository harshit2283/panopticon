//! Login-secret protection: withhold any field with credential context.
//!
//! Masking a secret means finding where its value starts and ends, and SQL
//! dialects, string escapes and encodings keep defeating that. So the rule
//! is: a field whose *normalised view* shows credential context is withheld
//! whole, unless every credential in it sits in a structure whose value is
//! delimited with certainty, in which case only those values are masked.
//!
//! The normalised view (used for detection only, never exported): JSON
//! escapes decoded (`p`), percent-decoding repeated up to three times
//! (`%2570` → `p`) with `+` as a space, ASCII case folded, and SQL comment
//! delimiters (`/*`, `/*!`, `*/`, `--`, `#`) blanked so their content is
//! read as text. Credential context is:
//! - a word containing a credential part ([`PARTS`]: `password`, `secret`,
//!   `token`, `api_key`, ...), ending in `_pass` or `_auth`, or
//!   `identified` followed by `by`, `with`, `via`, `as` or `using`;
//! - a short credential name ([`NAMES`]: `auth`, `key`, `session`, `pwd`,
//!   ...) used as a name, that is followed by `=` or `:`;
//! - userinfo, `user:password@host`, with or without a scheme (the `:` of
//!   `scheme://` and of `mailto:` do not count).
//!
//! The certain structures, on the raw text: a query or form parameter
//! (`name=value` at the start of the text or after `?` or `&`), a JSON
//! member whose value is a string, number, `true`, `false` or `null`, and
//! the userinfo of a `//` authority. Their names must be plain names (no
//! `=`, quotes or spaces once decoded). The text with those clauses
//! removed is checked again; any context left withholds the whole field.

use super::REDACTED_CREDENTIAL;

/// What a field with credential context that cannot be masked with
/// certainty is replaced with. Holds no word that is credential context.
pub const FIELD_WITHHELD: &str = "<field withheld>";

/// What follows the verb of a SQL statement with credential context.
pub const STATEMENT_WITHHELD: &str = "<statement withheld>";

/// Parts that make any word credential context.
const PARTS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api_key",
    "access_key",
    "private_key",
    "credential",
    "signature",
    "requirepass",
    "masterauth",
    "authorization",
    "csrf",
    "xsrf",
];

/// Short names that are credential context only when used as a name.
const NAMES: &[&str] = &[
    "auth",
    "pwd",
    "pass",
    "key",
    "sig",
    "session",
    "sessionid",
    "session_id",
    "sid",
    "cookie",
    "jwt",
    "masteruser",
];

fn strong_word(w: &str) -> bool {
    PARTS.iter().any(|p| w.contains(p)) || w.ends_with("_pass") || w.ends_with("_auth")
}

/// Whether a parameter, field, header or config name names a secret
/// (any length; percent- and JSON-decoded, case-folded).
pub fn is_credential_name(name: &str) -> bool {
    let n = normalize(name);
    let whole = n.trim().replace(['-', '.'], "_");
    NAMES.contains(&whole.as_str())
        || words(&n).any(|(w, _)| strong_word(&w) || NAMES.contains(&w.as_str()))
}

/// Whether `text` shows credential context (see the module docs).
pub fn has_credential_context(text: &str) -> bool {
    let n = normalize(text);
    let b = n.as_bytes();
    let mut prev_identified = false;
    for (w, end) in words(&n) {
        if prev_identified && matches!(w.as_str(), "by" | "with" | "via" | "as" | "using") {
            return true;
        }
        prev_identified = w == "identified";
        if w != "identified" && strong_word(&w) {
            return true;
        }
        if NAMES.contains(&w.as_str()) && used_as_name(b, end) {
            return true;
        }
    }
    has_userinfo(b)
}

/// `text` with credential values masked where certain, or the field
/// withheld; None when it has no credential context or nothing changes.
pub fn protect_text(text: &str) -> Option<String> {
    if !has_credential_context(text) {
        return None;
    }
    let (mask, delete) = certain_clauses(text);
    let residual = remove(text, &delete);
    let out = if has_credential_context(&residual) {
        FIELD_WITHHELD.to_string()
    } else {
        replace_spans(text, &mask)
    };
    (out != text).then_some(out)
}

/// A SQL statement with credential context, as exported: its verb and
/// [`STATEMENT_WITHHELD`].
pub fn withheld_statement(sql: &str) -> String {
    let mut s = sql.trim_start();
    // Leading comments.
    loop {
        if let Some(rest) = s.strip_prefix("/*") {
            s = rest.split_once("*/").map_or("", |(_, r)| r).trim_start();
        } else if s.starts_with("--") || s.starts_with('#') {
            s = s.split_once('\n').map_or("", |(_, r)| r).trim_start();
        } else {
            break;
        }
    }
    let verb: String = s
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .take(32)
        .collect();
    if verb.is_empty() {
        STATEMENT_WITHHELD.to_string()
    } else {
        format!("{} {STATEMENT_WITHHELD}", verb.to_ascii_uppercase())
    }
}

// ── Normalised view ─────────────────────────────────────────────────────

fn normalize(text: &str) -> String {
    let mut s = json_unescape(text);
    for _ in 0..3 {
        match percent_decode(&s) {
            Some(d) => s = d,
            None => break,
        }
    }
    s.make_ascii_lowercase();
    for delim in ["/*!", "/*", "*/", "--", "#"] {
        if s.contains(delim) {
            s = s.replace(delim, &" ".repeat(delim.len()));
        }
    }
    s
}

/// JSON string escapes decoded wherever they appear.
fn json_unescape(text: &str) -> String {
    if !text.contains('\\') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('u') => {
                let hex: String = chars.by_ref().take(4).collect();
                let mut code = u32::from_str_radix(&hex, 16).unwrap_or(0xFFFD);
                if (0xD800..0xDC00).contains(&code) {
                    // A surrogate pair: 😀.
                    let mut ahead = chars.clone();
                    if ahead.next() == Some('\\') && ahead.next() == Some('u') {
                        let low: String = ahead.by_ref().take(4).collect();
                        if let Ok(l) = u32::from_str_radix(&low, 16)
                            && (0xDC00..0xE000).contains(&l)
                        {
                            code = 0x10000 + ((code - 0xD800) << 10) + (l - 0xDC00);
                            chars = ahead;
                        }
                    }
                }
                out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
            }
            Some('b' | 'f' | 'n' | 'r' | 't') => out.push(' '),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// One pass of `%XX` and `+` decoding, or None when there is nothing to
/// decode.
fn percent_decode(text: &str) -> Option<String> {
    if !text.contains(['%', '+']) {
        return None;
    }
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    let decoded = String::from_utf8_lossy(&out).into_owned();
    (decoded != text).then_some(decoded)
}

/// The words of a normalised text (`a-z`, digits, `_`; `-` and `.` read
/// as `_`) and where each ends.
fn words(n: &str) -> impl Iterator<Item = (String, usize)> + '_ {
    let b = n.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.');
    let mut i = 0;
    std::iter::from_fn(move || {
        while i < b.len() && !is_word(b[i]) {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        let start = i;
        while i < b.len() && is_word(b[i]) {
            i += 1;
        }
        let w = n[start..i]
            .replace(['-', '.'], "_")
            .trim_matches('_')
            .to_string();
        Some((w, i))
    })
}

/// Whether the word ending at `end` is followed (after spaces and closing
/// quotes) by `=` or `:`.
fn used_as_name(b: &[u8], end: usize) -> bool {
    b[end..]
        .iter()
        .find(|c| !c.is_ascii_whitespace() && !matches!(c, b'"' | b'\'' | b'`' | b']'))
        .is_some_and(|c| matches!(c, b'=' | b':'))
}

/// `user:password@host` anywhere: a `:` (not that of `scheme://` or
/// `mailto:`) then `@` and a host character, with no whitespace, quote or
/// bracket between. One forward pass.
fn has_userinfo(b: &[u8]) -> bool {
    let mut colon = false;
    for i in 0..b.len() {
        match b[i] {
            c if c.is_ascii_whitespace()
                || matches!(
                    c,
                    b'"' | b'\'' | b'`' | b'<' | b'>' | b'(' | b')' | b',' | b';' | b'&'
                ) =>
            {
                colon = false
            }
            b':' => {
                let scheme = b[i + 1..].starts_with(b"//");
                let mailto = b[..i].ends_with(b"mailto");
                colon |= !scheme && !mailto;
            }
            b'@' if colon
                && b.get(i + 1)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'[') =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

// ── Certain structures ──────────────────────────────────────────────────

type Spans = Vec<(usize, usize)>;

/// Value spans to mask and clause spans to remove for the residual check.
fn certain_clauses(text: &str) -> (Spans, Spans) {
    let b = text.as_bytes();
    let (mut mask, mut delete) = (Vec::new(), Vec::new());
    form_params(b, text, &mut mask, &mut delete);
    json_members(b, text, &mut mask, &mut delete);
    authorities(b, &mut mask, &mut delete);
    (mask, delete)
}

/// A name that, decoded, is a plain identifier.
fn plain_credential_name(raw: &str) -> bool {
    let n = normalize(raw);
    !n.is_empty()
        && n.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'[' | b']'))
        && is_credential_name(&n)
}

/// `name=value` at the start or after `?` / `&`; the value runs to `&` or
/// the end, without whitespace (a value with a space is not a form value:
/// `password=correct horse` in prose).
fn form_params(b: &[u8], text: &str, mask: &mut Spans, delete: &mut Spans) {
    for p in 0..b.len() {
        if p > 0 && !matches!(b[p - 1], b'?' | b'&') {
            continue;
        }
        let Some(eq) = b[p..]
            .iter()
            .position(|&c| matches!(c, b'=' | b'&' | b'#' | b'?' | b'/') || c.is_ascii_whitespace())
            .map(|o| p + o)
            .filter(|&e| e > p && b[e] == b'=')
        else {
            continue;
        };
        if !plain_credential_name(&text[p..eq]) {
            continue;
        }
        let end = b[eq + 1..]
            .iter()
            .position(|&c| c == b'&')
            .map_or(b.len(), |o| eq + 1 + o);
        if b[eq + 1..end].iter().any(u8::is_ascii_whitespace) {
            continue;
        }
        mask.push((eq + 1, end));
        delete.push((p, end));
    }
}

/// `"name": value` with a string, number or literal value, followed by `,`
/// or `}`.
fn json_members(b: &[u8], text: &str, mask: &mut Spans, delete: &mut Spans) {
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let name_end = json_string_end(b, i);
        let colon = skip_ws(b, name_end);
        if b.get(colon) != Some(&b':') {
            i = name_end;
            continue;
        }
        let vs = skip_ws(b, colon + 1);
        let ve = match b.get(vs) {
            Some(b'"') => Some(json_string_end(b, vs)),
            // Masked by an earlier pass.
            Some(b'<') if b[vs..].starts_with(REDACTED_CREDENTIAL.as_bytes()) => {
                Some(vs + REDACTED_CREDENTIAL.len())
            }
            Some(c) if c.is_ascii_digit() || matches!(c, b'-' | b't' | b'f' | b'n') => {
                let e = b[vs..]
                    .iter()
                    .position(|c| !(c.is_ascii_alphanumeric() || matches!(c, b'.' | b'+' | b'-')))
                    .map_or(b.len(), |o| vs + o);
                let lit = &text[vs..e];
                (matches!(lit, "true" | "false" | "null") || lit.parse::<f64>().is_ok())
                    .then_some(e)
            }
            _ => None,
        };
        if let Some(ve) = ve
            && ve <= b.len()
            && matches!(b.get(skip_ws(b, ve)), Some(b',' | b'}'))
            && name_end >= i + 2
            && plain_credential_name(&text[i + 1..name_end - 1])
        {
            // A string keeps its quotes: the JSON stays valid.
            if b[vs] == b'"' && ve >= vs + 2 && b[ve - 1] == b'"' {
                mask.push((vs + 1, ve - 1));
            } else {
                mask.push((vs, ve));
            }
            delete.push((i, ve));
            i = ve;
        } else {
            i = name_end;
        }
    }
}

/// End of the JSON string at `k` (after its closing quote; the end of the
/// text when unterminated).
fn json_string_end(b: &[u8], k: usize) -> usize {
    let mut i = k + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    b.len()
}

fn skip_ws(b: &[u8], mut k: usize) -> usize {
    while k < b.len() && b[k].is_ascii_whitespace() {
        k += 1;
    }
    k
}

/// The userinfo of a `//` authority (scheme optional): the password, after
/// the first `:` and up to the last `@` before `/`, `?`, `#`, whitespace or
/// a quote.
fn authorities(b: &[u8], mask: &mut Spans, delete: &mut Spans) {
    let mut from = 0;
    while let Some(o) = b[from..].windows(2).position(|w| w == b"//") {
        let a = from + o + 2;
        from = a;
        let e = b[a..]
            .iter()
            .position(|&c| {
                c.is_ascii_whitespace()
                    || matches!(c, b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>' | b'\\')
            })
            .map_or(b.len(), |p| a + p);
        if let Some(at) = b[a..e].iter().rposition(|&c| c == b'@').map(|p| a + p)
            && let Some(colon) = b[a..at].iter().position(|&c| c == b':').map(|p| a + p)
        {
            mask.push((colon + 1, at));
            delete.push((a, at + 1));
        }
    }
}

fn remove(text: &str, spans: &Spans) -> String {
    let mut spans = spans.clone();
    spans.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (s, e) in spans {
        if e <= at {
            continue;
        }
        out.push_str(&text[at..s.max(at)]);
        out.push(' ');
        at = e;
    }
    out.push_str(&text[at..]);
    out
}

fn replace_spans(text: &str, spans: &Spans) -> String {
    let mut spans: Spans = spans
        .iter()
        .copied()
        .filter(|&(s, e)| &text[s..e] != REDACTED_CREDENTIAL)
        .collect();
    spans.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (s, e) in spans {
        if e <= at {
            continue;
        }
        out.push_str(&text[at..s.max(at)]);
        out.push_str(REDACTED_CREDENTIAL);
        at = e;
    }
    out.push_str(&text[at..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> String {
        protect_text(s).unwrap_or_else(|| s.to_string())
    }

    #[test]
    fn certain_values_are_masked_the_rest_kept() {
        for (input, want) in [
            ("password=x&y=1", "password=<REDACTED>&y=1"),
            ("/l?%70assword=x&q=keep", "/l?%70assword=<REDACTED>&q=keep"),
            (
                "/l?%2570assword=x&q=keep",
                "/l?%2570assword=<REDACTED>&q=keep",
            ),
            (
                r#"{"client_secret": "a\"b", "n": 1}"#,
                r#"{"client_secret": "<REDACTED>", "n": 1}"#,
            ),
            (
                r#"{"pin":1,"api_key":12345}"#,
                r#"{"pin":1,"api_key":<REDACTED>}"#,
            ),
            (
                "x-api-key=k1&keyword=shoes",
                "x-api-key=<REDACTED>&keyword=shoes",
            ),
            (
                "amqp://guest:p@ss@rabbit:5672/vh",
                "amqp://guest:<REDACTED>@rabbit:5672/vh",
            ),
            ("//alice:pw@[::1]/db", "//alice:<REDACTED>@[::1]/db"),
        ] {
            assert_eq!(p(input), want, "{input}");
        }
    }

    #[test]
    fn uncertain_credential_context_withholds_the_field() {
        for input in [
            r#"{"access_tokens":["c1","c2"]}"#,
            r#"{"password":{"value":"c"}}"#,
            "/cb?next=alice:canary@db.internal",
            "Authorization: Bearer abc",
            "requirepass, s3cret",
            "pass%77ord=x as text",
            "dsn=u:pa/ss@h",
            "a password%3Dc=1",
            &format!("{}_password: x", "a".repeat(70)),
            "{\"pass\\u0077ord\": [1]}",
            "ALTER USER a IDENTIFIED BY /*!80000 'c' */",
            "key: value",
        ] {
            assert_eq!(p(input), FIELD_WITHHELD, "{input}");
        }
    }

    /// Redis text after the parser's own masking (USER-GUIDE 5.3): `AUTH`
    /// stays readable, a credential parameter's name withholds the field.
    #[test]
    fn masked_redis_text() {
        for text in [
            "<REDACTED>",
            "3 AUTH default <REDACTED>",
            "default, <REDACTED>",
        ] {
            assert_eq!(protect_text(text), None, "{text}");
        }
        for text in [
            "requirepass <REDACTED>",
            "masterauth",
            "requirepass, <REDACTED>",
        ] {
            assert_eq!(
                protect_text(text).as_deref(),
                Some(FIELD_WITHHELD),
                "{text}"
            );
        }
    }

    #[test]
    fn plain_text_is_left_alone() {
        for input in [
            "see https://medium.com/@user and mailto:alice@example.com",
            "author=bob&title=x&keyword=shoes",
            "GET /api/auth/login",
            "AUTH",
            "we identified a bug",
            "Press any key to continue",
            FIELD_WITHHELD,
            STATEMENT_WITHHELD,
            "ALTER <statement withheld>",
        ] {
            assert_eq!(protect_text(input), None, "{input}");
        }
    }

    #[test]
    fn a_second_pass_changes_nothing() {
        for s in [
            "password=x&token=y",
            r#"{"secret":"x"}"#,
            "postgres://u:p@h/db",
            "Authorization: Bearer x",
        ] {
            let once = p(s);
            assert_eq!(protect_text(&once), None, "{once}");
        }
    }

    #[test]
    fn statements() {
        assert_eq!(
            withheld_statement("  /* c */ alter user a identified by 'x'"),
            "ALTER <statement withheld>"
        );
        assert_eq!(withheld_statement("'x'"), STATEMENT_WITHHELD);
        assert!(has_credential_context(
            "SET PASSWORD FOR \u{fc}@localhost = 'c'"
        ));
        assert!(has_credential_context(
            "select 1 # 2; alter role a identified by 'c'"
        ));
        assert!(!has_credential_context("SELECT name FROM users"));
    }

    #[test]
    fn credential_names() {
        for n in [
            "password",
            "X-Api-Key",
            "client_secret",
            "auth-pass",
            "tls-key-file-pass",
            "passwords",
            "access_token",
            "sid",
            "key",
            "auth",
            &"a".repeat(80), /* plain */
        ] {
            if n.starts_with("aaa") {
                assert!(!is_credential_name(n));
                assert!(is_credential_name(&format!("{n}_password")));
                continue;
            }
            assert!(is_credential_name(n), "{n}");
        }
        for n in ["keyword", "author", "monkey", "maxmemory", "state", "q"] {
            assert!(!is_credential_name(n), "{n}");
        }
    }

    #[test]
    fn non_ascii_text_is_cut_on_char_boundaries() {
        assert_eq!(
            p("pässword=é&password=ü€x&ß"),
            "pässword=é&password=<REDACTED>&ß"
        );
        assert_eq!(p("€ db://ü:é@h"), "€ db://ü:<REDACTED>@h");
        assert_eq!(p("\\ud83d\\ude00 token"), FIELD_WITHHELD);
    }

    /// Linear in the field size, whatever its shape.
    #[test]
    fn scan_time_is_bounded() {
        for body in [
            "password=x&".repeat(6000),
            "lorem ipsum ".repeat(6000),
            "'".repeat(64 * 1024),
            "%25".repeat(20_000),
            "\\u0070".repeat(10_000),
            "a:b@c ".repeat(10_000),
            "\"k\":".repeat(15_000),
            "//".repeat(30_000),
            "a=".repeat(30_000),
        ] {
            let t = std::time::Instant::now();
            let _ = protect_text(&body);
            assert!(
                t.elapsed() < std::time::Duration::from_millis(500),
                "{:?} {:?}",
                &body[..8],
                t.elapsed()
            );
        }
    }
}
