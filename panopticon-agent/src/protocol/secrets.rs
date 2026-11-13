//! Login-secret protection: withhold any field with credential context.
//!
//! Masking a secret means finding where its value starts and ends, and SQL
//! dialects, string escapes and encodings keep defeating that. So the rule
//! is: a field whose *normalised view* shows credential context is withheld
//! whole, unless every credential in it sits in a structure whose value is
//! delimited with certainty, in which case only those values are masked.
//!
//! The normalised view (used for detection only, never exported): NUL
//! bytes dropped (UTF-16 text of ASCII), then up to three rounds of JSON
//! string escapes (`\u0070`), HTML character references (`&#112;`,
//! `&#x70;`, `&amp;` ...) and percent-decoding (`%70`, `+` as a space), so
//! one encoding revealed by another is decoded too; ASCII case folded; SQL
//! comment delimiters (`/*`, `/*!`, `*/`, `--`, `#`) blanked so their
//! content is read as text; `-` and `.` read as `_`. Credential context is:
//! - a word containing a credential part ([`PARTS`]: `password`, `secret`,
//!   `token`, `api_key`, ...), ending in `_pass` or `_auth`, or
//!   `identified` followed by `by`, `with`, `via`, `as` or `using`;
//! - a short credential name ([`NAMES`]: `auth`, `key`, `session`, `pwd`,
//!   ...) used as a name: followed by `=` or `:`, given as a form or HTML
//!   field name (`name="pwd"`), or an XML element (`<pwd>`); in SQL also a
//!   column in a list or assignment (`users(pwd)`, `, pwd)`);
//! - userinfo, `user:password@host`, with or without a scheme (the `:` of
//!   `scheme://` and of `mailto:` do not count), and any `//` authority
//!   whose userinfo has a `:` (RFC 3986: `,` and `;` may appear in it).
//!
//! The certain structures, on the raw text: a query or form parameter
//! (`name=value` at the start of the text or after `?` or `&`), a JSON
//! member whose value is a string, number, `true`, `false` or `null`, and
//! the userinfo of a `//` authority. Their names must be plain names (no
//! `=`, quotes or spaces once decoded). The text with those clauses
//! removed is checked again; any context left withholds the whole field.

use super::REDACTED_CREDENTIAL;
use super::credential_rules::{Builtin, CredentialRules, count_builtin, count_user};

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
    "bearer",
    "client_assertion",
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
    "otp",
    "pin",
];

fn strong_word(w: &str) -> bool {
    PARTS.iter().any(|p| p.len() <= w.len() && w.contains(p))
        || w.ends_with("_pass")
        || w.ends_with("_auth")
}

/// Substrings at least one of which every word of [`PARTS`] and [`NAMES`],
/// the `_pass` / `_auth` endings and `identified` contains: text holding
/// none of them (lowercase) has no word-based context.
const HINTS: &[&str] = &[
    "pass", "pwd", "secret", "token", "key", "auth", "cred", "sig", "sess", "sid", "cookie", "jwt",
    "csrf", "xsrf", "bearer", "assert", "master", "otp", "pin", "identif",
];

/// [`HINTS`] as one alternation: a single literal-prefilter pass over the
/// text instead of one search per hint.
static HINT_SEARCH: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(&HINTS.join("|")).expect("HINTS are literals"));

fn has_hint(lower: &str) -> bool {
    HINT_SEARCH.is_match(lower)
}

/// Characters a decoding step of the normalised view acts on.
fn may_decode(raw: &str) -> bool {
    raw.contains(['%', '+', '\\', '&', '\0'])
}

/// Whether a parameter, field, header or config name names a secret
/// (any length; percent- and JSON-decoded, case-folded).
pub fn is_credential_name(name: &str) -> bool {
    let n = normalize(name);
    NAMES.contains(&n.trim()) || words(&n).any(|(w, _, _)| strong_word(w) || NAMES.contains(&w))
}

/// Whether `text` shows credential context (see the module docs).
pub fn has_credential_context(text: &str) -> bool {
    context(text, false)
}

/// [`has_credential_context`] for a SQL statement: a short credential name
/// also counts as a column in a list or assignment (`users(pwd)`,
/// `SET a = 1, pass = $1`).
pub fn has_sql_credential_context(sql: &str) -> bool {
    context(sql, true)
}

fn context(text: &str, sql: bool) -> bool {
    let n = normalize(text);
    let b = n.as_bytes();
    if !has_hint(&n) {
        return has_userinfo(b);
    }
    let mut prev_identified = false;
    for (w, start, end) in words(&n) {
        if prev_identified && matches!(w, "by" | "with" | "via" | "as" | "using") {
            return true;
        }
        prev_identified = w == "identified";
        if w != "identified" && strong_word(w) {
            return true;
        }
        if NAMES.contains(&w) && (used_as_name(b, start, end) || sql && sql_column(b, start, end)) {
            return true;
        }
    }
    has_userinfo(b)
}

/// `text` with credential values masked where certain, or the field
/// withheld, under the rules in effect; None when nothing changes.
#[cfg(test)]
fn protect_text(text: &str) -> Option<String> {
    protect_text_with(&super::credential_rules::credential_rules(), text)
}

/// `text` protected under `rules` (see [`decide`]); None when nothing
/// changes.
pub fn protect_text_with(rules: &CredentialRules, text: &str) -> Option<String> {
    decide(rules, text, true).apply(text)
}

/// Most spans masked in one field; past it the field is withheld. Each
/// span is replaced by [`REDACTED_CREDENTIAL`], so this bounds both the
/// matching work kept and how much a field can grow.
pub const MAX_SPANS: usize = 1024;

/// What credential protection does to one field.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Keep,
    /// Replace these byte spans (sorted, disjoint, not touching) by
    /// [`REDACTED_CREDENTIAL`].
    Mask(Vec<(usize, usize)>),
    /// Replace the field by [`FIELD_WITHHELD`].
    Withhold,
}

impl Decision {
    /// The protected field, or None when it is kept as is.
    pub fn apply(&self, text: &str) -> Option<String> {
        match self {
            Decision::Keep => None,
            Decision::Withhold => Some(FIELD_WITHHELD.to_string()),
            Decision::Mask(spans) => Some(replace_spans(text, spans)),
        }
    }
}

/// Decide how to protect `text`. Every rule runs on the original field:
/// the user's patterns on the raw text and on its decoded view, then,
/// unless `builtin` is false, the built-in rules at their level. Their
/// spans are merged and the field is rewritten once by
/// [`Decision::apply`], so no rule hides another's match and rule order
/// does not matter. The field is withheld when a rule says so, when a
/// match in the decoded view is not the same raw match at the same place
/// (it cannot be placed in the field), or when it has more than
/// [`MAX_SPANS`] spans.
pub fn decide(rules: &CredentialRules, text: &str, builtin: bool) -> Decision {
    // A span that already reads exactly `<REDACTED>` would be replaced by
    // itself: dropped as a no-op. Nothing else in captured text is exempt,
    // whatever it reads like.
    let keep = |&(s, e): &(usize, usize)| &text[s..e] != REDACTED_CREDENTIAL;
    let mut spans = Vec::new();
    if let Some(user) = &rules.user {
        match user_spans(user, text) {
            Some(found) => {
                let before = spans.len();
                spans.extend(found.into_iter().filter(keep));
                count_user((spans.len() - before) as u64);
            }
            None => {
                count_user(1);
                return Decision::Withhold;
            }
        }
    }
    if builtin {
        let found = match rules.builtin {
            Builtin::Full => builtin_full(text),
            Builtin::NamesOnly => Some(certain_clauses(text).0),
        };
        match found {
            None => {
                count_builtin();
                return Decision::Withhold;
            }
            Some(found) => {
                let before = spans.len();
                spans.extend(found.into_iter().filter(keep));
                if spans.len() > before {
                    count_builtin();
                }
            }
        }
    }
    if spans.is_empty() {
        return Decision::Keep;
    }
    let spans = merge(spans);
    if spans.len() > MAX_SPANS {
        return Decision::Withhold;
    }
    Decision::Mask(spans)
}

/// The user's patterns: the spans of their raw matches (empty matches
/// skipped), or None when the field must be withheld: more than
/// [`MAX_SPANS`] matches, or, when decoding changes the field, any match
/// in the decoded view (escapes, entities and percent-encoding decoded,
/// not case-folded) that is not a raw match of the same pattern at the
/// same position with the same text: only then is it certainly masked.
fn user_spans(
    (set, each): &(regex::RegexSet, Vec<regex::Regex>),
    text: &str,
) -> Option<Vec<(usize, usize)>> {
    let mut spans = Vec::new();
    for i in set.matches(text).iter() {
        for m in each[i].find_iter(text).filter(|m| !m.is_empty()) {
            if spans.len() == MAX_SPANS {
                return None;
            }
            spans.push((m.start(), m.end()));
        }
    }
    if let Some(decoded) = decode(text) {
        for i in set.matches(&decoded).iter() {
            for m in each[i].find_iter(&decoded).filter(|m| !m.is_empty()) {
                let raw = text.get(m.start()..m.end());
                if raw != Some(m.as_str())
                    || !each[i]
                        .find_at(text, m.start())
                        .is_some_and(|r| r.range() == m.range())
                {
                    return None;
                }
            }
        }
    }
    Some(spans)
}

/// Every built-in rule: the values to mask where certain, or None (the
/// field withheld) when any context is left.
fn builtin_full(text: &str) -> Option<Vec<(usize, usize)>> {
    if !has_credential_context(text) {
        return Some(Vec::new());
    }
    let (mask, delete) = certain_clauses(text);
    let residual = remove(text, &delete);
    (!has_credential_context(&residual)).then_some(mask)
}

/// Sorted, with overlapping or touching spans joined.
fn merge(mut spans: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    spans.sort_unstable();
    let mut out: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
    for (s, e) in spans {
        match out.last_mut() {
            Some(last) if s <= last.1 => last.1 = last.1.max(e),
            _ => out.push((s, e)),
        }
    }
    out
}

/// A SQL statement with credential context, as exported: its verb and
/// [`STATEMENT_WITHHELD`].
pub fn withheld_statement(sql: &str) -> String {
    match sql_verb(sql) {
        Some(verb) => format!("{verb} {STATEMENT_WITHHELD}"),
        None => STATEMENT_WITHHELD.to_string(),
    }
}

/// Statement keywords a SQL statement may start with. Only these are
/// exported as a method: a malformed statement's leading word may be
/// anything, a secret included.
const SQL_VERBS: &[&str] = &[
    "ABORT",
    "ALTER",
    "ANALYZE",
    "BEGIN",
    "CALL",
    "CHANGE",
    "CHECK",
    "CHECKPOINT",
    "CHECKSUM",
    "CLOSE",
    "CLUSTER",
    "COMMENT",
    "COMMIT",
    "COPY",
    "CREATE",
    "DEALLOCATE",
    "DECLARE",
    "DELETE",
    "DESC",
    "DESCRIBE",
    "DISCARD",
    "DO",
    "DROP",
    "END",
    "EXECUTE",
    "EXPLAIN",
    "FETCH",
    "FLUSH",
    "GRANT",
    "HANDLER",
    "IMPORT",
    "INSERT",
    "INSTALL",
    "KILL",
    "LISTEN",
    "LOAD",
    "LOCK",
    "MERGE",
    "MOVE",
    "NOTIFY",
    "OPTIMIZE",
    "PREPARE",
    "PURGE",
    "REASSIGN",
    "REFRESH",
    "REINDEX",
    "RELEASE",
    "RENAME",
    "REPAIR",
    "REPLACE",
    "RESET",
    "REVOKE",
    "ROLLBACK",
    "SAVEPOINT",
    "SECURITY",
    "SELECT",
    "SET",
    "SHOW",
    "START",
    "TABLE",
    "TRUNCATE",
    "UNINSTALL",
    "UNLISTEN",
    "UNLOCK",
    "UPDATE",
    "USE",
    "VACUUM",
    "VALUES",
    "WITH",
    "XA",
];

/// The statement's keyword (after leading comments), uppercased, if it is
/// a known SQL statement keyword.
pub fn sql_verb(sql: &str) -> Option<&'static str> {
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
    let end = s
        .find(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or(s.len());
    let word = &s[..end];
    SQL_VERBS
        .iter()
        .find(|v| v.eq_ignore_ascii_case(word))
        .copied()
}

// ── Normalised view ─────────────────────────────────────────────────────

fn normalize(text: &str) -> String {
    let mut s = decode(text).unwrap_or_else(|| text.to_string());
    s.make_ascii_lowercase();
    for delim in ["/*!", "/*", "*/", "--", "#"] {
        if s.contains(delim) {
            s = s.replace(delim, &" ".repeat(delim.len()));
        }
    }
    if s.contains(['-', '.']) {
        s = s.replace(['-', '.'], "_");
    }
    s
}

/// The decoded view: NUL bytes dropped, then up to three rounds of JSON
/// escapes, HTML references and percent-decoding. None when nothing
/// changes.
fn decode(text: &str) -> Option<String> {
    let mut s: Option<String> = None;
    for _ in 0..3 {
        let mut changed = false;
        let cur = s.as_deref().unwrap_or(text);
        if cur.contains('\0') {
            let mut d = cur.to_string();
            d.retain(|c| c != '\0');
            s = Some(d);
            changed = true;
        }
        for step in [json_unescape, html_unescape, percent_decode] {
            if let Some(d) = step(s.as_deref().unwrap_or(text)) {
                s = Some(d);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    if let Some(d) = s.as_mut() {
        d.retain(|c| c != '\0');
    }
    s
}

/// HTML character references decoded (`&#119;`, `&#x77;`, `&amp;`,
/// `&quot;`, `&apos;`, `&lt;`, `&gt;`), or None when there are none.
fn html_unescape(text: &str) -> Option<String> {
    if !text.contains('&') {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut changed = false;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let semi = rest.as_bytes()[..rest.len().min(12)]
            .iter()
            .position(|&c| c == b';');
        let decoded = semi.and_then(|e| {
            let body = &rest[1..e];
            let c = if let Some(num) = body.strip_prefix('#') {
                match num.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok(),
                    None => num.parse().ok(),
                }
                .and_then(char::from_u32)
            } else {
                match body {
                    "amp" => Some('&'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    _ => None,
                }
            };
            c.map(|c| (c, e + 1))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
                changed = true;
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// JSON string escapes decoded wherever they appear, or None when there
/// are none.
fn json_unescape(text: &str) -> Option<String> {
    if !text.contains('\\') {
        return None;
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
    (out != text).then_some(out)
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

/// The words of a normalised text (`a-z`, digits, `_`), borrowed with
/// leading and trailing `_` dropped for classification, and where the
/// whole token starts and ends: what precedes and follows a name is read
/// from the token's own bounds (`pwd_=` is followed by `=`).
fn words(n: &str) -> impl Iterator<Item = (&str, usize, usize)> + '_ {
    let b = n.as_bytes();
    let is_word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut i = 0;
    std::iter::from_fn(move || {
        loop {
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
            let word = n[start..i].trim_matches('_');
            if !word.is_empty() {
                return Some((word, start, i));
            }
        }
    })
}

/// The next byte after `end` that is not a space or closing quote.
fn after(b: &[u8], end: usize) -> Option<u8> {
    b[end..]
        .iter()
        .copied()
        .find(|c| !c.is_ascii_whitespace() && !matches!(c, b'"' | b'\'' | b'`' | b']'))
}

/// The last byte before `start` that is not a space or opening quote.
fn before(b: &[u8], start: usize) -> Option<u8> {
    b[..start]
        .iter()
        .copied()
        .rev()
        .find(|c| !c.is_ascii_whitespace() && !matches!(c, b'"' | b'\'' | b'`' | b'['))
}

/// Whether the word at `start..end` is used as a name: followed by `=` or
/// `:`, a form or HTML field name (`name="w"`), or an XML element (`<w>`).
fn used_as_name(b: &[u8], start: usize, end: usize) -> bool {
    let head = &b[..start];
    matches!(after(b, end), Some(b'=' | b':'))
        || [&b"name=\""[..], b"name='", b"name="]
            .iter()
            .any(|p| head.ends_with(p))
        || (head.ends_with(b"<") || head.ends_with(b"</")) && b.get(end) == Some(&b'>')
}

/// In SQL, a column in a list or assignment: after `(` or `,`, or before
/// `)` or `,`.
fn sql_column(b: &[u8], start: usize, end: usize) -> bool {
    matches!(before(b, start), Some(b'(' | b',')) || matches!(after(b, end), Some(b')' | b','))
}

/// `user:password@host` anywhere: a `:` (not that of `scheme://` or
/// `mailto:`) then `@` and a host character, with no whitespace, quote or
/// bracket between. One forward pass.
fn has_userinfo(b: &[u8]) -> bool {
    authority_userinfo(b) || schemeless_userinfo(b)
}

/// A `//` authority (RFC 3986) whose userinfo, before its last `@`, holds a
/// `:`: the authority runs to `/`, `?`, `#`, whitespace, a quote or `<>\`,
/// so `,` and `;` in the password are kept.
fn authority_userinfo(b: &[u8]) -> bool {
    let mut from = 0;
    while let Some(o) = b[from..].windows(2).position(|w| w == b"//") {
        let a = from + o + 2;
        from = a;
        let e = b[a..]
            .iter()
            .position(|&c| {
                c.is_ascii_whitespace()
                    || matches!(
                        c,
                        b'/' | b'?' | b'#' | b'"' | b'\'' | b'`' | b'<' | b'>' | b'\\'
                    )
            })
            .map_or(b.len(), |p| a + p);
        if let Some(at) = b[a..e].iter().rposition(|&c| c == b'@').map(|p| a + p)
            && b[a..at].contains(&b':')
            && b.get(at + 1)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'[')
        {
            return true;
        }
    }
    false
}

/// `user:password@host` without a `//`: a `:` then `@` and a host
/// character, with no whitespace, quote, bracket or `,;&` between.
fn schemeless_userinfo(b: &[u8]) -> bool {
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
    // Most names are plain and hold no hint: answer without normalising.
    if !may_decode(raw)
        && !HINTS.iter().any(|h| {
            raw.as_bytes()
                .windows(h.len())
                .any(|w| w.eq_ignore_ascii_case(h.as_bytes()))
        })
    {
        return false;
    }
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

/// `text` with each span (sorted, disjoint) replaced by
/// [`REDACTED_CREDENTIAL`].
fn replace_spans(text: &str, spans: &[(usize, usize)]) -> String {
    let mut out = String::with_capacity(text.len() + spans.len() * REDACTED_CREDENTIAL.len());
    let mut at = 0;
    for &(s, e) in spans {
        out.push_str(&text[at..s]);
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

    /// The prefilter skips the word scan when no hint is present: every
    /// word that can be context must contain one.
    #[test]
    fn hints_cover_every_credential_word() {
        for w in PARTS
            .iter()
            .chain(NAMES)
            .chain(&["x_pass", "x_auth", "identified"])
        {
            assert!(has_hint(w), "{w}");
            assert!(plain_credential_name(w) || *w == "identified", "{w}");
        }
    }

    fn rules(patterns: &[&str], builtin: Builtin) -> CredentialRules {
        let p: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        CredentialRules::compile(&p, builtin).unwrap()
    }

    /// User patterns: raw matches replaced, a match only in the decoded
    /// view withholds the field; the built-in rules apply too.
    #[test]
    fn user_patterns_mask_their_matches() {
        let r = rules(&["acme_[a-z0-9]{8}", "(?i)tok-[0-9]{4}"], Builtin::Full);
        let p = |t: &str| protect_text_with(&r, t).unwrap_or_else(|| t.to_string());
        assert_eq!(p("id acme_abcd1234 ok"), "id <REDACTED> ok");
        assert_eq!(p("a TOK-1234 b tok-9999"), "a <REDACTED> b <REDACTED>");
        assert_eq!(p("/x?t=acme%5Fabcd1234"), FIELD_WITHHELD);
        // `acme` + JSON escape of `_` (backslash built at run time).
        let escaped = format!(r#"{{"k":"acme{}u005fabcd1234"}}"#, char::from(92));
        assert_eq!(p(&escaped), FIELD_WITHHELD);
        // Built-in rules as well as the user's.
        assert_eq!(
            p("q=acme_abcd1234&password=x"),
            "q=<REDACTED>&password=<REDACTED>"
        );
        assert_eq!(protect_text_with(&r, "plain text"), None);
    }

    /// `names_only`: certain structures and their names only; free text
    /// with credential words is not withheld.
    #[test]
    fn names_only_skips_free_text_context() {
        let r = rules(&[], Builtin::NamesOnly);
        let p = |t: &str| protect_text_with(&r, t).unwrap_or_else(|| t.to_string());
        assert_eq!(p("/login?password=x&q=1"), "/login?password=<REDACTED>&q=1");
        assert_eq!(
            p(r#"{"api_key":"k","n":1}"#),
            r#"{"api_key":"<REDACTED>","n":1}"#
        );
        assert_eq!(p("postgres://u:pw@db/x"), "postgres://u:<REDACTED>@db/x");
        for prose in ["your token expired", r#"{"access_tokens":["c1"]}"#] {
            assert_eq!(p(prose), prose);
            assert_ne!(
                protect_text_with(&rules(&[], Builtin::Full), prose).as_deref(),
                None
            );
        }
    }

    /// Codex round 5 #1, #3: every rule is matched against the original
    /// field and the field is rewritten once, so the output is bounded
    /// and no rule hides another's match.
    #[test]
    fn rules_match_the_original_field() {
        // #1: ten copies of `[A-Z]` once grew `GET` to gigabytes.
        let r = rules(&["[A-Z]"; 10], Builtin::Full);
        assert_eq!(protect_text_with(&r, "GET").as_deref(), Some("<REDACTED>"));
        // R5 M1: captured text is never exempt, whatever it reads like.
        assert_eq!(
            protect_text_with(&r, "a <REDACTED> b").as_deref(),
            Some("a <<REDACTED>> b")
        );
        let marker = rules(&["REDACTED"], Builtin::Full);
        assert_eq!(
            protect_text_with(&marker, "<REDACTED>").as_deref(),
            Some("<<REDACTED>>")
        );
        // R5 H2: the right value at the wrong occurrence. The raw match is
        // the first one; decoded, only the second (encoded) one matches.
        let bounded = rules(&[r"acme_[a-z0-9]{8}\b"], Builtin::Full);
        assert_eq!(
            protect_text_with(&bounded, "acme_abcd1234%61 acme%5fabcd1234").as_deref(),
            Some(FIELD_WITHHELD)
        );
        // R5 review: a decoded match straddling a raw match and an encoded
        // tail, and one built across a raw match of another pattern.
        let prefix = rules(&["acme_[a-z0-9]+"], Builtin::Full);
        assert_eq!(
            protect_text_with(&prefix, "acme_abcd%31234").as_deref(),
            Some(FIELD_WITHHELD)
        );
        let across = rules(&["x[a-z0-9]+y", "abc"], Builtin::Full);
        assert_eq!(
            protect_text_with(&across, "xabc%31y").as_deref(),
            Some(FIELD_WITHHELD)
        );
        // An encoded neighbour that is not a match still masks.
        let acme = rules(&["acme_[a-z0-9]{8}"], Builtin::Full);
        assert_eq!(
            protect_text_with(&acme, "acme_abcd1234 q=a%20b").as_deref(),
            Some("<REDACTED> q=a%20b")
        );
        let many = "A ".repeat(MAX_SPANS + 1);
        assert_eq!(
            protect_text_with(&r, &many).as_deref(),
            Some(FIELD_WITHHELD)
        );
        // #3: order does not matter; the longer match is masked whole.
        for order in [["acme_", "acme_[a-z0-9]{8}"], ["acme_[a-z0-9]{8}", "acme_"]] {
            let r = rules(&order, Builtin::Full);
            assert_eq!(
                protect_text_with(&r, "id acme_abcd1234 ok").as_deref(),
                Some("id <REDACTED> ok"),
                "{order:?}"
            );
        }
        // #3: a user match does not hide a credential name from the
        // built-in rules.
        let r = rules(&["password"], Builtin::Full);
        let out = protect_text_with(&r, "password=canary").unwrap();
        assert!(!out.contains("canary"), "{out}");
        let r = rules(&["password"], Builtin::NamesOnly);
        let out = protect_text_with(&r, "password=canary").unwrap();
        assert!(!out.contains("canary"), "{out}");
    }

    /// Codex round 5 #2: a name with a trailing separator is still used as
    /// a name (`pwd_=`): the token's own end decides what follows it.
    #[test]
    fn trailing_separators_keep_the_name() {
        for t in [
            "pwd_=s3cret",
            r#"{"pwd_":"s3cret"}"#,
            "pwd-=s3cret",
            "pwd.=s3cret",
            "x _pwd_: s3cret",
        ] {
            assert!(has_credential_context(t), "{t}");
            let out = p(t);
            assert!(!out.contains("s3cret"), "{t} -> {out}");
        }
    }

    /// Codex round 4: forms the detector missed.
    #[test]
    fn round_four_forms_are_context() {
        // #10: URI userinfo may hold `,` `;` (RFC 3986).
        assert_eq!(
            p("https://alice:ca,nary@host/db"),
            "https://alice:<REDACTED>@host/db"
        );
        assert_eq!(p("//alice:ca;nary@host/db"), "//alice:<REDACTED>@host/db");
        // #8: short names in SQL column lists and multipart / HTML names.
        assert!(has_sql_credential_context(
            "INSERT INTO users(pwd) VALUES ('s7Kf2v9LmQ8z')"
        ));
        assert!(has_sql_credential_context("UPDATE u SET a = 1, pass = $1"));
        for clean in [
            "INSERT INTO t (id) VALUES (1) ON DUPLICATE KEY UPDATE n = 2",
            "CREATE TABLE t (id int, PRIMARY KEY (id))",
            "SET SESSION sql_mode = ''",
        ] {
            assert!(!has_sql_credential_context(clean), "{clean}");
        }
        for withheld in [
            "Content-Disposition: form-data; name=\"pwd\"\r\n\r\ns7Kf2v9LmQ8z",
            // #7: decodings revealed by other decodings, entities, UTF-16.
            "/login?data=%7B%22pass%5Cu0077ord%22%3A%22s7Kf2v9LmQ8z%22%7D",
            "<input name=\"pass&#119;ord\" value=\"s7Kf2v9LmQ8z\">",
            "<input name=\"pass&#x77;ord\" value=\"s7Kf2v9LmQ8z\">",
            "&item=₹2;&x=1&#112;assword=s7Kf2v9LmQ8z",
            "<\0p\0a\0s\0s\0w\0o\0r\0d\0>\0s\0q\0K\0<\0/\0p\0>\0",
            // #9: more authentication material.
            r#"{"otp":"739204","n":[1]}"#,
            r#"{"pin":"739204","n":[1]}"#,
            r#"{"bearer":"s7Kf2v9LmQ8z","n":[1]}"#,
            r#"{"client_assertion":"s7Kf2v9LmQ8z","n":[1]}"#,
        ] {
            assert!(has_credential_context(withheld), "{withheld:?}");
            assert!(!p(withheld).contains("s7Kf2v9LmQ8z"), "{withheld:?}");
            assert!(!p(withheld).contains("739204"), "{withheld:?}");
        }
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
                r#"{"pin":<REDACTED>,"api_key":<REDACTED>}"#,
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
        // Codex: the leading word of a malformed statement may be the
        // secret itself; only a known SQL verb is shown.
        assert_eq!(
            withheld_statement("KJHGFDSA PASSWORD x"),
            STATEMENT_WITHHELD
        );
        assert_eq!(sql_verb("KJHGFDSA x"), None);
        assert_eq!(sql_verb("  /* c */ select 1"), Some("SELECT"));
        assert_eq!(
            sql_verb("with t as (select 1) select * from t"),
            Some("WITH")
        );
        assert_eq!(sql_verb("(select 1)"), None);
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
