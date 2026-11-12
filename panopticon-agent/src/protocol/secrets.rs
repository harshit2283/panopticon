//! Login-secret masking: one linear scanner shared by every protocol.
//!
//! A *clause* is a credential name followed by its value. Three kinds:
//! - **strong** keywords, whose value may follow after whitespace alone:
//!   `PASSWORD` / `PASSWD` / `*_PASSWORD` (also `SET PASSWORD FOR account`),
//!   `requirepass`, `masterauth`, and `IDENTIFIED [WITH|VIA plugin]
//!   BY|AS|USING [PASSWORD]`, each with an optional `REPLACE '<current>'`;
//! - **credential names** ([`is_credential_name`]: `token`, `api_key`,
//!   `client_secret`, `authorization`, ...), which need an explicit `=` or
//!   `:` (query and form parameters, JSON fields, `Name: value` text);
//! - **URI passwords**: `scheme://user:password@host`.
//!
//! Names are percent-decoded before they are classified (`%70assword`).
//! Values are lexed whole: quoted strings with doubled quotes and backslash
//! escapes, prefixed strings (`E'…'`, `N'…'`, `U&'…'`, `_utf8mb4'…'`),
//! dollar quotes (`$tag$…$tag$`), adjacent string literals, and in SQL mode
//! comments between the name and the value. A strong clause whose value
//! cannot be delimited (an expression such as `CONCAT(…)` or `(SELECT …)`,
//! an unterminated string) is masked to the end of the text instead of in
//! part.
//!
//! Detection looks at every word, inside strings and comments too: masking
//! a secret quoted in a comment costs nothing, and skipping comments would
//! miss a clause after a PostgreSQL `#` operator.

use super::REDACTED_CREDENTIAL;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// SQL text (MySQL, PostgreSQL queries and error messages): comments
    /// may sit between a keyword and its value.
    Sql,
    /// Any other text (HTTP fields, bodies, Redis payloads).
    Text,
}

/// `text` with every login secret replaced by [`REDACTED_CREDENTIAL`], or
/// None when there is none. For any field of any protocol.
pub fn mask_secrets(text: &str) -> Option<String> {
    mask(text, Mode::Text)
}

/// [`mask_secrets`] for SQL text: queries and server error messages.
pub fn mask_sql_secrets(text: &str) -> Option<String> {
    mask(text, Mode::Sql)
}

/// Whether a parameter, field, header-style or config name names a secret.
/// Percent-decoded and case-folded, `-` and `.` read as `_`, before the
/// test. Narrower than the credential-header test: `key` or `auth` inside
/// a longer name (`keyword`, `author`) is not a secret.
pub fn is_credential_name(name: &str) -> bool {
    let mut buf = [0u8; MAX_NAME];
    normalize(name.as_bytes(), &mut buf).is_some_and(|n| credential_name(n) != Class::None)
}

/// Longest name classified; longer words are not credential names.
const MAX_NAME: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    None,
    Strong,
    Identified,
    Name,
}

/// `name` percent-decoded, lowercased, `-`/`.` as `_`, into `buf`.
fn normalize<'b>(name: &[u8], buf: &'b mut [u8; MAX_NAME]) -> Option<&'b str> {
    let (mut i, mut n) = (0, 0);
    while i < name.len() {
        let mut c = name[i];
        if c == b'%'
            && let Some(v) = name
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            c = v;
            i += 2;
        }
        i += 1;
        *buf.get_mut(n)? = match c.to_ascii_lowercase() {
            b'-' | b'.' => b'_',
            c => c,
        };
        n += 1;
    }
    std::str::from_utf8(&buf[..n]).ok()
}

fn credential_name(n: &str) -> Class {
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
        "csrf",
        "xsrf",
    ];
    const EXACT: &[&str] = &[
        "pwd",
        "pass",
        "auth",
        "authorization",
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
    let n = n.trim_start_matches('_');
    // `t.password` is the column `password` (dots read as `_`).
    let last = n.rsplit('_').next().unwrap_or(n);
    if matches!(n, "password" | "passwd" | "requirepass" | "masterauth")
        || matches!(last, "password" | "passwd")
    {
        Class::Strong
    } else if n == "identified" {
        Class::Identified
    } else if EXACT.contains(&n) || n.ends_with("_pass") || PARTS.iter().any(|p| n.contains(p)) {
        Class::Name
    } else {
        Class::None
    }
}

fn classify(word: &[u8]) -> Class {
    let mut buf = [0u8; MAX_NAME];
    normalize(word, &mut buf).map_or(Class::None, credential_name)
}

/// Bytes of a name: letters, digits, `_`, `-`, `.` and `%` (escapes).
fn is_name_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'%')
}

fn mask(text: &str, mode: Mode) -> Option<String> {
    let b = text.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if is_name_byte(b[i]) && (i == 0 || !is_name_byte(b[i - 1])) {
            let mut j = i;
            while j < b.len() && is_name_byte(b[j]) {
                j += 1;
            }
            match clause(b, i, j, mode, &mut spans) {
                Some(next) => i = next,
                None => i = j,
            }
        } else {
            i += 1;
        }
    }
    uri_passwords(b, &mut spans);
    // Already masked values need no rewrite (a second pass is a no-op).
    spans.retain(|&(s, e)| &text[s..e] != REDACTED_CREDENTIAL);
    if spans.is_empty() {
        return None;
    }
    spans.sort_unstable();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (s, e) in spans {
        if e <= at {
            continue;
        }
        let s = s.max(at);
        out.push_str(&text[at..s]);
        out.push_str(REDACTED_CREDENTIAL);
        at = e;
    }
    out.push_str(&text[at..]);
    Some(out)
}

/// The clause whose name is `b[ws..we]`, if any: pushes the value span(s)
/// and returns where scanning resumes.
fn clause(
    b: &[u8],
    ws: usize,
    we: usize,
    mode: Mode,
    spans: &mut Vec<(usize, usize)>,
) -> Option<usize> {
    let class = classify(&b[ws..we]);
    if class == Class::None {
        return None;
    }
    let n = b.len();
    let mut k = we;
    // The closing quote of a quoted name: JSON `"password":`, `` `col` ``.
    if ws > 0 && k < n && matches!(b[k], b'"' | b'\'' | b'`') && b[ws - 1] == b[k] {
        k += 1;
    }
    k = skip_trivia(b, k, mode);
    let mut explicit = false;
    match class {
        Class::Identified => {
            let (mut w, mut after) = word_at(b, k);
            if eq(w, "with") || eq(w, "via") {
                k = skip_trivia(b, after, mode);
                k = skip_token(b, k);
                k = skip_trivia(b, k, mode);
                (w, after) = word_at(b, k);
            }
            if !(eq(w, "by") || eq(w, "as") || eq(w, "using")) {
                return None;
            }
            k = skip_trivia(b, after, mode);
            let (w, after) = word_at(b, k);
            if eq(w, "password") {
                k = skip_trivia(b, after, mode);
            }
            explicit = true;
        }
        Class::Strong => {
            let (w, after) = word_at(b, k);
            if eq(w, "for") {
                k = skip_trivia(b, after, mode);
                k = skip_account(b, k);
                k = skip_trivia(b, k, mode);
            }
        }
        _ => {}
    }
    if k < n && matches!(b[k], b'=' | b':') {
        k = skip_trivia(b, k + 1, mode);
        explicit = true;
    } else if class == Class::Name {
        return None;
    }
    let strong = class != Class::Name;
    let mut paren = false;
    // Where a value that cannot be delimited is masked from.
    let fail_from = k;
    if strong && k < n && b[k] == b'(' {
        k = skip_trivia(b, k + 1, mode);
        paren = true;
        explicit = true;
    }
    let vs = k;
    let fail_closed = |spans: &mut Vec<(usize, usize)>| {
        spans.push((fail_from, n));
        Some(n)
    };
    let Some((mut end, is_str)) = value_at(b, k) else {
        // `password, email`, `password)`: a column, not a clause; but
        // `PASSWORD = (…` with no value we can delimit fails closed.
        return if strong && explicit && k < n && b[k] == b'(' {
            fail_closed(spans)
        } else {
            None
        };
    };
    if is_str {
        // Adjacent literals concatenate ('a' 'b', and across a newline in
        // PostgreSQL).
        loop {
            let t = skip_trivia(b, end, mode);
            match value_at(b, t) {
                Some((e, true)) if t > end => end = e,
                _ => break,
            }
        }
    } else if strong {
        // A function call (`CONCAT(…)`) cannot be delimited.
        let t = if mode == Mode::Sql {
            skip_trivia(b, end, mode)
        } else {
            end
        };
        if t < n && b[t] == b'(' {
            return fail_closed(spans);
        }
    } else if [&b"bearer"[..], b"basic", b"digest", b"negotiate", b"token"]
        .iter()
        .any(|s| b[vs..end].eq_ignore_ascii_case(s))
        && end + 1 < n
        && b[end] == b' '
        && let Some((e, _)) = value_at(b, end + 1)
    {
        // `Authorization: Bearer <token>`
        end = e;
    }
    let mut next = end;
    if paren {
        let t = skip_trivia(b, end, mode);
        if t >= n || b[t] != b')' {
            return fail_closed(spans);
        }
        next = t + 1;
    }
    spans.push((vs, end));
    if strong {
        // `IDENTIFIED BY 'new' REPLACE 'current'`
        let t = skip_trivia(b, next, mode);
        let (w, after) = word_at(b, t);
        if eq(w, "replace") {
            let t = skip_trivia(b, after, mode);
            if let Some((e, true)) = value_at(b, t) {
                spans.push((t, e));
                next = e;
            }
        }
    }
    Some(next)
}

fn eq(word: &[u8], kw: &str) -> bool {
    word.eq_ignore_ascii_case(kw.as_bytes())
}

/// The name at `k` (possibly empty) and where it ends.
fn word_at(b: &[u8], k: usize) -> (&[u8], usize) {
    let mut e = k;
    while e < b.len() && is_name_byte(b[e]) {
        e += 1;
    }
    (&b[k..e], e)
}

/// Whitespace, and in SQL mode `/* … */`, `-- …` and `# …` comments.
fn skip_trivia(b: &[u8], mut k: usize, mode: Mode) -> usize {
    let n = b.len();
    loop {
        while k < n && b[k].is_ascii_whitespace() {
            k += 1;
        }
        if mode != Mode::Sql || k >= n {
            return k;
        }
        if b[k..].starts_with(b"/*") {
            k = find(b, k + 2, b"*/").map_or(n, |e| e + 2);
        } else if b[k..].starts_with(b"--") || b[k] == b'#' {
            k = find(b, k, b"\n").map_or(n, |e| e + 1);
        } else {
            return k;
        }
    }
}

fn find(b: &[u8], from: usize, pat: &[u8]) -> Option<usize> {
    b.get(from..)?
        .windows(pat.len())
        .position(|w| w == pat)
        .map(|p| p + from)
}

/// One token: a quoted string or a name (a plugin name).
fn skip_token(b: &[u8], k: usize) -> usize {
    match value_at(b, k) {
        Some((e, _)) => e,
        None => k,
    }
}

/// A MySQL account: `'app user'@'%'`, `app@localhost`, `` `a`@`b` ``.
fn skip_account(b: &[u8], mut k: usize) -> usize {
    while k < b.len() {
        if matches!(b[k], b'\'' | b'"' | b'`') {
            k = quoted_end(b, k);
        } else if is_name_byte(b[k]) || b[k] == b'@' {
            k += 1;
        } else {
            break;
        }
    }
    k
}

/// The value at `k`: its end, and whether it is a string literal. None for
/// punctuation or the end of the text.
fn value_at(b: &[u8], k: usize) -> Option<(usize, bool)> {
    let n = b.len();
    let c = *b.get(k)?;
    if matches!(c, b'\'' | b'"' | b'`') {
        return Some((quoted_end(b, k), true));
    }
    if c == b'$'
        && let Some(e) = dollar_end(b, k)
    {
        return Some((e, true));
    }
    // A prefixed literal: E'…', N'…', X'…', U&'…', _utf8mb4'…'.
    let mut p = k;
    while p < n && (b[p].is_ascii_alphanumeric() || matches!(b[p], b'_' | b'&')) {
        p += 1;
    }
    let prefix = &b[k..p];
    let literal_prefix = (b.get(p) == Some(&b'\'')
        && ["e", "n", "b", "x", "u&"]
            .iter()
            .any(|s| prefix.eq_ignore_ascii_case(s.as_bytes())))
        || (prefix.len() > 1 && prefix[0] == b'_' && matches!(b.get(p), Some(b'\'' | b'"')));
    if literal_prefix {
        return Some((quoted_end(b, p), true));
    }
    let mut e = k;
    while e < n
        && !b[e].is_ascii_whitespace()
        && !matches!(
            b[e],
            b',' | b';' | b'(' | b')' | b'&' | b'"' | b'\'' | b'}' | b']' | b'<' | b'>'
        )
    {
        e += 1;
    }
    (e > k).then_some((e, false))
}

/// End of the quoted string at `k` (after its closing quote; the end of the
/// text when unterminated). Doubled quotes and backslash escapes stay
/// inside.
fn quoted_end(b: &[u8], k: usize) -> usize {
    let q = b[k];
    let mut i = k + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            c if c == q => {
                if b.get(i + 1) == Some(&q) {
                    i += 2;
                } else {
                    return i + 1;
                }
            }
            _ => i += 1,
        }
    }
    b.len()
}

/// End of a PostgreSQL dollar-quoted string `$tag$…$tag$` at `k`, or None
/// when `k` does not open one (`$1` is a parameter).
fn dollar_end(b: &[u8], k: usize) -> Option<usize> {
    let mut t = k + 1;
    while t < b.len() && (b[t].is_ascii_alphanumeric() || b[t] == b'_') {
        t += 1;
    }
    if b.get(t) != Some(&b'$') || b.get(k + 1).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let tag = &b[k..=t];
    Some(find(b, t + 1, tag).map_or(b.len(), |e| e + tag.len()))
}

/// `scheme://user:password@host`: the password, up to the last `@` of the
/// authority (a password may contain `@`).
fn uri_passwords(b: &[u8], spans: &mut Vec<(usize, usize)>) {
    let mut from = 0;
    while let Some(sep) = find(b, from, b"://") {
        from = sep + 3;
        let scheme = b[..sep]
            .iter()
            .rev()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'.' | b'-'))
            .count();
        if scheme == 0 {
            continue;
        }
        let a = sep + 3;
        let e = b[a..]
            .iter()
            .position(|&c| {
                c.is_ascii_whitespace()
                    || matches!(c, b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>' | b'\\')
            })
            .map_or(b.len(), |p| a + p);
        if let Some(at) = b[a..e].iter().rposition(|&c| c == b'@').map(|p| a + p)
            && let Some(colon) = b[a..at].iter().position(|&c| c == b':').map(|p| a + p)
            && colon + 1 < at
        {
            spans.push((colon + 1, at));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> String {
        mask_secrets(s).unwrap_or_else(|| s.to_string())
    }

    fn sql(s: &str) -> String {
        mask_sql_secrets(s).unwrap_or_else(|| s.to_string())
    }

    #[test]
    fn masks_named_values_and_keeps_the_rest() {
        for (input, want) in [
            ("password=x&y=1", "password=<REDACTED>&y=1"),
            ("?%70assword=x&q=keep", "?%70assword=<REDACTED>&q=keep"),
            (
                r#"{"client_secret": "a\"b", "n": 1}"#,
                r#"{"client_secret": <REDACTED>, "n": 1}"#,
            ),
            ("Authorization: Bearer abc.def", "Authorization: <REDACTED>"),
            (
                "x-api-key=k1;keyword=shoes",
                "x-api-key=<REDACTED>;keyword=shoes",
            ),
            ("author=bob&title=x", "author=bob&title=x"),
            ("requirepass s3cret", "requirepass <REDACTED>"),
            (
                "amqp://guest:p@ss@rabbit:5672/vh",
                "amqp://guest:<REDACTED>@rabbit:5672/vh",
            ),
            ("see https://example.com/a@b", "see https://example.com/a@b"),
        ] {
            assert_eq!(text(input), want, "{input}");
        }
    }

    #[test]
    fn sql_clauses() {
        for (input, want) in [
            (
                "ALTER USER a IDENTIFIED BY 'x' REPLACE 'y'",
                "ALTER USER a IDENTIFIED BY <REDACTED> REPLACE <REDACTED>",
            ),
            (
                "CREATE USER a IDENTIFIED WITH 'p' AS '*h'",
                "CREATE USER a IDENTIFIED WITH 'p' AS <REDACTED>",
            ),
            (
                "CREATE USER a IDENTIFIED WITH auth_socket",
                "CREATE USER a IDENTIFIED WITH auth_socket",
            ),
            (
                "ALTER ROLE a PASSWORD $1",
                "ALTER ROLE a PASSWORD <REDACTED>",
            ),
            (
                "SET PASSWORD FOR app@localhost = 'x'",
                "SET PASSWORD FOR app@localhost = <REDACTED>",
            ),
            (
                "UPDATE t SET password = (SELECT h FROM s)",
                "UPDATE t SET password = <REDACTED>",
            ),
            (
                "ALTER ROLE a PASSWORD NULL",
                "ALTER ROLE a PASSWORD <REDACTED>",
            ),
        ] {
            assert_eq!(sql(input), want, "{input}");
        }
    }

    #[test]
    fn a_second_pass_changes_nothing() {
        for s in [
            "password=x&token=y",
            "ALTER USER a IDENTIFIED BY 'x' REPLACE 'y'",
            "SET PASSWORD = CONCAT('a', 'b')",
            "postgres://u:p@h/db",
        ] {
            let once = sql(&text(s));
            assert_eq!(mask_secrets(&once), None, "{once}");
            assert_eq!(mask_sql_secrets(&once), None, "{once}");
        }
    }

    #[test]
    fn non_ascii_text_is_cut_on_char_boundaries() {
        assert_eq!(
            text("pässword=é&password=ü€x&ß"),
            "pässword=é&password=<REDACTED>&ß"
        );
        assert_eq!(sql("PASSWORD 'é€'"), "PASSWORD <REDACTED>");
        assert_eq!(text("€ db://ü:é@h"), "€ db://ü:<REDACTED>@h");
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
        ] {
            assert!(is_credential_name(n), "{n}");
        }
        for n in ["keyword", "author", "monkey", "maxmemory", "state", "q"] {
            assert!(!is_credential_name(n), "{n}");
        }
    }

    /// Linear: a 64 KiB body of clauses and a 64 KiB body of words.
    #[test]
    fn scan_time_is_bounded() {
        for body in [
            "password=x&".repeat(6000),
            "lorem ipsum ".repeat(6000),
            "'".repeat(64 * 1024),
        ] {
            let t = std::time::Instant::now();
            let _ = mask_secrets(&body);
            let _ = mask_sql_secrets(&body);
            assert!(
                t.elapsed() < std::time::Duration::from_millis(500),
                "{:?}",
                t.elapsed()
            );
        }
    }
}
