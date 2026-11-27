//! Login-secret protection: withhold any field where a credential value
//! could be present.
//!
//! Masking a secret means finding where its value starts and ends, and SQL
//! dialects, string escapes and encodings keep defeating that. So the rule
//! is: a field whose *normalised view* shows credential context is withheld
//! whole, unless every credential in it sits in a structure whose value is
//! delimited with certainty, in which case only those values are masked.
//! A credential word that is a *bare name*, in one of two allowlisted
//! positions of a field of the right kind, is not context (see
//! [`BareShapes`]); anything outside the allowlist is (fail closed). A
//! bare path's query and fragment are never exported: the path part is
//! followed by [`QUERY_WITHHELD`] ([`decide_as`]).
//!
//! The normalised view (used for detection only, never exported): NUL
//! bytes dropped (UTF-16 text of ASCII), then up to three rounds of JSON
//! string escapes (`\u0070`; a `\u` without four hex digits is kept as
//! it is and consumes nothing), HTML character references (`&#112;`,
//! `&#x70;`, `&amp;` ...) and percent-decoding (`%70`, `+` as a space), so
//! one encoding revealed by another is decoded too; ASCII case folded; SQL
//! comment delimiters (`/*`, `/*!`, `*/`, `--`, `#`) blanked so their
//! content is read as text; `-` and `.` read as `_`. A backslash before a
//! letter is read both ways ([`Reading`], [`normalize_views`]), context in
//! either counting: as JSON (`\t` a tab, `\k` a `k`) and as a separator
//! with the letter kept (`C:\token` is `C: token`, `dir\key` is
//! `dir key`). Credential context is:
//! - a word containing a credential part ([`PARTS`]: `password`, `pwd`,
//!   `secret`, `token`, `api_key`, ..., each part of two words also
//!   folded: `apikey`, `privatekey`, so `privateKey` is one), ending in
//!   `_pass` or `_auth`, or `identified` followed by `by`, `with`, `via`,
//!   `as` or `using`;
//! - a credential name in a position that delimits the whole name, read
//!   whole with `-` and `.` splitting segments too
//!   ([`credential_name_in_a_name_position`]): a JSON member name, a query
//!   or form parameter name, a form or HTML field name (`name="old-pwd"`)
//!   and an XML element name (`<ns:newPwd>`, `<user.pin>`);
//! - a short credential name ([`NAMES`]: `auth`, `key`, `session`, `pin`,
//!   ...; `pwd` is a part too), the whole word or one of its segments
//!   ([`has_name_segment`]:
//!   split at `_` and at case and digit boundaries of the text as decoded,
//!   so `old_pwd`, `newPwd`, `card_pin`, `PIN_CODE`, `otp2`, and a
//!   segment ending in `pin` or `otp`, `cardpin`, `SMSOTP`, `mpin`; not
//!   `spinner`, `pinned` or `keyboard`; no plural), used as a name:
//!   followed by `=` or `:`, given as a form or HTML field name
//!   (`name="pwd"`), or an XML element (`<pwd>`); in SQL also a column in
//!   a list or assignment (`users(pwd)`, `, pwd)`) or next to an operator
//!   (`pwd - 0`). Short names are also looked for with `-` and `.` as
//!   boundaries (`users.pwd`, `?user.pwd=`, `old-pwd:`), and in SQL on the
//!   statement as captured (`pin+1`, whose `+` decodes to a space); a
//!   short name followed by `-` or `.` is not used as a name in free
//!   text, so a host and port is not one (`auth-service:8080`), except in
//!   what is left of a field once its certain clauses are removed;
//! - userinfo, `user:password@host`, with or without a scheme (the `:` of
//!   `scheme://` and of `mailto:` do not count), and any `//` authority
//!   whose userinfo has a `:` (RFC 3986: `,` and `;` may appear in it),
//!   whatever follows its `@` (`postgres://u:pw@/db`, a Unix socket).
//!
//! Bare names are an allowlist tied to the field's kind ([`FieldKind`],
//! passed in by the caller, never inferred from the text), and none
//! applies on a view from which a NUL was dropped or to a word with a
//! digit:
//! - in an HTTP/1 or HTTP/2 request path (not an HTTP/1 path read on a
//!   TLS key whose start is unproven, which the parser checks with no
//!   bare name: `http1::tls_path`): the last segment of the path
//!   part (the raw text before any `?` or `#`), when every segment is a
//!   plain name (`A`-`Z`, `a`-`z`, `_`, `-`, `.`: no `%`, `+`, space or
//!   other byte) and the word ends in a whole credential part
//!   (`access_token`, not `token_abc`) ([`path_last_segment`]);
//! - in a MySQL or PostgreSQL statement: a projection item of
//!   `SELECT item, ... FROM table [rest]` ([`select_list`]), read on the
//!   raw tokens with no comment marker, `\`, `"` or backtick and nothing
//!   decoding would change: each item `*` or a plain identifier (no
//!   qualifier, literal, value keyword such as `TRUE`, number, function
//!   or alias), the table a plain
//!   identifier, no credential word in any form from the table to the
//!   end, and the rest only `WHERE` comparisons with numbers, parameters
//!   or plain strings, `ORDER BY` and `LIMIT`.
//!
//! Every other field (Redis, Kafka, AMQP, DNS, gRPC, headers, bodies,
//! error text) has no bare name. So an HTTP path `/oauth/token` and a
//! statement `SELECT password, email FROM users` are not context, while
//! `/reset/token/abc123`, `WHERE password = 'x'`, `WHERE pwd LIKE 'x'`,
//! `SELECT password, 0x68756e74657232`, `token abc123`, `hunter2 is my
//! password`, `CONFIG GET requirepass` and a Redis value `/oauth/token`
//! are. A statement exported this way loses its bound values
//! ([`has_any_sql_credential_context`]); no SQL parser exports server
//! error text for any statement.
//!
//! The certain structures, on the raw text: a query or form parameter
//! (`name=value` at the start of the text or after `?` or `&`), a JSON
//! member whose value is a string, number, `true`, `false` or `null`, and
//! the userinfo of a `//` authority. Their names must be plain names (no
//! `=`, quotes or spaces once decoded). The text with those clauses
//! removed is checked again, strictly: any context left, a credential
//! name left in a name position (its value an array, an object or cut
//! off: `{"pin-code":["7392"]}`), or any word with a short name as a
//! segment wherever it is (`"note":"pin-code: 7392"`), withholds the whole
//! field. Full masks all `names_only` masks by construction: with no
//! context, it still masks the certain clauses `names_only` masks
//! ([`builtin_full`]).

use super::REDACTED_CREDENTIAL;
use super::credential_rules::{Builtin, CredentialRules, count_builtin, count_user};

/// What a field with credential context that cannot be masked with
/// certainty is replaced with. Holds no word that is credential context.
pub const FIELD_WITHHELD: &str = "<field withheld>";

/// What replaces the query and fragment of an HTTP request path whose
/// path part ends in a bare credential name (`/oauth/token?<query
/// withheld>`): no byte of either is exported.
pub const QUERY_WITHHELD: &str = "?<query withheld>";

/// What follows the verb of a SQL statement with credential context.
pub const STATEMENT_WITHHELD: &str = "<statement withheld>";

/// Parts that make any word credential context. Each part of two words is
/// listed with `_` and folded (`api_key`, `apikey`), so its camelCase
/// form, case folded, is one too (`privateKey` is `privatekey`).
const PARTS: &[&str] = &[
    "password",
    "passwd",
    // Rarely part of another word: `newpwd`, `OLDPWD`, `x-loginpwd` (a
    // header name as the parsers deliver it, lowercased).
    "pwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "privatekey",
    "private_key",
    "credential",
    "signature",
    "requirepass",
    "masterauth",
    "authorization",
    "csrf",
    "xsrf",
    "bearer",
    "clientassertion",
    "client_assertion",
];

/// Short names that are credential context only when used as a name,
/// whole or as a segment of a name ([`has_name_segment`]). `pwd` is also a
/// part ([`PARTS`]), so it is context anywhere; it stays here for the
/// rules that read names.
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

/// Whether a string read as segments (a Redis argument: no free text
/// around it to show a short name is used as a name) names a credential.
/// Every character that is not an ASCII letter or digit separates segments
/// (`u:1:otp`, `u|otp`, `u otp`, `u{1}otp`), and so do case and digit
/// boundaries: a lower-case letter or digit followed by an upper-case one
/// (`pinCode` is `pin`, `Code`), an upper-case letter followed by an
/// upper-case one and a lower-case one (`OTPCode` is `OTP`, `Code`), and a
/// letter next to a digit (`otp2` is `otp`, `2`); case folded. It names a
/// credential when it contains a word of [`PARTS`] anywhere, separators
/// read as `_` (`u:1:apikey`, `session_token`, `client-assertion`,
/// `clientAssertion`), or when one of its segments is a word of [`NAMES`]
/// whole or with a plural `s` (`otp`, `user:1:pin`, `api-key`, `pinCode`,
/// `sessions`, `otps`). Both readings are tried, with and without the case
/// and digit boundaries (`masterUser`). A short name joined to other
/// letters with no boundary does not count (owner ruling for Redis keys
/// and command names, unlike [`has_name_segment`]'s `pin` / `otp`
/// endings): `mykey`, `spinner`, `author`, `otpcode` and `SETOTP` name no
/// credential.
pub fn segmented_name_has_credential_word(name: &str) -> bool {
    [true, false].into_iter().any(|bounded| {
        let mut norm = segments_joined(name, bounded);
        let found = PARTS.iter().any(|p| norm.contains(p))
            || norm.split('_').any(|s| {
                NAMES.contains(&s) || s.strip_suffix('s').is_some_and(|t| NAMES.contains(&t))
            });
        zeroize::Zeroize::zeroize(&mut norm);
        found
    })
}

/// `name` case folded, with `_` for each run of characters that are not
/// ASCII letters or digits and, if `bounded`, at each case or digit
/// boundary (see [`segmented_name_has_credential_word`]).
fn segments_joined(name: &str, bounded: bool) -> String {
    let b = name.as_bytes();
    let mut out = String::with_capacity(name.len() + 8);
    for (i, &c) in b.iter().enumerate() {
        if !c.is_ascii_alphanumeric() {
            if !out.ends_with('_') {
                out.push('_');
            }
            continue;
        }
        if bounded && case_or_digit_boundary(b, i) && !out.ends_with('_') {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase() as char);
    }
    out
}

/// Whether a new segment starts at the letter or digit `b[i]` because of
/// case or digits (see [`segmented_name_has_credential_word`]): after a
/// lower-case letter or digit when upper-case (`pin|Code`), after an
/// upper-case letter when upper-case and followed by a lower-case one
/// (`OTP|Code`), and between a letter and a digit (`otp|2`).
fn case_or_digit_boundary(b: &[u8], i: usize) -> bool {
    let c = b[i];
    let prev = i
        .checked_sub(1)
        .map(|j| b[j])
        .filter(u8::is_ascii_alphanumeric);
    let next = b.get(i + 1).copied();
    prev.is_some_and(|p| {
        (c.is_ascii_uppercase() && (p.is_ascii_lowercase() || p.is_ascii_digit()))
            || (c.is_ascii_uppercase()
                && p.is_ascii_uppercase()
                && next.is_some_and(|n| n.is_ascii_lowercase()))
            || (c.is_ascii_digit() != p.is_ascii_digit())
    })
}

/// Whether one of the segments of `token` (as captured, case kept) is a
/// word of [`NAMES`], case folded: the segments of
/// [`segments_joined`] with its boundaries, every character that is not an
/// ASCII letter or digit separating them (`old_pwd`, `newPwd`, `PIN_CODE`,
/// `x.sms.otp`, `otp2`). Unlike a Redis argument
/// ([`segmented_name_has_credential_word`]), no plural (`keys`, `pins`):
/// these are names in free text and structured bodies, where a plural is
/// more often a list than a secret. A segment that ends in `pin` or `otp`
/// counts too ([`ends_in_pin_or_otp`]: `cardpin`, `SMSOTP`, `mpin`). Any
/// other short name inside a segment with no boundary is not one:
/// `spinner`, `pinned`, `shipping`, `keyboard`, `otpcode`. No allocation:
/// one pass over the token.
fn has_name_segment(token: &[u8]) -> bool {
    let is_name = |seg: &[u8]| {
        NAMES.iter().any(|n| seg.eq_ignore_ascii_case(n.as_bytes())) || ends_in_pin_or_otp(seg)
    };
    let mut start: Option<usize> = None;
    for i in 0..=token.len() {
        let alnum = token.get(i).is_some_and(u8::is_ascii_alphanumeric);
        let cut = !alnum || case_or_digit_boundary(token, i);
        if cut
            && let Some(s) = start.take()
            && is_name(&token[s..i])
        {
            return true;
        }
        if alnum && start.is_none() {
            start = Some(i);
        }
    }
    false
}

/// A segment of more than three letters or digits ending in `pin` or
/// `otp` (case folded): names written in one case join a short name to the
/// word before it with no boundary (`cardpin`, `smsotp`, `mpin`, `totp`, a
/// lowercased header `x-cardpin`). Only the end counts, so `spinner`,
/// `pinned`, `shipping`, `opinion`, `option`, `topic` and `footprint` do
/// not; `spin`, `backspin` and `hairpin` do (masked as credentials: a
/// known over-match).
fn ends_in_pin_or_otp(seg: &[u8]) -> bool {
    seg.len() > 3 && {
        let tail = &seg[seg.len() - 3..];
        tail.eq_ignore_ascii_case(b"pin") || tail.eq_ignore_ascii_case(b"otp")
    }
}

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
/// (any length; percent- and JSON-decoded, case-folded): it holds a word
/// with a credential part ([`PARTS`], `_pass`, `_auth`), or one of its
/// segments, split at every character that is not an ASCII letter or digit
/// and at case and digit boundaries, is a short name or ends in `pin` or
/// `otp` ([`has_name_segment`]: `X-Old-Pwd`, `new_pwd`, `loginPwd`,
/// `card_pin`, `x-cardpin`; `x-newpwd` by the part `pwd`; not `spinner`).
pub fn is_credential_name(name: &str) -> bool {
    let (d, _, letter) = decode_nul(name, Reading::Json);
    let json = match d {
        Some(d) => decoded_name_is_credential(d.as_bytes()),
        None => decoded_name_is_credential(name.as_bytes()),
    };
    // A backslash before a letter, also read as a separator ([`Reading`]):
    // `dir\key`, `x\token`.
    json || letter
        && decode_nul(name, Reading::Separator)
            .0
            .is_some_and(|d| decoded_name_is_credential(d.as_bytes()))
}

/// [`is_credential_name`] of a name already decoded (as in the normalised
/// view), case kept: a word of it (`-` and `.` read as `_`, any other
/// character that is not a letter, digit or `_` a separator), case
/// folded, has a credential part or is a short name, or one of its
/// segments is a short name ([`has_name_segment`]). No allocation for a
/// name of up to 128 bytes.
fn decoded_name_is_credential(name: &[u8]) -> bool {
    if has_name_segment(name) {
        return true;
    }
    let mut stack = [0u8; 128];
    let mut heap = Vec::new();
    let lower: &mut [u8] = if name.len() <= stack.len() {
        &mut stack[..name.len()]
    } else {
        heap.resize(name.len(), 0);
        &mut heap
    };
    for (o, &c) in lower.iter_mut().zip(name) {
        *o = match c.to_ascii_lowercase() {
            b'-' | b'.' => b'_',
            c if c.is_ascii_alphanumeric() || c == b'_' => c,
            _ => b' ',
        };
    }
    let found = lower
        .split(|&c| c == b' ')
        .filter_map(|w| std::str::from_utf8(w).ok())
        .map(|w| w.trim_matches('_'))
        .any(|w| !w.is_empty() && (strong_word(w) || NAMES.contains(&w)));
    zeroize::Zeroize::zeroize(&mut stack);
    zeroize::Zeroize::zeroize(&mut heap);
    found
}

/// What a field is, as its parser knows it. Only an HTTP request path and
/// a SQL statement can hold a bare name; every other field (Redis, Kafka,
/// AMQP, DNS, gRPC, headers, bodies, error text ...) holds none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Other,
    /// The path (and query) of an HTTP/1 or HTTP/2 request.
    HttpPath,
    /// The statement text of a MySQL or PostgreSQL query.
    SqlStatement,
}

/// Whether `text` shows credential context (see the module docs), for a
/// field that holds no bare name: any credential word is context.
pub fn has_credential_context(text: &str) -> bool {
    context(text, false, Slot::None)
}

/// Credential context of a SQL statement: a short credential name also
/// counts as a column in a list or assignment (`users(pwd)`,
/// `SET a = 1, pass = $1`) or next to an operator; a credential word that
/// is a column of an allowlisted `SELECT` ([`select_list`]) is not.
pub fn has_sql_credential_context(sql: &str) -> bool {
    context(sql, true, Slot::Sql)
}

/// [`has_sql_credential_context`] counting bare names too: a statement
/// whose bound values cannot be shown to be unrelated to a credential.
pub fn has_any_sql_credential_context(sql: &str) -> bool {
    context(sql, true, Slot::None)
}

/// Which bare names a check allows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// None: every credential word is context.
    None,
    /// The last segment of an HTTP request path part
    /// ([`path_last_segment`]), its bounds taken on the path part as
    /// captured.
    Path(Option<(usize, usize)>),
    /// A column of an allowlisted `SELECT` ([`select_list`]).
    Sql,
}

fn context(text: &str, sql: bool, slot: Slot) -> bool {
    let (v, alt) = normalize_views(text);
    context_in_views(text, &v, alt.as_ref(), sql, slot, false)
}

/// [`context_in`] of either normalised view of `text` ([`normalize_views`]).
fn context_in_views(
    text: &str,
    v: &View,
    alt: Option<&View>,
    sql: bool,
    slot: Slot,
    strict: bool,
) -> bool {
    context_in(text, v, sql, slot, strict)
        || alt.is_some_and(|a| context_in(text, a, sql, slot, strict))
}

/// [`context`] of `text` whose normalised view is `v`. `strict` for the
/// rest of a field known to hold a credential (what is left once its
/// certain clauses are removed, [`builtin_full`]): there a word with a
/// short name as a segment is context wherever it is (`pin-code 7392` in
/// a note beside a masked password), not only used as a name.
fn context_in(text: &str, v: &View, sql: bool, slot: Slot, strict: bool) -> bool {
    let n = &v.text;
    let b = n.as_bytes();
    if !v.hint {
        return has_userinfo(b);
    }
    // The view as decoded, case kept (same offsets): where a token's
    // case boundaries are read.
    let cased = v.cased.as_deref().unwrap_or(n).as_bytes();
    // Names in a position that delimits the whole name, read whole.
    let named = v.cased.as_deref().or(v.split.as_deref()).unwrap_or(n);
    if credential_name_in_a_name_position(named.as_bytes(), n) {
        return true;
    }
    // A NUL dropped from the view may have joined a name to its value.
    let bare = (slot != Slot::None && !v.nul).then(|| BareShapes::new(text, v, slot));
    let is_bare = |w: &str, start, end| bare.as_ref().is_some_and(|s| s.bare(w, start, end));
    // A short name, whole or as a segment of the token ([`has_name_segment`],
    // if `segments`: `new_pwd`, `newPwd`; `cased` is the view's text with case
    // kept), used as a name: followed by `=` or `:` ...; in SQL also a
    // column in a list or assignment, or next to an operator.
    let short_name = |b: &[u8], cased: &[u8], segments: bool, w: &str, start, end| {
        (NAMES.contains(&w) || segments && has_name_segment(&cased[start..end]))
            && !is_bare(w, start, end)
            && (used_as_name(b, start, end)
                || sql && (sql_column(b, start, end) || sql_operand(b, start, end)))
    };
    // Segments are read only where `-` and `.` end a token: read as `_`
    // they would join a short name to the word after it, and a host and
    // port would read as a name (`auth-service:8080`, `pin.example:80`).
    let segments = v.split.is_none();
    let mut prev_identified = false;
    for (w, start, end) in words(n) {
        if prev_identified && matches!(w, "by" | "with" | "via" | "as" | "using") {
            return true;
        }
        prev_identified = w == "identified";
        if is_bare(w, start, end) {
            continue;
        }
        if w != "identified" && strong_word(w) || short_name(b, cased, segments, w, start, end) {
            return true;
        }
        if strict && !NAMES.contains(&w) && has_name_segment(&cased[start..end]) {
            return true;
        }
    }
    // Short names again with `-` and `.` as boundaries, as in the field:
    // read as `_` they join a name to its neighbour (`users.pwd`, `pwd-0`).
    // In SQL, also on the statement as captured, whose operators decoding
    // may have turned into spaces (`pin+1`). Segments count in both.
    let raw_sql = sql.then(|| (text.to_ascii_lowercase(), text.as_bytes()));
    let views = [v.split.as_ref().map(|s| (s, cased))]
        .into_iter()
        .chain([raw_sql.as_ref().map(|(s, raw)| (s, *raw))]);
    for (view, cased) in views.flatten() {
        if words(view)
            .any(|(w, start, end)| short_name(view.as_bytes(), cased, true, w, start, end))
        {
            return true;
        }
    }
    has_userinfo(b)
}

/// Whether a name in a position that delimits it whole is a credential
/// name ([`decoded_name_is_credential`]): a JSON member name (`"…":`), a
/// query or form parameter name (`…=` at the start or after `?`, `&`, `;`
/// or whitespace: `a=1;pin-code=…`, a name on its own line), a
/// form or HTML field name (`name="…"`, `name='…'`, `name=…`), or an XML
/// element name (`<…>`, `</…>`, `<… attr>`; `:` of a namespace and `-`,
/// `.` included). Read whole, so `-` and `.` split its segments as `_`
/// does (`"pin-code":`, `name="user.newPwd"`, `<ns:newPwd>`,
/// `<user.pin>`), which free text cannot do (`auth-service:8080`).
/// `named` is the view as decoded (case kept where it had any), `lower`
/// the normalised view, with the same offsets. Linear: each byte is read by
/// at most one name of each position (form names stop at the next `&`,
/// `?`, `;` or whitespace, XML names at the next `<`, an unquoted field
/// name at the next `=`).
fn credential_name_in_a_name_position(named: &[u8], lower: &str) -> bool {
    let l = lower.as_bytes();
    let hit = |s: usize, e: usize| {
        e > s
            && lower.is_char_boundary(s)
            && lower.is_char_boundary(e)
            && has_hint(&lower[s..e])
            && decoded_name_is_credential(&named[s..e])
    };
    // JSON member names: a quote followed by `:` closes a name that starts
    // after the quote before it. No string parity: the view has decoded
    // `\"` to `"` (`{"a":"x\"y","pin-code":…}`), so quotes cannot be
    // paired as [`json_members`] pairs them on the raw text. One pass.
    let mut prev_quote: Option<usize> = None;
    for (q, _) in l.iter().enumerate().filter(|&(_, &c)| c == b'"') {
        if let Some(p) = prev_quote
            && l.get(skip_ws(l, q + 1)) == Some(&b':')
            && hit(p + 1, q)
        {
            return true;
        }
        prev_quote = Some(q);
    }
    let mut i = 0;
    while i < l.len() {
        let c = l[i];
        // A form or query parameter name, also after `;` or whitespace
        // (`a=1;pin-code=…`, a name on its own line).
        if i == 0 || matches!(l[i - 1], b'?' | b'&' | b';') || l[i - 1].is_ascii_whitespace() {
            let e = l[i..]
                .iter()
                .position(|&c| {
                    matches!(c, b'=' | b'&' | b'#' | b'?' | b'/' | b';') || c.is_ascii_whitespace()
                })
                .map_or(l.len(), |o| i + o);
            if l.get(e) == Some(&b'=') && hit(i, e) {
                return true;
            }
        }
        match c {
            b'<' => {
                let s = i + 1 + usize::from(l.get(i + 1) == Some(&b'/'));
                let e = l[s..]
                    .iter()
                    .position(|&c| {
                        !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b':' | b'-' | b'.'))
                    })
                    .map_or(l.len(), |o| s + o);
                let closed = l
                    .get(e)
                    .is_some_and(|&c| c == b'>' || c == b'/' || c.is_ascii_whitespace());
                if closed && hit(s, e) {
                    return true;
                }
            }
            b'n' if l[i..].starts_with(b"name=")
                && (i == 0 || !l[i - 1].is_ascii_alphanumeric()) =>
            {
                let v = i + 5;
                let (s, e) = match l.get(v) {
                    Some(&q @ (b'"' | b'\'')) => {
                        let e = l[v + 1..]
                            .iter()
                            .position(|&c| c == q)
                            .map_or(l.len(), |o| v + 1 + o);
                        (v + 1, e)
                    }
                    _ => {
                        let e = l[v..]
                            .iter()
                            .position(|&c| {
                                matches!(c, b';' | b'&' | b'=' | b'<' | b'>' | b'"' | b'\'')
                                    || c.is_ascii_whitespace()
                            })
                            .map_or(l.len(), |o| v + o);
                        (v, e)
                    }
                };
                if hit(s, e) {
                    return true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

// ── Bare names ──────────────────────────────────────────────────────────

/// The allowlisted positions of a field where a credential word is a bare
/// name, for the field's kind ([`Slot`]); anything else is context (fail
/// closed). The bounds are token bounds from [`words`].
struct BareShapes {
    /// The last segment of a raw path part made only of plain name
    /// segments ([`path_last_segment`]).
    path: Option<(usize, usize)>,
    /// The select list of an allowlisted `SELECT` ([`select_list`]).
    select: Option<(usize, usize)>,
}

impl BareShapes {
    fn new(raw: &str, v: &View, slot: Slot) -> Self {
        // The SQL grammar reads the raw statement, case folded: only with no
        // comment marker, nothing the normalised view decoded (so its
        // offsets are the raw ones) and no string or identifier syntax that
        // differs by dialect or setting.
        let plain_sql = !v.comment && !v.decoded && !raw.contains(['\\', '"', '`']);
        BareShapes {
            path: match slot {
                Slot::Path(path) => path,
                _ => None,
            },
            select: (slot == Slot::Sql && plain_sql && sql_verb(raw) == Some("SELECT"))
                .then(|| select_list(raw.to_ascii_lowercase().trim_end().as_bytes()))
                .flatten(),
        }
    }

    /// Whether the word `w` at `start..end` is a bare credential name.
    fn bare(&self, w: &str, start: usize, end: usize) -> bool {
        // A digit: may be a value (`token9f8e`), whatever the position.
        if w.bytes().any(|c| c.is_ascii_digit()) {
            return false;
        }
        // A column name: SQL syntax keeps a value out of it.
        if self.select.is_some_and(|(s, e)| s <= start && end <= e) {
            return true;
        }
        ends_in_a_credential_part(w) && self.path == Some((start, end))
    }
}

/// A word spelled as a credential name: it ends in a whole credential
/// part, plural allowed (`token`, `access_token`, `x_api_key`, `passwords`,
/// `tls_key_file_pass`), not with more after it (`token_abcdef`,
/// `canary_secret_value`) or glued to it (`hunterpassword`).
fn ends_in_a_credential_part(w: &str) -> bool {
    let ends_in = |w: &str| {
        PARTS.iter().chain(&["pass", "auth"]).any(|p| {
            w.strip_suffix(p)
                .is_some_and(|head| head.is_empty() || head.ends_with('_'))
        })
    };
    ends_in(w) || w.strip_suffix('s').is_some_and(ends_in)
}

/// On the RAW path part (the text before any `?` or `#`, cut off by
/// [`decide_as`]), printable ASCII only (no space, no other whitespace,
/// no byte past 0x7E): a path `/seg/.../seg` whose every segment is a
/// plain name (`A`-`Z`, `a`-`z`, `_`, `.`, `-`: no digit, `%`, `+`, `?`
/// or `#`, nothing value-like): the bounds of the last segment. Nothing in
/// it is decoded, so the bounds are those of its word in the normalised
/// view. `/oauth/token` qualifies; `/reset/abc123/token`, `/v1/token`,
/// `/reset/token/++++`, `/token/` and `/oauth\u{a0}/token` do not.
fn path_last_segment(b: &[u8]) -> Option<(usize, usize)> {
    let p = b.strip_prefix(b"/")?;
    let mut start = 1;
    let mut last = None;
    for seg in p.split(|&c| c == b'/') {
        let plain = |c: &u8| c.is_ascii_alphabetic() || matches!(c, b'_' | b'.' | b'-');
        if seg.is_empty() || !seg.iter().all(plain) {
            return None;
        }
        last = Some((start, start + seg.len()));
        start += seg.len() + 1;
    }
    last
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tok {
    Word,
    Str,
    Param,
    Op,
    Comma,
    Star,
    Semi,
}

/// The tokens of a raw lowercased statement for [`select_list`], or None at
/// anything else: a double quote, backtick or backslash (identifier or
/// string syntax that differs by dialect or mode), a string literal with a
/// doubled quote, `(`, `:`, `.`, `+` ... A string literal is `'...'`.
fn sql_tokens(b: &[u8]) -> Option<Vec<(Tok, usize, usize)>> {
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let (tok, len) = match c {
            _ if word(c) => (Tok::Word, b[i..].iter().take_while(|&&c| word(c)).count()),
            b'\'' => {
                let close = b[i + 1..].iter().position(|&c| c == b'\'')?;
                if b.get(i + close + 2) == Some(&b'\'') {
                    return None;
                }
                (Tok::Str, close + 2)
            }
            b'$' => {
                let d = b[i + 1..].iter().take_while(|c| c.is_ascii_digit()).count();
                if d == 0 || b.get(i + 1 + d).is_some_and(|&c| word(c) || c == b'$') {
                    return None;
                }
                (Tok::Param, 1 + d)
            }
            b'?' => (Tok::Param, 1),
            b',' => (Tok::Comma, 1),
            b'*' => (Tok::Star, 1),
            b';' => (Tok::Semi, 1),
            b'=' => (Tok::Op, 1),
            b'<' | b'>' | b'!' => {
                let two = matches!(&b[i..b.len().min(i + 2)], b"<=" | b">=" | b"<>" | b"!=");
                if c == b'!' && !two {
                    return None;
                }
                (Tok::Op, 1 + two as usize)
            }
            _ => return None,
        };
        out.push((tok, i, i + len));
        i += len;
    }
    Some(out)
}

/// The projection of an allowlisted `SELECT`, as a byte range of the raw
/// lowercased statement `b` (no comment marker, nothing decoded), or None.
/// The allowlist:
///
/// `SELECT item [, item]* FROM table [WHERE pred [AND|OR pred]*]
/// [ORDER BY col [ASC|DESC] [, ...]] [LIMIT n [OFFSET n]] [;]`
///
/// - an item is `*` or a plain identifier `[a-z_][a-z0-9_]*` that is not
///   a value keyword ([`VALUE_WORDS`]: `TRUE`, `NULL`, `CURRENT_USER`, ...):
///   no qualifier, literal, number (`0x68756e74657232`), function or alias;
/// - the table is a plain identifier, and from it to the end no credential
///   word appears in any form: none of the substrings [`HINTS`] (so not
///   `pwd LIKE 'x'`, `WHERE password = ...`, `session IN ...`), whatever
///   the boundaries;
/// - a pred is `col op operand`, `col LIKE operand` or `col IS [NOT] NULL`,
///   its col an identifier that is not the table (whole-row) and its
///   operand a number ([`number`]), a parameter or a string literal without `(`, `)`,
///   `,`, `{` or `}` (no row or array value).
///
/// Credential words may appear only as projection items. Nothing here can
/// put a value in a column's place: no other query, `VALUES`, row
/// constructor, cast, join or alias.
/// Niladic SQL value keywords: these are SQL value literals, not columns
/// (`SELECT password, TRUE FROM users` projects `1` in MySQL), so none is
/// a plain identifier in [`select_list`].
const VALUE_WORDS: &[&[u8]] = &[
    b"true",
    b"false",
    b"null",
    b"unknown",
    b"default",
    b"current_user",
    b"current_role",
    b"session_user",
    b"user",
    b"system_user",
    b"current_date",
    b"current_time",
    b"current_timestamp",
    b"localtime",
    b"localtimestamp",
    b"current_catalog",
    b"current_schema",
    b"utc_date",
    b"utc_time",
    b"utc_timestamp",
];

/// A decimal number: it starts and ends with a digit, and each `_` sits
/// between two digits (`1_000`, not `_123456`, `__` or `1_`).
fn number(w: &[u8]) -> bool {
    w.first().is_some_and(u8::is_ascii_digit)
        && w.last().is_some_and(u8::is_ascii_digit)
        && w.iter().all(|c| c.is_ascii_digit() || *c == b'_')
        && !w.windows(2).any(|p| p == b"__")
}

fn select_list(b: &[u8]) -> Option<(usize, usize)> {
    let toks = sql_tokens(b)?;
    let text = |k: usize| &b[toks[k].1..toks[k].2];
    let is_word =
        |k: usize, w: &[u8]| toks.get(k).is_some_and(|t| t.0 == Tok::Word) && text(k) == w;
    let kind = |k: usize| toks.get(k).map(|t| t.0);
    if !is_word(0, b"select") {
        return None;
    }
    // A plain identifier: a word not starting with a digit and not a
    // value keyword.
    let ident = |k: usize| {
        kind(k) == Some(Tok::Word)
            && !text(k)[0].is_ascii_digit()
            && !VALUE_WORDS.contains(&text(k))
    };
    let mut k = 1;
    loop {
        if !(ident(k) || kind(k) == Some(Tok::Star)) || is_word(k, b"from") {
            return None;
        }
        k += 1;
        match kind(k) {
            Some(Tok::Comma) => k += 1,
            _ if is_word(k, b"from") => break,
            _ => return None,
        }
    }
    let list = (toks[0].2, toks[k].1);
    k += 1;
    if !ident(k) || has_hint(std::str::from_utf8(&b[toks[k].1..]).ok()?) {
        return None;
    }
    let table = text(k);
    k += 1;
    // A column, not the table's row (`users`, or `users` of `public.users`).
    let column = |k: usize| {
        if !ident(k) {
            return false;
        }
        let c = text(k);
        table != c && !(table.ends_with(c) && table[table.len() - c.len() - 1] == b'_')
    };
    let operand = |k: usize| match kind(k) {
        Some(Tok::Param) => true,
        Some(Tok::Str) => !text(k).iter().any(|c| b"(),{}".contains(c)),
        Some(Tok::Word) => number(text(k)),
        _ => false,
    };
    if is_word(k, b"where") {
        loop {
            if !column(k + 1) {
                return None;
            }
            k += 2;
            if is_word(k, b"is") {
                k += 1;
                if is_word(k, b"not") {
                    k += 1;
                }
                if !is_word(k, b"null") {
                    return None;
                }
                k += 1;
            } else if (kind(k) == Some(Tok::Op) || is_word(k, b"like")) && operand(k + 1) {
                k += 2;
            } else {
                return None;
            }
            if !(is_word(k, b"and") || is_word(k, b"or")) {
                break;
            }
        }
    }
    if is_word(k, b"order") {
        if !is_word(k + 1, b"by") {
            return None;
        }
        k += 1;
        loop {
            if !column(k + 1) {
                return None;
            }
            k += 2;
            if is_word(k, b"asc") || is_word(k, b"desc") {
                k += 1;
            }
            if kind(k) != Some(Tok::Comma) {
                break;
            }
        }
    }
    let count = |k: usize| {
        matches!(kind(k), Some(Tok::Param))
            || kind(k) == Some(Tok::Word) && text(k).iter().all(u8::is_ascii_digit)
    };
    if is_word(k, b"limit") {
        if !count(k + 1) {
            return None;
        }
        k += 2;
        if is_word(k, b"offset") {
            if !count(k + 1) {
                return None;
            }
            k += 2;
        }
    }
    if kind(k) == Some(Tok::Semi) {
        k += 1;
    }
    (k == toks.len()).then_some(list)
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
    /// Keep `text[..at]` with these spans masked, and replace everything
    /// from `at` (a query or fragment beside a bare path) by
    /// [`QUERY_WITHHELD`].
    Cut(usize, Vec<(usize, usize)>),
}

impl Decision {
    /// The protected field, or None when it is kept as is.
    pub fn apply(&self, text: &str) -> Option<String> {
        match self {
            Decision::Keep => None,
            Decision::Withhold => Some(FIELD_WITHHELD.to_string()),
            Decision::Mask(spans) => Some(replace_spans(text, spans)),
            Decision::Cut(at, spans) => Some(replace_spans(&text[..*at], spans) + QUERY_WITHHELD),
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
    decide_as(rules, text, builtin, FieldKind::Other)
}

/// [`decide`] for a field of a known kind: an HTTP request path or a SQL
/// statement may hold a bare name ([`FieldKind`]). An HTTP path with a
/// query or fragment whose path part (before the first `?` or `#`) has
/// credential context is decided on its path part alone: withheld unless
/// that part is bare, else the path part exported followed by
/// [`QUERY_WITHHELD`], no byte of the query or fragment kept (withheld too
/// when one of the user's patterns matches across the cut). A path part
/// with no credential word leaves the whole field to the usual rules
/// (keyed parameters masked).
pub fn decide_as(rules: &CredentialRules, text: &str, builtin: bool, kind: FieldKind) -> Decision {
    if kind == FieldKind::HttpPath
        && builtin
        && rules.builtin == Builtin::Full
        && let Some(at) = text.find(['?', '#'])
        && has_credential_context(&text[..at])
    {
        // The user's patterns also run on the whole field: a match across
        // the cut (`acme_token?`) cannot be masked in the path part.
        if let Some(user) = &rules.user
            && user_spans(user, text).is_none_or(|f| f.iter().any(|&(s, e)| s < at && at < e))
        {
            count_user(1);
            return Decision::Withhold;
        }
        return match decide_as(rules, &text[..at], builtin, kind) {
            Decision::Keep => Decision::Cut(at, Vec::new()),
            Decision::Mask(spans) => Decision::Cut(at, spans),
            Decision::Withhold | Decision::Cut(..) => Decision::Withhold,
        };
    }
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
            Builtin::Full => builtin_full(text, kind),
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
/// not case-folded) that is not one of the raw matches collected for
/// masking, of the same pattern, at the same position, with the same text:
/// only then is it certainly masked.
fn user_spans(
    (set, each): &(regex::RegexSet, Vec<regex::Regex>),
    text: &str,
) -> Option<Vec<(usize, usize)>> {
    // (pattern, start, end) of every raw match collected for masking, in
    // ascending order (patterns in order, each one's matches left to
    // right), so a decoded match is looked up by binary search: at most
    // MAX_SPANS of each, and no scan of one list per item of the other.
    let mut found = Vec::new();
    for i in set.matches(text).iter() {
        for m in each[i].find_iter(text).filter(|m| !m.is_empty()) {
            if found.len() == MAX_SPANS {
                return None;
            }
            found.push((i, m.start(), m.end()));
        }
    }
    if let Some(decoded) = decode(text) {
        for i in set.matches(&decoded).iter() {
            for m in each[i].find_iter(&decoded).filter(|m| !m.is_empty()) {
                let collected = found.binary_search(&(i, m.start(), m.end())).is_ok();
                if !collected || text.get(m.range()) != Some(m.as_str()) {
                    return None;
                }
            }
        }
    }
    Some(found.into_iter().map(|(_, s, e)| (s, e)).collect())
}

/// Every built-in rule: the values to mask where certain, or None (the
/// field withheld) when any context is left.
fn builtin_full(text: &str, kind: FieldKind) -> Option<Vec<(usize, usize)>> {
    let slot = match kind {
        FieldKind::Other => Slot::None,
        FieldKind::HttpPath => Slot::Path(path_last_segment(text.as_bytes())),
        FieldKind::SqlStatement => Slot::Sql,
    };
    // Full masks all names_only masks, by construction: with no context
    // its certain clauses are still masked. Skipped only where no name
    // can pass [`plain_credential_name`], which needs a hint in the name
    // as decoded: none in the view, and nothing decoded (then no part of
    // the text decodes either, since every decoding step acts on any
    // escape it finds and leaves a malformed one in place, and the view
    // keeps every hint's letters).
    let (v, alt) = normalize_views(text);
    if !context_in_views(text, &v, alt.as_ref(), false, slot, false) {
        let names = v.hint || v.decoded;
        return Some(if names {
            certain_clauses(text).0
        } else {
            Vec::new()
        });
    }
    let (mask, delete) = certain_clauses(text);
    let residual = remove(text, &delete);
    // The rest, read strictly: any credential name left in a name position
    // (an array, object or cut value, `{"pin-code":["7392"]}`), and any
    // word with a short name as a segment (`"note":"pin-code: 7392"`),
    // withholds the field.
    let (rv, ralt) = normalize_views(&residual);
    (!context_in_views(&residual, &rv, ralt.as_ref(), false, slot, true)).then_some(mask)
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
    normalize_flagged(text).text
}

/// The normalised view of a field.
struct View {
    text: String,
    /// The decoded text before case folding, when it has an upper-case
    /// ASCII letter: same offsets as `text` (case folding, blanking and
    /// reading `-` and `.` as `_` keep every byte's place), for reading
    /// case boundaries ([`has_name_segment`]).
    cased: Option<String>,
    /// The text holds a hint ([`has_hint`]).
    hint: bool,
    /// Decoding changed the text (escapes, entities, percent-encoding,
    /// `+` or NUL bytes).
    decoded: bool,
    /// Decoding dropped a NUL byte.
    nul: bool,
    /// A SQL comment marker was blanked.
    comment: bool,
    /// The view before `-` and `.` were read as `_`, when there were any.
    split: Option<String>,
}

fn normalize_flagged(text: &str) -> View {
    normalize_as(text, Reading::Json).0
}

/// The normalised views of a field: the JSON reading, and the separator
/// reading when a backslash before a letter makes them differ
/// ([`Reading`]). Credential context in either counts.
fn normalize_views(text: &str) -> (View, Option<View>) {
    let (v, letter) = normalize_as(text, Reading::Json);
    (v, letter.then(|| normalize_as(text, Reading::Separator).0))
}

/// [`normalize_flagged`] under `reading`, and whether a backslash before a
/// letter was read.
fn normalize_as(text: &str, reading: Reading) -> (View, bool) {
    let (d, nul, letter) = decode_nul(text, reading);
    let decoded = d.is_some();
    let mut s = d.unwrap_or_else(|| text.to_string());
    let cased = s.bytes().any(|c| c.is_ascii_uppercase()).then(|| s.clone());
    s.make_ascii_lowercase();
    let mut comment = false;
    for delim in ["/*!", "/*", "*/", "--", "#"] {
        if s.contains(delim) {
            comment = true;
            s = s.replace(delim, &" ".repeat(delim.len()));
        }
    }
    let hint = has_hint(&s);
    let mut split = None;
    if s.contains(['-', '.']) {
        let joined = s.replace(['-', '.'], "_");
        split = Some(std::mem::replace(&mut s, joined));
    }
    let v = View {
        text: s,
        cased,
        hint,
        decoded,
        nul,
        comment,
        split,
    };
    (v, letter)
}

/// The decoded view: NUL bytes dropped, then up to three rounds of JSON
/// escapes, HTML references and percent-decoding. None when nothing
/// changes.
fn decode(text: &str) -> Option<String> {
    decode_nul(text, Reading::Json).0
}

/// How [`json_unescape_as`] reads a backslash before an ASCII letter
/// (other than a `\u` with four hex digits).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reading {
    /// As JSON: `\b`, `\f`, `\n`, `\r`, `\t` a control character (read as
    /// a space), any other letter kept without its backslash.
    Json,
    /// As a separator, the letter kept (`C:\token` is `C: token`,
    /// `dir\key` is `dir key`): the backslash of a Windows path, prose or
    /// LaTeX, which is not an escape there.
    Separator,
}

/// [`decode`] under `reading`, whether a NUL byte was dropped, and whether
/// a backslash before a letter was read. The two readings differ only
/// there, so if no round of the JSON reading reads one, the separator
/// reading decodes the same text.
fn decode_nul(text: &str, reading: Reading) -> (Option<String>, bool, bool) {
    let mut s: Option<String> = None;
    let mut nul = false;
    let mut letter = false;
    for _ in 0..3 {
        let mut changed = false;
        let cur = s.as_deref().unwrap_or(text);
        if cur.contains('\0') {
            nul = true;
            let mut d = cur.to_string();
            d.retain(|c| c != '\0');
            s = Some(d);
            changed = true;
        }
        let (d, l) = json_unescape_as(s.as_deref().unwrap_or(text), reading);
        letter |= l;
        if let Some(d) = d {
            s = Some(d);
            changed = true;
        }
        for step in [html_unescape, percent_decode] {
            if let Some(d) = step(s.as_deref().unwrap_or(text)) {
                s = Some(d);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    if let Some(d) = s.as_mut()
        && d.contains('\0')
    {
        nul = true;
        d.retain(|c| c != '\0');
    }
    (s, nul, letter)
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
#[cfg(test)]
fn json_unescape(text: &str) -> Option<String> {
    json_unescape_as(text, Reading::Json).0
}

/// [`json_unescape`] with a backslash before a letter read as `reading`
/// says ([`Reading`]), and whether one was read.
fn json_unescape_as(text: &str, reading: Reading) -> (Option<String>, bool) {
    if !text.contains('\\') {
        return (None, false);
    }
    let mut letter = false;
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('u') => {
                // Four hex digits, or the `\u` is kept as it is and nothing
                // after it is consumed (`\u","password"` must keep its name).
                let hex: String = chars.clone().take(4).collect();
                if hex.len() != 4 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                    out.push_str("\\u");
                    continue;
                }
                chars.nth(3);
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
            Some(c) if c.is_ascii_alphabetic() => {
                letter = true;
                match (reading, c) {
                    (Reading::Separator, _) => {
                        out.push(' ');
                        out.push(c);
                    }
                    (Reading::Json, 'b' | 'f' | 'n' | 'r' | 't') => out.push(' '),
                    (Reading::Json, _) => out.push(c),
                }
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    ((out != text).then_some(out), letter)
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

/// In SQL, an operand: next to an operator (`pwd - 0`, `1 + pin`, `pwd||x`).
fn sql_operand(b: &[u8], start: usize, end: usize) -> bool {
    let op = |c: Option<u8>| c.is_some_and(|c| b"=<>!+-*/%|&^~".contains(&c));
    op(before(b, start)) || op(after(b, end))
}

/// `user:password@host` anywhere: a `//` authority whose userinfo holds a
/// `:` ([`authority_userinfo`], host optional), or a `:` (not that of
/// `scheme://` or `mailto:`) then `@` and a host character, with no
/// whitespace, quote or bracket between ([`schemeless_userinfo`]).
fn has_userinfo(b: &[u8]) -> bool {
    authority_userinfo(b) || schemeless_userinfo(b)
}

/// A `//` authority (RFC 3986) whose userinfo, before its last `@`, holds a
/// `:`, whatever follows the `@` (the host may be empty): the authority
/// runs to `/`, `?`, `#`, whitespace, a quote or `<>\`, so `,` and `;` in
/// the password are kept.
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
        // No host needed: `postgres://u:pw@/db` (a Unix socket) has a
        // password too, and [`authorities`] masks it.
        if let Some(at) = b[a..e].iter().rposition(|&c| c == b'@').map(|p| a + p)
            && b[a..at].contains(&b':')
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
    // The name as captured: its case boundaries are read (`newPwd`).
    !n.is_empty()
        && n.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'[' | b']'))
        && is_credential_name(raw)
}

/// `name=value` at the start or after `?` / `&`; the value runs to `&` or
/// the end, without whitespace (a value with a space is not a form value:
/// `password=correct horse` in prose).
///
/// Linear in the field (security scan F1): every byte is read by at most
/// one name scan and one value scan. A name scan stops at the next `?` or
/// `&`, where the next parameter starts. The value scan runs to the first
/// `&` or whitespace and is remembered: a later parameter whose value
/// starts before that stop (`?pwd=?pwd=…`) reaches the same stop, so its
/// value is not read again. A masked value covers every parameter that
/// starts inside it, and those would only push spans inside the ones
/// already pushed (same end), so the scan resumes at its end.
fn form_params(b: &[u8], text: &str, mask: &mut Spans, delete: &mut Spans) {
    // The first `&` or whitespace at or after the start of the last value
    // scanned (b.len() when none).
    let mut stop: Option<usize> = None;
    let mut p = 0;
    while p < b.len() {
        if p > 0 && !matches!(b[p - 1], b'?' | b'&') {
            p += 1;
            continue;
        }
        let Some(eq) = b[p..]
            .iter()
            .position(|&c| matches!(c, b'=' | b'&' | b'#' | b'?' | b'/') || c.is_ascii_whitespace())
            .map(|o| p + o)
            .filter(|&e| e > p && b[e] == b'=')
        else {
            p += 1;
            continue;
        };
        if !plain_credential_name(&text[p..eq]) {
            p += 1;
            continue;
        }
        let from = eq + 1;
        let s = match stop {
            Some(s) if from <= s => s,
            _ => b[from..]
                .iter()
                .position(|&c| c == b'&' || c.is_ascii_whitespace())
                .map_or(b.len(), |o| from + o),
        };
        stop = Some(s);
        if s < b.len() && b[s] != b'&' {
            // Whitespace before the value's end: not a form value.
            p += 1;
            continue;
        }
        mask.push((from, s));
        delete.push((p, s));
        p = s.max(p + 1);
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

    /// `s` protected as a field of `kind`.
    fn pk(s: &str, kind: FieldKind) -> String {
        let r = super::super::credential_rules::credential_rules();
        decide_as(&r, s, true, kind)
            .apply(s)
            .unwrap_or_else(|| s.to_string())
    }

    const KINDS: [FieldKind; 3] = [
        FieldKind::Other,
        FieldKind::HttpPath,
        FieldKind::SqlStatement,
    ];

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
        // R6 N1: a decoded match that is a raw match of the pattern, but
        // not one find_iter collected (it overlaps an earlier one).
        let overlap = rules(&[r"foo\+acme_|acme_[a-z0-9]{8}"], Builtin::Full);
        let out = protect_text_with(&overlap, "foo+acme_abcd1234").unwrap();
        assert!(!out.contains("abcd1234"), "{out}");
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
    /// stays readable; a credential parameter's name is withheld, alone
    /// (`CONFIG GET masterauth`, or a value that reads so) or with its
    /// value next to it, masked or not.
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
            "masterauth",
            "requirepass",
            "tls-key-file-pass",
            "requirepass <REDACTED>",
            "requirepass, <REDACTED>",
            "requirepass masterauth",
            "requirepass hunter2",
            "requirepass\nhunter2",
            "requirepass%20hunter2",
            "require\0pass",
            "requirepass9",
        ] {
            assert_eq!(
                protect_text(text).as_deref(),
                Some(FIELD_WITHHELD),
                "{text:?}"
            );
        }
    }

    /// The bare names the narrowed rule exports (USER-GUIDE 5.3): an HTTP
    /// request path's last segment and a projection item of an allowlisted
    /// SELECT statement, each only in a field of that kind.
    #[test]
    fn bare_names_are_exported() {
        for text in [
            "/oauth/token",
            "/users/me/password",
            "/account/reset-password",
            // A named limit (USER-GUIDE 5.3): a letters-only segment
            // before the word cannot be told from a route word.
            "/reset/abcdef/token",
        ] {
            assert_eq!(pk(text, FieldKind::HttpPath), text);
            for kind in [FieldKind::Other, FieldKind::SqlStatement] {
                assert_eq!(pk(text, kind), FIELD_WITHHELD, "{text} {kind:?}");
            }
            assert!(has_credential_context(text), "{text}");
        }
        for text in [
            "SELECT password, email FROM users",
            "SELECT password FROM users WHERE id = 1",
            "SELECT password FROM users WHERE id = 1_000",
            "SELECT password, email FROM users;",
            "select id, password_hash, email from users where id = $1",
            "SELECT pwd, email FROM users",
            "SELECT id, password_hash FROM users",
            "SELECT password FROM users WHERE email = 'a@b.c' AND id > 5",
            "SELECT password FROM users WHERE deleted_at IS NOT NULL",
            "SELECT password FROM users WHERE name LIKE ? ORDER BY id DESC, name LIMIT 10 OFFSET $2",
        ] {
            assert!(!has_sql_credential_context(text), "{text}");
            assert_eq!(pk(text, FieldKind::SqlStatement), text);
            // In any other field (a Redis value, a body), withheld
            // (`pwd` is a credential part, F1 review round 2).
            for kind in [FieldKind::Other, FieldKind::HttpPath] {
                assert_eq!(pk(text, kind), FIELD_WITHHELD, "{text} {kind:?}");
            }
            assert!(has_any_sql_credential_context(text), "{text}");
        }
        // DNS names: no bare name.
        assert!(has_credential_context("db.password"));
    }

    /// A query or fragment beside a bare path is never exported, whatever
    /// it holds: the path part is followed by [`QUERY_WITHHELD`]. Every
    /// query input Codex raised from round 6 on, and the earlier ones,
    /// included. In any other field kind, withheld as before.
    #[test]
    fn query_beside_a_bare_path_is_cut() {
        for text in [
            "/oauth/token?scope=read&state=xyz",
            "/oauth/token?scope=a%20b",
            "/oauth/token?client_secret=x",
            "/oauth/token?client_secret=abc&x=1",
            "/oauth/token?x=1&password=a&y=2",
            "/oauth/token#",
            "/token?abc123",
            "/token?&abc123",
            "/oauth/token?",
            "/oauth/token?x=1&",
            "/oauth/token?=x",
            "/token?x=1& ",
            "/oauth/token?client_secret=x&",
            "/oauth/token?client_secret=x&&y=1",
            "/oauth/token?client_secret=x&abc123",
            "/oauth/token?scope=read\u{a0}hunter2",
            "/oauth/token?scope=read\u{2003}hunter2",
            "/oauth/token?scope=read\u{2028}hunter2",
            "/oauth/token?scope=read\thunter2",
            "/oauth/token?user.pwd=hunter2",
            "/oauth/token?user-pin=739204",
            "/reset/token?scope=read&++++&password=x",
            "/token?x=1&abc123",
            "/token?x=a b",
            "/reset/token?scope=read&abc123&password=x",
            "/oauth/token#abc123",
            "/reset/token?hunter2#x=y",
            "/reset/token?scope=read#hunter2",
            "/reset/token?hunter2;x=y",
            "/reset/token?scope=read;hunter2",
            "/reset/token?scope=read,hunter2",
            "/reset/token?aHVudGVyMg==",
            "/reset/token?aHVudGVyMg=",
            "/reset/token?scope=",
            "/reset/token?pwd%5Baccount%20name%5D=hunter2",
            "/reset/token?pwd%5B%2A%5D=hunter2",
            "/reset/token?%70wd=hunter2",
            "/reset/token?pwd.x=hunter2",
            "/oauth/token?keyword=hunter2",
            "/reset/token?next=%2Flogin%3Fpwd%5Baccount%20name%5D%3Dhunter2",
            "/reset/token?next=%252570wd%253Dhunter2",
            "/reset/token?next=x%25252570wd",
            "/reset/token?pwd%5B%5D=hunter2",
            "/reset/token?session%5Bid%5D=abc123",
            "/reset/token?pin%5B%5D=739204",
            "/reset/token?x=y/hunter2",
        ] {
            let at = text.find(['?', '#']).unwrap();
            let want = format!("{}{QUERY_WITHHELD}", &text[..at]);
            assert_eq!(pk(text, FieldKind::HttpPath), want, "{text}");
            // A second pass changes nothing.
            assert_eq!(pk(&want, FieldKind::HttpPath), want, "{want}");
            for kind in [FieldKind::Other, FieldKind::SqlStatement] {
                assert_eq!(pk(text, kind), FIELD_WITHHELD, "{text} {kind:?}");
            }
        }
        // A path part that is not bare: the whole field is withheld.
        for text in [
            "/reset/token/abc123?x=1",
            "/token/?abc123",
            "/reset/%74oken?x=1",
            "/oauth\u{a0}/token?x=1",
            "/v1/token#x",
        ] {
            assert_eq!(pk(text, FieldKind::HttpPath), FIELD_WITHHELD, "{text}");
        }
        // No credential word in the path part: keyed parameters are masked
        // as before, the rest of the query kept.
        assert_eq!(
            pk("/login?password=x&q=1", FieldKind::HttpPath),
            "/login?password=<REDACTED>&q=1"
        );
        // Codex round 13: a user pattern's match across the cut withholds.
        let r = rules(&["acme_[a-z]+[?#]"], Builtin::Full);
        for text in ["/oauth/acme_token?scope=read", "/oauth/acme_token#x"] {
            assert_eq!(
                decide_as(&r, text, true, FieldKind::HttpPath),
                Decision::Withhold,
                "{text}"
            );
        }
        // A match inside the path part is masked, the query still cut.
        let r = rules(&["acme_[a-z]+"], Builtin::Full);
        assert_eq!(
            decide_as(
                &r,
                "/oauth/acme_token?scope=read",
                true,
                FieldKind::HttpPath
            )
            .apply("/oauth/acme_token?scope=read")
            .as_deref(),
            Some("/oauth/<REDACTED>?<query withheld>")
        );
    }

    /// A credential word with anything that could be its value next to
    /// it, on either side, still withholds the field, encoded, commented,
    /// split by whitespace or UTF-16 included.
    #[test]
    fn values_next_to_a_name_withhold() {
        for text in [
            // The decision's examples.
            "/reset/token/abc123",
            "SELECT * FROM users WHERE password='x'",
            // Paths: every segment a plain name.
            "/reset/abc123/token",
            "/api/v1/token",
            "/oauth2/token",
            "/a//token",
            "/oauth/token/",
            // Codex round 3 #3: printable ASCII only.
            "/oauth\u{a0}/token",
            // Codex round 3 #1: `.` and `-` split a short name from its
            // neighbour; next to a SQL operator it is a value position.
            "SELECT password FROM users WHERE users.pwd = 'hunter2'",
            "SELECT password FROM users WHERE users.pin = 739204",
            "SELECT password FROM users WHERE pwd-0 = 123456",
            "SELECT password FROM users WHERE u.session = 'x'",
            "SELECT password FROM users WHERE t.cookie = 'x'",
            "SELECT password FROM users WHERE a.jwt = 'x'",
            "SELECT password FROM users WHERE a.otp = 'x'",
            "SELECT u.password FROM users",
            // Codex round 2 #1: decoding must not erase a segment or a
            // component (`+` is a space once decoded).
            "/reset/token/++++",
            "/reset/token/%20",
            "/reset/%74oken",
            "/reset/x+y/token",
            "/token/?abc123",
            "/oauth/token;abc123",
            "/oauth/token/abc/",
            "/oauth/token abc123",
            "/oauth/token9f8e7d",
            "/oauth/tokenabcdef",
            "/oauth/token.json",
            "/caf\u{e9}/token",
            "login with alice/hunter2 as username/password",
            "https://h/oauth/token",
            // No generic whole-field name: these may be values.
            "token",
            "requirepass",
            "swordfish_password",
            "access_tokens",
            "x-api-key",
            "token_abcdef",
            "canary-secret-value",
            "hunterpassword",
            // Encodings that reveal a value after a bare-looking name.
            "/oauth/token%2Fabc123",
            "/oauth/token%3Fabc123",
            "/oauth/token%20abc123",
            "/oauth/token%253Dabc123",
            "/oauth/token\\u002fabc123",
            "/oauth/token&#47;abc123",
            "requirepass%20hunter2",
            "password%00hunter",
            "password\\u0000hunter",
            "password&#0;hunter",
            "pass\0word\0hunter",
            // Whitespace, newlines and non-ASCII separators.
            "password hunter2",
            "password\nhunter2",
            "password\thunter",
            "password\u{a0}hunter",
            "password\u{2028}hunter",
            "hunter2 is my password",
            "your token expired",
            "token abc123",
            // UTF-16 (NUL bytes dropped): never a bare name.
            "p\0a\0s\0s\0w\0o\0r\0d\0",
            "p\0a\0s\0s\0w\0o\0r\0d\0 \0h\0u\0n\0t\0e\0r\0",
            "/\0t\0o\0k\0e\0n\0",
            "/\0t\0o\0k\0e\0n\0/\0a\0b\0c\0",
            // SQL: comparisons, literals, positional values.
            "SELECT email FROM users WHERE password = 'x'",
            "SELECT 'x' AS password FROM t",
            "SELECT 'x' password FROM t",
            "SELECT 'x', password FROM t",
            "SELECT password = 'x' FROM t",
            "SELECT password FROM users UNION SELECT 'hunter2'",
            "SELECT password FROM users WHERE id IN (SELECT 1)",
            "SELECT password FROM t, (VALUES ('x')) v",
            "SELECT DISTINCT password FROM users",
            "SELECT md5(password) FROM users",
            "SELECT password FROM users WHERE token = 'x'",
            "SELECT password FROM users u",
            "SELECT password FROM users JOIN t ON t.id = users.id",
            "SELECT password FROM users WHERE id = 1 OR 'x' = 'x'",
            "SELECT password FROM users WHERE id = -1 + 2",
            "select password, then type hunter2 from the list",
            "SELECT password",
            "SELECT password FROM",
            "SELECT password FROM users; SELECT 'hunter2'",
            "INSERT INTO users (email, password, name) VALUES ('a', 'x', 'b')",
            "INSERT INTO users (password) SELECT 'x'",
            "UPDATE users SET (email, password) = ('a', 'x')",
            "ALTER ROLE app PASSWORD 'x'",
            "ALTER USER app IDENTIFIED BY password",
            "SELECT password FROM users; SET PASSWORD = 'x'",
            "WITH t AS (SELECT 'x' AS password) SELECT password FROM t",
            // Codex round 1 #3: whole-row values line up with the columns.
            "SELECT password FROM users WHERE users = ROW('alice','hunter2')::users",
            "SELECT password FROM users WHERE users = $1::users",
            "SELECT password FROM users WHERE users = $1",
            "SELECT password FROM public.users WHERE users = $1",
            "SELECT password FROM users WHERE creds = '(alice,hunter2)'",
            "SELECT password FROM users WHERE tags = '{hunter2}'",
            "SELECT password FROM users WHERE id = $1abc",
            // Codex round 2 #2: escapes the decoded view would hide
            // (PostgreSQL octal escapes with standard_conforming_strings
            // off), and any decoding at all.
            "SELECT password FROM users WHERE profile = '\\050alice\\054hunter2\\051'",
            "SELECT password FROM users WHERE profile = '\\(alice'",
            "SELECT password FROM users WHERE profile = '%28alice%2Chunter2%29'",
            "SELECT password FROM users WHERE profile = '&#40;alice&#44;hunter2&#41;'",
            "SELECT password FROM users WHERE id = 1+1",
            r#"SELECT password FROM users WHERE name = 'a"b'"#,
            // Codex round 2 #5: truncated statements (no panic).
            "SELECT password FROM users WHERE",
            "SELECT password FROM users WHERE id = 1 AND",
            "SELECT password FROM users ORDER BY",
            "SELECT password FROM users ORDER BY id,",
            "SELECT password FROM users LIMIT",
            "SELECT password FROM users WHERE id = $$hunter2$$",
            "SELECT password FROM users WHERE name = 'it''s'",
            "SELECT password FROM users WHERE name = 'a\\' OR users = $1 -- '",
            "SELECT password FROM users WHERE name = E'x'",
            // Codex round 1 #1, #2: comments and double quotes anywhere.
            "SELECT password /* FROM ignored */ = 'canary' FROM users",
            "SELECT password -- FROM ignored\n= 'canary' FROM users",
            "SELECT password # FROM ignored\n= 'canary' FROM users",
            "SELECT password--\n= 'x' FROM t",
            "SELECT password/**/= 'x' FROM t",
            "SELECT password /* = 'x' */ FROM t",
            "SELECT password -- hunter2\n, email FROM t",
            "SELECT password FROM users -- note",
            "SELECT password FROM users /* hunter2 */",
            "/* hunter2 */ SELECT password FROM users",
            r#"SELECT "password", "hunter2" FROM dual"#,
            r#"SELECT "users"."password" FROM "users""#,
            r#"SELECT password FROM users WHERE name = "hunter2""#,
            r#"SELECT "hunter2,password" FROM t"#,
            r#"SELECT password"hunter2" FROM t"#,
            "SELECT `password`, `hunter2` FROM t",
            "SELECT *password FROM t",
            // Codex round 4: credential words outside the projection, in any
            // form; projection items that are not plain identifiers.
            "SELECT password FROM users WHERE pwd LIKE 'hunter2'",
            "SELECT password FROM users WHERE pwd ILIKE 'x'",
            "SELECT password FROM users WHERE session IN ('a')",
            "SELECT password FROM users WHERE Session = 'a'",
            "SELECT password FROM users WHERE user_pin = 'a'",
            "SELECT password FROM user_tokens",
            "SELECT password FROM users ORDER BY token_id",
            "SELECT password, 0x68756e74657232 FROM users",
            "SELECT password, 123456 FROM users",
            "SELECT password, 1e5 FROM users",
            "SELECT password, _x FROM users WHERE pin = 1",
            // Codex round 5: keyword literals are values, not columns.
            "SELECT password, TRUE FROM users",
            "SELECT password, FALSE FROM users",
            "SELECT password, NULL FROM users",
            "SELECT password, CURRENT_USER FROM users",
            "SELECT password, UTC_TIME FROM users",
            "SELECT password, UTC_DATE FROM users",
            "SELECT password, UTC_TIMESTAMP FROM users",
            "SELECT password FROM users WHERE utc_time = 1",
            // Prose and the rest.
            "token=abc 123",
            "token: abc123",
            "Authorization: Bearer abc",
            "requirepass, s3cret",
        ] {
            assert!(has_credential_context(text), "{text:?}");
            for kind in KINDS {
                assert_eq!(pk(text, kind), FIELD_WITHHELD, "{text:?} {kind:?}");
            }
        }
        for sql in [
            "SELECT password FROM users WHERE pwd LIKE 'hunter2'",
            "SELECT password FROM users WHERE pwd ILIKE 'x'",
            "SELECT password FROM users WHERE session IN ('a')",
            "SELECT password, 0x68756e74657232 FROM users",
            "SELECT password, 123456 FROM users",
            "SELECT password, TRUE FROM users",
            "SELECT password, FALSE FROM users",
            "SELECT password, NULL FROM users",
            "SELECT password, CURRENT_USER FROM users",
            "SELECT password, UTC_TIME FROM users",
            "SELECT password, UTC_DATE FROM users",
            "SELECT password, UTC_TIMESTAMP FROM users",
            "SELECT password FROM users WHERE utc_time = 1",
            "SELECT password FROM users WHERE id = _123456",
            "SELECT password FROM users WHERE id = __",
            "SELECT password FROM users WHERE id = 1_",
            "SELECT password FROM users WHERE users.pwd = 'hunter2'",
            "SELECT email FROM users WHERE users.pwd = 'hunter2'",
            "SELECT email FROM users WHERE pwd-0 = 123456",
            "SELECT email FROM users WHERE pin + 1 = 739205",
            "SELECT email FROM users WHERE 739204 = otp",
            "SELECT password FROM users WHERE password = $1",
            "INSERT INTO users(pwd) VALUES ($1)",
            "SELECT pwd, email FROM users WHERE pwd = $1",
            "SELECT password /* FROM ignored */ = 'canary' FROM users",
            "SELECT password FROM users WHERE users = $1",
        ] {
            assert!(has_sql_credential_context(sql), "{sql}");
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

    /// Security scan F1: a short credential name joined to other words by
    /// `_` or a case boundary (`old_pwd`, `newPwd`), and the camel-folded
    /// form of a multi-word part (`privateKey`), name a credential in a
    /// JSON or form body, a header name and a SQL column, as `old-pwd`
    /// already did.
    #[test]
    fn compound_short_names_are_credential_names() {
        const R: &str = REDACTED_CREDENTIAL;
        for (input, want) in [
            (
                r#"{"old_pwd":"hunter2","new_pwd":"hunter3"}"#,
                format!(r#"{{"old_pwd":"{R}","new_pwd":"{R}"}}"#),
            ),
            (r#"{"newPwd":"hunter2"}"#, format!(r#"{{"newPwd":"{R}"}}"#)),
            (
                r#"{"user":"bob","loginPwd":"hunter2"}"#,
                format!(r#"{{"user":"bob","loginPwd":"{R}"}}"#),
            ),
            (
                r#"{"card_pin":"7392","n":1}"#,
                format!(r#"{{"card_pin":"{R}","n":1}}"#),
            ),
            (r#"{"sms_otp":482913}"#, format!(r#"{{"sms_otp":{R}}}"#)),
            (
                r#"{"privateKey":"-----BEGIN PRIVATE KEY-----MIIE"}"#,
                format!(r#"{{"privateKey":"{R}"}}"#),
            ),
            (
                r#"{"privatekey":"MIIE"}"#,
                format!(r#"{{"privatekey":"{R}"}}"#),
            ),
            (
                r#"{"accessKey":"AKIAX","clientAssertion":"eyJx"}"#,
                format!(r#"{{"accessKey":"{R}","clientAssertion":"{R}"}}"#),
            ),
            (
                r#"{"PIN_CODE":"7392","userSessionId":"s9"}"#,
                format!(r#"{{"PIN_CODE":"{R}","userSessionId":"{R}"}}"#),
            ),
            (
                r#"{"dbPass":"hunter2","otp2":"482913"}"#,
                format!(r#"{{"dbPass":"{R}","otp2":"{R}"}}"#),
            ),
            // A form body.
            (
                "old_pwd=hunter2&new_pwd=hunter3&q=1",
                format!("old_pwd={R}&new_pwd={R}&q=1"),
            ),
            ("newPwd=hunter2&q=1", format!("newPwd={R}&q=1")),
            (
                "cardPin=7392&sms_otp=482913",
                format!("cardPin={R}&sms_otp={R}"),
            ),
            ("privateKey=MIIE&q=1", format!("privateKey={R}&q=1")),
        ] {
            assert!(has_credential_context(input), "{input}");
            assert_eq!(p(input), want, "{input}");
        }
        // Uncertain structures: withheld.
        for input in [
            "new_pwd: hunter2",
            "<newPwd>hunter2</newPwd>",
            "Content-Disposition: form-data; name=\"card_pin\"\r\n\r\n7392",
            r#"{"privateKey":["MIIE"]}"#,
            r#"{"old_pwd":{"v":"hunter2"}}"#,
        ] {
            assert_eq!(p(input), FIELD_WITHHELD, "{input}");
        }
        // An HTTP path's query: masked.
        assert_eq!(
            pk("/account?newPwd=hunter2&q=1", FieldKind::HttpPath),
            format!("/account?newPwd={R}&q=1")
        );
        // Header (and any) names.
        for n in [
            "old_pwd",
            "newPwd",
            "loginPwd",
            "card_pin",
            "sms_otp",
            "privateKey",
            "privatekey",
            "accessKey",
            "clientAssertion",
            "X-Old-Pwd",
            "X-User-Pin",
            "x.sms.otp",
            "SessionId",
            "PIN_CODE",
        ] {
            assert!(is_credential_name(n), "{n}");
        }
        // SQL columns and assignments.
        for sql in [
            "INSERT INTO users (id, new_pwd) VALUES (1, 'hunter2')",
            "UPDATE users SET newPwd = 'hunter2' WHERE id = 1",
            "UPDATE cards SET card_pin = $1 WHERE id = 2",
            "SELECT email FROM users WHERE sms_otp = '482913'",
            "INSERT INTO keys (id, privateKey) VALUES (1, 'MIIE')",
            "UPDATE t SET a = 1, loginPwd = $1",
        ] {
            assert!(has_sql_credential_context(sql), "{sql}");
            let (_, shown, bound) =
                super::super::export_statement(sql.to_string(), Some("'hunter2'".into()));
            assert_eq!(shown, withheld_statement(sql), "{sql}");
            assert_eq!(bound, None, "{sql}");
        }
        // A short name before a `-` or `.` in a certain structure's name:
        // masked by full and names_only alike (a body that was withheld
        // whole for `old-pwd` is now masked, its other members exported).
        let names_only = rules(&[], Builtin::NamesOnly);
        for (input, want) in [
            (
                r#"{"old-pwd":"hunter2","a":1}"#,
                format!(r#"{{"old-pwd":"{R}","a":1}}"#),
            ),
            (r#"{"pin-code":"7392"}"#, format!(r#"{{"pin-code":"{R}"}}"#)),
            ("otp-code=482913&q=1", format!("otp-code={R}&q=1")),
            ("x.pin.code=7392", format!("x.pin.code={R}")),
        ] {
            assert_eq!(p(input), want, "{input}");
            assert_eq!(
                protect_text_with(&names_only, input).as_deref(),
                Some(want.as_str()),
                "{input}"
            );
        }
        // A known limit: in free text, a short name before a `-` is not
        // read as a name (it could be a host and port, `auth-service:8080`).
        assert_eq!(protect_text("pin-code: 7392"), None);
        // `_` joins segments, so a host name with `_` (not a valid DNS
        // host name) reads as a name used as one.
        assert_eq!(p("auth_service:8080"), FIELD_WITHHELD);
        // The folded parts are bare at a path's end like the others.
        for path in ["/vault/privatekey", "/vault/privateKey", "/iam/accessKey"] {
            assert_eq!(pk(path, FieldKind::HttpPath), path);
            assert_eq!(pk(path, FieldKind::Other), FIELD_WITHHELD, "{path}");
            assert_eq!(
                pk(&format!("{path}?x=1"), FieldKind::HttpPath),
                format!("{path}{QUERY_WITHHELD}")
            );
        }
        // A projection item of an allowlisted SELECT is still a bare name.
        for sql in [
            "SELECT card_pin, email FROM cards",
            "SELECT privateKey FROM vault WHERE id = 1",
        ] {
            assert!(!has_sql_credential_context(sql), "{sql}");
            assert!(has_any_sql_credential_context(sql), "{sql}");
            assert_eq!(pk(sql, FieldKind::SqlStatement), sql);
        }
    }

    /// F1's fix matches a short name only as a whole segment: letters of
    /// one inside a word with no `_` or case boundary (`spinner`, `pinned`,
    /// `shipping`) do not count, nor does a short name a `-` or `.` joins
    /// to the word after it (`auth-service:8080`, a host and port), and a
    /// plural is not a name outside Redis.
    #[test]
    fn letters_inside_a_word_are_not_a_short_name() {
        for t in [
            r#"{"spinner":"on","option":"a","pinned":true,"shipping":"x","topic":"t","keyboard":"k"}"#,
            "spinner=1&option=2&pinned=3&shipping=4&topic=5&keyboard=6",
            "spinner: on, pinned: yes, shipping: 2",
            r#"{"isPinned":true,"keyboardLayout":"us","topicName":"t","shippingOption":"x"}"#,
            r#"{"authorName":"bob","passport":"x","sessionless":1,"bypass":2,"compass":3}"#,
            "auth-service:8080",
            "auth.example.com:8443",
            "http://session-store:6379/x",
            r#"{"host":"key-vault.example.net:443","url":"pin-svc.local"}"#,
            r#"{"keys":["a"],"pins":2,"sessions":[1]}"#,
            "SELECT spinner, option FROM t WHERE topic = 1",
            "INSERT INTO t (shipping, keyboard) VALUES (1, 2)",
        ] {
            assert_eq!(protect_text(t), None, "{t}");
            if t.starts_with(['S', 'I']) {
                assert!(!has_sql_credential_context(t), "{t}");
            }
        }
        for n in [
            "spinner",
            "option",
            "pinned",
            "shipping",
            "topic",
            "keyboard",
            "isPinned",
            "keyboardLayout",
            "passport",
            "authorName",
            "bypass",
            "Otpcode",
        ] {
            assert!(!is_credential_name(n), "{n}");
        }
    }

    /// F1 review round 2, item 1: nothing the rules before F1 (faf63a1)
    /// withheld is exported now, and no planted credential is exported in
    /// full mode. The review's table, with each row's output at faf63a1.
    #[test]
    fn no_field_withheld_before_f1_is_exported() {
        const SECRETS: [&str; 5] = ["hunter2", "7392", "482913", "1234", "MIIE"];
        // (input, withheld whole at faf63a1 in full mode)
        for (input, was_withheld) in [
            ("name=\"old-pwd\"\r\n\r\nhunter2", false),
            (
                "Content-Disposition: form-data; name=\"user.newPwd\"\r\n\r\nhunter2",
                false,
            ),
            (
                "Content-Disposition: form-data; name=\"pin-code\"\r\n\r\n7392",
                true,
            ),
            ("<old-pwd>hunter2</old-pwd>", false),
            ("<ns:newPwd>hunter2</ns:newPwd>", false),
            ("<pin-code>7392</pin-code>", false),
            ("<user.pin>7392</user.pin>", false),
            (r#"{"pin-code":["7392"]}"#, false),
            (r#"{"pin_code":["7392"]}"#, false),
            (r#"{"otp-code":{"v":"482913"}}"#, false),
            (r#"{"pin-code":"73"#, false),
            ("pin-code=73 92", false),
            (r#"{"old-pwd":"hunter2","pin-code":["7392"]}"#, true),
            (r#"{"old-pwd":"hunter2","pin-code":"7392"#, true),
            (r#"{"old-pwd":"hunter2","otp-code":{"v":"482913"}}"#, true),
            (r#"{"old-pwd":"hunter2","note":"pin-code: 7392"}"#, true),
            (r#"{"old_pwd":"hunter2","note":"pin-code: 7392"}"#, false),
            (r#"{"newPwd":"hunter2","note":"pin-code: 7392"}"#, false),
            (r#"{"pin-code":"7392","note":"pin-code: 7392"}"#, false),
            ("old-pwd=hunter2&note=pin-code:7392", true),
            ("old-pwd=hunter2&x=pin-code+7392", true),
            ("postgres://user:hunter2@/db", false),
            ("x://u:hunter2@/", false),
            (r#"{"OLDPWD":"hunter2"}"#, false),
            (r#"{"mpin":"1234"}"#, false),
            ("pin-code: 7392\nold-pwd=hunter2", true),
            (r#"{"a":"x-y","old_pwd":"hunter2"}"#, false),
            ("é%2Fx newPwd=hunter2/*", false),
            (r#"{"x":"é","new\u0050wd":"hunter2","c":"--"}"#, false),
            // An escaped quote before the name: the decoded view's quotes
            // do not pair (review round 2, advisor).
            (r#"{"a":"x\"y","pin-code":"7392"}"#, false),
            (r#"{"a":"x\"y","otp-code":["482913"]}"#, false),
        ] {
            let out = p(input);
            if was_withheld {
                assert_eq!(out, FIELD_WITHHELD, "{input:?}");
            }
            for secret in SECRETS {
                assert!(!out.contains(secret), "{input:?} -> {out:?}");
            }
        }
    }

    /// F1 review round 2: credential names the parsers deliver in lower
    /// case (header names) or that are written in one case (`newpwd`,
    /// `OLDPWD`, `cardpin`, `SMSOTP`, `mpin`); multipart and XML names
    /// read whole; a URI password before an empty host (a Unix socket).
    #[test]
    fn single_case_names_quoted_names_and_socket_uris() {
        const R: &str = REDACTED_CREDENTIAL;
        for n in [
            "x-loginpwd",
            "x-newpwd",
            "x-cardpin",
            "x-smsotp",
            "x-mpin",
            "newpwd",
            "OLDPWD",
            "cardpin",
            "SMSOTP",
            "mpin",
            "totp",
            "x-smsotp-code",
        ] {
            assert!(is_credential_name(n), "{n}");
        }
        for (input, want) in [
            (r#"{"newpwd":"hunter2"}"#, format!(r#"{{"newpwd":"{R}"}}"#)),
            (r#"{"OLDPWD":"hunter2"}"#, format!(r#"{{"OLDPWD":"{R}"}}"#)),
            (r#"{"cardpin":"7392"}"#, format!(r#"{{"cardpin":"{R}"}}"#)),
            (r#"{"SMSOTP":"482913"}"#, format!(r#"{{"SMSOTP":"{R}"}}"#)),
            (r#"{"mpin":"1234"}"#, format!(r#"{{"mpin":"{R}"}}"#)),
            ("cardpin=7392&q=1", format!("cardpin={R}&q=1")),
            (
                "postgres://user:hunter2@/db",
                format!("postgres://user:{R}@/db"),
            ),
            ("x://u:hunter2@/", format!("x://u:{R}@/")),
            (
                r#"{"a":"x\"y","pin-code":"7392"}"#,
                format!(r#"{{"a":"x\"y","pin-code":"{R}"}}"#),
            ),
        ] {
            assert_eq!(p(input), want, "{input}");
            let names_only = rules(&[], Builtin::NamesOnly);
            assert_eq!(
                protect_text_with(&names_only, input).as_deref(),
                Some(want.as_str()),
                "{input}"
            );
        }
        for sql in [
            "UPDATE users SET newpwd = 'hunter2' WHERE id = 1",
            "UPDATE cards SET cardpin = $1",
            "INSERT INTO u (id, smsotp) VALUES (1, '482913')",
        ] {
            assert!(has_sql_credential_context(sql), "{sql}");
        }
        for input in [
            "name=\"old-pwd\"\r\n\r\nhunter2",
            "Content-Disposition: form-data; name=\"user.newPwd\"\r\n\r\nhunter2",
            "Content-Disposition: form-data; name='pin-code'\r\n\r\n7392",
            "<old-pwd>hunter2</old-pwd>",
            "<ns:newPwd>hunter2</ns:newPwd>",
            "<pin-code>7392</pin-code>",
            "<user.pin>7392</user.pin>",
            "<user.pin attr=\"1\">7392</user.pin>",
        ] {
            assert_eq!(p(input), FIELD_WITHHELD, "{input:?}");
        }
        // Words that hold the letters but name no credential.
        for t in [
            r#"{"spinner":1,"option":2,"topic":3,"shipping":4,"pinned":5,"keyboard":6}"#,
            r#"{"opinion":"x","mapping":"y","footprint":"z","hotplate":1,"pinpoint":2}"#,
            "<spinner>1</spinner><option>2</option><topic-name>3</topic-name>",
            "Content-Disposition: form-data; name=\"shipping-option\"\r\n\r\nground",
            "topic=1&option=2&opinion=3&mapping=4",
        ] {
            assert_eq!(protect_text(t), None, "{t}");
        }
        // A known limit: other short names glued to a word in one case are
        // not names (`bypass`, `compass`, `consider`, `design` would be),
        // so these lowercased headers are exported.
        for n in ["x-dbpass", "x-userjwt", "x-usersid", "x-reqsig"] {
            assert!(!is_credential_name(n), "{n}");
        }
        for n in [
            "x-shipping-option",
            "opinion",
            "mapping",
            "footprint",
            "pinpoint",
            "topic",
            "spinner",
        ] {
            assert!(!is_credential_name(n), "{n}");
        }
    }

    /// F1 delta review (HIGH): a decoder must not consume what follows a
    /// malformed escape (`\u` without four hex digits, which multi-round
    /// decoding makes of `\\u` and `%5Cu`), or the view loses the start of
    /// the next credential name. Full mode kept these; names_only masked.
    #[test]
    fn malformed_escapes_hide_no_name() {
        const S: &str = "Zq9Xv7Wk";
        assert_eq!(json_unescape(r#"\u","x"#).as_deref(), None);
        assert_eq!(json_unescape(r"\u00").as_deref(), None);
        assert_eq!(json_unescape(r"a\u0070b").as_deref(), Some("apb"));
        for name in ["password", "token", "otp", "pin", "pin-code", "newPwd"] {
            for input in [
                format!("/login?dir=C:%5Cusr&{name}={S}"),
                format!(r"dir=C:\usr&{name}={S}"),
                format!(r#"{{"p":"C:\\u","{name}":"{S}"}}"#),
                format!(r#"{{"re":"\\u","{name}":"{S}"}}"#),
                format!(r#"{{"re":"%5Cu","{name}":"{S}"}}"#),
                format!(r#"{{"re":"\u00","{name}":"{S}"}}"#),
            ] {
                for kind in KINDS {
                    let out = pk(&input, kind);
                    assert!(!out.contains(S), "{input:?} {kind:?} -> {out:?}");
                }
            }
        }
    }

    /// M4: a backslash before a word in text that is not JSON (a Windows
    /// path, prose, LaTeX) is not an escape there. JSON reads `\t`, `\b`,
    /// `\n`, `\r` and `\f` as control characters (`\token` as a tab and
    /// `oken`) and drops the backslash of any other letter (`dir\key` as
    /// `dirkey`); both readings hid the credential word. The view is also
    /// read with a backslash before a letter as a separator.
    #[test]
    fn a_backslash_before_a_word_hides_no_credential() {
        const S: &str = "Zq9Xv7Wk";
        let names_only = rules(&[], Builtin::NamesOnly);
        for input in [
            format!(r"\token={S}"),
            format!(r"\token={S}&b=1"),
            format!(r"see C:\token {S}"),
            format!(r"x \token {S}"),
            format!(r"\\token={S}"),
            format!("%5Ctoken={S}"),
            format!(r"\bearer {S}"),
            format!(r"\requirepass {S}"),
            format!(r"\secret: {S}"),
            format!(r"dir\key={S}"),
            format!(r"a\session={S}"),
            format!(r"x\auth: {S}"),
            format!(r"x\pin: {S}"),
            format!(r#"{{"p":"C:\\token","v":"{S}"}}"#),
            format!(r#"{{"dir\\token":"{S}"}}"#),
        ] {
            for kind in KINDS {
                let out = pk(&input, kind);
                assert!(!out.contains(S), "{input:?} {kind:?} -> {out:?}");
            }
            // Full masks what names_only masks.
            if let Some(n) = protect_text_with(&names_only, &input) {
                assert!(!n.contains(S) || p(&input) == FIELD_WITHHELD, "{input:?}");
            }
        }
        // A certain structure under a name read with the separator: masked
        // in both modes.
        let want = format!(r"dir\key={REDACTED_CREDENTIAL}");
        assert_eq!(p(&format!(r"dir\key={S}")), want);
        assert_eq!(
            protect_text_with(&names_only, &format!(r"dir\key={S}")).as_deref(),
            Some(want.as_str())
        );
        assert!(is_credential_name(r"x\token"));
        // The JSON reading still counts: a tab escape before a short name.
        assert_eq!(p(&format!(r#"{{"m":"a\tkey={S}"}}"#)), FIELD_WITHHELD);
        assert_eq!(p(&format!(r#"{{"m":"a\npwd: {S}"}}"#)), FIELD_WITHHELD);
        // Paths, prose and escapes with no credential word stay exported.
        for t in [
            r"C:\Users\bob\notes.txt",
            r"see C:\tmp\report and \textbf{bold}",
            r#"{"path":"C:\\tmp\\report.txt","n":1}"#,
            r#"{"msg":"line1\nline2\tdone"}"#,
            r"\begin{document}\section{Intro}\end{document}",
            r#"{"re":"\\d+\\s\\w"}"#,
        ] {
            assert_eq!(protect_text(t), None, "{t}");
        }
    }

    /// F1 delta review: full masks every value names_only masks (or
    /// withholds the field), over a generated corpus of names, values,
    /// structures and encoding noise (the reviewer's generator, ported).
    #[test]
    fn full_masks_all_names_only_does() {
        const S: &str = "Zq9Xv7Wk";
        let names = [
            "pwd",
            "old-pwd",
            "newPwd",
            "pin-code",
            "user.pin",
            "cardpin",
            "SMSOTP",
            "otp-code",
            "mpin",
            "x-loginpwd",
            "password",
            "api-key",
            "session-id",
            "auth-token",
            "sid",
            "jwt",
            "key",
            "sig",
            "pin",
            "otp",
            "token",
            "secret",
        ];
        let noise = [
            r#"\""#, r"\\", r"\u0022", "\"", "'", ":", ",", "{", "}", "[", "]", "&", "?", "=", "<",
            ">", "/", "--", "#", "/*", "*/", "%22", "%2D", "&quot;", "&amp;", " ", "\n", "\0", "é",
            "x", "-", ".", "_", "name=", r"\u00", r"\u", "\\", "%", "+", ";", "@", "//", "%5C",
            "%5Cu", r"\\u", "C:", "\t",
        ];
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut rnd = move |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let full = super::super::credential_rules::credential_rules();
        let names_only = rules(&[], Builtin::NamesOnly);
        for _ in 0..30_000 {
            let noise_of = |k: usize, rnd: &mut dyn FnMut(usize) -> usize| {
                (0..rnd(k + 1))
                    .map(|_| noise[rnd(noise.len())])
                    .collect::<String>()
            };
            let mut text = String::new();
            for part in 0..1 + rnd(5) {
                if part > 0 {
                    text.push_str([",", "&", "\n", " ", "", ";"][rnd(6)]);
                }
                let mut n = names[rnd(names.len())].to_string();
                match rnd(10) {
                    0 | 1 => n = n.to_ascii_uppercase(),
                    2 => n = format!("{}{n}{}", noise_of(2, &mut rnd), noise_of(2, &mut rnd)),
                    _ => {}
                }
                let v = match rnd(6) {
                    0 => format!("\"{S}\""),
                    1 => format!("[\"{S}\"]"),
                    2 => format!("{{\"v\":\"{S}\"}}"),
                    3 => format!("\"{S}"),
                    4 => S.to_string(),
                    _ => format!("\"{}{S}{}\"", noise_of(3, &mut rnd), noise_of(3, &mut rnd)),
                };
                let frag = match rnd(10) {
                    0 => format!("\"{n}\"{}:{v}", ["", ": ", " :"][rnd(3)]),
                    1 => format!("{}{n}={S}", ["", "&", "?", ";"][rnd(4)]),
                    2 => format!("<{n}>{S}</{n}>"),
                    3 => {
                        let q = ["\"", "'", ""][rnd(3)];
                        format!("name={q}{n}{q}\r\n\r\n{S}")
                    }
                    4 => format!(
                        "\"{}\":\"{}\"",
                        noise_of(6, &mut rnd),
                        noise_of(6, &mut rnd)
                    ),
                    5 => noise_of(8, &mut rnd),
                    6 => format!("scheme://u:{S}@{}", ["", "/", "h", "[::1]"][rnd(4)]),
                    7 => format!("{n}: {S}"),
                    8 => r#""old-pwd":"h""#.to_string(),
                    _ => format!("\"a\":\"{}\"", noise_of(5, &mut rnd)),
                };
                text.push_str(&frag);
            }
            if rnd(2) == 0 {
                text = format!("{{{text}{}", ["}", ""][rnd(2)]);
            }
            let n_spans = match decide(&names_only, &text, true) {
                Decision::Mask(sp) => sp,
                _ => continue,
            };
            match decide(&full, &text, true) {
                Decision::Withhold => {}
                Decision::Mask(f) => {
                    for (s, e) in n_spans {
                        assert!(
                            f.iter().any(|&(fs, fe)| fs <= s && e <= fe),
                            "{text:?}: names_only masks {s}..{e}, full {f:?}"
                        );
                    }
                }
                other => panic!("{text:?}: names_only masks {n_spans:?}, full {other:?}"),
            }
        }
    }

    /// F1 delta review (LOW): a parameter name read whole also starts
    /// after `;`, a line break or other whitespace.
    #[test]
    fn parameter_names_after_semicolons_and_whitespace() {
        const S: &str = "Zq9Xv7Wk";
        for input in [
            format!("a=1;pin-code={S}"),
            format!("a=1\npin-code={S}"),
            format!("a=1\r\npin-code={S}"),
            format!("x=1 pin-code={S}"),
            format!("x=1\totp-code={S}"),
        ] {
            assert!(!p(&input).contains(S), "{input:?} -> {:?}", p(&input));
        }
        for t in [
            "text/plain; charset=utf-8",
            "a=1;b=2\nc=3 d=4",
            "spinner=1; option=2\ntopic=3 shipping-option=4",
        ] {
            assert_eq!(protect_text(t), None, "{t}");
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

    /// The form-parameter scan before it was made linear (security scan
    /// F1): the reference for what it masks and removes.
    fn form_params_quadratic(b: &[u8], text: &str, mask: &mut Spans, delete: &mut Spans) {
        for p in 0..b.len() {
            if p > 0 && !matches!(b[p - 1], b'?' | b'&') {
                continue;
            }
            let Some(eq) = b[p..]
                .iter()
                .position(|&c| {
                    matches!(c, b'=' | b'&' | b'#' | b'?' | b'/') || c.is_ascii_whitespace()
                })
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

    /// The linear scan masks and removes exactly what the quadratic one
    /// did, so no value it masked is exported now.
    #[test]
    fn form_params_matches_the_quadratic_scan() {
        for text in [
            "?pwd=a?pwd=b&q=1",
            "?pwd=a b?pwd=c",
            "?pwd=a b?pwd=c&token=d e&x=1?secret=f",
            "/login?password=x&q=1",
            "/a?b=1?token=2 3&pwd=4",
            "pwd=?pwd=?pwd=",
            "pwd=&pwd=&",
            "?pwd=\t?pwd=x",
            "token=abc?def",
            "?q=1&api_key=k1?api_key=k2&a=b c&secret=s",
            "x?y=1&pwd=v?w&pass=v2?pwd= &token=t",
            "&&??pwd==&=pwd=a",
            "pässword=é&password=x&ß",
        ] {
            let b = text.as_bytes();
            let (mut m1, mut d1, mut m2, mut d2) = (vec![], vec![], vec![], vec![]);
            form_params(b, text, &mut m1, &mut d1);
            form_params_quadratic(b, text, &mut m2, &mut d2);
            assert_eq!(merge(m1), merge(m2), "mask {text:?}");
            assert_eq!(remove(text, &d1), remove(text, &d2), "removed {text:?}");
        }
        assert_eq!(p("?pwd=a?pwd=b&q=1"), "?pwd=<REDACTED>&q=1");
        assert_eq!(p("token=abc?def"), "token=<REDACTED>");
    }

    /// Review (LOW): segments split on every character that is not an
    /// ASCII letter or digit, and at a lower-to-upper case boundary; a
    /// short name inside a segment with no boundary does not count.
    #[test]
    fn segments_split_on_any_separator_case_and_digit_boundary() {
        for name in [
            "otp",
            "u:1:otp",
            "u{1}otp",
            "u|otp",
            "u#otp",
            "u,otp",
            "u;pin",
            "u otp",
            "u\totp",
            "u\u{e9}otp",
            "$.otp",
            "pinCode",
            "userOtp",
            "u1Otp",
            "apiKey",
            "clientAssertion",
            "client-assertion",
            "masterUser",
            "SessionToken",
            "API_KEY",
            "u:1:apikey",
            // Review: plural `s`, an acronym before a word, digits.
            "sessions",
            ":1:django.contrib.sessions.cachexk3v9",
            "pins",
            "u:otps",
            "tokens",
            "keys",
            "OTPCode",
            "PINCode",
            "otp2",
            "user1pin",
            "pin_2fa",
            "API2Key",
        ] {
            assert!(segmented_name_has_credential_word(name), "{name}");
        }
        for name in [
            "mykey",
            "spinner",
            "author",
            "otpcode",
            "Otpcode",
            "OTPCODE",
            "pinto",
            "2fa:alice",
            "pinsx",
            "otpcodes",
            "",
        ] {
            assert!(!segmented_name_has_credential_word(name), "{name}");
        }
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
            // Security scan F1: `?`-chained parameters, each value running
            // to the field's end, or to whitespace at its end.
            "?pwd=".repeat(13_000),
            "?pwd=".repeat(13_000) + " ",
            "pwd=?".repeat(13_000) + " ",
            "?password=".repeat(6_500) + " x",
            "?pwd=&".repeat(11_000),
            "?pwd=a".repeat(11_000) + "\n",
            "&pwd=?pwd=".repeat(6_500) + " ",
            "\"pwd\":\"".repeat(9_000),
            "\"pwd\":\"\\\"".repeat(7_000),
            "//a:b@c".repeat(9_000),
            "pwd ".repeat(16_000),
            // The name-position scan (F1 review round 2).
            "<a:".repeat(20_000),
            "name='".repeat(10_000),
            "name=,".repeat(10_000),
            "name=\"".repeat(10_000),
            "\"spinner-x\":".repeat(5_000),
            "&spinner-x=".repeat(5_000),
            "\\\"".repeat(20_000),
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
