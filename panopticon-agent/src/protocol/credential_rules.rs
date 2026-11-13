//! `[credentials]`: the user's own credential patterns and how much of the
//! built-in detection runs. Compiled once per (re)load and swapped in
//! whole: a message is protected with one rule set, the one current when
//! its fields are scanned.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwap;
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};

/// Most user patterns accepted.
pub const MAX_PATTERNS: usize = 256;
/// Longest user pattern accepted, in bytes.
pub const MAX_PATTERN_LEN: usize = 1024;
/// Compiled size limits: one pattern, and all of them as a set. A pattern
/// that would compile past them (`\w{1000}{1000}`) is refused.
const PATTERN_SIZE_LIMIT: usize = 1 << 20;
const SET_SIZE_LIMIT: usize = 32 << 20;
const DFA_SIZE_LIMIT: usize = 8 << 20;

/// `[credentials] builtin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Builtin {
    /// Every built-in rule (the default).
    #[default]
    Full,
    /// Credential-named headers, the certain structures (form parameters,
    /// JSON members, URI userinfo) and SQL statement withholding only: no
    /// free-text context detection on other fields.
    NamesOnly,
}

impl Builtin {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "full" => Some(Self::Full),
            "names_only" => Some(Self::NamesOnly),
            _ => None,
        }
    }
}

/// The compiled `[credentials]` settings.
#[derive(Debug, Default)]
pub struct CredentialRules {
    pub builtin: Builtin,
    /// The user's patterns: one set to test a field once, and each pattern
    /// alone to replace its matches.
    pub(super) user: Option<(RegexSet, Vec<Regex>)>,
}

impl CredentialRules {
    /// Compile `patterns`, refusing any that is invalid or over the limits.
    pub fn compile(patterns: &[String], builtin: Builtin) -> Result<Self, String> {
        if patterns.len() > MAX_PATTERNS {
            return Err(format!(
                "{} patterns; at most {MAX_PATTERNS} are accepted",
                patterns.len()
            ));
        }
        let mut each = Vec::with_capacity(patterns.len());
        for (i, p) in patterns.iter().enumerate() {
            if p.len() > MAX_PATTERN_LEN {
                return Err(format!(
                    "pattern {i} is {} bytes; at most {MAX_PATTERN_LEN} are accepted",
                    p.len()
                ));
            }
            if p.is_empty() {
                return Err(format!("pattern {i} is empty"));
            }
            let re = RegexBuilder::new(p)
                .size_limit(PATTERN_SIZE_LIMIT)
                .dfa_size_limit(DFA_SIZE_LIMIT)
                .build()
                .map_err(|e| format!("pattern {i} ({p:?}): {e}"))?;
            if re.is_match("") {
                return Err(format!("pattern {i} ({p:?}) matches the empty string"));
            }
            each.push(re);
        }
        let user = if patterns.is_empty() {
            None
        } else {
            let set = RegexSetBuilder::new(patterns)
                .size_limit(SET_SIZE_LIMIT)
                .dfa_size_limit(DFA_SIZE_LIMIT)
                .build()
                .map_err(|e| format!("patterns together: {e}"))?;
            Some((set, each))
        };
        Ok(Self { builtin, user })
    }
}

static RULES: LazyLock<ArcSwap<CredentialRules>> =
    LazyLock::new(|| ArcSwap::from_pointee(CredentialRules::default()));

/// Install the rules used for every field protected from now on.
pub fn set_credential_rules(rules: CredentialRules) {
    RULES.store(Arc::new(rules));
}

/// The rules in effect.
pub(super) fn credential_rules() -> Arc<CredentialRules> {
    RULES.load_full()
}

/// `panopticon_credential_matches_total{source="user"}`: user-pattern
/// matches replaced (a field withheld because a pattern matched only its
/// decoded view counts once).
static USER_MATCHES: AtomicU64 = AtomicU64::new(0);
/// `{source="builtin"}`: fields the built-in rules changed (a value masked
/// or the field withheld; a credential header wiped; a SQL statement
/// withheld).
static BUILTIN_MATCHES: AtomicU64 = AtomicU64::new(0);

pub(super) fn count_user(n: u64) {
    USER_MATCHES.fetch_add(n, Ordering::Relaxed);
}

pub fn count_builtin() {
    BUILTIN_MATCHES.fetch_add(1, Ordering::Relaxed);
}

/// (user, builtin) totals.
pub fn credential_matches() -> (u64, u64) {
    (
        USER_MATCHES.load(Ordering::Relaxed),
        BUILTIN_MATCHES.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_and_oversized_patterns_are_refused() {
        let s = |v: &[&str]| v.iter().map(|p| p.to_string()).collect::<Vec<_>>();
        assert!(CredentialRules::compile(&s(&["acme_[a-z0-9]{32}"]), Builtin::Full).is_ok());
        for (bad, why) in [
            (s(&["acme_[a-z"]), "pattern 0"),
            (s(&["ok_[0-9]+", "(unclosed"]), "pattern 1"),
            (s(&[""]), "empty"),
            (s(&["x*"]), "empty string"),
            (s(&[&"a".repeat(MAX_PATTERN_LEN + 1)]), "bytes"),
            (s(&[r"\w{1000}{1000}"]), "pattern 0"),
            (vec!["k[0-9]".to_string(); MAX_PATTERNS + 1], "patterns"),
        ] {
            let err = CredentialRules::compile(&bad, Builtin::Full).unwrap_err();
            assert!(err.contains(why), "{err}");
        }
    }
}
