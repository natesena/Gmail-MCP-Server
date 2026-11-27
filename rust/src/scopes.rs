//! Gmail OAuth2 scope names and helpers (port of `src/scopes.ts`).
//!
//! Scope hierarchy:
//!   - gmail.readonly: read-only access
//!   - gmail.modify: read and write (superset of readonly)
//!   - gmail.compose: create drafts and send
//!   - gmail.send: send only
//!   - gmail.labels: manage labels only
//!   - gmail.settings.basic: manage filters and settings
//!   - gmail.full: full mailbox access, including permanent deletion

/// Shorthand scope names and their Google API URLs.
pub const SCOPE_MAP: &[(&str, &str)] = &[
    (
        "gmail.readonly",
        "https://www.googleapis.com/auth/gmail.readonly",
    ),
    (
        "gmail.modify",
        "https://www.googleapis.com/auth/gmail.modify",
    ),
    (
        "gmail.compose",
        "https://www.googleapis.com/auth/gmail.compose",
    ),
    ("gmail.send", "https://www.googleapis.com/auth/gmail.send"),
    (
        "gmail.labels",
        "https://www.googleapis.com/auth/gmail.labels",
    ),
    ("gmail.full", "https://mail.google.com/"),
    (
        "gmail.settings.basic",
        "https://www.googleapis.com/auth/gmail.settings.basic",
    ),
    (
        "gmail.settings.sharing",
        "https://www.googleapis.com/auth/gmail.settings.sharing",
    ),
];

/// Scopes used when none are specified (the original behaviour).
pub const DEFAULT_SCOPES: &[&str] = &["gmail.modify", "gmail.settings.basic"];

/// Scopes that `gmail.full` (https://mail.google.com/) satisfies. It does NOT
/// cover the settings scopes: Gmail's settings endpoints only accept
/// `gmail.settings.*`.
const GMAIL_FULL_COVERS: &[&str] = &[
    "gmail.readonly",
    "gmail.modify",
    "gmail.compose",
    "gmail.send",
    "gmail.labels",
    "gmail.full",
];

pub fn default_scopes() -> Vec<String> {
    DEFAULT_SCOPES.iter().map(|s| s.to_string()).collect()
}

/// "gmail.readonly" -> "https://www.googleapis.com/auth/gmail.readonly".
/// Unknown values pass through unchanged.
pub fn scope_name_to_url(scope: &str) -> String {
    SCOPE_MAP
        .iter()
        .find(|(name, _)| *name == scope)
        .map(|(_, url)| url.to_string())
        .unwrap_or_else(|| scope.to_string())
}

/// Full URL -> shorthand name. Unknown values pass through unchanged.
pub fn scope_url_to_name(scope: &str) -> String {
    SCOPE_MAP
        .iter()
        .find(|(_, url)| *url == scope)
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| scope.to_string())
}

pub fn scope_names_to_urls(scopes: &[String]) -> Vec<String> {
    scopes.iter().map(|s| scope_name_to_url(s)).collect()
}

/// True if ANY of `required` is granted by `authorized` (shorthand or URL form).
pub fn has_scope<A: AsRef<str>, R: AsRef<str>>(authorized: &[A], required: &[R]) -> bool {
    let normalized: Vec<String> = authorized
        .iter()
        .map(|s| scope_url_to_name(s.as_ref()))
        .collect();
    let has_full = normalized.iter().any(|s| s == "gmail.full");
    required.iter().any(|req| {
        let req = req.as_ref();
        normalized.iter().any(|s| s == req) || (has_full && GMAIL_FULL_COVERS.contains(&req))
    })
}

/// Parse a comma- or whitespace-separated scope list.
pub fn parse_scopes(input: &str) -> Vec<String> {
    input
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Returns the scopes that are not recognised.
pub fn invalid_scopes(scopes: &[String]) -> Vec<String> {
    scopes
        .iter()
        .filter(|s| !SCOPE_MAP.iter().any(|(name, _)| name == s))
        .cloned()
        .collect()
}

pub fn available_scope_names() -> Vec<&'static str> {
    SCOPE_MAP.iter().map(|(name, _)| *name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_url_roundtrip() {
        assert_eq!(
            scope_name_to_url("gmail.readonly"),
            "https://www.googleapis.com/auth/gmail.readonly"
        );
        assert_eq!(scope_url_to_name("https://mail.google.com/"), "gmail.full");
        assert_eq!(scope_name_to_url("custom"), "custom");
    }

    #[test]
    fn has_scope_any_match_and_url_form() {
        assert!(has_scope(
            &["gmail.readonly"],
            &["gmail.readonly", "gmail.modify"]
        ));
        assert!(has_scope(
            &["https://www.googleapis.com/auth/gmail.modify"],
            &["gmail.modify"]
        ));
        assert!(!has_scope(&["gmail.readonly"], &["gmail.modify"]));
    }

    // Port of delete-scopes.test.ts
    #[test]
    fn delete_requires_full_and_full_covers_mail_scopes() {
        assert!(!has_scope(&["gmail.modify"], &["gmail.full"]));
        assert!(has_scope(&["gmail.full"], &["gmail.full"]));
        assert!(has_scope(&["https://mail.google.com/"], &["gmail.modify"]));
        assert!(has_scope(&["gmail.full"], &["gmail.readonly"]));
        // gmail.full does not cover settings scopes
        assert!(!has_scope(&["gmail.full"], &["gmail.settings.basic"]));
    }

    #[test]
    fn parse_and_validate() {
        assert_eq!(
            parse_scopes("gmail.readonly, gmail.send  gmail.labels"),
            vec!["gmail.readonly", "gmail.send", "gmail.labels"]
        );
        assert_eq!(
            invalid_scopes(&["gmail.readonly".into(), "nope".into()]),
            vec!["nope".to_string()]
        );
    }
}
