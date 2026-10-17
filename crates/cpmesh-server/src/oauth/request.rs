//! Request parameters shared by the authorization server's endpoints and the consent
//! API: which client and redirect URI a request names, `state`, PKCE, scopes and the
//! agent's name for itself.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use super::codes::is_valid_code_challenge;
use super::{Client, Scope, Scopes};

/// Longest `state` accepted; it is sent back to the client.
pub const STATE_MAX_LEN: usize = 512;
/// Longest agent name accepted, in characters.
pub const AGENT_NAME_MAX_CHARS: usize = 100;

/// Query or form parameters. Empty values count as absent (RFC 6749 section 3.1), and
/// a parameter given more than once is not used at all.
#[derive(Debug, Default)]
pub struct Params {
    values: HashMap<String, String>,
    repeated: Option<String>,
}

impl Params {
    pub fn new(pairs: impl IntoIterator<Item = (String, String)>) -> Params {
        let mut params = Params::default();
        let mut seen = HashSet::new();
        for (name, value) in pairs {
            if !seen.insert(name.clone()) {
                params.values.remove(&name);
                params.repeated.get_or_insert(name);
            } else if !value.is_empty() {
                params.values.insert(name, value);
            }
        }
        params
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// The first parameter given more than once (RFC 6749 section 3.1 forbids that).
    pub fn repeated(&self) -> Option<&str> {
        self.repeated.as_deref()
    }
}

/// Why a request was refused: an OAuth error code and a description for developers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid {
    pub error: &'static str,
    pub description: Cow<'static, str>,
}

impl Invalid {
    pub fn new(error: &'static str, description: impl Into<Cow<'static, str>>) -> Invalid {
        Invalid {
            error,
            description: description.into(),
        }
    }

    pub fn request(description: impl Into<Cow<'static, str>>) -> Invalid {
        Invalid::new("invalid_request", description)
    }
}

/// The client and redirect URI a request names. These are checked before anything
/// else: until both are known to be registered, errors are never sent to the
/// redirect URI.
pub fn redirect_target(
    client_id: Option<&str>,
    redirect_uri: Option<&str>,
) -> Result<(&'static Client, String), Invalid> {
    let client = client_id
        .and_then(super::client)
        .ok_or_else(|| Invalid::new("invalid_client", "client_id is missing or not registered"))?;
    match redirect_uri {
        Some(uri) if client.allows_redirect_uri(uri) => Ok((client, uri.to_string())),
        _ => Err(Invalid::new(
            "invalid_redirect_uri",
            "redirect_uri is missing or not registered for this client",
        )),
    }
}

/// `state`, which is required: 1 to 512 printable ASCII characters (VSCHAR, RFC 6749
/// appendix A.5).
pub fn state(value: Option<&str>) -> Result<String, Invalid> {
    match value.filter(|state| !state.is_empty()) {
        Some(state)
            if state.len() <= STATE_MAX_LEN
                && state.bytes().all(|b| (0x20..=0x7e).contains(&b)) =>
        {
            Ok(state.to_string())
        }
        Some(_) => Err(Invalid::request(
            "state must be at most 512 printable ASCII characters",
        )),
        None => Err(Invalid::request("state is required")),
    }
}

/// The PKCE challenge, which is required; only S256 is supported.
pub fn code_challenge(challenge: Option<&str>, method: Option<&str>) -> Result<String, Invalid> {
    if method != Some("S256") {
        return Err(Invalid::request("code_challenge_method must be S256"));
    }
    match challenge {
        Some(challenge) if is_valid_code_challenge(challenge) => Ok(challenge.to_string()),
        _ => Err(Invalid::request(
            "code_challenge must be the base64url SHA-256 of the code verifier",
        )),
    }
}

/// The scopes an agent asks for. Without `scope` it asks for every scope; the consent
/// page lets the user choose (it starts with only clipboard:read and clipboard:write).
pub fn requested_scopes(value: Option<&str>) -> Result<Scopes, Invalid> {
    match Scopes::parse(value.unwrap_or_default()) {
        Ok(scopes) if scopes.is_empty() => Ok(Scope::ALL.into_iter().collect()),
        Ok(scopes) => Ok(scopes),
        Err(unknown) => Err(Invalid::new("invalid_scope", unknown.to_string())),
    }
}

/// The scopes a user approved: at least one, all known.
pub fn approved_scopes(value: Option<&str>) -> Result<Scopes, Invalid> {
    match Scopes::parse(value.unwrap_or_default()) {
        Ok(scopes) if scopes.is_empty() => {
            Err(Invalid::new("invalid_scope", "approve at least one scope"))
        }
        Ok(scopes) => Ok(scopes),
        Err(unknown) => Err(Invalid::new("invalid_scope", unknown.to_string())),
    }
}

/// The name an agent reports for itself (shown to the user as reported by the agent):
/// trimmed, at most 100 characters, without control or bidirectional formatting
/// characters. Empty when absent.
pub fn agent_name(value: Option<&str>) -> Result<String, Invalid> {
    let name = value.unwrap_or_default().trim();
    if name.chars().count() > AGENT_NAME_MAX_CHARS {
        return Err(Invalid::request(
            "agent_name must be at most 100 characters",
        ));
    }
    if name.chars().any(|c| c.is_control() || is_formatting(c)) {
        return Err(Invalid::request(
            "agent_name must not contain control or formatting characters",
        ));
    }
    Ok(name.to_string())
}

/// Characters that reorder or break the text around them when displayed.
fn is_formatting(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// `pairs` as a URL query, percent-encoded.
pub fn query_string(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={}", urlencoding::encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// A registered redirect URI (which has no query) with `pairs` as its query.
pub fn redirect_uri_with(redirect_uri: &str, pairs: &[(&str, &str)]) -> String {
    format!("{redirect_uri}?{}", query_string(pairs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::MCP_CLIENT_ID;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn empty_parameters_are_absent_and_repeated_ones_are_not_used() {
        let params = Params::new(pairs(&[
            ("client_id", "cpmesh-mcp"),
            ("scope", ""),
            ("state", "a"),
            ("state", "b"),
            ("state", "c"),
        ]));
        assert_eq!(params.get("client_id"), Some("cpmesh-mcp"));
        assert_eq!(params.get("scope"), None);
        assert_eq!(params.get("state"), None);
        assert_eq!(params.repeated(), Some("state"));
        let params = Params::new(pairs(&[("scope", ""), ("scope", "clipboard:read")]));
        assert_eq!(params.get("scope"), None);
        assert_eq!(params.repeated(), Some("scope"));
        assert_eq!(Params::new(pairs(&[("a", "1")])).repeated(), None);
    }

    #[test]
    fn the_client_and_redirect_uri_are_checked_first() {
        let uri = "http://127.0.0.1:4000/callback";
        let (client, redirect) = redirect_target(Some(MCP_CLIENT_ID), Some(uri)).unwrap();
        assert_eq!((client.id, redirect.as_str()), (MCP_CLIENT_ID, uri));
        for (client_id, redirect_uri, error) in [
            (None, Some(uri), "invalid_client"),
            (Some("other"), Some(uri), "invalid_client"),
            (Some(MCP_CLIENT_ID), None, "invalid_redirect_uri"),
            (
                Some(MCP_CLIENT_ID),
                Some("http://localhost:4000/callback"),
                "invalid_redirect_uri",
            ),
        ] {
            assert_eq!(
                redirect_target(client_id, redirect_uri).unwrap_err().error,
                error
            );
        }
    }

    #[test]
    fn state_is_required_printable_and_bounded() {
        assert_eq!(state(Some("x")).unwrap(), "x");
        assert_eq!(state(Some(" ~!\"#")).unwrap(), " ~!\"#");
        assert!(state(Some(&"s".repeat(512))).is_ok());
        for bad in [
            None,
            Some(""),
            Some("tab\there"),
            Some("é"),
            Some(&*"s".repeat(513)),
        ] {
            assert_eq!(state(bad).unwrap_err().error, "invalid_request", "{bad:?}");
        }
    }

    #[test]
    fn pkce_is_required_and_s256_only() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(
            code_challenge(Some(challenge), Some("S256")).unwrap(),
            challenge
        );
        for (challenge, method) in [
            (Some(challenge), Some("plain")),
            (Some(challenge), Some("s256")),
            (Some(challenge), None),
            (None, Some("S256")),
            (Some("too-short"), Some("S256")),
        ] {
            assert!(code_challenge(challenge, method).is_err());
        }
    }

    #[test]
    fn scopes_are_strict_and_default_to_every_scope_when_requested() {
        let all: Scopes = Scope::ALL.into_iter().collect();
        assert_eq!(requested_scopes(None).unwrap(), all);
        assert_eq!(requested_scopes(Some(" ")).unwrap(), all);
        assert_eq!(
            requested_scopes(Some("clipboard:write")).unwrap(),
            Scopes::of(&[Scope::ClipboardWrite])
        );
        assert_eq!(
            requested_scopes(Some("clipboard:read admin"))
                .unwrap_err()
                .error,
            "invalid_scope"
        );
        assert_eq!(
            approved_scopes(Some("clipboard:read")).unwrap(),
            Scopes::of(&[Scope::ClipboardRead])
        );
        for bad in [None, Some(""), Some("clipboard:everything")] {
            assert_eq!(approved_scopes(bad).unwrap_err().error, "invalid_scope");
        }
    }

    #[test]
    fn agent_names_are_trimmed_bounded_and_plain() {
        assert_eq!(agent_name(None).unwrap(), "");
        assert_eq!(
            agent_name(Some("  Claude Code via cpmesh-mcp on laptop ")).unwrap(),
            "Claude Code via cpmesh-mcp on laptop"
        );
        assert_eq!(
            agent_name(Some(&"é".repeat(100))).unwrap().chars().count(),
            100
        );
        for bad in [
            "é".repeat(101),
            "line\nbreak".into(),
            "nul\0".into(),
            "evil\u{202E}txt.exe".into(),
            "isolate\u{2066}x".into(),
        ] {
            assert!(agent_name(Some(&bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn redirects_percent_encode_their_parameters() {
        assert_eq!(
            redirect_uri_with(
                "http://127.0.0.1:4000/callback",
                &[
                    ("code", "a b&c"),
                    ("state", "x=y"),
                    ("iss", "https://cpmesh.test")
                ]
            ),
            "http://127.0.0.1:4000/callback?code=a%20b%26c&state=x%3Dy&iss=https%3A%2F%2Fcpmesh.test"
        );
    }
}
