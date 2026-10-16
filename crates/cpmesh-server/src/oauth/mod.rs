//! OAuth for AI agents. The server authorizes agents (OAuth clients such as
//! cpmesh-mcp) through grants the user approves; agent tokens carry the grant's
//! client, scopes and ID (the `cid`, `scp` and `gid` claims).
//!
//! - [`scopes`]: what a grant can allow.
//! - [`policy`]: which routes and WebSocket messages agents may use (default-deny).
//! - [`grants`]: checking grants on every request, binding a grant to its agent's
//!   device, and revoking grants.
//! - [`server`]: the authorization server's endpoints (`/oauth/*`, RFC 8414 metadata,
//!   `/activate`): authorization code with PKCE, the device authorization grant
//!   (RFC 8628), refresh and revocation (RFC 7009).
//! - [`consent`]: the dashboard's side: approving or denying an agent, and the
//!   "Connected agents" list.
//! - [`codes`] and [`request`]: codes and request parameters shared by both.

pub mod codes;
pub mod consent;
pub mod grants;
pub mod policy;
pub mod request;
pub mod scopes;
pub mod server;

use std::time::Duration;

pub use scopes::{Scope, Scopes};

use crate::config::Config;

/// Client ID of cpmesh-mcp, the first-party MCP server (a public client).
pub const MCP_CLIENT_ID: &str = "cpmesh-mcp";

/// A client the server issues agent tokens to. Every client is a first-party public
/// client (`token_endpoint_auth_method: none`): there is no dynamic registration.
#[derive(Debug)]
pub struct Client {
    pub id: &'static str,
    /// Shown on the consent page and in the list of connected agents.
    pub name: &'static str,
    /// Path of the client's loopback redirect URIs (RFC 8252 section 7.3).
    loopback_path: &'static str,
}

/// The registered clients. A token or request naming any other client is invalid.
static CLIENTS: &[Client] = &[Client {
    id: MCP_CLIENT_ID,
    name: "cpmesh MCP",
    loopback_path: "/callback",
}];

/// The registered client with this ID.
pub fn client(client_id: &str) -> Option<&'static Client> {
    CLIENTS.iter().find(|client| client.id == client_id)
}

/// The ID of the registered client with this ID.
pub fn registered_client(client_id: &str) -> Option<&'static str> {
    client(client_id).map(|client| client.id)
}

impl Client {
    /// Whether `uri` is one of this client's redirect URIs, compared as a string:
    /// exactly `http://127.0.0.1:{port}{path}` or `http://[::1]:{port}{path}`, with any
    /// port from 1 to 65535 (the agent listens on whatever port it got). `localhost`,
    /// https, other hosts and paths, userinfo, queries and fragments are refused.
    pub fn allows_redirect_uri(&self, uri: &str) -> bool {
        let Some(rest) = uri
            .strip_prefix("http://127.0.0.1:")
            .or_else(|| uri.strip_prefix("http://[::1]:"))
        else {
            return false;
        };
        let Some(slash) = rest.find('/') else {
            return false;
        };
        let (port, path) = rest.split_at(slash);
        let canonical_port = (1..=5).contains(&port.len())
            && port.bytes().all(|b| b.is_ascii_digit())
            && !port.starts_with('0');
        canonical_port && port.parse::<u16>().is_ok() && path == self.loopback_path
    }
}

/// This server's issuer identifier (RFC 8414): `BASE_URL` without a trailing slash.
/// `None` when `BASE_URL` is not configured; agents cannot sign in then.
pub fn issuer(config: &Config) -> Option<&str> {
    let issuer = config.base_url.trim_end_matches('/');
    (!issuer.is_empty()).then_some(issuer)
}

/// How long an agent refresh token lasts. Every refresh issues a new one, so a grant
/// stays usable for as long as its agent refreshes at least this often.
pub const AGENT_REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

/// How long an authorization code can be exchanged after the user approved.
pub const AUTHORIZATION_CODE_TTL: Duration = Duration::from_secs(120);

/// How long a device code (and its user code) waits for the user's decision.
pub const DEVICE_CODE_TTL: Duration = Duration::from_secs(600);

/// How often an agent may poll for its device code's outcome, at first. Every
/// `slow_down` answer adds [`SLOW_DOWN_STEP`] for that device code.
pub const DEVICE_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// What polling too fast adds to a device code's interval (RFC 8628 section 3.5).
pub const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

/// The device authorization grant type (RFC 8628).
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// The agent behind a session, as recorded in its tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentClaims {
    pub client_id: &'static str,
    pub scopes: Scopes,
    pub grant_id: uuid::Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_registered_clients_are_known() {
        assert_eq!(registered_client("cpmesh-mcp"), Some(MCP_CLIENT_ID));
        assert_eq!(registered_client("cpmesh-MCP"), None);
        assert_eq!(registered_client(""), None);
        assert_eq!(client(MCP_CLIENT_ID).unwrap().name, "cpmesh MCP");
    }

    #[test]
    fn loopback_redirect_uris_take_any_port_and_nothing_else() {
        let mcp = client(MCP_CLIENT_ID).unwrap();
        for allowed in [
            "http://127.0.0.1:1/callback",
            "http://127.0.0.1:8080/callback",
            "http://127.0.0.1:65535/callback",
            "http://[::1]:49152/callback",
            "http://[::1]:1/callback",
        ] {
            assert!(mcp.allows_redirect_uri(allowed), "{allowed}");
        }
        for refused in [
            "",
            "http://localhost:8080/callback",
            "https://127.0.0.1:8080/callback",
            "HTTP://127.0.0.1:8080/callback",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:/callback",
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1:65536/callback",
            "http://127.0.0.1:99999/callback",
            "http://127.0.0.1:080/callback",
            "http://127.0.0.1:123456/callback",
            "http://127.0.0.1:+80/callback",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8080/callback/",
            "http://127.0.0.1:8080/Callback",
            "http://127.0.0.1:8080/callback?next=x",
            "http://127.0.0.1:8080/callback#frag",
            "http://127.0.0.1:8080/other",
            "http://127.0.0.1:8080/callback/../callback",
            "http://127.0.0.1:8080/%63allback",
            "http://user@127.0.0.1:8080/callback",
            "http://127.0.0.1:8080@evil.example/callback",
            "http://127.0.0.1.evil.example:8080/callback",
            "http://127.0.0.2:8080/callback",
            "http://0.0.0.0:8080/callback",
            "http://[::1]/callback",
            "http://[0:0:0:0:0:0:0:1]:8080/callback",
            "http://[::ffff:127.0.0.1]:8080/callback",
            "http://evil.example/callback",
            "cpmesh://auth/callback",
            " http://127.0.0.1:8080/callback",
            "http://127.0.0.1:8080/callback ",
        ] {
            assert!(!mcp.allows_redirect_uri(refused), "{refused:?}");
        }
    }

    #[test]
    fn the_issuer_is_the_base_url_without_a_trailing_slash() {
        let mut config = Config::from_lookup(|_| None);
        assert_eq!(issuer(&config), None);
        config.base_url = "https://cpmesh.example/".into();
        assert_eq!(issuer(&config), Some("https://cpmesh.example"));
        config.base_url = "https://example.com/cpmesh".into();
        assert_eq!(issuer(&config), Some("https://example.com/cpmesh"));
        config.base_url = "/".into();
        assert_eq!(issuer(&config), None);
    }
}
