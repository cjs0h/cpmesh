//! OAuth for AI agents. The server authorizes agents (OAuth clients such as
//! cpmesh-mcp) through grants the user approves; agent tokens carry the grant's
//! client, scopes and ID (the `cid`, `scp` and `gid` claims).
//!
//! - [`scopes`]: what a grant can allow.
//! - [`policy`]: which routes and WebSocket messages agents may use (default-deny).
//! - [`grants`]: checking grants on every request, binding a grant to its agent's
//!   device, and revoking grants.

pub mod grants;
pub mod policy;
pub mod scopes;

use std::time::Duration;

pub use scopes::{Scope, Scopes};

/// Client ID of cpmesh-mcp, the first-party MCP server (a public client).
pub const MCP_CLIENT_ID: &str = "cpmesh-mcp";

/// Clients the server issues agent tokens to. A token naming any other client is invalid.
const CLIENT_IDS: &[&str] = &[MCP_CLIENT_ID];

/// The registered client with this ID.
pub fn registered_client(client_id: &str) -> Option<&'static str> {
    CLIENT_IDS.iter().copied().find(|id| *id == client_id)
}

/// How long an agent refresh token lasts. Every refresh issues a new one, so a grant
/// stays usable for as long as its agent refreshes at least this often.
pub const AGENT_REFRESH_TTL: Duration = Duration::from_secs(30 * 24 * 3600);

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
    }
}
