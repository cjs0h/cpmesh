//! Scopes an agent grant can hold.

use std::fmt;

/// Read clipboard history: `GET /api/clipboard`, and new entries on the WebSocket.
pub const SCOPE_CLIPBOARD_READ: &str = "clipboard:read";
/// Push clipboard entries over the WebSocket.
pub const SCOPE_CLIPBOARD_WRITE: &str = "clipboard:write";
/// Delete single clipboard entries (never the whole history).
pub const SCOPE_CLIPBOARD_DELETE: &str = "clipboard:delete";
/// Remove devices from the account.
pub const SCOPE_DEVICES_MANAGE: &str = "devices:manage";

/// One scope of an agent grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    ClipboardRead,
    ClipboardWrite,
    ClipboardDelete,
    DevicesManage,
}

impl Scope {
    pub const ALL: [Scope; 4] = [
        Scope::ClipboardRead,
        Scope::ClipboardWrite,
        Scope::ClipboardDelete,
        Scope::DevicesManage,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Scope::ClipboardRead => SCOPE_CLIPBOARD_READ,
            Scope::ClipboardWrite => SCOPE_CLIPBOARD_WRITE,
            Scope::ClipboardDelete => SCOPE_CLIPBOARD_DELETE,
            Scope::DevicesManage => SCOPE_DEVICES_MANAGE,
        }
    }

    pub fn parse(name: &str) -> Option<Scope> {
        Scope::ALL.into_iter().find(|scope| scope.as_str() == name)
    }

    const fn bit(self) -> u8 {
        1 << self as u8
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A set of scopes. Formats as an RFC 6749 scope string: names separated by spaces.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Scopes(u8);

impl Scopes {
    pub const NONE: Scopes = Scopes(0);

    pub const fn of(scopes: &[Scope]) -> Scopes {
        let mut bits = 0;
        let mut i = 0;
        while i < scopes.len() {
            bits |= scopes[i].bit();
            i += 1;
        }
        Scopes(bits)
    }

    /// Parses a scope string from a request; a scope this server does not know is an
    /// error (`invalid_scope`).
    pub fn parse(value: &str) -> Result<Scopes, UnknownScope> {
        value
            .split_ascii_whitespace()
            .try_fold(Scopes::NONE, |scopes, name| match Scope::parse(name) {
                Some(scope) => Ok(scopes.with(scope)),
                None => Err(UnknownScope(name.to_string())),
            })
    }

    /// Reads the scopes recorded in a token or a stored grant. Names this server does
    /// not know (from a newer or older version) are dropped, never granted.
    pub fn from_recorded<'a>(names: impl IntoIterator<Item = &'a str>) -> Scopes {
        names
            .into_iter()
            .filter_map(Scope::parse)
            .fold(Scopes::NONE, Scopes::with)
    }

    pub const fn contains(self, scope: Scope) -> bool {
        self.0 & scope.bit() != 0
    }

    /// Whether this set and `other` have a scope in common.
    pub const fn intersects(self, other: Scopes) -> bool {
        self.0 & other.0 != 0
    }

    pub const fn with(self, scope: Scope) -> Scopes {
        Scopes(self.0 | scope.bit())
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn iter(self) -> impl Iterator<Item = Scope> {
        Scope::ALL
            .into_iter()
            .filter(move |scope| self.contains(*scope))
    }

    pub fn names(self) -> Vec<&'static str> {
        self.iter().map(Scope::as_str).collect()
    }
}

impl fmt::Display for Scopes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.names().join(" "))
    }
}

impl fmt::Debug for Scopes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.names()).finish()
    }
}

impl FromIterator<Scope> for Scopes {
    fn from_iter<I: IntoIterator<Item = Scope>>(iter: I) -> Self {
        iter.into_iter().fold(Scopes::NONE, Scopes::with)
    }
}

/// A requested scope this server does not offer.
#[derive(Debug, PartialEq, Eq)]
pub struct UnknownScope(pub String);

impl fmt::Display for UnknownScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown scope: {}", self.0)
    }
}

impl std::error::Error for UnknownScope {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_names_round_trip() {
        for scope in Scope::ALL {
            assert_eq!(Scope::parse(scope.as_str()), Some(scope));
            assert_eq!(scope.to_string(), scope.as_str());
        }
        assert_eq!(Scope::parse("clipboard:READ"), None);
        assert_eq!(Scope::parse(""), None);
    }

    #[test]
    fn scope_strings_parse_strictly_and_format_in_a_fixed_order() {
        let scopes = Scopes::parse("devices:manage  clipboard:read\tclipboard:read").unwrap();
        assert_eq!(scopes.to_string(), "clipboard:read devices:manage");
        assert!(scopes.contains(Scope::ClipboardRead));
        assert!(!scopes.contains(Scope::ClipboardWrite));
        assert_eq!(Scopes::parse("").unwrap(), Scopes::NONE);
        assert_eq!(
            Scopes::parse("clipboard:read admin").unwrap_err(),
            UnknownScope("admin".into())
        );

        let all: Scopes = Scope::ALL.into_iter().collect();
        assert_eq!(
            all.to_string(),
            "clipboard:read clipboard:write clipboard:delete devices:manage"
        );
        assert_eq!(Scopes::parse(&all.to_string()).unwrap(), all);
        assert_eq!(format!("{all:?}").matches(':').count(), 4);
    }

    #[test]
    fn recorded_scopes_drop_unknown_names() {
        let scopes = Scopes::from_recorded("clipboard:write admin:all".split(' '));
        assert_eq!(scopes, Scopes::of(&[Scope::ClipboardWrite]));
        assert!(Scopes::from_recorded([]).is_empty());
    }

    #[test]
    fn intersection_needs_a_common_scope() {
        let read_or_write = Scopes::of(&[Scope::ClipboardRead, Scope::ClipboardWrite]);
        assert!(Scopes::of(&[Scope::ClipboardWrite]).intersects(read_or_write));
        assert!(!Scopes::of(&[Scope::DevicesManage]).intersects(read_or_write));
        assert!(!Scopes::NONE.intersects(read_or_write));
    }
}
