//! Roles and permissions for the admin console.
//!
//! Every account has a role. `user` is a regular member; the other roles are staff
//! with access to the admin console, each a superset of the one before it.

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    /// Read-only access to the admin console.
    Viewer,
    /// Viewer, plus account support: verify emails, change plans, suspend and sign out members.
    Support,
    /// Support, plus deleting users, resetting 2FA, and managing plans, releases,
    /// settings and API tokens.
    Admin,
    /// Admin, plus managing staff accounts and roles.
    Owner,
}

impl Role {
    pub const ALL: [Role; 5] = [
        Role::User,
        Role::Viewer,
        Role::Support,
        Role::Admin,
        Role::Owner,
    ];

    pub fn parse(value: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == value)
    }

    /// Unknown values (which the schema should never hold) fall back to the least
    /// privileged role.
    pub fn from_db(value: &str) -> Role {
        Role::parse(value).unwrap_or(Role::User)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Viewer => "viewer",
            Role::Support => "support",
            Role::Admin => "admin",
            Role::Owner => "owner",
        }
    }

    /// Staff roles can open the admin console.
    pub fn is_staff(self) -> bool {
        self != Role::User
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    /// Read users, stats, audit logs, plans, releases and settings.
    View,
    /// Verify emails, resend verification, change plans, suspend and sign out members.
    ManageUsers,
    DeleteUsers,
    /// Reset a member's two-factor authentication.
    ResetMfa,
    /// Plans, download links, releases and installer uploads.
    ManageContent,
    /// Runtime settings and SMTP/OIDC checks.
    ManageSettings,
    ManageApiTokens,
    /// Change roles, and act on other staff accounts.
    ManageStaff,
}

impl Permission {
    pub const ALL: [Permission; 8] = [
        Permission::View,
        Permission::ManageUsers,
        Permission::DeleteUsers,
        Permission::ResetMfa,
        Permission::ManageContent,
        Permission::ManageSettings,
        Permission::ManageApiTokens,
        Permission::ManageStaff,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Permission::View => "view",
            Permission::ManageUsers => "manage_users",
            Permission::DeleteUsers => "delete_users",
            Permission::ResetMfa => "reset_mfa",
            Permission::ManageContent => "manage_content",
            Permission::ManageSettings => "manage_settings",
            Permission::ManageApiTokens => "manage_api_tokens",
            Permission::ManageStaff => "manage_staff",
        }
    }

    /// The least privileged role that holds this permission.
    fn minimum_role(self) -> Role {
        match self {
            Permission::View => Role::Viewer,
            Permission::ManageUsers => Role::Support,
            Permission::DeleteUsers
            | Permission::ResetMfa
            | Permission::ManageContent
            | Permission::ManageSettings
            | Permission::ManageApiTokens => Role::Admin,
            Permission::ManageStaff => Role::Owner,
        }
    }
}

pub fn permits(role: Role, permission: Permission) -> bool {
    role >= permission.minimum_role()
}

/// Permission names held by `role`, for clients deciding which controls to show.
pub fn permission_names(role: Role) -> Vec<&'static str> {
    Permission::ALL
        .into_iter()
        .filter(|p| permits(role, *p))
        .map(Permission::as_str)
        .collect()
}

/// Acting on another staff account needs the staff permission on top of the action's own.
pub fn permits_on_target(actor: Role, permission: Permission, target: Role) -> bool {
    permits(actor, permission) && (!target.is_staff() || permits(actor, Permission::ManageStaff))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_round_trip_and_unknown_values_are_least_privileged() {
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert_eq!(Role::parse("root"), None);
        assert_eq!(Role::parse("Admin"), None);
        assert_eq!(Role::from_db("root"), Role::User);
        assert!(!Role::User.is_staff());
        assert!(Role::Viewer.is_staff() && Role::Owner.is_staff());
        assert_eq!(serde_json::to_value(Role::Support).unwrap(), "support");
    }

    #[test]
    fn permission_matrix() {
        use Permission::*;
        let expect: [(Role, &[Permission]); 5] = [
            (Role::User, &[]),
            (Role::Viewer, &[View]),
            (Role::Support, &[View, ManageUsers]),
            (
                Role::Admin,
                &[
                    View,
                    ManageUsers,
                    DeleteUsers,
                    ResetMfa,
                    ManageContent,
                    ManageSettings,
                    ManageApiTokens,
                ],
            ),
            (Role::Owner, &Permission::ALL),
        ];
        for (role, allowed) in expect {
            for p in Permission::ALL {
                assert_eq!(permits(role, p), allowed.contains(&p), "{role:?} {p:?}");
            }
            assert_eq!(
                permission_names(role),
                allowed.iter().map(|p| p.as_str()).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn acting_on_staff_needs_the_staff_permission() {
        use Permission::*;
        assert!(permits_on_target(Role::Support, ManageUsers, Role::User));
        assert!(!permits_on_target(Role::Support, ManageUsers, Role::Viewer));
        assert!(permits_on_target(Role::Admin, DeleteUsers, Role::User));
        assert!(!permits_on_target(Role::Admin, DeleteUsers, Role::Admin));
        assert!(permits_on_target(Role::Owner, DeleteUsers, Role::Admin));
        assert!(!permits_on_target(Role::Viewer, ManageUsers, Role::User));
    }
}
