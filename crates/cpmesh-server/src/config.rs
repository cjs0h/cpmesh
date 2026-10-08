#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    // RS256 JWT (replaces JWT_SECRET)
    pub jwt_active_kid: String,
    pub jwt_private_key_path: String,
    pub jwt_public_keys_path: String,
    pub addr: String,
    pub downloads_dir: String,
    pub allowed_origins: Vec<String>,
    pub pii_master_key: String,
    pub pii_hmac_key: String,
    pub initial_admin: String,
    pub initial_admin_password: String,
    pub initial_admin_email: String,
    pub insecure_dev: bool,
    pub registration_open: bool,
    pub base_url: String,
    // OIDC
    pub oidc_issuer_url: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
    pub oidc_callback_url: String,
    pub trust_proxy_headers: bool,
    // Group key rotation
    pub group_key_rotation_interval_hours: i64,
}

impl Config {
    /// Builds the configuration from process environment variables.
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Builds the configuration from an arbitrary variable source.
    ///
    /// `lookup` returns the raw value for a variable name, or `None` when unset.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        let env = |key: &str, default: &str| lookup(key).unwrap_or_else(|| default.to_string());

        let allowed_origins_str = env("ALLOWED_ORIGINS", "");
        let allowed_origins: Vec<String> = if allowed_origins_str.is_empty() {
            vec![]
        } else {
            allowed_origins_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        };

        let reg = env("REGISTRATION_OPEN", "true");
        let registration_open = !matches!(reg.to_lowercase().as_str(), "false" | "0");

        Config {
            database_url: env(
                "DATABASE_URL",
                "postgres://cpmesh:cpmesh@localhost:5432/cpmesh?sslmode=disable",
            ),
            jwt_active_kid: env("JWT_ACTIVE_KID", ""),
            jwt_private_key_path: env("JWT_PRIVATE_KEY_PATH", ""),
            jwt_public_keys_path: env("JWT_PUBLIC_KEYS_PATH", ""),
            addr: env("ADDR", "0.0.0.0:8080"),
            downloads_dir: env("DOWNLOADS_DIR", "./downloads"),
            allowed_origins,
            pii_master_key: env("PII_MASTER_KEY", ""),
            pii_hmac_key: env("PII_HMAC_KEY", ""),
            initial_admin: env("INITIAL_ADMIN", ""),
            initial_admin_password: env("INITIAL_ADMIN_PASSWORD", ""),
            initial_admin_email: env("INITIAL_ADMIN_EMAIL", ""),
            insecure_dev: env("CPNET_INSECURE_DEV", "0") == "1",
            registration_open,
            base_url: env("BASE_URL", "").trim_end_matches('/').to_string(),
            oidc_issuer_url: env("OIDC_ISSUER_URL", ""),
            oidc_client_id: env("OIDC_CLIENT_ID", ""),
            oidc_client_secret: env("OIDC_CLIENT_SECRET", ""),
            oidc_callback_url: env("OIDC_CALLBACK_URL", ""),
            trust_proxy_headers: env("TRUST_PROXY_HEADERS", "0") == "1",
            group_key_rotation_interval_hours: env("GROUP_KEY_ROTATION_INTERVAL_HOURS", "24")
                .parse()
                .unwrap_or(24),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config_from(vars: &[(&str, &str)]) -> Config {
        let map: HashMap<&str, &str> = vars.iter().copied().collect();
        Config::from_lookup(|k| map.get(k).map(|v| v.to_string()))
    }

    #[test]
    fn defaults_when_nothing_is_set() {
        let cfg = config_from(&[]);
        assert_eq!(
            cfg.database_url,
            "postgres://cpmesh:cpmesh@localhost:5432/cpmesh?sslmode=disable"
        );
        assert_eq!(cfg.addr, "0.0.0.0:8080");
        assert_eq!(cfg.downloads_dir, "./downloads");
        assert!(cfg.allowed_origins.is_empty());
        assert!(cfg.jwt_active_kid.is_empty());
        assert!(cfg.pii_master_key.is_empty());
        assert!(!cfg.insecure_dev);
        assert!(cfg.registration_open);
        assert_eq!(cfg.base_url, "");
        assert!(!cfg.trust_proxy_headers);
        assert_eq!(cfg.group_key_rotation_interval_hours, 24);
    }

    #[test]
    fn allowed_origins_are_split_trimmed_and_filtered() {
        let cfg = config_from(&[(
            "ALLOWED_ORIGINS",
            " https://a.example , https://b.example,, ,http://localhost:5173 ",
        )]);
        assert_eq!(
            cfg.allowed_origins,
            vec![
                "https://a.example",
                "https://b.example",
                "http://localhost:5173"
            ]
        );
    }

    #[test]
    fn registration_open_accepts_false_and_zero_case_insensitively() {
        for v in ["false", "FALSE", "False", "0"] {
            assert!(
                !config_from(&[("REGISTRATION_OPEN", v)]).registration_open,
                "{v}"
            );
        }
        for v in ["true", "1", "yes", "anything-else", ""] {
            assert!(
                config_from(&[("REGISTRATION_OPEN", v)]).registration_open,
                "{v}"
            );
        }
    }

    #[test]
    fn boolean_flags_require_exactly_one() {
        assert!(config_from(&[("CPNET_INSECURE_DEV", "1")]).insecure_dev);
        assert!(!config_from(&[("CPNET_INSECURE_DEV", "true")]).insecure_dev);
        assert!(!config_from(&[("CPNET_INSECURE_DEV", "0")]).insecure_dev);
        assert!(config_from(&[("TRUST_PROXY_HEADERS", "1")]).trust_proxy_headers);
        assert!(!config_from(&[("TRUST_PROXY_HEADERS", "yes")]).trust_proxy_headers);
    }

    #[test]
    fn base_url_trailing_slashes_are_trimmed() {
        let cfg = config_from(&[("BASE_URL", "https://cpmesh.example///")]);
        assert_eq!(cfg.base_url, "https://cpmesh.example");
        let cfg = config_from(&[("BASE_URL", "https://cpmesh.example")]);
        assert_eq!(cfg.base_url, "https://cpmesh.example");
    }

    #[test]
    fn rotation_interval_parses_or_falls_back() {
        assert_eq!(
            config_from(&[("GROUP_KEY_ROTATION_INTERVAL_HOURS", "72")])
                .group_key_rotation_interval_hours,
            72
        );
        assert_eq!(
            config_from(&[("GROUP_KEY_ROTATION_INTERVAL_HOURS", "soon")])
                .group_key_rotation_interval_hours,
            24
        );
    }

    #[test]
    fn explicit_values_are_passed_through() {
        let cfg = config_from(&[
            ("DATABASE_URL", "postgres://u:p@db/x"),
            ("JWT_ACTIVE_KID", "kid-1"),
            ("JWT_PRIVATE_KEY_PATH", "/keys/priv.pem"),
            ("JWT_PUBLIC_KEYS_PATH", "/keys/pub.json"),
            ("ADDR", "127.0.0.1:9000"),
            ("DOWNLOADS_DIR", "/srv/dl"),
            ("PII_MASTER_KEY", "mk"),
            ("PII_HMAC_KEY", "hk"),
            ("INITIAL_ADMIN", "admin"),
            ("INITIAL_ADMIN_PASSWORD", "pw"),
            ("INITIAL_ADMIN_EMAIL", "a@b.c"),
            ("OIDC_ISSUER_URL", "https://accounts.google.com"),
            ("OIDC_CLIENT_ID", "cid"),
            ("OIDC_CLIENT_SECRET", "cs"),
            ("OIDC_CALLBACK_URL", "https://cb"),
        ]);
        assert_eq!(cfg.database_url, "postgres://u:p@db/x");
        assert_eq!(cfg.jwt_active_kid, "kid-1");
        assert_eq!(cfg.jwt_private_key_path, "/keys/priv.pem");
        assert_eq!(cfg.jwt_public_keys_path, "/keys/pub.json");
        assert_eq!(cfg.addr, "127.0.0.1:9000");
        assert_eq!(cfg.downloads_dir, "/srv/dl");
        assert_eq!(cfg.pii_master_key, "mk");
        assert_eq!(cfg.pii_hmac_key, "hk");
        assert_eq!(cfg.initial_admin, "admin");
        assert_eq!(cfg.initial_admin_password, "pw");
        assert_eq!(cfg.initial_admin_email, "a@b.c");
        assert_eq!(cfg.oidc_issuer_url, "https://accounts.google.com");
        assert_eq!(cfg.oidc_client_id, "cid");
        assert_eq!(cfg.oidc_client_secret, "cs");
        assert_eq!(cfg.oidc_callback_url, "https://cb");
    }

    #[test]
    fn from_env_does_not_panic() {
        // Smoke test: reads whatever the process environment holds.
        let _ = Config::from_env();
    }
}
