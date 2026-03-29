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
    pub fn from_env() -> Self {
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
            database_url: env("DATABASE_URL", "postgres://cpmesh:cpmesh@localhost:5432/cpmesh?sslmode=disable"),
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
            group_key_rotation_interval_hours: env("GROUP_KEY_ROTATION_INTERVAL_HOURS", "24").parse().unwrap_or(24),
        }
    }
}

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
