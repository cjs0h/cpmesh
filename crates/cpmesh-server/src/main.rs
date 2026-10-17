use argon2::PasswordHasher;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use cpmesh_server::config::Config;
use cpmesh_server::db::Db;
use cpmesh_server::pii::PiiService;
use cpmesh_server::routes::auth::PkceCodeStore;
use cpmesh_server::settings::SettingsCache;
use cpmesh_server::ws::Hub;
use cpmesh_server::{AppState, RateLimiters, email, routes, ws};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cpmesh_server=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env();

    // Security validation: RS256 JWT keys
    let mut missing_jwt_config = Vec::new();
    if config.jwt_active_kid.trim().is_empty() {
        missing_jwt_config.push("JWT_ACTIVE_KID");
    }
    if config.jwt_private_key_path.trim().is_empty() {
        missing_jwt_config.push("JWT_PRIVATE_KEY_PATH");
    }
    if config.jwt_public_keys_path.trim().is_empty() {
        missing_jwt_config.push("JWT_PUBLIC_KEYS_PATH");
    }
    if !missing_jwt_config.is_empty() {
        error!(
            "FATAL: Missing required RS256 JWT configuration: {}.",
            missing_jwt_config.join(", ")
        );
        error!(
            "Generate dev keys with ./scripts/generate-dev-jwt.sh or pwsh ./scripts/generate-dev-jwt.ps1 and set the env vars explicitly."
        );
        std::process::exit(1);
    }

    if config.database_url.contains("sslmode=disable") {
        warn!("Database connection uses sslmode=disable. Use sslmode=require for production.");
    }

    // PII encryption
    let pii = if !config.pii_master_key.is_empty() && !config.pii_hmac_key.is_empty() {
        match PiiService::new(&config.pii_master_key, &config.pii_hmac_key) {
            Ok(p) => {
                info!("PII encryption at rest: enabled");
                Some(p)
            }
            Err(e) => {
                error!("Failed to initialize PII encryption: {e}");
                std::process::exit(1);
            }
        }
    } else {
        warn!("PII_MASTER_KEY and/or PII_HMAC_KEY not set. PII encryption disabled.");
        if !config.insecure_dev {
            error!(
                "FATAL: Refusing to start without PII encryption keys. Set CPNET_INSECURE_DEV=1 to bypass."
            );
            std::process::exit(1);
        }
        None
    };

    // Database
    let db = match Db::connect(&config.database_url).await {
        Ok(db) => db,
        Err(e) => {
            error!("Failed to connect to database: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = db.migrate().await {
        error!("Failed to run migrations: {e}");
        std::process::exit(1);
    }
    info!("Database migrated successfully");

    // Seed initial admin (uses Argon2 for password hashing — no JWT keys needed)
    if !config.initial_admin.is_empty() {
        let admin_password = &config.initial_admin_password;
        if admin_password.is_empty() {
            warn!("INITIAL_ADMIN_PASSWORD is empty, skipping admin seeding");
        } else {
            if (admin_password == "changeme123" || admin_password == "admin123")
                && !config.insecure_dev
            {
                error!(
                    "FATAL: Refusing to start with weak admin password. Set CPNET_INSECURE_DEV=1 to bypass."
                );
                std::process::exit(1);
            }
            match argon2::Argon2::default().hash_password(admin_password.as_bytes()) {
                Ok(hash) => {
                    if let Err(e) = db
                        .seed_admin(
                            &config.initial_admin,
                            &hash.to_string(),
                            &config.initial_admin_email,
                            pii.as_ref(),
                        )
                        .await
                    {
                        warn!("Could not seed admin {:?}: {e}", config.initial_admin);
                    } else {
                        info!("Admin account {:?} ready", config.initial_admin);
                    }
                }
                Err(e) => warn!("Could not hash admin password: {e}"),
            }
        }
    }

    // Build auth service with RS256 keys from file paths
    let private_pem = std::fs::read_to_string(&config.jwt_private_key_path).unwrap_or_else(|e| {
        error!(
            "FATAL: Cannot read JWT private key from '{}': {e}",
            config.jwt_private_key_path
        );
        std::process::exit(1);
    });
    let public_keys_json =
        std::fs::read_to_string(&config.jwt_public_keys_path).unwrap_or_else(|e| {
            error!(
                "FATAL: Cannot read JWT public keys from '{}': {e}",
                config.jwt_public_keys_path
            );
            std::process::exit(1);
        });
    let auth = match routes::auth_service::AuthService::new(
        &config.jwt_active_kid,
        &private_pem,
        &public_keys_json,
        Some(db.pool.clone()),
    ) {
        Ok(a) => {
            info!(
                "JWT signing: RS256 (kid={}, key={})",
                config.jwt_active_kid, config.jwt_private_key_path
            );
            a
        }
        Err(e) => {
            error!("Failed to initialize RS256 auth: {e}");
            std::process::exit(1);
        }
    };
    let hub = Hub::new();
    let email_svc = email::EmailService::from_env();

    let rate_limiters = RateLimiters {
        login: routes::middleware::build_rate_limiter(5), // 5 per minute
        register: routes::middleware::build_rate_limiter(3), // 3 per minute
        refresh: routes::middleware::build_rate_limiter(10), // 10 per minute
        mfa: routes::middleware::build_rate_limiter(10),  // 10 per minute
        oauth_device: routes::middleware::build_rate_limiter(10), // 10 per minute
        user_code_ip: routes::middleware::build_rate_limiter(20), // 20 per minute
        user_code_user: routes::middleware::build_user_rate_limiter(10), // 10 per minute
    };

    let state = Arc::new(AppState {
        db,
        config: config.clone(),
        hub,
        pii,
        auth,
        email: email_svc,
        pkce_store: PkceCodeStore::new(),
        rate_limiters,
        settings: SettingsCache::new(),
    });

    // Start background cleanup tasks
    state.auth.start_cleanup();
    ws::start_hub_cleanup(state.clone());

    // Start PKCE code store cleanup (remove expired codes every 30s)
    {
        let store = state.pkce_store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                store.cleanup();
            }
        });
    }

    let app = routes::build_router(state.clone());

    let addr: SocketAddr = config.addr.parse().unwrap_or_else(|_| {
        warn!("Invalid ADDR '{}', using 0.0.0.0:8080", config.addr);
        "0.0.0.0:8080"
            .parse()
            .expect("default address parse failed")
    });

    info!("cpmesh server listening on {addr}");
    if !config.allowed_origins.is_empty() {
        info!("Allowed CORS origins: {:?}", config.allowed_origins);
    } else {
        info!("No ALLOWED_ORIGINS set: CORS disabled (same-origin only)");
    }

    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind TCP listener");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("Axum server failed to start");

    info!("Server stopped");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received, stopping...");
}
