//! cpmesh relay server library.
//!
//! The binary in `main.rs` wires configuration, the database and the HTTP router
//! together; everything else lives here so it can be exercised by tests.

pub mod audit;
pub mod blocking;
pub mod config;
pub mod db;
pub mod email;
pub mod mfa;
pub mod models;
pub mod pii;
pub mod rbac;
pub mod routes;
pub mod settings;
pub mod spa;
pub mod ws;

#[cfg(test)]
pub(crate) mod test_support;

use std::sync::Arc;

use crate::config::Config;
use crate::db::Db;
use crate::pii::PiiService;
use crate::routes::auth::PkceCodeStore;
use crate::settings::SettingsCache;
use crate::ws::Hub;

pub struct RateLimiters {
    pub login: Arc<routes::middleware::IpRateLimiter>,
    pub register: Arc<routes::middleware::IpRateLimiter>,
    pub refresh: Arc<routes::middleware::IpRateLimiter>,
    /// Second-factor codes and emailed confirmation codes.
    pub mfa: Arc<routes::middleware::IpRateLimiter>,
}

pub struct AppState {
    pub db: Db,
    pub config: Config,
    pub hub: Hub,
    pub pii: Option<PiiService>,
    pub auth: routes::auth_service::AuthService,
    pub email: email::EmailService,
    pub pkce_store: PkceCodeStore,
    pub rate_limiters: RateLimiters,
    /// Settings changed from the admin console.
    pub settings: SettingsCache,
}
