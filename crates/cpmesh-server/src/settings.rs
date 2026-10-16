//! Settings changed at runtime from the admin console.
//!
//! Stored in `app_settings`; a setting nobody changed falls back to its environment
//! default. Values are cached briefly so hot paths (registration, the public settings
//! endpoint) do not query the database every time.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::Config;
use crate::db::Db;

pub const KEY_REGISTRATION_OPEN: &str = "registration_open";
pub const KEY_BANNER: &str = "banner";

const CACHE_TTL: Duration = Duration::from_secs(15);
pub const BANNER_MAX_LEN: usize = 500;
pub const BANNER_TONES: [&str; 3] = ["info", "warning", "danger"];

/// A notice shown at the top of the web dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Banner {
    pub message: String,
    /// "info", "warning" or "danger".
    pub tone: String,
}

impl Banner {
    pub fn validate(&self) -> Result<(), &'static str> {
        let len = self.message.trim().chars().count();
        if len == 0 {
            return Err("banner message is empty");
        }
        if len > BANNER_MAX_LEN {
            return Err("banner message is too long (500 characters at most)");
        }
        if !BANNER_TONES.contains(&self.tone.as_str()) {
            return Err("banner tone must be info, warning or danger");
        }
        Ok(())
    }
}

/// Overrides set from the admin console; `None` means "use the default".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeSettings {
    pub registration_open: Option<bool>,
    pub banner: Option<Banner>,
}

impl RuntimeSettings {
    pub fn from_rows(rows: Vec<(String, serde_json::Value)>) -> Self {
        let mut settings = RuntimeSettings::default();
        for (key, value) in rows {
            match key.as_str() {
                KEY_REGISTRATION_OPEN => settings.registration_open = value.as_bool(),
                KEY_BANNER => settings.banner = serde_json::from_value(value).ok(),
                _ => {}
            }
        }
        settings
    }

    /// Whether self-service registration is open: the override, else `REGISTRATION_OPEN`.
    pub fn registration_open(&self, config: &Config) -> bool {
        self.registration_open.unwrap_or(config.registration_open)
    }
}

#[derive(Default)]
pub struct SettingsCache {
    inner: RwLock<Option<(Instant, RuntimeSettings)>>,
}

impl SettingsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current settings. When the database is unreachable, the last known settings (or
    /// the defaults) apply.
    pub async fn get(&self, db: &Db) -> RuntimeSettings {
        if let Some((loaded, settings)) = &*self.inner.read().await
            && loaded.elapsed() < CACHE_TTL
        {
            return settings.clone();
        }
        match db.load_settings().await {
            Ok(rows) => {
                let settings = RuntimeSettings::from_rows(rows);
                *self.inner.write().await = Some((Instant::now(), settings.clone()));
                settings
            }
            Err(_) => self
                .inner
                .read()
                .await
                .as_ref()
                .map(|(_, s)| s.clone())
                .unwrap_or_default(),
        }
    }

    /// Drops the cached copy after a change, so this instance sees it immediately.
    pub async fn invalidate(&self) {
        *self.inner.write().await = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rows_become_settings_and_unknown_keys_are_ignored() {
        let settings = RuntimeSettings::from_rows(vec![
            (KEY_REGISTRATION_OPEN.into(), json!(false)),
            (
                KEY_BANNER.into(),
                json!({"message": "Maintenance tonight", "tone": "warning"}),
            ),
            ("something_else".into(), json!(1)),
        ]);
        assert_eq!(settings.registration_open, Some(false));
        assert_eq!(
            settings.banner,
            Some(Banner {
                message: "Maintenance tonight".into(),
                tone: "warning".into()
            })
        );
        assert_eq!(
            RuntimeSettings::from_rows(vec![]),
            RuntimeSettings::default()
        );
    }

    #[test]
    fn registration_override_wins_over_environment() {
        let mut config = Config::from_lookup(|_| None);
        config.registration_open = true;
        let mut settings = RuntimeSettings::default();
        assert!(settings.registration_open(&config));
        settings.registration_open = Some(false);
        assert!(!settings.registration_open(&config));
        config.registration_open = false;
        settings.registration_open = Some(true);
        assert!(settings.registration_open(&config));
    }

    #[test]
    fn banners_are_validated() {
        let banner = |message: &str, tone: &str| Banner {
            message: message.into(),
            tone: tone.into(),
        };
        assert!(banner("Hello", "info").validate().is_ok());
        assert!(banner("  ", "info").validate().is_err());
        assert!(banner("Hello", "neon").validate().is_err());
        assert!(banner(&"x".repeat(501), "danger").validate().is_err());
        assert!(banner(&"x".repeat(500), "danger").validate().is_ok());
    }

    #[tokio::test]
    async fn cache_falls_back_to_defaults_without_a_database() {
        let pool = sqlx::PgPool::connect_lazy("postgres://x@127.0.0.1:1/none").unwrap();
        pool.close().await;
        let db = Db { pool };
        let cache = SettingsCache::new();
        assert_eq!(cache.get(&db).await, RuntimeSettings::default());
        cache.invalidate().await;
        assert_eq!(cache.get(&db).await, RuntimeSettings::default());
    }
}
