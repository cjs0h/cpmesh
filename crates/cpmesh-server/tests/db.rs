//! PostgreSQL-backed integration tests for the data layer.
//!
//! These run only when `TEST_DATABASE_URL` is set (e.g. by the Server CI job's
//! Postgres service container); otherwise every test prints a notice and passes.
//! Each test runs its migrations inside a fresh, uniquely named schema so tests
//! are fully isolated from each other and can execute in parallel.
//!
//! Locally:
//! ```text
//! docker run --rm -d --name cpmesh-test-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:55432:5432 postgres:16-alpine
//! TEST_DATABASE_URL=postgres://postgres:pw@127.0.0.1:55432/postgres cargo test -p cpmesh-server --test db
//! ```

use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;

use chrono::Utc;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, PgPool};

use cpmesh_server::db::{
    AppReleaseParams, CreateOidcUserParams, CreateUserParams, Db, DownloadLinkParams,
    SubscriptionPlanParams,
};
use cpmesh_server::models::*;
use cpmesh_server::pii::PiiService;

const PII_MASTER_KEY: &str = "q88dhm/y/vHc80+0LxAr8OFZwMfkPChvdR9UTMztn5I=";
const PII_HMAC_KEY: &str = "/aowWex7ni3uUnazmQk+rn6GPvb9lQFaSNIPlpiRAM0=";

fn pii() -> PiiService {
    PiiService::new(PII_MASTER_KEY, PII_HMAC_KEY).unwrap()
}

/// Runs `body` against a freshly migrated schema, then drops the schema even if the
/// body panicked (the panic is re-raised afterwards so the test still fails).
async fn with_db<F, Fut>(body: F)
where
    F: FnOnce(Arc<Db>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping database integration test");
        return;
    };

    let schema = format!("t_{}", uuid::Uuid::new_v4().simple());
    let admin = PgPool::connect(&url)
        .await
        .expect("connect to TEST_DATABASE_URL");

    // The extension must live in `public` so every per-test schema can resolve
    // uuid_generate_v4() through its search_path. Concurrent IF NOT EXISTS can race;
    // a failure here only matters if the extension really is missing, which the
    // migration below would surface.
    let _ = sqlx::query("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\" WITH SCHEMA public")
        .execute(&admin)
        .await;
    sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .expect("create test schema");

    let options = PgConnectOptions::from_str(&url)
        .expect("parse TEST_DATABASE_URL")
        .options([("search_path", format!("{schema},public"))]);
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .expect("connect test pool");
    let db = Arc::new(Db { pool: pool.clone() });
    db.migrate().await.expect("migrate test schema");

    let result = tokio::spawn(body(db)).await;

    pool.close().await;
    let _ = sqlx::query(AssertSqlSafe(format!("DROP SCHEMA \"{schema}\" CASCADE")))
        .execute(&admin)
        .await;
    admin.close().await;

    if let Err(e) = result {
        if e.is_panic() {
            std::panic::resume_unwind(e.into_panic());
        }
        panic!("test body was cancelled: {e}");
    }
}

async fn make_user(db: &Db, username: &str, pii: Option<&PiiService>) -> User {
    db.create_user(CreateUserParams {
        username,
        password_hash: "$argon2id$fake",
        email: &format!("{username}@example.com"),
        full_name: &format!("{username} Fullname"),
        country: Some("GB"),
        mobile: None,
        pii,
    })
    .await
    .expect("create user")
}

async fn make_device(db: &Db, user: &User, name: &str, status: &str) -> Device {
    db.create_device(user.id, name, &[4, 1, 2, 3], Some(&[0x30]), status, None)
        .await
        .expect("create device")
}

fn plan_params<'a>(name: &'a str, sort_order: i32, is_active: bool) -> SubscriptionPlanParams<'a> {
    SubscriptionPlanParams {
        name,
        description: "desc",
        price: 9.99,
        currency: "EUR",
        billing_period: "yearly",
        max_devices: 7,
        max_clipboard_history: 250,
        allowed_file_types: Box::leak(Box::new(serde_json::json!(["text", "image"]))),
        is_active,
        sort_order,
    }
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn migrate_is_idempotent_and_seeds_default_plans() {
    with_db(|db| async move {
        db.migrate().await.expect("second migrate");
        let plans = db.list_subscription_plans().await.unwrap();
        let names: Vec<&str> = plans.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["Free", "Pro", "Team"]);
        assert!(plans.iter().all(|p| p.is_active));
        assert_eq!(plans[0].max_devices, 2);
        assert_eq!(plans[1].price.to_string(), "5.99");

        let stats = db.admin_get_stats().await.unwrap();
        assert_eq!(stats.total_users, 0);
        assert_eq!(stats.total_devices, 0);
        assert_eq!(stats.total_entries, 0);
        assert_eq!(stats.active_connections, 0);
    })
    .await;
}

#[tokio::test]
async fn user_lifecycle_without_pii() {
    with_db(|db| async move {
        let user = make_user(&db, "Alice", None).await;
        assert_eq!(user.username, "Alice");
        assert_eq!(user.email.as_deref(), Some("Alice@example.com"));
        assert_eq!(user.email_idx.as_deref(), Some("alice@example.com"));
        assert_eq!(user.username_idx.as_deref(), Some("alice"));
        assert_eq!(user.full_name, "Alice Fullname");
        assert_eq!(user.country.as_deref(), Some("GB"));
        assert!(user.mobile.is_none());
        assert!(!user.email_verified);
        assert!(!user.is_admin);
        assert_eq!(user.auth_provider, "local");
        assert_eq!(user.tokens_revoked_before, Some(0));

        // Lookups are case-insensitive through the index columns
        assert_eq!(db.get_user_by_username("ALICE").await.unwrap().id, user.id);
        assert_eq!(
            db.get_user_by_username(" alice ").await.unwrap().id,
            user.id
        );
        assert_eq!(
            db.get_user_by_email("ALICE@EXAMPLE.COM", None)
                .await
                .unwrap()
                .id,
            user.id
        );
        assert_eq!(db.get_user_by_id(user.id).await.unwrap().username, "Alice");
        assert!(db.get_user_by_username("nobody").await.is_err());
        assert!(db.get_user_by_id(uuid::Uuid::new_v4()).await.is_err());

        // Usernames and emails are unique (case-insensitively)
        let dup = db
            .create_user(CreateUserParams {
                username: "alice",
                password_hash: "x",
                email: "other@example.com",
                full_name: "Other",
                country: None,
                mobile: None,
                pii: None,
            })
            .await;
        assert!(dup.is_err(), "duplicate username must be rejected");
        let dup_email = db
            .create_user(CreateUserParams {
                username: "bob",
                password_hash: "x",
                email: "alice@EXAMPLE.com",
                full_name: "Bob",
                country: None,
                mobile: None,
                pii: None,
            })
            .await;
        assert!(dup_email.is_err(), "duplicate email must be rejected");

        db.change_password(user.id, "$argon2id$new").await.unwrap();
        assert_eq!(
            db.get_user_by_id(user.id).await.unwrap().password,
            "$argon2id$new"
        );
        assert!(matches!(
            db.change_password(uuid::Uuid::new_v4(), "x").await,
            Err(sqlx::Error::RowNotFound)
        ));

        db.set_email_verified(user.id, true).await.unwrap();
        assert!(db.get_user_by_id(user.id).await.unwrap().email_verified);
        assert!(matches!(
            db.set_email_verified(uuid::Uuid::new_v4(), true).await,
            Err(sqlx::Error::RowNotFound)
        ));

        db.admin_delete_user(user.id).await.unwrap();
        assert!(db.get_user_by_id(user.id).await.is_err());
        assert!(matches!(
            db.admin_delete_user(user.id).await,
            Err(sqlx::Error::RowNotFound)
        ));
    })
    .await;
}

#[tokio::test]
async fn user_lifecycle_with_pii_encryption() {
    with_db(|db| async move {
        let p = pii();
        let user = db
            .create_user(CreateUserParams {
                username: "carol",
                password_hash: "h",
                email: "Carol@Example.com",
                full_name: "Carol Danvers",
                country: Some("US"),
                mobile: Some("+1555"),
                pii: Some(&p),
            })
            .await
            .unwrap();

        // Stored values are ciphertext; the blind index allows lookup
        let stored_email = user.email.clone().unwrap();
        assert_ne!(stored_email, "Carol@Example.com");
        assert_eq!(p.decrypt(&stored_email).unwrap(), "Carol@Example.com");
        assert_eq!(p.decrypt(&user.full_name).unwrap(), "Carol Danvers");
        assert_eq!(p.decrypt(user.country.as_deref().unwrap()).unwrap(), "US");
        assert_eq!(p.decrypt(user.mobile.as_deref().unwrap()).unwrap(), "+1555");
        assert_eq!(
            user.email_idx.as_deref(),
            Some(p.blind_index("carol@example.com").as_str())
        );

        let found = db
            .get_user_by_email("  CAROL@example.COM ", Some(&p))
            .await
            .unwrap();
        assert_eq!(found.id, user.id);
        // Without the PII service the plaintext index does not exist
        assert!(
            db.get_user_by_email("carol@example.com", None)
                .await
                .is_err()
        );

        // Admin listing decrypts on the way out
        let listed = db.admin_list_users(Some(&p)).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].email, "Carol@Example.com");
        assert_eq!(listed[0].full_name, "Carol Danvers");
        assert_eq!(listed[0].device_count, 0);
    })
    .await;
}

#[tokio::test]
async fn oidc_users_are_verified_and_found_by_provider_subject() {
    with_db(|db| async move {
        let p = pii();
        let user = db
            .create_oidc_user(CreateOidcUserParams {
                username: "dave_google",
                email: "dave@example.com",
                full_name: "Dave",
                provider: "google",
                provider_id: "sub-123",
                avatar_url: Some("https://img.example/dave.png"),
                pii: Some(&p),
            })
            .await
            .unwrap();
        assert!(user.email_verified);
        assert_eq!(user.auth_provider, "google");
        assert_eq!(user.password, "");
        assert_eq!(
            user.avatar_url.as_deref(),
            Some("https://img.example/dave.png")
        );
        assert_eq!(
            p.decrypt(user.auth_provider_id.as_deref().unwrap())
                .unwrap(),
            "sub-123"
        );

        let found = db
            .get_user_by_provider_id("google", "sub-123", Some(&p))
            .await
            .unwrap();
        assert_eq!(found.id, user.id);
        assert!(
            db.get_user_by_provider_id("github", "sub-123", Some(&p))
                .await
                .is_err()
        );
        assert!(
            db.get_user_by_provider_id("google", "sub-999", Some(&p))
                .await
                .is_err()
        );

        // Plaintext mode stores and looks up the raw subject
        let plain = db
            .create_oidc_user(CreateOidcUserParams {
                username: "erin_okta",
                email: "erin@example.com",
                full_name: "Erin",
                provider: "okta",
                provider_id: "okta-1",
                avatar_url: None,
                pii: None,
            })
            .await
            .unwrap();
        assert_eq!(plain.auth_provider_id.as_deref(), Some("okta-1"));
        assert_eq!(
            db.get_user_by_provider_id("okta", "okta-1", None)
                .await
                .unwrap()
                .id,
            plain.id
        );
    })
    .await;
}

#[tokio::test]
async fn seed_admin_is_idempotent() {
    with_db(|db| async move {
        db.seed_admin("Admin", "$argon2id$hash", "admin@example.com", None)
            .await
            .unwrap();
        db.seed_admin("admin", "$argon2id$other", "admin@example.com", None)
            .await
            .unwrap();

        let admin = db.get_user_by_username("admin").await.unwrap();
        assert!(admin.is_admin);
        assert!(admin.email_verified);
        assert_eq!(
            admin.password, "$argon2id$hash",
            "second seed must not overwrite"
        );
        assert_eq!(db.admin_get_stats().await.unwrap().total_users, 1);

        // Empty email is stored as NULL index rather than violating uniqueness
        db.seed_admin("admin2", "h", "", None).await.unwrap();
        db.seed_admin("admin3", "h", "", None).await.unwrap();
        assert_eq!(db.admin_get_stats().await.unwrap().total_users, 3);

        // With PII the admin's email is encrypted and the blind index set
        let p = pii();
        db.seed_admin("root", "h", "root@example.com", Some(&p))
            .await
            .unwrap();
        let root = db
            .get_user_by_email("root@example.com", Some(&p))
            .await
            .unwrap();
        assert!(root.is_admin);
        assert_eq!(
            p.decrypt(root.email.as_deref().unwrap()).unwrap(),
            "root@example.com"
        );
    })
    .await;
}

#[tokio::test]
async fn device_lifecycle_and_approval_status() {
    with_db(|db| async move {
        let user = make_user(&db, "frank", None).await;
        let other = make_user(&db, "grace", None).await;

        let approved = make_device(&db, &user, "Laptop", "approved").await;
        assert_eq!(approved.status, "approved");
        assert!(approved.approved_at.is_some());
        assert!(approved.last_seen.is_some());
        assert_eq!(approved.public_key, vec![4, 1, 2, 3]);
        assert_eq!(approved.public_key_sig, Some(vec![0x30]));
        assert!(approved.fingerprint.is_none());

        let pending = make_device(&db, &user, "Phone", "pending").await;
        assert_eq!(pending.status, "pending");
        assert!(pending.approved_at.is_none());

        let all = db.get_devices_by_user(user.id).await.unwrap();
        assert_eq!(
            all.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            vec!["Laptop", "Phone"]
        );
        assert_eq!(
            db.get_approved_devices_by_user(user.id)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            db.get_pending_devices_by_user(user.id).await.unwrap().len(),
            1
        );
        assert!(db.get_devices_by_user(other.id).await.unwrap().is_empty());
        assert_eq!(db.get_device_by_id(pending.id).await.unwrap().name, "Phone");
        assert_eq!(db.get_device_status(pending.id).await.unwrap(), "pending");

        // Approve the pending device, recording who approved it
        db.update_device_status(pending.id, user.id, "approved", Some(approved.id))
            .await
            .unwrap();
        let now_approved = db.get_device_by_id(pending.id).await.unwrap();
        assert_eq!(now_approved.status, "approved");
        assert!(now_approved.approved_at.is_some());
        assert_eq!(now_approved.approved_by_device_id, Some(approved.id));
        assert_eq!(
            db.get_approved_devices_by_user(user.id)
                .await
                .unwrap()
                .len(),
            2
        );

        // A different user cannot change the status
        assert!(matches!(
            db.update_device_status(pending.id, other.id, "revoked", None)
                .await,
            Err(sqlx::Error::RowNotFound)
        ));

        // Fingerprint backfill only applies once
        assert!(
            db.set_device_fingerprint(approved.id, user.id, "fp-1")
                .await
                .unwrap()
        );
        assert!(
            !db.set_device_fingerprint(approved.id, user.id, "fp-2")
                .await
                .unwrap()
        );
        assert_eq!(
            db.get_device_by_fingerprint(user.id, "fp-1")
                .await
                .unwrap()
                .unwrap()
                .id,
            approved.id
        );
        assert!(
            db.get_device_by_fingerprint(user.id, "fp-2")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            db.get_device_by_fingerprint(other.id, "fp-1")
                .await
                .unwrap()
                .is_none()
        );

        // Fingerprints are unique per user
        let dup = db
            .create_device(user.id, "Clone", &[4], None, "pending", Some("fp-1"))
            .await;
        assert!(dup.is_err());
        db.create_device(
            other.id,
            "Other laptop",
            &[4],
            None,
            "approved",
            Some("fp-1"),
        )
        .await
        .expect("same fingerprint is fine for another user");

        db.update_device_last_seen(approved.id).await.unwrap();

        // Re-registration replaces keys, resets approval and drops old group keys
        db.store_group_keys(approved.id, &[(now_approved.id, vec![9, 9])])
            .await
            .unwrap();
        assert!(db.get_group_key(now_approved.id).await.is_ok());
        let rereg = db
            .reregister_device(now_approved.id, "Phone v2", &[4, 9, 9, 9], None, "pending")
            .await
            .unwrap();
        assert_eq!(rereg.name, "Phone v2");
        assert_eq!(rereg.public_key, vec![4, 9, 9, 9]);
        assert!(rereg.public_key_sig.is_none());
        assert_eq!(rereg.status, "pending");
        assert!(rereg.approved_at.is_none());
        assert!(rereg.approved_by_device_id.is_none());
        assert!(matches!(
            db.get_group_key(now_approved.id).await,
            Err(sqlx::Error::RowNotFound)
        ));

        // Deletion is scoped to the owning user
        assert!(matches!(
            db.delete_device(approved.id, other.id).await,
            Err(sqlx::Error::RowNotFound)
        ));
        db.delete_device(approved.id, user.id).await.unwrap();
        assert!(db.get_device_by_id(approved.id).await.is_err());
        assert!(db.get_device_status(approved.id).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn clipboard_history_pagination_and_limits() {
    with_db(|db| async move {
        let user = make_user(&db, "heidi", None).await;
        let other = make_user(&db, "ivan", None).await;
        let device = make_device(&db, &user, "Laptop", "approved").await;
        let other_device = make_device(&db, &other, "Other", "approved").await;

        let mut ids = Vec::new();
        for i in 0..5u8 {
            let row = db
                .create_clipboard_entry(user.id, device.id, "text", &[i], &format!("m{i}"), 2)
                .await
                .unwrap();
            assert_eq!(row.user_id, user.id);
            assert_eq!(row.device_id, device.id);
            assert_eq!(row.content_type, "text");
            assert_eq!(row.encrypted_data, vec![i]);
            assert_eq!(row.metadata.as_deref(), Some(format!("m{i}").as_str()));
            assert_eq!(row.key_version, 2);
            ids.push(row.id);
        }
        db.create_clipboard_entry(other.id, other_device.id, "image", &[0xff], "", 1)
            .await
            .unwrap();

        assert_eq!(db.count_user_clipboard_entries(user.id).await.unwrap(), 5);
        assert_eq!(db.count_user_clipboard_entries(other.id).await.unwrap(), 1);

        let page = db.get_clipboard_history(user.id, 2, 0).await.unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].id, ids[4], "newest first");
        assert_eq!(page[1].id, ids[3]);
        assert_eq!(page[0].device_name, "Laptop");
        assert_eq!(page[0].key_version, 2);
        let page2 = db.get_clipboard_history(user.id, 2, 4).await.unwrap();
        assert_eq!(page2.len(), 1);
        assert_eq!(page2[0].id, ids[0]);

        db.delete_oldest_clipboard_entries(user.id, 2)
            .await
            .unwrap();
        let remaining: Vec<uuid::Uuid> = db
            .get_clipboard_history(user.id, 10, 0)
            .await
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert_eq!(remaining, vec![ids[4], ids[3], ids[2]]);

        assert!(matches!(
            db.delete_clipboard_entry(ids[4], other.id).await,
            Err(sqlx::Error::RowNotFound)
        ));
        db.delete_clipboard_entry(ids[4], user.id).await.unwrap();
        assert_eq!(db.count_user_clipboard_entries(user.id).await.unwrap(), 2);

        db.clear_clipboard_history(user.id).await.unwrap();
        assert_eq!(db.count_user_clipboard_entries(user.id).await.unwrap(), 0);
        assert_eq!(db.count_user_clipboard_entries(other.id).await.unwrap(), 1);

        // Deleting the device cascades to its entries
        db.delete_device(other_device.id, other.id).await.unwrap();
        assert_eq!(db.count_user_clipboard_entries(other.id).await.unwrap(), 0);
    })
    .await;
}

#[tokio::test]
async fn legacy_group_keys_upsert() {
    with_db(|db| async move {
        let user = make_user(&db, "judy", None).await;
        let a = make_device(&db, &user, "A", "approved").await;
        let b = make_device(&db, &user, "B", "approved").await;

        db.store_group_keys(a.id, &[(b.id, vec![1, 2, 3])])
            .await
            .unwrap();
        let key = db.get_group_key(b.id).await.unwrap();
        assert_eq!(key.encrypted_key, vec![1, 2, 3]);
        assert_eq!(key.from_device_id, a.id);

        // Upsert replaces the wrapped key and sender
        db.store_group_keys(b.id, &[(b.id, vec![7])]).await.unwrap();
        let key = db.get_group_key(b.id).await.unwrap();
        assert_eq!(key.encrypted_key, vec![7]);
        assert_eq!(key.from_device_id, b.id);

        assert!(matches!(
            db.get_group_key(a.id).await,
            Err(sqlx::Error::RowNotFound)
        ));
    })
    .await;
}

#[tokio::test]
async fn versioned_group_key_rotation_uses_compare_and_swap() {
    with_db(|db| async move {
        let user = make_user(&db, "kim", None).await;
        let a = make_device(&db, &user, "A", "approved").await;
        let b = make_device(&db, &user, "B", "approved").await;

        assert!(
            db.get_current_group_key_version(user.id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(!db.is_rotation_due(user.id).await.unwrap());

        // First rotation from "no key" (version 0) to version 1
        let ok = db
            .rotate_group_key(user.id, a.id, 0, 1, &[(a.id, vec![1]), (b.id, vec![2])], 24)
            .await
            .unwrap();
        assert!(ok);
        let current = db
            .get_current_group_key_version(user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.version, 1);
        assert!(current.is_current);
        assert_eq!(current.created_by_device_id, Some(a.id));
        assert!(current.rotation_due_at.unwrap() > Utc::now());
        assert_eq!(
            db.get_device_group_key(b.id, 1)
                .await
                .unwrap()
                .encrypted_key,
            vec![2]
        );
        assert_eq!(
            db.get_device_group_key(b.id, 1)
                .await
                .unwrap()
                .from_device_id,
            a.id
        );
        assert!(db.get_device_group_key(b.id, 2).await.is_err());

        // Stale expectation fails the CAS without side effects
        let stale = db
            .rotate_group_key(user.id, b.id, 0, 2, &[(a.id, vec![9])], 24)
            .await
            .unwrap();
        assert!(!stale);
        assert_eq!(
            db.get_current_group_key_version(user.id)
                .await
                .unwrap()
                .unwrap()
                .version,
            1
        );
        assert!(db.get_device_group_key(a.id, 2).await.is_err());

        // Correct expectation rotates to version 2 (with a rotation already due)
        let ok = db
            .rotate_group_key(user.id, b.id, 1, 2, &[(a.id, vec![3]), (b.id, vec![4])], -1)
            .await
            .unwrap();
        assert!(ok);
        let current = db
            .get_current_group_key_version(user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.version, 2);
        assert_eq!(current.created_by_device_id, Some(b.id));
        assert!(db.is_rotation_due(user.id).await.unwrap());

        let since = db.get_device_group_keys_since(a.id, 0).await.unwrap();
        assert_eq!(
            since.iter().map(|k| k.version).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(since[1].encrypted_key, vec![3]);
        let since1 = db.get_device_group_keys_since(a.id, 1).await.unwrap();
        assert_eq!(since1.len(), 1);
        assert_eq!(since1[0].version, 2);
        assert!(
            db.get_device_group_keys_since(a.id, 2)
                .await
                .unwrap()
                .is_empty()
        );

        // Removing a device cascades its own wrapped keys AND the keys it wrapped for
        // other devices (they cannot be unwrapped without the sender's public key).
        db.delete_device(a.id, user.id).await.unwrap();
        assert!(
            db.get_device_group_keys_since(a.id, 0)
                .await
                .unwrap()
                .is_empty()
        );
        let b_keys = db.get_device_group_keys_since(b.id, 0).await.unwrap();
        assert_eq!(b_keys.len(), 1, "v1 was wrapped by the deleted device");
        assert_eq!(b_keys[0].version, 2);
        assert_eq!(b_keys[0].from_device_id, b.id);
    })
    .await;
}

#[tokio::test]
async fn approval_sessions_are_single_and_expire() {
    with_db(|db| async move {
        let user = make_user(&db, "leo", None).await;
        let approver = make_device(&db, &user, "Approver", "approved").await;
        let pending = make_device(&db, &user, "Pending", "pending").await;

        assert!(db.get_approval_session(pending.id).await.unwrap().is_none());

        let session = db
            .create_approval_session(pending.id, approver.id, 300)
            .await
            .unwrap();
        assert_eq!(session.pending_device_id, pending.id);
        assert_eq!(session.approver_device_id, approver.id);
        assert_eq!(session.status, "pending");
        assert!(session.expires_at > Utc::now());
        assert_eq!(
            db.get_approval_session(pending.id)
                .await
                .unwrap()
                .unwrap()
                .id,
            session.id
        );

        // Starting again replaces the previous session for that device
        let replacement = db
            .create_approval_session(pending.id, approver.id, 300)
            .await
            .unwrap();
        assert_ne!(replacement.id, session.id);
        assert_eq!(
            db.get_approval_session(pending.id)
                .await
                .unwrap()
                .unwrap()
                .id,
            replacement.id
        );

        db.complete_approval_session(replacement.id).await.unwrap();
        assert!(db.get_approval_session(pending.id).await.unwrap().is_none());

        // An already-expired session is not returned
        db.create_approval_session(pending.id, approver.id, -10)
            .await
            .unwrap();
        assert!(db.get_approval_session(pending.id).await.unwrap().is_none());
    })
    .await;
}

#[tokio::test]
async fn subscription_plans_crud_and_assignment() {
    with_db(|db| async move {
        let user = make_user(&db, "mallory", None).await;
        assert_eq!(
            db.get_user_subscription(user.id).await.unwrap().plan_id,
            None
        );

        let plan = db
            .create_subscription_plan(&plan_params("Custom", 10, true))
            .await
            .unwrap();
        assert_eq!(plan.name, "Custom");
        assert_eq!(plan.price.to_string(), "9.99");
        assert_eq!(plan.currency, "EUR");
        assert_eq!(plan.billing_period, "yearly");
        assert_eq!(plan.max_devices, 7);
        assert_eq!(plan.max_clipboard_history, 250);
        assert_eq!(
            plan.allowed_file_types,
            serde_json::json!(["text", "image"])
        );
        assert_eq!(db.get_subscription_plan(plan.id).await.unwrap().id, plan.id);

        let inactive = db
            .create_subscription_plan(&plan_params("Hidden", 5, false))
            .await
            .unwrap();
        let all = db.list_subscription_plans().await.unwrap();
        assert_eq!(all.len(), 5, "3 seeded + 2 created");
        assert_eq!(all.last().unwrap().id, plan.id, "ordered by sort_order");
        let active = db.list_active_subscription_plans().await.unwrap();
        assert!(active.iter().all(|p| p.is_active));
        assert!(!active.iter().any(|p| p.id == inactive.id));

        let updated = db
            .update_subscription_plan(plan.id, &plan_params("Custom v2", 11, true))
            .await
            .unwrap();
        assert_eq!(updated.name, "Custom v2");
        assert_eq!(updated.sort_order, 11);
        assert!(updated.updated_at >= plan.updated_at);

        db.assign_user_subscription(user.id, plan.id).await.unwrap();
        let info = db.get_user_subscription(user.id).await.unwrap();
        assert_eq!(info.plan_id, Some(plan.id));
        assert_eq!(info.plan_name.as_deref(), Some("Custom v2"));
        assert_eq!(info.max_devices, Some(7));
        assert_eq!(info.max_clipboard_history, Some(250));
        assert_eq!(info.allowed_file_types, vec!["text", "image"]);
        assert_eq!(info.price.unwrap().to_string(), "9.99");

        let err = db.delete_subscription_plan(plan.id).await.unwrap_err();
        assert!(err.contains("1 users are still assigned"), "{err}");

        db.remove_user_subscription(user.id).await.unwrap();
        let cleared = db.get_user_subscription(user.id).await.unwrap();
        assert!(cleared.plan_id.is_none());
        assert!(cleared.plan_name.is_none());
        assert!(cleared.allowed_file_types.is_empty());
        db.delete_subscription_plan(plan.id).await.unwrap();
        assert!(db.get_subscription_plan(plan.id).await.is_err());
        assert_eq!(
            db.delete_subscription_plan(plan.id).await.unwrap_err(),
            "plan not found"
        );

        // Deleting an assigned plan via cascade (SET NULL) is handled by the schema
        db.assign_user_subscription(user.id, inactive.id)
            .await
            .unwrap();
        let listed = db.admin_list_users(None).await.unwrap();
        assert_eq!(listed[0].subscription_plan_name.as_deref(), Some("Hidden"));
    })
    .await;
}

#[tokio::test]
async fn download_links_and_releases() {
    with_db(|db| async move {
        let r1 = db
            .create_app_release(&AppReleaseParams {
                version: "0.1.0",
                platform: "windows",
                arch: "amd64",
                download_url: "https://dl/0.1.0.exe",
                release_notes: "first",
                is_current: true,
            })
            .await
            .unwrap();
        assert!(r1.is_current);
        let r2 = db
            .create_app_release(&AppReleaseParams {
                version: "0.2.0",
                platform: "windows",
                arch: "amd64",
                download_url: "https://dl/0.2.0.exe",
                release_notes: "second",
                is_current: true,
            })
            .await
            .unwrap();
        // Marking a new current release unsets the previous one for the same platform/arch
        let releases = db.list_app_releases().await.unwrap();
        assert_eq!(releases.len(), 2);
        assert!(!releases.iter().find(|r| r.id == r1.id).unwrap().is_current);
        assert!(releases.iter().find(|r| r.id == r2.id).unwrap().is_current);
        assert_eq!(
            db.get_current_release("windows", "amd64")
                .await
                .unwrap()
                .unwrap()
                .version,
            "0.2.0"
        );
        assert_eq!(
            db.get_current_release("windows", "")
                .await
                .unwrap()
                .unwrap()
                .version,
            "0.2.0"
        );
        assert!(
            db.get_current_release("macos", "arm64")
                .await
                .unwrap()
                .is_none()
        );

        let mac = db
            .create_app_release(&AppReleaseParams {
                version: "0.2.0",
                platform: "macos",
                arch: "arm64",
                download_url: "https://dl/0.2.0.dmg",
                release_notes: "",
                is_current: false,
            })
            .await
            .unwrap();
        assert!(
            db.get_current_release("macos", "arm64")
                .await
                .unwrap()
                .is_none()
        );
        let mac = db
            .update_app_release(
                mac.id,
                &AppReleaseParams {
                    version: "0.2.1",
                    platform: "macos",
                    arch: "arm64",
                    download_url: "https://dl/0.2.1.dmg",
                    release_notes: "patch",
                    is_current: true,
                },
            )
            .await
            .unwrap();
        assert_eq!(mac.version, "0.2.1");
        assert!(mac.is_current);
        // Windows current release is untouched by the macOS update
        assert_eq!(
            db.get_current_release("windows", "amd64")
                .await
                .unwrap()
                .unwrap()
                .id,
            r2.id
        );

        let link = db
            .create_download_link(&DownloadLinkParams {
                name: "Windows installer",
                url: "https://dl/0.2.0.exe",
                platform: "windows",
                arch: "amd64",
                format: "exe",
                sort_order: 1,
                is_active: true,
                release_id: Some(r2.id),
            })
            .await
            .unwrap();
        let old_link = db
            .create_download_link(&DownloadLinkParams {
                name: "Old installer",
                url: "https://dl/0.1.0.exe",
                platform: "windows",
                arch: "amd64",
                format: "exe",
                sort_order: 0,
                is_active: true,
                release_id: Some(r1.id),
            })
            .await
            .unwrap();
        let hidden = db
            .create_download_link(&DownloadLinkParams {
                name: "Hidden",
                url: "https://dl/hidden",
                platform: "linux",
                arch: "",
                format: "",
                sort_order: 2,
                is_active: false,
                release_id: None,
            })
            .await
            .unwrap();

        let all = db.list_download_links().await.unwrap();
        assert_eq!(
            all.iter().map(|l| l.id).collect::<Vec<_>>(),
            vec![old_link.id, link.id, hidden.id]
        );
        let active = db.list_active_download_links().await.unwrap();
        assert_eq!(active.len(), 2);
        let current = db.list_downloads_for_current_releases().await.unwrap();
        assert_eq!(current.len(), 1, "only links attached to a current release");
        assert_eq!(current[0].id, link.id);

        let updated = db
            .update_download_link(
                hidden.id,
                &DownloadLinkParams {
                    name: "Visible",
                    url: "https://dl/visible",
                    platform: "linux",
                    arch: "amd64",
                    format: "deb",
                    sort_order: 2,
                    is_active: true,
                    release_id: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(updated.name, "Visible");
        assert!(updated.is_active);
        assert_eq!(db.list_active_download_links().await.unwrap().len(), 3);

        // Deleting a release detaches its links instead of deleting them
        db.delete_app_release(r1.id).await.unwrap();
        let detached = db.list_download_links().await.unwrap();
        assert!(
            detached
                .iter()
                .find(|l| l.id == old_link.id)
                .unwrap()
                .release_id
                .is_none()
        );
        assert!(matches!(
            db.delete_app_release(r1.id).await,
            Err(sqlx::Error::RowNotFound)
        ));

        db.delete_download_link(old_link.id).await.unwrap();
        assert!(matches!(
            db.delete_download_link(old_link.id).await,
            Err(sqlx::Error::RowNotFound)
        ));
        assert_eq!(db.list_download_links().await.unwrap().len(), 2);
    })
    .await;
}

#[tokio::test]
async fn admin_listing_and_stats() {
    with_db(|db| async move {
        let a = make_user(&db, "nina", None).await;
        let b = make_user(&db, "oscar", None).await;
        make_device(&db, &a, "A1", "approved").await;
        let a2 = make_device(&db, &a, "A2", "pending").await;
        db.create_clipboard_entry(a.id, a2.id, "text", &[1], "", 1)
            .await
            .unwrap();

        let plan = db
            .create_subscription_plan(&plan_params("Biz", 1, true))
            .await
            .unwrap();
        db.assign_user_subscription(b.id, plan.id).await.unwrap();

        let users = db.admin_list_users(None).await.unwrap();
        assert_eq!(users.len(), 2);
        let nina = users.iter().find(|u| u.username == "nina").unwrap();
        assert_eq!(nina.device_count, 2);
        assert_eq!(nina.email, "nina@example.com");
        assert!(nina.subscription_plan_id.is_none());
        let oscar = users.iter().find(|u| u.username == "oscar").unwrap();
        assert_eq!(oscar.device_count, 0);
        assert_eq!(oscar.subscription_plan_id, Some(plan.id));
        assert_eq!(oscar.subscription_plan_name.as_deref(), Some("Biz"));

        let stats = db.admin_get_stats().await.unwrap();
        assert_eq!(stats.total_users, 2);
        assert_eq!(stats.total_devices, 2);
        assert_eq!(stats.total_entries, 1);

        // Deleting a user cascades to devices and entries
        db.admin_delete_user(a.id).await.unwrap();
        let stats = db.admin_get_stats().await.unwrap();
        assert_eq!(stats.total_users, 1);
        assert_eq!(stats.total_devices, 0);
        assert_eq!(stats.total_entries, 0);
    })
    .await;
}

#[tokio::test]
async fn email_verification_tokens() {
    with_db(|db| async move {
        let user = make_user(&db, "peggy", None).await;
        assert!(!user.email_verified);

        let token = db.create_email_verification(user.id).await.unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

        // Issuing a new token invalidates the previous one
        let token2 = db.create_email_verification(user.id).await.unwrap();
        assert_ne!(token, token2);
        assert_eq!(db.verify_email(&token).await.unwrap_err(), "invalid verification token");

        db.verify_email(&token2).await.unwrap();
        assert!(db.get_user_by_id(user.id).await.unwrap().email_verified);
        // Single use
        assert_eq!(db.verify_email(&token2).await.unwrap_err(), "invalid verification token");

        // Expired tokens are rejected
        let token3 = db.create_email_verification(user.id).await.unwrap();
        sqlx::query("UPDATE email_verifications SET expires_at = NOW() - INTERVAL '1 hour' WHERE user_id = $1")
            .bind(user.id)
            .execute(&db.pool)
            .await
            .unwrap();
        assert_eq!(db.verify_email(&token3).await.unwrap_err(), "verification token has expired");
    })
    .await;
}

#[tokio::test]
async fn token_revocation_persistence() {
    with_db(|db| async move {
        let user = make_user(&db, "quinn", None).await;
        let now = Utc::now().timestamp() as u64;

        assert!(!db.is_token_revoked_db("jti-1").await.unwrap());
        db.persist_revoked_token("jti-1", user.id, now + 3600)
            .await
            .unwrap();
        db.persist_revoked_token("jti-1", user.id, now + 3600)
            .await
            .unwrap(); // idempotent
        db.persist_revoked_token("jti-old", user.id, now - 10)
            .await
            .unwrap();
        assert!(db.is_token_revoked_db("jti-1").await.unwrap());
        assert!(db.is_token_revoked_db("jti-old").await.unwrap());

        assert_eq!(db.cleanup_expired_revoked_tokens().await.unwrap(), 1);
        assert!(db.is_token_revoked_db("jti-1").await.unwrap());
        assert!(!db.is_token_revoked_db("jti-old").await.unwrap());

        db.revoke_all_user_tokens(user.id, now).await.unwrap();
        assert_eq!(
            db.get_user_by_id(user.id)
                .await
                .unwrap()
                .tokens_revoked_before,
            Some(now as i64)
        );

        // Deleting the user removes their revoked tokens
        db.admin_delete_user(user.id).await.unwrap();
        assert!(!db.is_token_revoked_db("jti-1").await.unwrap());
    })
    .await;
}

#[tokio::test]
async fn audit_log_filters_and_ordering() {
    with_db(|db| async move {
        let a = make_user(&db, "rita", None).await;
        let b = make_user(&db, "sam", None).await;
        db.write_audit_log(
            Some(a.id),
            AUDIT_LOGIN_OK,
            Some("10.0.0.1"),
            Some("UA"),
            &serde_json::json!({"n": 1}),
        )
        .await
        .unwrap();
        db.write_audit_log(
            Some(a.id),
            AUDIT_LOGIN_FAIL,
            None,
            None,
            &serde_json::json!({"n": 2}),
        )
        .await
        .unwrap();
        db.write_audit_log(
            Some(b.id),
            AUDIT_LOGIN_OK,
            Some("10.0.0.2"),
            None,
            &serde_json::json!({"n": 3}),
        )
        .await
        .unwrap();
        db.write_audit_log(
            None,
            AUDIT_REGISTER,
            Some("10.0.0.3"),
            None,
            &serde_json::json!({"n": 4}),
        )
        .await
        .unwrap();

        let all = db.list_audit_logs(10, 0, None, None).await.unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].details["n"], 4, "newest first");
        assert_eq!(all[0].action, AUDIT_REGISTER);
        assert!(all[0].user_id.is_none());
        assert_eq!(all[3].ip_address.as_deref(), Some("10.0.0.1"));
        assert_eq!(all[3].user_agent.as_deref(), Some("UA"));

        let page = db.list_audit_logs(2, 1, None, None).await.unwrap();
        assert_eq!(
            page.iter()
                .map(|l| l.details["n"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            vec![3, 2]
        );

        let by_user = db.list_audit_logs(10, 0, Some(a.id), None).await.unwrap();
        assert_eq!(by_user.len(), 2);
        assert!(by_user.iter().all(|l| l.user_id == Some(a.id)));

        let by_action = db
            .list_audit_logs(10, 0, None, Some(AUDIT_LOGIN_OK))
            .await
            .unwrap();
        assert_eq!(by_action.len(), 2);

        let both = db
            .list_audit_logs(10, 0, Some(a.id), Some(AUDIT_LOGIN_OK))
            .await
            .unwrap();
        assert_eq!(both.len(), 1);
        assert_eq!(both[0].details["n"], 1);

        // Deleting a user keeps the audit trail but detaches it
        db.admin_delete_user(a.id).await.unwrap();
        let after = db
            .list_audit_logs(10, 0, None, Some(AUDIT_LOGIN_FAIL))
            .await
            .unwrap();
        assert_eq!(after.len(), 1);
        assert!(after[0].user_id.is_none());
    })
    .await;
}

/// RS256 key material for an `AuthService` under test: (private PEM, public keys JSON).
fn test_jwt_keys() -> (String, String) {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use aws_lc_rs::signature::KeyPair as _;
    use base64::Engine;

    let to_pem = |label: &str, der: &[u8]| {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            lines.join("\n")
        )
    };
    let key_pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let private_pem = to_pem("PRIVATE KEY", key_pair.as_der().unwrap().as_ref());
    let public_pem = to_pem(
        "PUBLIC KEY",
        key_pair.public_key().as_der().unwrap().as_ref(),
    );
    let public_json = serde_json::json!([{ "kid": "k1", "pem": public_pem }]).to_string();
    (private_pem, public_json)
}

#[tokio::test]
async fn auth_service_persists_revocations_to_the_database() {
    with_db(|db| async move {
        use cpmesh_server::routes::auth_service::{AuthService, RefreshResult, RefreshTokenUse};

        let (private_pem, public_json) = test_jwt_keys();
        let user = make_user(&db, "trent", None).await;
        let svc =
            AuthService::new("k1", &private_pem, &public_json, Some(db.pool.clone())).unwrap();

        let refresh = svc.generate_refresh_token(user.id, None).unwrap();
        let (_, jti, exp) = match svc.validate_refresh_token(&refresh) {
            RefreshResult::Ok(c, jti, exp) => (c, jti, exp),
            _ => panic!("fresh token rejected"),
        };

        // Revocation is written to the database asynchronously
        svc.revoke_token(&jti, user.id, exp);
        let mut persisted = false;
        for _ in 0..50 {
            if db.is_token_revoked_db(&jti).await.unwrap() {
                persisted = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(
            persisted,
            "revoked token should be persisted to revoked_tokens"
        );

        // A fresh service instance (e.g. after a restart) learns about it from the database
        let restarted = AuthService::new("k1", &private_pem, &public_json, Some(db.pool.clone()))
            .unwrap()
            .with_refresh_reuse_grace(std::time::Duration::ZERO);
        assert!(restarted.check_revoked_db_async(&jti).await);
        assert_eq!(
            restarted
                .consume_refresh_token(&jti, user.id, exp)
                .await
                .unwrap(),
            RefreshTokenUse::Reused
        );
        assert!(!restarted.check_revoked_db_async("unknown-jti").await);
    })
    .await;
}

#[tokio::test]
async fn refresh_tokens_are_single_use_across_instances() {
    with_db(|db| async move {
        use cpmesh_server::routes::auth_service::{AuthService, RefreshResult, RefreshTokenUse};

        let (private_pem, public_json) = test_jwt_keys();
        let user = make_user(&db, "ursula", None).await;
        // Two server instances sharing one database
        let a = Arc::new(
            AuthService::new("k1", &private_pem, &public_json, Some(db.pool.clone())).unwrap(),
        );
        let b = Arc::new(
            AuthService::new("k1", &private_pem, &public_json, Some(db.pool.clone())).unwrap(),
        );

        let refresh = a.generate_refresh_token(user.id, None).unwrap();
        let RefreshResult::Ok(_, jti, exp) = a.validate_refresh_token(&refresh) else {
            panic!("fresh token rejected");
        };

        // Many simultaneous refreshes with the same token: exactly one may win
        let attempts: Vec<_> = (0..8)
            .map(|i| {
                let svc = if i % 2 == 0 { a.clone() } else { b.clone() };
                let jti = jti.clone();
                let user_id = user.id;
                tokio::spawn(
                    async move { svc.consume_refresh_token(&jti, user_id, exp).await.unwrap() },
                )
            })
            .collect();
        let mut outcomes = Vec::new();
        for attempt in attempts {
            outcomes.push(attempt.await.unwrap());
        }
        assert_eq!(
            outcomes
                .iter()
                .filter(|o| **o == RefreshTokenUse::First)
                .count(),
            1,
            "{outcomes:?}"
        );
        assert!(
            outcomes.iter().all(|o| *o != RefreshTokenUse::Reused),
            "a race between a client's own requests is not theft: {outcomes:?}"
        );

        // Once the grace window has passed, presenting the token again is theft
        let later = AuthService::new("k1", &private_pem, &public_json, Some(db.pool.clone()))
            .unwrap()
            .with_refresh_reuse_grace(std::time::Duration::ZERO);
        assert_eq!(
            later
                .consume_refresh_token(&jti, user.id, exp)
                .await
                .unwrap(),
            RefreshTokenUse::Reused
        );
    })
    .await;
}

// ---- Router flows that need a real database ---------------------------------

mod router {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode, header};
    use cpmesh_server::config::Config;
    use cpmesh_server::email::EmailService;
    use cpmesh_server::routes::auth::PkceCodeStore;
    use cpmesh_server::routes::auth_service::{AuthService, RefreshResult};
    use cpmesh_server::routes::middleware::build_rate_limiter;
    use cpmesh_server::ws::Hub;
    use cpmesh_server::{AppState, RateLimiters};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app(db: &Db) -> (Router, Arc<AppState>) {
        let (private_pem, public_json) = test_jwt_keys();
        let mut config = Config::from_lookup(|_| None);
        config.jwt_active_kid = "k1".into();
        let state = Arc::new(AppState {
            db: Db {
                pool: db.pool.clone(),
            },
            config,
            hub: Hub::new(),
            pii: None,
            auth: AuthService::new("k1", &private_pem, &public_json, Some(db.pool.clone()))
                .unwrap(),
            email: EmailService::disabled(),
            pkce_store: PkceCodeStore::new(),
            rate_limiters: RateLimiters {
                login: build_rate_limiter(1000),
                register: build_rate_limiter(1000),
                refresh: build_rate_limiter(1000),
            },
        });
        (cpmesh_server::routes::build_router(state.clone()), state)
    }

    fn request(method: &str, uri: &str) -> axum::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(uri)
            .extension(ConnectInfo::<std::net::SocketAddr>(
                "203.0.113.10:4242".parse().unwrap(),
            ))
    }

    fn ws_upgrade(uri: &str) -> axum::http::request::Builder {
        request("GET", uri)
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
    }

    async fn call(app: &Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    #[tokio::test]
    async fn browser_session_connects_with_a_single_use_ticket() {
        with_db(|db| async move {
            let (app, state) = app(&db);
            let user = make_user(&db, "wendy", None).await;
            // Web dashboard sessions are not bound to a device
            let token = state.auth.generate_access_token(user.id, None).unwrap();

            let (status, body) = call(
                &app,
                request("POST", "/api/ws/ticket")
                    .header(header::AUTHORIZATION, bearer(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let ticket = body["ticket"].as_str().unwrap().to_string();

            // Ticket alone (no Authorization header) gets through authentication to
            // the upgrade itself, which the in-process transport cannot perform.
            let (status, _) = call(
                &app,
                ws_upgrade(&format!("/ws?ticket={ticket}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::UPGRADE_REQUIRED);

            let (status, body) = call(
                &app,
                ws_upgrade(&format!("/ws?ticket={ticket}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["error"], "invalid or expired ticket");
        })
        .await;
    }

    #[tokio::test]
    async fn devices_connect_with_a_bearer_token_once_approved() {
        with_db(|db| async move {
            let (app, state) = app(&db);
            let user = make_user(&db, "xavier", None).await;
            let approved = make_device(&db, &user, "laptop", "approved").await;
            let pending = make_device(&db, &user, "phone", "pending").await;

            let token = state
                .auth
                .generate_access_token(user.id, Some(approved.id))
                .unwrap();
            let (status, _) = call(
                &app,
                ws_upgrade("/ws")
                    .header(header::AUTHORIZATION, bearer(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::UPGRADE_REQUIRED);

            let token = state
                .auth
                .generate_access_token(user.id, Some(pending.id))
                .unwrap();
            let (status, body) = call(
                &app,
                ws_upgrade("/ws")
                    .header(header::AUTHORIZATION, bearer(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        })
        .await;
    }

    #[tokio::test]
    async fn refresh_binds_a_session_to_one_of_the_users_devices() {
        with_db(|db| async move {
            let (app, state) = app(&db);
            let user = make_user(&db, "yvonne", None).await;
            let other = make_user(&db, "zack", None).await;
            let device = make_device(&db, &user, "laptop", "approved").await;
            let foreign = make_device(&db, &other, "desk", "approved").await;
            let revoked = make_device(&db, &user, "old", "revoked").await;

            let refresh_with = |token: String, device_id: uuid::Uuid| {
                request("POST", "/api/auth/refresh")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"refresh_token": token, "device_id": device_id})
                            .to_string(),
                    ))
                    .unwrap()
            };

            // Someone else's device, or a revoked one, is refused
            for device_id in [foreign.id, revoked.id] {
                let token = state.auth.generate_refresh_token(user.id, None).unwrap();
                let (status, body) = call(&app, refresh_with(token, device_id)).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
            }

            let token = state.auth.generate_refresh_token(user.id, None).unwrap();
            let (status, body) = call(&app, refresh_with(token, device.id)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let access = state
                .auth
                .validate_access_token(body["access_token"].as_str().unwrap())
                .unwrap();
            assert_eq!(access.device_id, Some(device.id));
            // The rotated refresh token stays bound to the device
            let RefreshResult::Ok(claims, _, _) = state
                .auth
                .validate_refresh_token(body["refresh_token"].as_str().unwrap())
            else {
                panic!("rotated refresh token rejected");
            };
            assert_eq!(claims.device_id, Some(device.id));

            // Removing the device ends its session
            db.delete_device(device.id, user.id).await.unwrap();
            let next = body["refresh_token"].as_str().unwrap().to_string();
            let (status, body) = call(
                &app,
                request("POST", "/api/auth/refresh")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"refresh_token": next}).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        })
        .await;
    }
}
