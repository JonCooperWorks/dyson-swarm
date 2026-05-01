//! Postgres backend skeleton.
//!
//! Enabled by the `postgres` cargo feature. The `*Store` traits in
//! [`crate::traits`] are pool-agnostic; the Pg impls below mirror the
//! SQLite ones in [`crate::db`] but bind to a `sqlx::PgPool` and use
//! `$N` placeholders instead of `?`.
//!
//! This module ships *empty* in this codebase. Phase 7 lays down the seam
//! so adding Pg later is a contained, additive change:
//!
//! 1. Implement `PgInstanceStore`, `PgSecretStore`, `PgTokenStore`,
//!    `PgUserStore`, `PgSnapshotStore`, `PgPolicyStore`, `PgAuditStore`
//!    — one per existing trait, mirroring the sqlite/*.rs files.
//! 2. Add a `db::open_pg(url)` that mirrors `db::open(path)` but builds a
//!    `PgPool` and runs `migrations/postgres/`.
//! 3. In `main.rs`, branch on the config (sqlite path vs postgres URL) at
//!    pool construction; the rest of the wiring (services, routes, etc.)
//!    is unchanged because every consumer holds `Arc<dyn ...Store>`.
//!
//! See `migrations/postgres/*.sql` for the schema (kept in lockstep with
//! the sqlite migrations).

#[cfg(feature = "postgres")]
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");
