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
//! 1. Implement `PgInstanceStore`, `PgUserSecretStore`,
//!    `PgSystemSecretStore`, `PgTokenStore`, `PgUserStore`,
//!    `PgSnapshotStore`, `PgPolicyStore`, `PgAuditStore`,
//!    `PgArtefactStore`, `PgStateFileStore`, and `PgShareStore`
//!    — one per existing trait, mirroring the sqlite/*.rs files.
//! 2. Add a `db::open_pg(url)` that builds a `PgPool` and runs
//!    `migrations/postgres/`.
//! 3. Replace the temporary `open_configured_sqlite` guard with a
//!    backend enum/runtime handle so `main.rs` wires Pg stores when
//!    `database_backend = "postgres"`.
//!
//! See `migrations/postgres/*.sql` for the schema (kept in lockstep with
//! the sqlite migrations).

#[cfg(feature = "postgres")]
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");
