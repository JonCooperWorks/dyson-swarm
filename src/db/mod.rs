//! SQLite-backed implementations of the *Store traits.
//!
//! Note: queries are runtime-checked (`sqlx::query`/`query_as`) rather than
//! compile-time-checked (`sqlx::query!`). The brief asks for the macro form,
//! but it requires either sqlx-cli to prepare an offline cache or a live
//! `DATABASE_URL` at build time — neither fits a clean `cargo build` here.
//! Every query is exercised by unit tests under `tests` modules below, so
//! malformed SQL fails fast; switching to the macro form is a mechanical
//! swap once a `cargo sqlx prepare` step exists in CI.

use std::path::Path;
use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::SqlitePool;

pub mod audit;
pub mod instances;
pub mod policies;
pub mod secrets;
pub mod snapshots;
pub mod tokens;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

pub async fn open(path: &Path) -> Result<SqlitePool, sqlx::Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(sqlx::Error::Io)?;
        }
    }
    let url = format!("sqlite://{}", path.display());
    let opts = SqliteConnectOptions::from_str(&url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await?;
    MIGRATOR
        .run(&pool)
        .await
        .map_err(|e| sqlx::Error::Migrate(Box::new(e)))?;
    secure_db_perms(path)?;
    Ok(pool)
}

#[cfg(unix)]
fn secure_db_perms(path: &Path) -> Result<(), sqlx::Error> {
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(sqlx::Error::Io)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_db_perms(_path: &Path) -> Result<(), sqlx::Error> {
    Ok(())
}

/// In-memory pool for tests. Single connection so the same database is
/// visible across calls.
pub async fn open_in_memory() -> Result<SqlitePool, sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .min_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect("sqlite::memory:")
        .await?;
    MIGRATOR
        .run(&pool)
        .await
        .map_err(|e| sqlx::Error::Migrate(Box::new(e)))?;
    Ok(pool)
}
