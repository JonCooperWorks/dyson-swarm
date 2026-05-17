//! Postgres-backed implementations of the `*Store` traits.

use sqlx::postgres::PgPoolOptions;

use crate::error::StoreError;

pub mod agent_secrets;
pub mod agent_skill_publications;
pub mod artefacts;
pub mod audit;
pub mod channels;
pub mod instances;
pub mod mcp_catalog;
pub mod policies;
pub mod runtime_migrations;
pub mod secrets;
pub mod sessions;
pub mod shares;
pub mod skill_marketplace;
pub mod snapshots;
pub mod state_files;
pub mod tokens;
pub mod users;
pub mod webhooks;

#[cfg(feature = "postgres")]
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

pub(crate) fn map_sqlx(e: sqlx::Error) -> StoreError {
    match e {
        sqlx::Error::RowNotFound => StoreError::NotFound,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
            StoreError::Constraint(db.to_string())
        }
        other => StoreError::Io(other.to_string()),
    }
}

pub async fn open(url: &str) -> Result<sqlx::PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new().max_connections(8).connect(url).await?;
    MIGRATOR
        .run(&pool)
        .await
        .map_err(|e| sqlx::Error::Migrate(Box::new(e)))?;
    Ok(pool)
}
