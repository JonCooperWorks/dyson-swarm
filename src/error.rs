use thiserror::Error;

#[derive(Debug, Error)]
pub enum CubeError {
    #[error("cube returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("cube transport error: {0}")]
    Transport(String),
    #[error("cube response decode error: {0}")]
    Decode(String),
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("store i/o: {0}")]
    Io(String),
    #[error("not found")]
    NotFound,
    #[error("constraint violation: {0}")]
    Constraint(String),
    #[error("malformed row: {0}")]
    Malformed(String),
}

#[derive(Debug, Error)]
pub enum BackupError {
    #[error("backup sink error: {0}")]
    Sink(String),
    #[error("snapshot has no local copy and no remote URI")]
    Missing,
    #[error("backup i/o: {0}")]
    Io(String),
}

#[derive(Debug, Error)]
pub enum SwarmError {
    #[error(transparent)]
    Cube(#[from] CubeError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Backup(#[from] BackupError),
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    #[error("policy denied: {0}")]
    PolicyDenied(String),
    #[error("not found")]
    NotFound,
}
