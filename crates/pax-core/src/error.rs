use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum PaxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("config parse error at {path}:{line}: {message}")]
    ConfigParse {
        path: PathBuf,
        line: usize,
        message: String,
    },

    #[error("invalid version string: {0}")]
    InvalidVersion(String),

    #[error("package not found: {0}")]
    PackageNotFound(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("invalid dependency string: {0}")]
    InvalidDependency(String),
}

pub type Result<T> = std::result::Result<T, PaxError>;
