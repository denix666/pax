#[derive(Debug, thiserror::Error)]
pub enum AurError {
    #[error("HTTP request failed: {0}")]
    Http(String),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("AUR API error: {0}")]
    Api(String),

    #[error("package not found in AUR: {0}")]
    NotFound(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("build failed for {pkg}: {message}")]
    BuildFailed { pkg: String, message: String },

    #[error("git clone failed for {pkg}: {message}")]
    GitFailed { pkg: String, message: String },
}

pub type Result<T> = std::result::Result<T, AurError>;
