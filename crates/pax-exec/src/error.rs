use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("download failed for {pkg}: {message}")]
    Download { pkg: String, message: String },

    #[error("all mirrors failed for {pkg}")]
    AllMirrorsFailed { pkg: String },

    #[error("repository synchronization failed:\n{}", .failures.join("\n"))]
    RepositorySync { failures: Vec<String> },

    #[error("checksum mismatch for {pkg}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        pkg: String,
        expected: String,
        actual: String,
    },

    #[error("signature verification failed for {pkg}: {message}")]
    SignatureFailure { pkg: String, message: String },

    #[error("extraction failed for {pkg}: {message}")]
    Extraction { pkg: String, message: String },

    #[error("scriptlet failed for {pkg}: exit code {code}")]
    Scriptlet { pkg: String, code: i32 },

    #[error("hook failed: {name}: {message}")]
    Hook { name: String, message: String },

    #[error("packages were applied, but transaction maintenance is incomplete:\n{}", .failures.join("\n"))]
    MaintenanceIncomplete { failures: Vec<String> },

    #[error(
        "transaction did not complete: {cause}\njournal: {journal}; inspect with pax transaction-status using the same configuration and paths; do not retry blindly"
    )]
    TransactionIncomplete { cause: String, journal: PathBuf },

    #[error("conflicting files:\n{0}")]
    FileConflict(String),

    #[error("insufficient disk space: need {needed} MiB, only {available} MiB available on {path}")]
    InsufficientSpace {
        needed: u64,
        available: u64,
        path: String,
    },

    #[error("not running as root")]
    NotRoot,

    #[error("package file not found: {0}")]
    PackageFileNotFound(PathBuf),

    #[error(transparent)]
    Core(#[from] pax_core::error::PaxError),

    #[error(transparent)]
    Resolve(#[from] pax_resolver::ResolveError),
}

pub type Result<T> = std::result::Result<T, ExecError>;
