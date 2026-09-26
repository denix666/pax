use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("download failed for {pkg}: {message}")]
    Download { pkg: String, message: String },

    #[error("all mirrors failed for {pkg}")]
    AllMirrorsFailed { pkg: String },

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

    #[error("not running as root")]
    NotRoot,

    #[error("package file not found: {0}")]
    PackageFileNotFound(PathBuf),

    #[error(transparent)]
    Core(#[from] pax_core::error::PaxError),
}

pub type Result<T> = std::result::Result<T, ExecError>;
