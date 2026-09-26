use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::error::{ExecError, Result};

pub fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    let actual: String = hash.iter().map(|b| format!("{b:02x}")).collect();

    if actual != expected {
        return Err(ExecError::ChecksumMismatch {
            pkg: path.display().to_string(),
            expected: expected.to_string(),
            actual,
        });
    }

    Ok(())
}

pub fn compute_sha256(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    Ok(hash.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn verify_pgp(pkg_path: &Path, sig_path: &Path, gpg_dir: &Path) -> Result<()> {
    let output = Command::new("gpg")
        .args([
            "--homedir",
            &gpg_dir.display().to_string(),
            "--status-fd",
            "1",
            "--verify",
            &sig_path.display().to_string(),
            &pkg_path.display().to_string(),
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ExecError::SignatureFailure {
            pkg: pkg_path.display().to_string(),
            message: stderr.trim().to_string(),
        });
    }

    Ok(())
}
