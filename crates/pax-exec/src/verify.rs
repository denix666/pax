use std::io::{BufReader, Read};
use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::error::{ExecError, Result};

fn sha256_of_file(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path)?;
    let mut reader = BufReader::with_capacity(128 * 1024, file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 128 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hasher.finalize();
    Ok(hash.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let actual = sha256_of_file(path)?;

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
    sha256_of_file(path)
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
