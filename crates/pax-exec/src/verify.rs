use std::io::{BufReader, Read};
use std::os::unix::fs::PermissionsExt;
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

fn fix_gpg_dir_permissions(gpg_dir: &Path) {
    if let Ok(meta) = std::fs::metadata(gpg_dir) {
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            let _ = std::fs::set_permissions(
                gpg_dir,
                std::fs::Permissions::from_mode(0o700),
            );
        }
    }
}

fn extract_missing_key_id(stderr: &str) -> Option<String> {
    for line in stderr.lines() {
        if let Some(pos) = line.find("key ") {
            let rest = &line[pos + 4..];
            let key_id: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            if key_id.len() >= 16 {
                return Some(key_id);
            }
        }
    }
    None
}

fn recv_key(key_id: &str, gpg_dir: &Path) -> bool {
    let keyservers = [
        "hkps://keyserver.ubuntu.com",
        "hkps://keys.openpgp.org",
    ];
    for ks in &keyservers {
        let status = Command::new("gpg")
            .args([
                "--homedir",
                &gpg_dir.display().to_string(),
                "--keyserver",
                ks,
                "--recv-keys",
                key_id,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if status.map(|s| s.success()).unwrap_or(false) {
            return true;
        }
    }
    false
}

pub fn verify_pgp(pkg_path: &Path, sig_path: &Path, gpg_dir: &Path) -> Result<()> {
    fix_gpg_dir_permissions(gpg_dir);

    let run_gpg = || {
        Command::new("gpg")
            .args([
                "--homedir",
                &gpg_dir.display().to_string(),
                "--status-fd",
                "1",
                "--verify",
                &sig_path.display().to_string(),
                &pkg_path.display().to_string(),
            ])
            .output()
    };

    let output = run_gpg()?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);

    if stderr.contains("No public key") || stderr.contains("no public key") {
        if let Some(key_id) = extract_missing_key_id(&stderr) {
            eprintln!(":: Importing missing key {key_id}...");
            if recv_key(&key_id, gpg_dir) {
                let output2 = run_gpg()?;
                if output2.status.success() {
                    return Ok(());
                }
                let stderr2 = String::from_utf8_lossy(&output2.stderr);
                return Err(ExecError::SignatureFailure {
                    pkg: pkg_path.display().to_string(),
                    message: stderr2.trim().to_string(),
                });
            }
        }
    }

    Err(ExecError::SignatureFailure {
        pkg: pkg_path.display().to_string(),
        message: stderr.trim().to_string(),
    })
}
