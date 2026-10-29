use std::io::{BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

use pax_core::config::{SigLevel, SigTrust};

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
            let _ = std::fs::set_permissions(gpg_dir, std::fs::Permissions::from_mode(0o700));
        }
    }
}

/// Verify a detached signature using the default trusted-key policy.
pub fn verify_pgp(pkg_path: &Path, sig_path: &Path, gpg_dir: &Path) -> Result<()> {
    verify_pgp_with_trust(pkg_path, sig_path, gpg_dir, SigTrust::TrustedOnly)
}

pub fn verify_pgp_with_trust(
    pkg_path: &Path,
    sig_path: &Path,
    gpg_dir: &Path,
    trust: SigTrust,
) -> Result<()> {
    fix_gpg_dir_permissions(gpg_dir);
    let output = Command::new("gpg")
        .arg("--no-options")
        .arg("--homedir")
        .arg(gpg_dir)
        .args([
            "--batch",
            "--no-tty",
            "--no-auto-key-retrieve",
            "--trust-model",
            "pgp",
            "--status-fd",
            "1",
            "--verify",
        ])
        .arg(sig_path)
        .arg(pkg_path)
        .output()?;
    let status = String::from_utf8_lossy(&output.stdout);
    if signature_status_valid(output.status.success(), &status, trust) {
        return Ok(());
    }
    Err(ExecError::SignatureFailure {
        pkg: pkg_path.display().to_string(),
        message: format!(
            "signature invalid or signing key not trusted: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
    })
}

fn signature_status_valid(success: bool, status: &str, trust: SigTrust) -> bool {
    let mut valid = false;
    let mut trusted = false;
    for line in status.lines() {
        let Some(record) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        match record.split_whitespace().next().unwrap_or("") {
            "NEWSIG" => {
                if valid && trust == SigTrust::TrustedOnly && !trusted {
                    return false;
                }
                valid = false;
                trusted = false;
            }
            "VALIDSIG" => valid = true,
            "TRUST_FULLY" | "TRUST_ULTIMATE" if valid => trusted = true,
            "BADSIG" | "ERRSIG" | "EXPSIG" | "EXPKEYSIG" | "REVKEYSIG" | "NO_PUBKEY" | "NODATA"
            | "FAILURE" | "KEYREVOKED" | "KEYEXPIRED" | "SIGEXPIRED" => return false,
            _ => {}
        }
    }
    success && valid && (trust == SigTrust::TrustAll || trusted)
}

/// Only an explicit HTTP 404 means an optional signature is absent.
pub(crate) fn fetch_signature(
    agent: &ureq::Agent,
    url: &str,
    timeout: std::time::Duration,
) -> Result<Option<Vec<u8>>> {
    let response = match agent
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
    {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(404)) => return Ok(None),
        Err(error) => {
            return Err(ExecError::Download {
                pkg: url.to_string(),
                message: error.to_string(),
            });
        }
    };
    let body = response
        .into_body()
        .read_to_vec()
        .map_err(|error| ExecError::Download {
            pkg: url.to_string(),
            message: error.to_string(),
        })?;
    Ok(Some(body))
}

pub fn verify_signature(
    path: &Path,
    signature: Option<&Path>,
    gpg_dir: &Path,
    level: SigLevel,
    trust: SigTrust,
) -> Result<()> {
    if level == SigLevel::Never {
        return Ok(());
    }
    match signature {
        Some(sig) => verify_pgp_with_trust(path, sig, gpg_dir, trust),
        None if level == SigLevel::Optional => Ok(()),
        None => Err(ExecError::SignatureFailure {
            pkg: path.display().to_string(),
            message: "required signature is missing".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_policy_requires_valid_and_trusted_signature() {
        let valid = "[GNUPG:] GOODSIG key user\n[GNUPG:] VALIDSIG fingerprint\n";
        assert!(!signature_status_valid(true, valid, SigTrust::TrustedOnly));
        assert!(signature_status_valid(true, valid, SigTrust::TrustAll));
        for status in ["TRUST_UNDEFINED", "TRUST_NEVER", "TRUST_MARGINAL"] {
            assert!(!signature_status_valid(
                true,
                &format!("{valid}[GNUPG:] {status}\n"),
                SigTrust::TrustedOnly
            ));
        }
        let mixed = format!("{valid}[GNUPG:] NEWSIG\n{valid}[GNUPG:] TRUST_FULLY 0 pgp\n");
        assert!(!signature_status_valid(true, &mixed, SigTrust::TrustedOnly));
        for trust in [SigTrust::TrustedOnly, SigTrust::TrustAll] {
            let trusted = format!("{valid}[GNUPG:] TRUST_FULLY 0 pgp\n");
            assert!(signature_status_valid(true, &trusted, trust));
            assert!(!signature_status_valid(false, &trusted, trust));
            assert!(!signature_status_valid(
                true,
                "[GNUPG:] GOODSIG key user",
                trust
            ));
            for failure in [
                "BADSIG",
                "ERRSIG",
                "EXPKEYSIG",
                "REVKEYSIG",
                "NO_PUBKEY",
                "EXPSIG",
                "KEYEXPIRED",
            ] {
                assert!(!signature_status_valid(
                    true,
                    &format!("{trusted}[GNUPG:] {failure} key"),
                    trust
                ));
            }
        }
    }

    #[test]
    fn optional_allows_absence_but_rejects_present_invalid_signature() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive");
        let signature = dir.path().join("archive.sig");
        std::fs::write(&archive, b"archive").unwrap();
        std::fs::write(&signature, b"invalid signature").unwrap();
        assert!(
            verify_signature(
                &archive,
                None,
                dir.path(),
                SigLevel::Optional,
                SigTrust::TrustedOnly
            )
            .is_ok()
        );
        assert!(
            verify_signature(
                &archive,
                None,
                dir.path(),
                SigLevel::Required,
                SigTrust::TrustedOnly
            )
            .is_err()
        );
        for trust in [SigTrust::TrustedOnly, SigTrust::TrustAll] {
            assert!(
                verify_signature(
                    &archive,
                    Some(&signature),
                    dir.path(),
                    SigLevel::Optional,
                    trust
                )
                .is_err()
            );
        }
    }
}
