use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use pax_core::config::{SigLevel, SigTrust};

use crate::error::{ExecError, Result};
use crate::verify;

pub struct DownloadTarget {
    pub name: String,
    pub filename: String,
    pub expected_sha256: Option<String>,
    pub compressed_size: u64,
    pub mirrors: Vec<String>,
    pub sig_level: SigLevel,
    pub sig_trust: SigTrust,
}

pub struct DownloadedPackage {
    pub name: String,
    pub path: PathBuf,
}

pub fn download_packages(
    targets: &[DownloadTarget],
    cache_dir: &Path,
    parallel: u32,
    multi_progress: &MultiProgress,
    gpg_dir: &Path,
) -> Result<Vec<DownloadedPackage>> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(parallel.max(1) as usize)
        .build()
        .map_err(|e| ExecError::Download {
            pkg: String::new(),
            message: e.to_string(),
        })?;

    let gpg_dir = gpg_dir.to_path_buf();
    let results: Vec<Result<DownloadedPackage>> = pool.install(|| {
        targets
            .par_iter()
            .map(|target| download_one(target, cache_dir, multi_progress, &gpg_dir))
            .collect()
    });

    results.into_iter().collect()
}

fn signature_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".sig");
    PathBuf::from(name)
}

fn verify_cached(target: &DownloadTarget, path: &Path, gpg_dir: &Path) -> Result<()> {
    if let Some(expected) = &target.expected_sha256 {
        verify::verify_sha256(path, expected)?;
    }
    let signature = signature_path(path);
    // Metadata errors must not turn an unreadable signature into an absent one.
    let present = match std::fs::symlink_metadata(&signature) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    verify::verify_signature(
        path,
        present.then_some(signature.as_path()),
        gpg_dir,
        target.sig_level,
        target.sig_trust,
    )
}

fn download_one(
    target: &DownloadTarget,
    cache_dir: &Path,
    multi_progress: &MultiProgress,
    gpg_dir: &Path,
) -> Result<DownloadedPackage> {
    download_one_with_agent(
        target,
        cache_dir,
        multi_progress,
        gpg_dir,
        &crate::http_agent(),
    )
}

fn download_one_with_agent(
    target: &DownloadTarget,
    cache_dir: &Path,
    multi_progress: &MultiProgress,
    gpg_dir: &Path,
    agent: &ureq::Agent,
) -> Result<DownloadedPackage> {
    let cached = cache_dir.join(&target.filename);
    let cached_error = if cached.exists() {
        match verify_cached(target, &cached, gpg_dir) {
            Ok(()) => {
                return Ok(DownloadedPackage {
                    name: target.name.clone(),
                    path: cached,
                });
            }
            Err(error) => Some(error),
        }
    } else {
        None
    };
    if target.mirrors.is_empty() {
        if let Some(error) = cached_error {
            return Err(error);
        }
    }

    let style = ProgressStyle::with_template(
        " {spinner:.green} {msg:<30} [{bar:25.cyan/dim}] {bytes}/{total_bytes} {bytes_per_sec}",
    )
    .unwrap()
    .progress_chars("=> ");

    let pb = multi_progress.add(ProgressBar::new(target.compressed_size));
    pb.set_style(style);
    pb.set_message(target.name.clone());

    let mut last_error = String::new();

    for mirror_url in &target.mirrors {
        let url = format!("{mirror_url}/{}", target.filename);
        match try_download(&url, cache_dir, target, &pb, gpg_dir, agent) {
            Ok(path) => {
                pb.finish_with_message(format!("{} done", target.name));
                return Ok(DownloadedPackage {
                    name: target.name.clone(),
                    path,
                });
            }
            Err(e @ ExecError::SignatureFailure { .. }) => {
                pb.finish_with_message(format!("{} SIG FAIL", target.name));
                return Err(e);
            }
            Err(e) => {
                last_error = e.to_string();
                pb.set_position(0);
                continue;
            }
        }
    }

    pb.finish_with_message(format!("{} FAILED", target.name));
    Err(ExecError::AllMirrorsFailed {
        pkg: format!("{}: {}", target.name, last_error),
    })
}

fn try_download(
    url: &str,
    cache_dir: &Path,
    target: &DownloadTarget,
    pb: &ProgressBar,
    gpg_dir: &Path,
    agent: &ureq::Agent,
) -> Result<PathBuf> {
    let response = agent.get(url).call().map_err(|e| ExecError::Download {
        pkg: target.name.clone(),
        message: e.to_string(),
    })?;

    let mut tmp = NamedTempFile::new_in(cache_dir)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut body = response.into_body().into_reader();

    loop {
        let n = body.read(&mut buf).map_err(|e| ExecError::Download {
            pkg: target.name.clone(),
            message: e.to_string(),
        })?;
        if n == 0 {
            break;
        }
        tmp.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        pb.inc(n as u64);
    }

    tmp.flush()?;

    if let Some(ref expected) = target.expected_sha256 {
        let actual: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if actual != *expected {
            return Err(ExecError::ChecksumMismatch {
                pkg: target.name.clone(),
                expected: expected.clone(),
                actual,
            });
        }
    }

    let mut signature = None;
    if target.sig_level != SigLevel::Never {
        if let Some(body) = verify::fetch_signature(
            agent,
            &format!("{url}.sig"),
            std::time::Duration::from_secs(60),
        )? {
            let mut file = NamedTempFile::new_in(cache_dir)?;
            file.write_all(&body)?;
            file.flush()?;
            signature = Some(file);
        }
    }
    verify::verify_signature(
        tmp.path(),
        signature.as_ref().map(|file| file.path()),
        gpg_dir,
        target.sig_level,
        target.sig_trust,
    )?;

    let dest = cache_dir.join(&target.filename);
    let sig_dest = signature_path(&dest);
    // Once the replacement is verified, remove rejected cached bytes before changing
    // their sidecar. A failed persist must not leave old bytes with a new or absent sig.
    match std::fs::remove_file(&dest) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if let Some(signature) = signature {
        signature
            .persist(&sig_dest)
            .map_err(|error| ExecError::Download {
                pkg: target.name.clone(),
                message: format!("failed to persist signature: {error}"),
            })?;
    } else {
        match std::fs::remove_file(&sig_dest) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    tmp.persist(&dest).map_err(|e| ExecError::Download {
        pkg: target.name.clone(),
        message: format!("failed to persist download: {e}"),
    })?;
    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(level: SigLevel) -> DownloadTarget {
        DownloadTarget {
            name: "package".into(),
            filename: "package.pkg.tar.zst".into(),
            expected_sha256: None,
            compressed_size: 0,
            mirrors: vec![],
            sig_level: level,
            sig_trust: SigTrust::TrustedOnly,
        }
    }

    #[test]
    fn fresh_downloads_verify_before_cache_publication() {
        use std::net::TcpListener;
        use std::time::Duration;
        for (level, response, succeeds) in [
            (
                SigLevel::Required,
                &b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"[..],
                false,
            ),
            (
                SigLevel::Optional,
                &b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"[..],
                true,
            ),
            (
                SigLevel::Optional,
                &b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ninvalid"[..],
                false,
            ),
            (
                SigLevel::Optional,
                &b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"[..],
                false,
            ),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}/package", listener.local_addr().unwrap());
            let server = std::thread::spawn(move || {
                for response in [
                    &b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\narchive"[..],
                    response,
                ] {
                    let started = std::time::Instant::now();
                    loop {
                        match listener.accept() {
                            Ok((mut stream, _)) => {
                                stream
                                    .set_read_timeout(Some(Duration::from_secs(2)))
                                    .unwrap();
                                let mut request = [0; 4096];
                                stream.read(&mut request).unwrap();
                                stream.write_all(response).unwrap();
                                break;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                assert!(started.elapsed() < Duration::from_secs(5));
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            Err(error) => panic!("accept failed: {error}"),
                        }
                    }
                }
            });
            let dir = tempfile::tempdir().unwrap();
            let gpg = tempfile::tempdir().unwrap();
            let agent = ureq::Agent::config_builder()
                .proxy(None)
                .timeout_global(Some(Duration::from_secs(2)))
                .build()
                .new_agent();
            let target = target(level);
            let result = try_download(
                &url,
                dir.path(),
                &target,
                &ProgressBar::hidden(),
                gpg.path(),
                &agent,
            );
            server.join().unwrap();
            assert_eq!(result.is_ok(), succeeds, "{result:?}");
            assert_eq!(dir.path().join(&target.filename).exists(), succeeds);
            assert_eq!(
                std::fs::read_dir(dir.path()).unwrap().count(),
                usize::from(succeeds)
            );
            if !succeeds {
                // A retry cannot mistake the failed download for a cached success.
                assert!(
                    download_packages(&[target], dir.path(), 1, &MultiProgress::new(), gpg.path())
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn rejected_cache_is_replaced_only_by_verified_signed_download() {
        use std::net::TcpListener;
        use std::process::Command;
        use std::time::{Duration, Instant};

        let gpg = tempfile::tempdir().unwrap();
        let signing = tempfile::tempdir().unwrap();
        let archive = signing.path().join("archive");
        let signature = signing.path().join("archive.sig");
        std::fs::write(&archive, b"verified archive").unwrap();
        let output = Command::new("gpg")
            .arg("--no-options")
            .arg("--homedir")
            .arg(gpg.path())
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "Pax cache regression <cache@example.invalid>",
                "ed25519",
                "sign",
                "0",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new("gpg")
            .arg("--no-options")
            .arg("--homedir")
            .arg(gpg.path())
            .args([
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--output",
            ])
            .arg(&signature)
            .arg("--detach-sign")
            .arg(&archive)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let archive_bytes = std::fs::read(&archive).unwrap();
        let signature_bytes = std::fs::read(&signature).unwrap();

        for failure in ["checksum", "missing signature", "invalid signature"] {
            let dir = tempfile::tempdir().unwrap();
            let mut target = target(SigLevel::Required);
            target.expected_sha256 = Some(verify::compute_sha256(&archive).unwrap());
            let cached = dir.path().join(&target.filename);
            std::fs::write(
                &cached,
                if failure == "checksum" {
                    &b"corrupted archive"[..]
                } else {
                    &archive_bytes
                },
            )
            .unwrap();
            if failure != "missing signature" {
                std::fs::write(
                    signature_path(&cached),
                    if failure == "invalid signature" {
                        &b"invalid signature"[..]
                    } else {
                        &signature_bytes
                    },
                )
                .unwrap();
            }
            assert!(verify_cached(&target, &cached, gpg.path()).is_err());

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            target.mirrors = vec![format!("http://{}", listener.local_addr().unwrap())];
            let bodies = [archive_bytes.clone(), signature_bytes.clone()];
            let filename = target.filename.clone();
            let server = std::thread::spawn(move || {
                for (body, suffix) in bodies.into_iter().zip(["", ".sig"]) {
                    let started = Instant::now();
                    loop {
                        match listener.accept() {
                            Ok((mut stream, _)) => {
                                stream
                                    .set_read_timeout(Some(Duration::from_secs(2)))
                                    .unwrap();
                                let mut request = [0; 4096];
                                let n = stream.read(&mut request).unwrap();
                                assert!(
                                    String::from_utf8_lossy(&request[..n])
                                        .starts_with(&format!("GET /{filename}{suffix} "))
                                );
                                write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                                stream.write_all(&body).unwrap();
                                break;
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                assert!(started.elapsed() < Duration::from_secs(5));
                                std::thread::sleep(Duration::from_millis(10));
                            }
                            Err(error) => panic!("accept failed: {error}"),
                        }
                    }
                }
            });
            let agent = ureq::Agent::config_builder()
                .proxy(None)
                .timeout_global(Some(Duration::from_secs(2)))
                .build()
                .new_agent();
            let result = download_one_with_agent(
                &target,
                dir.path(),
                &MultiProgress::new(),
                gpg.path(),
                &agent,
            );
            server.join().unwrap();
            let package = result.unwrap_or_else(|error| panic!("{failure}: {error}"));
            assert_eq!(package.path, cached);
            assert_eq!(std::fs::read(&cached).unwrap(), archive_bytes);
            assert_eq!(
                std::fs::read(signature_path(&cached)).unwrap(),
                signature_bytes
            );
            assert!(verify_cached(&target, &cached, gpg.path()).is_ok());
            // No mirror is available now; a second use must verify the repaired cache.
            target.mirrors.clear();
            assert!(
                download_one_with_agent(
                    &target,
                    dir.path(),
                    &MultiProgress::new(),
                    gpg.path(),
                    &agent
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn cached_archives_require_signatures_on_every_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let target = target(SigLevel::Required);
        std::fs::write(dir.path().join(&target.filename), b"cached archive").unwrap();
        for _ in 0..2 {
            assert!(
                download_packages(
                    std::slice::from_ref(&target),
                    dir.path(),
                    1,
                    &MultiProgress::new(),
                    dir.path()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn optional_cached_archive_rejects_invalid_signature_repeatedly() {
        let dir = tempfile::tempdir().unwrap();
        let target = target(SigLevel::Optional);
        let path = dir.path().join(&target.filename);
        std::fs::write(&path, b"cached archive").unwrap();
        assert!(verify_cached(&target, &path, dir.path()).is_ok());
        std::fs::write(signature_path(&path), b"invalid signature").unwrap();
        for _ in 0..2 {
            assert!(
                download_packages(
                    std::slice::from_ref(&target),
                    dir.path(),
                    1,
                    &MultiProgress::new(),
                    dir.path()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn cached_checksum_still_enforced_when_signatures_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let mut target = target(SigLevel::Never);
        target.expected_sha256 = Some("wrong".into());
        let path = dir.path().join(&target.filename);
        std::fs::write(&path, b"cached archive").unwrap();
        assert!(verify_cached(&target, &path, dir.path()).is_err());
    }
}
