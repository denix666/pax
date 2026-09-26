use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::error::{ExecError, Result};
use crate::verify;

pub struct DownloadTarget {
    pub name: String,
    pub filename: String,
    pub expected_sha256: Option<String>,
    pub compressed_size: u64,
    pub mirrors: Vec<String>,
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
) -> Result<Vec<DownloadedPackage>> {
    let to_download: Vec<_> = targets
        .iter()
        .filter(|t| !is_cached(cache_dir, t))
        .collect();

    if to_download.is_empty() {
        return Ok(targets
            .iter()
            .map(|t| DownloadedPackage {
                name: t.name.clone(),
                path: cache_dir.join(&t.filename),
            })
            .collect());
    }

    let cached_count = targets.len() - to_download.len();
    if cached_count > 0 {
        let pb = multi_progress.add(ProgressBar::new_spinner());
        pb.finish_with_message(format!("{cached_count} package(s) already cached"));
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(parallel.max(1) as usize)
        .build()
        .map_err(|e| ExecError::Download {
            pkg: String::new(),
            message: e.to_string(),
        })?;

    let results: Vec<Result<DownloadedPackage>> = pool.install(|| {
        to_download
            .par_iter()
            .map(|target| download_one(target, cache_dir, multi_progress))
            .collect()
    });

    let mut downloaded: Vec<DownloadedPackage> = Vec::with_capacity(targets.len());

    for result in results {
        downloaded.push(result?);
    }

    for target in targets {
        if !downloaded.iter().any(|d| d.name == target.name) {
            downloaded.push(DownloadedPackage {
                name: target.name.clone(),
                path: cache_dir.join(&target.filename),
            });
        }
    }

    Ok(downloaded)
}

fn is_cached(cache_dir: &Path, target: &DownloadTarget) -> bool {
    let path = cache_dir.join(&target.filename);
    if !path.exists() {
        return false;
    }
    if let Some(ref expected) = target.expected_sha256 {
        verify::verify_sha256(&path, expected).is_ok()
    } else {
        true
    }
}

fn download_one(
    target: &DownloadTarget,
    cache_dir: &Path,
    multi_progress: &MultiProgress,
) -> Result<DownloadedPackage> {
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
        match try_download(&url, cache_dir, target, &pb) {
            Ok(path) => {
                pb.finish_with_message(format!("{} done", target.name));
                return Ok(DownloadedPackage {
                    name: target.name.clone(),
                    path,
                });
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
) -> Result<PathBuf> {
    let response = crate::http_agent().get(url).call().map_err(|e| ExecError::Download {
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
        let actual: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        if actual != *expected {
            return Err(ExecError::ChecksumMismatch {
                pkg: target.name.clone(),
                expected: expected.clone(),
                actual,
            });
        }
    }

    let dest = cache_dir.join(&target.filename);
    tmp.persist(&dest).map_err(|e| ExecError::Download {
        pkg: target.name.clone(),
        message: format!("failed to persist download: {e}"),
    })?;

    Ok(dest)
}
