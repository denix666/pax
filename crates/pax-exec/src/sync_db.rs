use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use tempfile::NamedTempFile;

use crate::error::{ExecError, Result};

pub struct SyncTarget {
    pub repo_name: String,
    pub mirrors: Vec<String>,
}

pub fn sync_databases(
    targets: &[SyncTarget],
    sync_dir: &Path,
    parallel: u32,
    multi_progress: &MultiProgress,
) -> Result<()> {
    std::fs::create_dir_all(sync_dir)?;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(parallel.max(1) as usize)
        .build()
        .map_err(|e| ExecError::Download {
            pkg: String::new(),
            message: e.to_string(),
        })?;

    let results: Vec<std::result::Result<(), String>> = pool.install(|| {
        targets
            .par_iter()
            .map(|target| sync_one(target, sync_dir, multi_progress).map_err(|e| e.to_string()))
            .collect()
    });

    let mut failed = 0;
    for result in &results {
        if let Err(e) = result {
            eprintln!("warning: {e}");
            failed += 1;
        }
    }

    if failed == targets.len() {
        return Err(ExecError::Download {
            pkg: String::new(),
            message: "all repository syncs failed".to_string(),
        });
    }

    Ok(())
}

fn sync_one(target: &SyncTarget, sync_dir: &Path, multi_progress: &MultiProgress) -> Result<()> {
    let style = ProgressStyle::with_template(
        " {spinner:.green} {msg:<20} [{bar:25.cyan/dim}] {bytes}/{total_bytes} {bytes_per_sec}",
    )
    .unwrap()
    .progress_chars("=> ");

    let pb = multi_progress.add(ProgressBar::new(0));
    pb.set_style(style);
    pb.set_message(format!("{}.db", target.repo_name));

    let filename = format!("{}.db", target.repo_name);
    let mut last_error = String::new();

    for mirror_url in &target.mirrors {
        let url = format!("{mirror_url}/{filename}");
        match try_download_db(&url, sync_dir, &filename, &pb) {
            Ok(()) => {
                pb.finish_with_message(format!("{} ok", target.repo_name));
                return Ok(());
            }
            Err(e) => {
                last_error = e.to_string();
                pb.set_position(0);
                continue;
            }
        }
    }

    pb.finish_with_message(format!("{} FAILED", target.repo_name));
    Err(ExecError::AllMirrorsFailed {
        pkg: format!("{}: {}", target.repo_name, last_error),
    })
}

fn try_download_db(
    url: &str,
    sync_dir: &Path,
    filename: &str,
    pb: &ProgressBar,
) -> Result<()> {
    let response = crate::http_agent().get(url).call().map_err(|e| ExecError::Download {
        pkg: filename.to_string(),
        message: e.to_string(),
    })?;

    if let Some(len) = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        pb.set_length(len);
    }

    let mut tmp = NamedTempFile::new_in(sync_dir)?;
    let mut buf = [0u8; 65536];
    let mut body = response.into_body().into_reader();

    loop {
        let n = body.read(&mut buf).map_err(|e| ExecError::Download {
            pkg: filename.to_string(),
            message: e.to_string(),
        })?;
        if n == 0 {
            break;
        }
        tmp.write_all(&buf[..n])?;
        pb.inc(n as u64);
    }

    tmp.flush()?;

    let dest = sync_dir.join(filename);
    tmp.persist(&dest).map_err(|e| ExecError::Download {
        pkg: filename.to_string(),
        message: format!("failed to persist: {e}"),
    })?;

    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o644))?;

    Ok(())
}
