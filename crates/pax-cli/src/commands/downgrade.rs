use std::collections::HashSet;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use indicatif::MultiProgress;
use pax_alpm::db::DatabaseHandle;
use pax_core::config::SigConfig;
use pax_core::version::Version;
use pax_exec::downgrade::{
    DowngradeCandidate, archive_filename, archive_versions, cached_versions, merge_candidates,
    resolve_archive_versions,
};
use pax_exec::download::download_packages_with_timeout;
use pax_exec::{DownloadTarget, read_pkginfo};

use super::localinstall::{DowngradeFile, install_downgrade_files};
use crate::cli::{DowngradeArgs, IgnoreMode};

struct Request {
    name: String,
    version: Option<Version>,
}

impl Request {
    fn parse(value: &str) -> Result<Self> {
        let (name, version) = match value.split_once('=') {
            Some((name, version)) => (name, Some(Version::parse(version)?)),
            None => (value, None),
        };
        ensure!(
            !name.is_empty()
                && !matches!(name.as_bytes()[0], b'.' | b'-')
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"@._+-".contains(&byte)),
            "invalid package name: {name:?}"
        );
        if let Some(version) = &version {
            ensure!(
                !version.to_string().contains(['=', '/', '\\'])
                    && !version.to_string().chars().any(char::is_whitespace),
                "invalid package version: {version}"
            );
        }
        Ok(Self {
            name: name.to_owned(),
            version,
        })
    }

    fn matches(&self, candidate: &DowngradeCandidate, installed: &Version) -> bool {
        candidate.version < *installed
            && self
                .version
                .as_ref()
                .is_none_or(|version| candidate.version == *version)
    }
}

pub fn run(db: &mut DatabaseHandle, config_path: &Path, args: &DowngradeArgs) -> Result<()> {
    let requests: Vec<_> = args
        .packages
        .iter()
        .map(|value| Request::parse(value))
        .collect::<Result<_>>()?;
    let mut names = HashSet::new();
    for request in &requests {
        ensure!(
            names.insert(&request.name),
            "duplicate package: {}",
            request.name
        );
        ensure!(
            args.list || !args.noconfirm || args.latest || request.version.is_some(),
            "{}: --noconfirm requires an exact version or --latest",
            request.name
        );
    }
    if !args.list {
        super::ensure_root();
    }
    let manjaro = is_manjaro(&db.config.root_dir);
    let use_archive =
        !args.cached_only && (args.ala_only || args.with_ala || args.ala_url.is_some() || !manjaro);
    if manjaro && use_archive {
        eprintln!(
            "warning: ALA contains Arch Linux packages; compatibility with Manjaro is not guaranteed"
        );
    } else if manjaro && !args.cached_only {
        println!(
            "Manjaro: searching local caches only (use --with-ala to include Arch Linux Archive)."
        );
    }
    let mut cache_dirs = db.config.cache_dirs.clone();
    cache_dirs.extend(args.cache_dirs.iter().cloned());
    cache_dirs.dedup();
    let archive_base = format!(
        "{}/packages",
        args.ala_url
            .as_deref()
            .unwrap_or("https://archive.archlinux.org")
            .trim_end_matches('/')
    );
    let mut chosen = Vec::new();
    for request in &requests {
        let installed = db
            .local_info(&request.name)?
            .with_context(|| format!("{}: package is not installed", request.name))?
            .info
            .version
            .clone();
        let cache = if args.ala_only {
            Vec::new()
        } else {
            let mut search_dirs = cache_dirs.clone();
            search_dirs.extend(cache_dirs.iter().map(|path| path.join("pax-ala")));
            let report = cached_versions(&request.name, &search_dirs, &db.config.architecture)?;
            for diagnostic in report.diagnostics {
                eprintln!(
                    "warning: {}: {}",
                    diagnostic.path.display(),
                    diagnostic.message
                );
            }
            report.candidates
        };
        let matching_cache = cache
            .iter()
            .any(|candidate| request.matches(candidate, &installed));
        let remote = if use_archive && !(args.prefer_cache && matching_cache) {
            let result = archive_versions(&request.name, &db.config.architecture, &archive_base)
                .map_err(anyhow::Error::from)
                .and_then(|candidates| hydrate_candidates(candidates, request));
            match result {
                Ok(candidates) => candidates,
                Err(error) if matching_cache => {
                    eprintln!("warning: {error}; using available cached versions");
                    Vec::new()
                }
                Err(error) => return Err(error),
            }
        } else {
            Vec::new()
        };
        let candidates: Vec<_> = merge_candidates(cache, remote)
            .into_iter()
            .filter(|candidate| request.matches(candidate, &installed))
            .collect();
        print_candidates(&request.name, &installed, &candidates);
        ensure!(
            !candidates.is_empty(),
            "{}: no matching older version found{}",
            request.name,
            if !use_archive {
                " in the local caches"
            } else {
                ""
            }
        );
        if args.list {
            continue;
        }
        let index = if args.latest || candidates.len() == 1 {
            0
        } else {
            ensure!(
                !args.noconfirm,
                "{}: more than one matching archive; use --latest",
                request.name
            );
            ensure!(
                std::io::stdin().is_terminal(),
                "version selection requires a terminal; specify an exact version or --latest"
            );
            print!("Select version [1-{}], or q to cancel: ", candidates.len());
            std::io::stdout().flush()?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            if answer.trim().eq_ignore_ascii_case("q") || answer.trim().is_empty() {
                println!("Downgrade cancelled.");
                return Ok(());
            }
            let index = answer
                .trim()
                .parse::<usize>()
                .context("invalid selection")?;
            ensure!(
                index > 0 && index <= candidates.len(),
                "selection is out of range"
            );
            index - 1
        };
        chosen.push((request, installed, candidates[index].clone()));
    }
    if args.list {
        return Ok(());
    }

    let mut files = Vec::new();
    for (request, installed, candidate) in chosen {
        let (path, policy) = prepare_candidate(db, &candidate, &cache_dirs)?;
        let metadata = read_pkginfo(&path)?;
        ensure!(
            metadata.name == request.name,
            "archive identity mismatch for {}",
            request.name
        );
        // ALA filenames may omit epoch. The signed package metadata is authoritative.
        ensure!(
            metadata.info.version.pkgver == candidate.version.pkgver
                && metadata.info.version.pkgrel == candidate.version.pkgrel
                && (candidate.version.epoch == 0
                    || metadata.info.version.epoch == candidate.version.epoch),
            "{}: downloaded version differs from selected version",
            request.name
        );
        if let Some(version) = &request.version {
            ensure!(
                metadata.info.version == *version,
                "{}: expected version {}, archive contains {}",
                request.name,
                version,
                metadata.info.version
            );
        }
        ensure!(
            metadata.info.version < installed,
            "{}: archive version {} is not older than {}",
            request.name,
            metadata.info.version,
            installed
        );
        files.push(DowngradeFile {
            path,
            name: request.name.clone(),
            version: metadata.info.version,
            installed_version: installed,
            policy,
        });
    }
    if !install_downgrade_files(db, &files, args.noconfirm)? {
        return Ok(());
    }

    let mut ignored = Vec::new();
    for file in &files {
        if db.config.ignore_pkgs.iter().any(|name| name == &file.name) {
            continue;
        }
        let add = match args.ignore {
            IgnoreMode::Always => true,
            IgnoreMode::Never => false,
            IgnoreMode::Prompt if args.noconfirm || !std::io::stdin().is_terminal() => {
                println!(
                    "{}: not added to IgnorePkg; use --ignore=always to pin the downgraded version.",
                    file.name
                );
                false
            }
            IgnoreMode::Prompt => {
                super::confirm_default_no(&format!("Add {} to IgnorePkg? [y/N]", file.name))?
            }
        };
        if add {
            ignored.push(file.name.clone());
        }
    }
    if !ignored.is_empty() {
        let _lock = pax_alpm::DbLock::acquire(&db.config.db_path)?;
        super::downgrade_ignore::add_ignored_packages(config_path, &ignored)
            .context("packages were downgraded, but updating IgnorePkg failed")?;
        println!("Added to IgnorePkg: {}", ignored.join(" "));
    }
    Ok(())
}

fn hydrate_candidates(
    candidates: Vec<DowngradeCandidate>,
    request: &Request,
) -> Result<Vec<DowngradeCandidate>> {
    let candidates = candidates
        .into_iter()
        .filter(|candidate| {
            request.version.as_ref().is_none_or(|version| {
                candidate.version.pkgver == version.pkgver
                    && candidate.version.pkgrel == version.pkgrel
            })
        })
        .collect();
    // Resolve omitted epochs before filtering or automatic ranking. The library
    // bounds concurrency and the entire metadata lookup, including queued work.
    Ok(resolve_archive_versions(candidates)?)
}

fn prepare_candidate(
    db: &DatabaseHandle,
    candidate: &DowngradeCandidate,
    cache_dirs: &[PathBuf],
) -> Result<(PathBuf, SigConfig)> {
    for path in &candidate.local_paths {
        let policy = if cache_dirs
            .iter()
            .any(|cache| path.starts_with(cache.join("pax-ala")))
        {
            db.config.sig_level
        } else {
            db.config.local_file_sig_level
        };
        let signature = PathBuf::from(format!("{}.sig", path.display()));
        let present = match std::fs::symlink_metadata(&signature) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        match pax_exec::verify::verify_signature(
            path,
            present.then_some(signature.as_path()),
            &db.config.gpg_dir,
            policy.package,
            policy.package_trust,
        ) {
            Ok(()) => return Ok((path.clone(), policy)),
            Err(error) => eprintln!("warning: rejecting cached {}: {error}", path.display()),
        }
    }
    let url = candidate
        .remote_url
        .as_ref()
        .context("no verified cached archive and no archive download available")?;
    let (mirror, filename) = url.rsplit_once('/').context("invalid archive URL")?;
    let cache = db
        .config
        .cache_dirs
        .first()
        .context("no package cache configured")?;
    std::fs::create_dir_all(cache)?;
    // Keep ALA downloads separate from cache entries with identical filenames:
    // they may carry different epochs or distributor builds.
    let directory = cache.join("pax-ala");
    std::fs::create_dir_all(&directory)?;
    let policy = db.config.sig_level;
    let downloaded = download_packages_with_timeout(
        &[DownloadTarget {
            name: candidate.name.clone(),
            filename: filename.to_owned(),
            expected_sha256: None,
            compressed_size: 0,
            mirrors: vec![mirror.to_owned()],
            sig_level: policy.package,
            sig_trust: policy.package_trust,
        }],
        &directory,
        1,
        &MultiProgress::new(),
        &db.config.gpg_dir,
        std::time::Duration::from_secs(300),
    )?;
    let mut path = downloaded
        .into_iter()
        .next()
        .context("archive download returned no package")?
        .path;
    let decoded = directory.join(archive_filename(url)?);
    if path != decoded {
        let signature = PathBuf::from(format!("{}.sig", path.display()));
        let decoded_signature = PathBuf::from(format!("{}.sig", decoded.display()));
        // Publishing either side under a new name must never expose an old
        // archive paired with a signature for different bytes.
        match std::fs::remove_file(&decoded) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if signature.exists() {
            std::fs::rename(&signature, &decoded_signature)?;
        } else {
            match std::fs::remove_file(&decoded_signature) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        std::fs::rename(&path, &decoded)?;
        path = decoded;
    }
    Ok((path, policy))
}

fn print_candidates(name: &str, installed: &Version, candidates: &[DowngradeCandidate]) {
    println!("\n{name} — installed: {installed}");
    println!("  #  {:<24} {:<12} Source", "Version", "Architecture");
    for (index, candidate) in candidates.iter().enumerate() {
        let mut sources: Vec<_> = candidate
            .local_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        if candidate.remote_url.is_some() {
            sources.push("ALA".to_owned());
        }
        println!(
            "{:>3}  {:<24} {:<12} {}",
            index + 1,
            candidate.version,
            candidate.arch,
            sources.join(", ")
        );
    }
}

fn is_manjaro(root: &Path) -> bool {
    let release = std::fs::read_to_string(root.join("etc/os-release")).unwrap_or_default();
    release.lines().any(|line| {
        line.trim().strip_prefix("ID=").is_some_and(|value| {
            value
                .trim_matches(['\'', '"'])
                .eq_ignore_ascii_case("manjaro")
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_versions_must_be_exact_and_older() {
        let request = Request::parse("pkg=1:2.0-1").unwrap();
        let mut candidate = DowngradeCandidate {
            name: "pkg".into(),
            version: Version::parse("1:2.0-1").unwrap(),
            arch: "any".into(),
            local_paths: vec![PathBuf::from("pkg.pkg.tar")],
            remote_url: None,
        };
        assert!(request.matches(&candidate, &Version::parse("1:3.0-1").unwrap()));
        assert!(!request.matches(&candidate, &candidate.version));
        candidate.version = Version::parse("2.0-1").unwrap();
        assert!(!request.matches(&candidate, &Version::parse("1:3.0-1").unwrap()));
        candidate.local_paths.clear();
        candidate.remote_url = Some("https://example.org/pkg.pkg.tar".into());
        assert!(!request.matches(&candidate, &Version::parse("1:3.0-1").unwrap()));
        for value in ["../pkg", "pkg=", "pkg=1=2", "pkg=1/2", "-pkg"] {
            assert!(Request::parse(value).is_err(), "{value}");
        }
    }

    #[test]
    fn distribution_detection_uses_target_root() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("etc")).unwrap();
        assert!(!is_manjaro(root.path()));
        std::fs::write(
            root.path().join("etc/os-release"),
            "ID=\"manjaro\"\nID_LIKE=arch\n",
        )
        .unwrap();
        assert!(is_manjaro(root.path()));
    }
}
