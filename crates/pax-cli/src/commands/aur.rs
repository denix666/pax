use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Result;
use indicatif::MultiProgress;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_aur::{clone_and_build, resolve_aur_targets};
use pax_exec::{execute_transaction, DownloadTarget, InstallContext};
use pax_resolver::{build_transaction, resolve, topological_sort, ConcretePool, ResolveOptions};

use crate::output::print_transaction;

struct SyncInfo {
    compressed_size: u64,
    installed_size: u64,
    repository: String,
    filename: String,
    sha256sum: Option<String>,
}

pub fn run(
    db: &mut DatabaseHandle,
    packages: &[String],
    skip_review: bool,
    noconfirm: bool,
) -> Result<()> {
    if packages.is_empty() {
        eprintln!("error: no targets specified");
        std::process::exit(1);
    }

    db.ensure_both()?;

    let installed: HashSet<String> = db
        .installed_packages()?
        .iter()
        .map(|p| p.info.name.clone())
        .collect();

    let sync_available: HashSet<String> = db
        .sync_packages_with_repo_index()?
        .iter()
        .map(|(p, _)| p.info.name.clone())
        .collect();

    let pkg_refs: Vec<&str> = packages.iter().map(|s| s.as_str()).collect();

    println!(":: Resolving AUR dependencies...");
    let aur_targets =
        resolve_aur_targets(&pkg_refs, &installed, &sync_available)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

    if aur_targets.is_empty() {
        println!("there is nothing to do");
        return Ok(());
    }

    // Collect all repo deps needed
    let mut all_repo_deps: Vec<String> = Vec::new();
    for target in &aur_targets {
        all_repo_deps.extend(target.repo_depends.iter().cloned());
        all_repo_deps.extend(target.make_depends.iter().cloned());
    }
    all_repo_deps.sort();
    all_repo_deps.dedup();

    // Print summary
    println!("\n{}", "AUR packages to build:".bold());
    for target in &aur_targets {
        println!(
            "  {}/{} {}",
            "aur".magenta(),
            target.package.name.bold(),
            target.package.version.green()
        );
    }

    if !all_repo_deps.is_empty() {
        println!("\n{}", "Repo dependencies to install:".bold());
        for dep in &all_repo_deps {
            println!("  {dep}");
        }
    }

    if !noconfirm {
        print!("\nProceed? [Y/n] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Cancelled.");
            return Ok(());
        }
    }

    // Step 1: Install repo deps if needed
    if !all_repo_deps.is_empty() {
        println!("\n:: Installing repo dependencies...");
        install_repo_packages(db, &all_repo_deps)?;
    }

    // Step 2: Build and install AUR packages in order
    let build_base = dirs_build_base();
    std::fs::create_dir_all(&build_base)?;

    for target in &aur_targets {
        println!(
            "\n:: Building {} {}...",
            target.package.name.bold(),
            target.package.version.green()
        );

        let result = clone_and_build(&target.package, &build_base, skip_review)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        println!(":: Installing {}...", target.package.name.bold());

        install_pkg_file(&result.package_path, &target.package.name)?;
    }

    println!(
        "\n{} AUR package(s) installed successfully.",
        aur_targets.len()
    );

    Ok(())
}

fn install_pkg_file(pkg_path: &Path, pkg_name: &str) -> Result<()> {
    use std::process::Command;

    let status = Command::new("sudo")
        .args(["pacman", "-U", "--noconfirm"])
        .arg(pkg_path)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()?;

    if !status.success() {
        return Err(anyhow::anyhow!(
            "failed to install {}: pacman -U exited with {}",
            pkg_name,
            status
        ));
    }

    Ok(())
}

fn install_repo_packages(db: &mut DatabaseHandle, packages: &[String]) -> Result<()> {
    let ignored: HashSet<String> = db.config.ignore_pkgs.iter().cloned().collect();
    let mut pool = ConcretePool::new(ignored);

    for pkg in db.installed_packages()? {
        pool.add_local(pkg.info.clone());
    }

    let sync_pkgs = db.sync_packages_with_repo_index()?;
    let mut sync_map: HashMap<String, SyncInfo> = HashMap::with_capacity(sync_pkgs.len());
    for (pkg, idx) in &sync_pkgs {
        sync_map.entry(pkg.info.name.clone()).or_insert_with(|| SyncInfo {
            compressed_size: pkg.compressed_size,
            installed_size: pkg.installed_size,
            repository: pkg.repository.clone(),
            filename: pkg.filename.clone(),
            sha256sum: pkg.sha256sum.clone(),
        });
        pool.add_sync(pkg.info.clone(), *idx);
    }

    let options = ResolveOptions::default();
    let mut resolved = resolve(&pool, packages, &options)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    topological_sort(&pool, &mut resolved);

    let sync_sizes: HashMap<String, (u64, u64, String)> = sync_map
        .iter()
        .map(|(k, v)| (k.clone(), (v.compressed_size, v.installed_size, v.repository.clone())))
        .collect();

    let tx = build_transaction(&pool, &resolved, packages, &|name| {
        sync_sizes.get(name).map(|(c, i, _)| (*c, *i)).unwrap_or((0, 0))
    }, false);

    if tx.is_empty() {
        return Ok(());
    }

    print_transaction(&tx, &sync_sizes);

    let repo_servers: HashMap<String, Vec<String>> = db
        .config
        .repos
        .iter()
        .map(|r| (r.name.clone(), r.servers.clone()))
        .collect();

    let mut targets: Vec<DownloadTarget> = Vec::new();
    let pkg_names: Vec<String> = tx
        .installs
        .iter()
        .map(|i| i.name.clone())
        .chain(tx.upgrades.iter().map(|u| u.name.clone()))
        .collect();

    for name in &pkg_names {
        let Some(info) = sync_map.get(name) else { continue };
        let servers = repo_servers.get(&info.repository).cloned().unwrap_or_default();
        targets.push(DownloadTarget {
            name: name.clone(),
            filename: info.filename.clone(),
            expected_sha256: info.sha256sum.clone(),
            compressed_size: info.compressed_size,
            mirrors: servers,
        });
    }

    let cache_dir = &db.config.cache_dirs[0];
    std::fs::create_dir_all(cache_dir)?;

    let multi = MultiProgress::new();
    let downloaded = pax_exec::download_packages(&targets, cache_dir, db.config.parallel_downloads, &multi)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let old_install_scripts = collect_old_install_scripts(&db.config.db_path, &tx);
    let old_backup_md5 = collect_old_backup_md5(&db.config.db_path, &tx);

    let ctx = InstallContext {
        root_dir: &db.config.root_dir,
        db_path: &db.config.db_path,
        downloaded: &downloaded,
        old_install_scripts: &old_install_scripts,
        old_backup_md5: &old_backup_md5,
        hook_dirs: &db.config.hook_dirs,
    };

    execute_transaction(&tx, &ctx).map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(())
}

fn collect_old_install_scripts(
    db_path: &std::path::Path,
    tx: &pax_resolver::Transaction,
) -> HashMap<String, String> {
    let mut scripts = HashMap::new();
    for upgrade in &tx.upgrades {
        let path = db_path
            .join("local")
            .join(format!("{}-{}", upgrade.name, upgrade.old_version))
            .join("install");
        if let Ok(content) = std::fs::read_to_string(&path) {
            scripts.insert(upgrade.name.clone(), content);
        }
    }
    scripts
}

fn collect_old_backup_md5(
    db_path: &std::path::Path,
    tx: &pax_resolver::Transaction,
) -> HashMap<String, HashMap<String, String>> {
    let mut result = HashMap::new();
    for upgrade in &tx.upgrades {
        let path = db_path
            .join("local")
            .join(format!("{}-{}", upgrade.name, upgrade.old_version))
            .join("files");
        if let Ok(content) = std::fs::read_to_string(&path) {
            let mut md5s = HashMap::new();
            let mut in_backup = false;
            for line in content.lines() {
                if line == "%BACKUP%" { in_backup = true; continue; }
                if line.starts_with('%') || line.is_empty() { in_backup = false; continue; }
                if in_backup {
                    if let Some((p, m)) = line.split_once('\t') {
                        md5s.insert(p.to_string(), m.to_string());
                    }
                }
            }
            result.insert(upgrade.name.clone(), md5s);
        }
    }
    result
}

fn dirs_build_base() -> PathBuf {
    if let Ok(cache) = std::env::var("XDG_CACHE_HOME") {
        PathBuf::from(cache).join("pax/aur")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".cache/pax/aur")
    } else {
        PathBuf::from("/tmp/pax-aur")
    }
}
