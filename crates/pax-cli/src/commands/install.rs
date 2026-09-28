use std::collections::{HashMap, HashSet};
use std::io::Write;

use anyhow::Result;
use indicatif::MultiProgress;
use pax_alpm::db::DatabaseHandle;
use pax_core::config::SigLevel;
use pax_exec::{execute_transaction, DownloadTarget, InstallContext};
use pax_resolver::{build_transaction, resolve, topological_sort, ConcretePool, ResolveOptions};

use crate::output::print_transaction;

struct SyncInfo {
    compressed_size: u64,
    installed_size: u64,
    repository: String,
    filename: String,
    sha256sum: Option<String>,
    sig_level: SigLevel,
}

pub fn run(db: &mut DatabaseHandle, packages: &[String], dry_run: bool, download_only: bool, noconfirm: bool, needed: bool, reinstall: bool) -> Result<()> {
    if !dry_run {
        super::ensure_root();
    }

    if packages.is_empty() {
        eprintln!("error: no targets specified");
        std::process::exit(1);
    }

    db.ensure_both()?;

    if needed {
        let mut filtered = Vec::new();
        for name in packages {
            let local_ver = db.local_info(name)?.map(|p| p.info.version.clone());
            if let Some(lv) = local_ver {
                let sync_ver = db.sync_info(name)?.map(|p| p.info.version.clone());
                if let Some(sv) = sync_ver {
                    if sv > lv {
                        filtered.push(name.clone());
                    } else {
                        eprintln!("{name} is up to date -- skipping");
                    }
                } else {
                    filtered.push(name.clone());
                }
            } else {
                filtered.push(name.clone());
            }
        }
        if filtered.is_empty() {
            println!("there is nothing to do");
            return Ok(());
        }
        return run_inner(db, &filtered, dry_run, download_only, noconfirm, reinstall);
    }

    run_inner(db, packages, dry_run, download_only, noconfirm, reinstall)
}

fn run_inner(db: &mut DatabaseHandle, packages: &[String], dry_run: bool, download_only: bool, noconfirm: bool, reinstall: bool) -> Result<()> {

    let mut ignored: HashSet<String> = db.config.ignore_pkgs.iter().cloned().collect();
    let ignore_groups: HashSet<String> = db.config.ignore_groups.iter().cloned().collect();
    let capacity = db.sync()?.package_count() + db.local()?.len();

    let installed = db.installed_packages()?;
    if !ignore_groups.is_empty() {
        for pkg in &installed {
            if pkg.info.groups.iter().any(|g| ignore_groups.contains(g)) {
                ignored.insert(pkg.info.name.clone());
            }
        }
    }

    let mut pool = ConcretePool::with_capacity(ignored, capacity);

    for pkg in installed {
        pool.add_local(pkg.info.clone());
    }

    let global_sig_level = db.config.sig_level.package;
    let repo_sig_levels: HashMap<String, SigLevel> = db
        .config
        .repos
        .iter()
        .map(|r| {
            let level = r.sig_level.map(|s| s.package).unwrap_or(global_sig_level);
            (r.name.clone(), level)
        })
        .collect();

    let sync_pkgs = db.sync_packages_with_repo_index()?;
    let mut sync_map: HashMap<String, SyncInfo> = HashMap::with_capacity(sync_pkgs.len());

    for (pkg, idx) in &sync_pkgs {
        sync_map.entry(pkg.info.name.clone()).or_insert_with(|| {
            let sig_level = repo_sig_levels
                .get(&pkg.repository)
                .copied()
                .unwrap_or(global_sig_level);
            SyncInfo {
                compressed_size: pkg.compressed_size,
                installed_size: pkg.installed_size,
                repository: pkg.repository.clone(),
                filename: pkg.filename.clone(),
                sha256sum: pkg.sha256sum.clone(),
                sig_level,
            }
        });
        pool.add_sync(pkg.info.clone(), *idx);
    }

    let options = ResolveOptions::default();
    let mut resolved = match resolve(&pool, packages, &options) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    topological_sort(&pool, &mut resolved);

    let sync_sizes: HashMap<String, (u64, u64, String)> = sync_map
        .iter()
        .map(|(k, v)| (k.clone(), (v.compressed_size, v.installed_size, v.repository.clone())))
        .collect();

    let tx = build_transaction(&pool, &resolved, packages, &|name| {
        sync_sizes
            .get(name)
            .map(|(c, i, _)| (*c, *i))
            .unwrap_or((0, 0))
    }, reinstall);

    if tx.is_empty() {
        for name in packages {
            if let Ok(Some(pkg)) = db.local_info(name) {
                eprintln!("{name} {} is already installed (use --reinstall to reinstall)", pkg.info.version);
            }
        }
        return Ok(());
    }

    print_transaction(&tx, &sync_sizes);

    if dry_run {
        return Ok(());
    }

    if !noconfirm {
        print!("\nProceed with installation? [Y/n] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Installation cancelled.");
            return Ok(());
        }
    }

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
        let Some(info) = sync_map.get(name) else {
            continue;
        };

        let servers = repo_servers.get(&info.repository).cloned().unwrap_or_default();

        targets.push(DownloadTarget {
            name: name.clone(),
            filename: info.filename.clone(),
            expected_sha256: info.sha256sum.clone(),
            compressed_size: info.compressed_size,
            mirrors: servers,
            sig_level: info.sig_level,
        });
    }

    let cache_dir = &db.config.cache_dirs[0];
    std::fs::create_dir_all(cache_dir)?;

    println!();
    let multi = MultiProgress::new();
    let downloaded = pax_exec::download_packages(
        &targets,
        cache_dir,
        db.config.parallel_downloads,
        &multi,
        &db.config.gpg_dir,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!(
        "\n{} package(s) downloaded to {}",
        downloaded.len(),
        cache_dir.display()
    );

    if download_only {
        return Ok(());
    }

    let old_install_scripts = collect_old_install_scripts(&db.config.db_path, &tx);
    let old_backup_md5 = collect_old_backup_md5(&db.config.db_path, &tx);

    let ctx = InstallContext {
        root_dir: &db.config.root_dir,
        db_path: &db.config.db_path,
        downloaded: &downloaded,
        old_install_scripts: &old_install_scripts,
        old_backup_md5: &old_backup_md5,
        hook_dirs: &db.config.hook_dirs,
        check_space: db.config.check_space,
    };

    execute_transaction(&tx, &ctx).map_err(|e| anyhow::anyhow!("{e}"))?;

    let total = tx.installs.len() + tx.upgrades.len();
    println!("{total} package(s) installed successfully.");

    Ok(())
}

fn collect_old_install_scripts(
    db_path: &std::path::Path,
    tx: &pax_resolver::Transaction,
) -> HashMap<String, String> {
    let mut scripts = HashMap::new();
    for upgrade in &tx.upgrades {
        let install_path = db_path
            .join("local")
            .join(format!("{}-{}", upgrade.name, upgrade.old_version))
            .join("install");
        if let Ok(content) = std::fs::read_to_string(&install_path) {
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
        let files_path = db_path
            .join("local")
            .join(format!("{}-{}", upgrade.name, upgrade.old_version))
            .join("files");
        if let Ok(content) = std::fs::read_to_string(&files_path) {
            let mut md5s = HashMap::new();
            let mut in_backup = false;
            for line in content.lines() {
                if line == "%BACKUP%" {
                    in_backup = true;
                    continue;
                }
                if line.starts_with('%') || line.is_empty() {
                    in_backup = false;
                    continue;
                }
                if in_backup {
                    if let Some((path, md5)) = line.split_once('\t') {
                        md5s.insert(path.to_string(), md5.to_string());
                    }
                }
            }
            result.insert(upgrade.name.clone(), md5s);
        }
    }
    result
}
