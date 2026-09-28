use std::collections::{HashMap, HashSet};

use anyhow::Result;
use indicatif::MultiProgress;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_core::config::SigLevel;
use pax_exec::{execute_transaction, DownloadTarget, InstallContext};
use pax_resolver::{
    build_transaction, compute_upgrades, resolve, topological_sort, ConcretePool, ResolveOptions,
};

use super::{collect_old_backup_md5, collect_old_install_scripts, confirm, SyncInfo};
use crate::output::print_transaction;

pub fn run(db: &mut DatabaseHandle, dry_run: bool, download_only: bool, noconfirm: bool) -> Result<()> {
    if !dry_run {
        super::ensure_root();
    }

    db.ensure_both()?;

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

    let upgrades = compute_upgrades(&pool);

    if upgrades.is_empty() {
        println!("there is nothing to do");
        return Ok(());
    }

    let upgrade_names: Vec<String> = upgrades.iter().map(|u| u.name.clone()).collect();

    let options = ResolveOptions::default();
    let mut resolved = resolve(&pool, &upgrade_names, &options)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    topological_sort(&pool, &mut resolved);

    let sync_sizes: HashMap<String, (u64, u64, String)> = sync_map
        .iter()
        .map(|(k, v)| (k.clone(), (v.compressed_size, v.installed_size, v.repository.clone())))
        .collect();

    let tx = build_transaction(&pool, &resolved, &upgrade_names, &|name| {
        sync_sizes
            .get(name)
            .map(|(c, i, _)| (*c, *i))
            .unwrap_or((0, 0))
    }, false);

    if tx.is_empty() {
        println!("there is nothing to do");
        return Ok(());
    }

    print_transaction(&tx, &sync_sizes);

    if dry_run {
        return Ok(());
    }

    if !noconfirm && !confirm("\nProceed with upgrade? [Y/n]")? {
        println!("Upgrade cancelled.");
        return Ok(());
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
    println!(
        "{} package(s) upgraded successfully.",
        total.to_string().bold()
    );

    Ok(())
}

