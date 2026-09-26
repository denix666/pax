use std::collections::{HashMap, HashSet};
use std::io::Write;

use anyhow::Result;
use indicatif::MultiProgress;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_exec::{execute_transaction, DownloadTarget, InstallContext};
use pax_resolver::{
    build_transaction, compute_upgrades, resolve, topological_sort, ConcretePool, ResolveOptions,
};

use crate::output::print_transaction;

struct SyncInfo {
    compressed_size: u64,
    installed_size: u64,
    repository: String,
    filename: String,
    sha256sum: Option<String>,
}

pub fn run(db: &mut DatabaseHandle, dry_run: bool, noconfirm: bool) -> Result<()> {
    db.ensure_both()?;

    let ignored: HashSet<String> = db.config.ignore_pkgs.iter().cloned().collect();
    let capacity = db.sync()?.package_count() + db.local()?.len();
    let mut pool = ConcretePool::with_capacity(ignored, capacity);

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

    let upgrades = compute_upgrades(&pool);

    if upgrades.is_empty() {
        println!("there is nothing to do");
        return Ok(());
    }

    let upgrade_names: Vec<String> = upgrades.iter().map(|u| u.name.clone()).collect();

    let options = ResolveOptions::default();
    let mut resolved = match resolve(&pool, &upgrade_names, &options) {
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

    if !noconfirm {
        print!("\nProceed with upgrade? [Y/n] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Upgrade cancelled.");
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
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!(
        "\n{} package(s) downloaded to {}",
        downloaded.len(),
        cache_dir.display()
    );

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

    let total = tx.installs.len() + tx.upgrades.len();
    println!(
        "{} package(s) upgraded successfully.",
        total.to_string().bold()
    );

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
                if line == "%BACKUP%" {
                    in_backup = true;
                    continue;
                }
                if line.starts_with('%') || line.is_empty() {
                    in_backup = false;
                    continue;
                }
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
