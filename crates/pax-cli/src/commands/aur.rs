use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use clap::Parser;
use indicatif::MultiProgress;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_aur::{clone_and_build, resolve_aur_targets};
use pax_core::config::SigLevel;
use pax_exec::{DownloadTarget, InstallContext, execute_transaction};
use pax_resolver::{ConcretePool, ResolveOptions, build_transaction, resolve, topological_sort};

use super::{
    SyncInfo, collect_old_backup_md5, collect_old_install_scripts, confirm, dirs_build_base,
};
use crate::output::print_transaction;

fn is_root() -> bool {
    (unsafe { libc::geteuid() }) == 0
}

fn privileged_pax_command(db: &DatabaseHandle) -> Result<std::process::Command> {
    let tool = escalate_tool()?;
    let pax_bin = std::env::current_exe()?;
    let cli = crate::cli::Cli::try_parse_from(std::env::args_os())?;
    install_command(&tool, &pax_bin, &cli.config, &db.config)
}

fn install_command(
    tool: &str,
    pax_bin: &Path,
    config_path: &Path,
    config: &pax_core::config::PacmanConfig,
) -> Result<std::process::Command> {
    let cwd = std::env::current_dir()?;
    let mut command = std::process::Command::new(tool);
    // Pass effective target paths even when they came from pacman.conf.
    command
        .arg(pax_bin)
        .arg("--config")
        .arg(cwd.join(config_path))
        .arg("--root")
        .arg(cwd.join(&config.root_dir))
        .arg("--dbpath")
        .arg(cwd.join(&config.db_path));
    Ok(command)
}

fn escalate_tool() -> Result<String> {
    super::privilege_escalation_tool().ok_or_else(|| {
        anyhow::anyhow!(
            "no privilege escalation tool found (install sudo or doas, or set PAX_SUDO)"
        )
    })
}

pub(crate) fn install_as_root(
    db: &mut DatabaseHandle,
    pkg_path: &Path,
    pkg_name: &str,
) -> Result<()> {
    if is_root() {
        super::localinstall::install_pkg_files(db, &[pkg_path.to_path_buf()])?;
    } else {
        let status = privileged_pax_command(db)?
            .args(["local-install", "--noconfirm", "--"])
            .arg(pkg_path.canonicalize()?)
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()?;

        db.invalidate();
        if !status.success() {
            return Err(anyhow::anyhow!(
                "failed to install {pkg_name}: exited with {status}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn install_repo_deps(db: &mut DatabaseHandle, packages: &[String]) -> Result<()> {
    if is_root() {
        install_repo_packages(db, packages)
    } else {
        let status = privileged_pax_command(db)?
            .args(["install", "--noconfirm", "--asdeps", "--"])
            .args(packages)
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()?;

        db.invalidate();
        if !status.success() {
            return Err(anyhow::anyhow!(
                "failed to install repo dependencies: exited with {status}"
            ));
        }
        Ok(())
    }
}

pub fn run(
    db: &mut DatabaseHandle,
    packages: &[String],
    skip_review: bool,
    noconfirm: bool,
    allow_root: bool,
    reinstall: bool,
) -> Result<()> {
    if packages.is_empty() {
        anyhow::bail!("no targets specified");
    }

    check_root(allow_root);

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

    let mut to_install: Vec<String> = Vec::new();
    for name in packages {
        if installed.contains(name) {
            if reinstall {
                to_install.push(name.clone());
            } else if let Ok(Some(pkg)) = db.local_info(name) {
                eprintln!(
                    "{name} {} is already installed (use --reinstall to reinstall)",
                    pkg.info.version
                );
            }
        } else {
            to_install.push(name.clone());
        }
    }

    if to_install.is_empty() {
        return Ok(());
    }

    let pkg_refs: Vec<&str> = to_install.iter().map(|s| s.as_str()).collect();

    println!(":: Resolving AUR dependencies...");
    let aur_targets = resolve_aur_targets(&pkg_refs, &installed, &sync_available)
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

    if !noconfirm && !confirm("\nProceed? [Y/n]")? {
        println!("Cancelled.");
        return Ok(());
    }

    // Step 1: Install repo deps if needed
    if !all_repo_deps.is_empty() {
        println!("\n:: Installing repo dependencies...");
        install_repo_deps(db, &all_repo_deps)?;
    }

    let build_base = dirs_build_base();
    std::fs::create_dir_all(&build_base)?;

    for target in &aur_targets {
        println!(
            "\n:: Building {} {}...",
            target.package.name.bold(),
            target.package.version.green()
        );

        let result = clone_and_build(
            &target.package,
            &build_base,
            skip_review,
            allow_root,
            noconfirm,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

        println!(":: Installing {}...", target.package.name.bold());

        install_as_root(db, &result.package_path, &target.package.name)?;
    }

    println!(
        "\n{} AUR package(s) installed successfully.",
        aur_targets.len()
    );

    Ok(())
}

fn install_repo_packages(db: &mut DatabaseHandle, packages: &[String]) -> Result<()> {
    let _lock = pax_alpm::DbLock::acquire(&db.config.db_path)
        .map_err(|e| anyhow::anyhow!("failed to acquire db lock: {e}"))?;
    db.invalidate();
    db.ensure_both()?;

    let mut ignored: HashSet<String> = db.config.ignore_pkgs.iter().cloned().collect();
    let ignore_groups: HashSet<String> = db.config.ignore_groups.iter().cloned().collect();

    let installed = db.installed_packages()?;
    if !ignore_groups.is_empty() {
        for pkg in &installed {
            if pkg.info.groups.iter().any(|g| ignore_groups.contains(g)) {
                ignored.insert(pkg.info.name.clone());
            }
        }
    }

    let mut pool = ConcretePool::new(ignored);

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
    let mut resolved = resolve(&pool, packages, &options).map_err(|e| anyhow::anyhow!("{e}"))?;

    topological_sort(&pool, &mut resolved);

    let sync_sizes: HashMap<String, (u64, u64, String)> = sync_map
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                (v.compressed_size, v.installed_size, v.repository.clone()),
            )
        })
        .collect();

    let empty_targets: &[String] = &[];
    let tx = build_transaction(
        &pool,
        &resolved,
        empty_targets,
        &|name| {
            sync_sizes
                .get(name)
                .map(|(c, i, _)| (*c, *i))
                .unwrap_or((0, 0))
        },
        false,
    );

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
        let Some(info) = sync_map.get(name) else {
            continue;
        };
        let servers = repo_servers
            .get(&info.repository)
            .cloned()
            .unwrap_or_default();
        targets.push(DownloadTarget {
            name: name.clone(),
            filename: info.filename.clone(),
            expected_sha256: info.sha256sum.clone(),
            compressed_size: info.compressed_size,
            mirrors: servers,
            sig_level: info.sig_level,
            sig_trust: db
                .config
                .repos
                .iter()
                .find(|repo| repo.name == info.repository)
                .and_then(|repo| repo.sig_level)
                .unwrap_or(db.config.sig_level)
                .package_trust,
        });
    }

    let cache_dir = &db.config.cache_dirs[0];
    std::fs::create_dir_all(cache_dir)?;

    let multi = MultiProgress::new();
    let downloaded = pax_exec::download_packages(
        &targets,
        cache_dir,
        db.config.parallel_downloads,
        &multi,
        &db.config.gpg_dir,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let old_install_scripts = collect_old_install_scripts(&db.config.db_path, &tx);
    let old_backup_md5 = collect_old_backup_md5(&db.config.db_path, &tx);

    let mut logger = pax_exec::PaxLogger::open(&db.config.log_file);

    let mut ctx = InstallContext {
        root_dir: &db.config.root_dir,
        db_path: &db.config.db_path,
        downloaded: &downloaded,
        old_install_scripts: &old_install_scripts,
        old_backup_md5: &old_backup_md5,
        hook_dirs: &db.config.hook_dirs,
        check_space: db.config.check_space,
        logger: &mut logger,
    };

    let result = execute_transaction(&tx, &mut ctx);
    db.invalidate();
    result.map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn privileged_installs_preserve_config_and_effective_target() {
        for config_arg in [
            vec!["--config", "config with spaces.conf"],
            vec!["--config=config with spaces.conf"],
        ] {
            let mut args = vec!["pax"];
            args.extend(config_arg);
            args.extend([
                "--root",
                "/target",
                "--dbpath",
                "/target/db",
                "aur-install",
                "foo",
            ]);
            let cli = crate::cli::Cli::try_parse_from(args).unwrap();
            let mut config = pax_core::config::PacmanConfig::default();
            config.root_dir = cli.root.unwrap();
            config.db_path = cli.dbpath.unwrap();
            for action in ["install", "local-install"] {
                let mut command =
                    install_command("sudo", Path::new("/bin/pax"), &cli.config, &config).unwrap();
                command.arg(action);
                let expected: Vec<OsString> = vec![
                    OsString::from("/bin/pax"),
                    OsString::from("--config"),
                    std::env::current_dir()
                        .unwrap()
                        .join("config with spaces.conf")
                        .into_os_string(),
                    OsString::from("--root"),
                    OsString::from("/target"),
                    OsString::from("--dbpath"),
                    OsString::from("/target/db"),
                    OsString::from(action),
                ];
                assert_eq!(
                    command.get_args().collect::<Vec<_>>(),
                    expected.iter().map(|s| s.as_os_str()).collect::<Vec<_>>()
                );
            }
        }
    }

    #[test]
    fn privileged_installs_forward_config_derived_paths_and_default_config() {
        let cli = crate::cli::Cli::try_parse_from(["pax", "aur-upgrade"]).unwrap();
        let mut config = pax_core::config::PacmanConfig::default();
        config.root_dir = "relative target".into();
        config.db_path = "relative db".into();
        let command = install_command("doas", Path::new("/bin/pax"), &cli.config, &config).unwrap();
        let args = command.get_args().collect::<Vec<_>>();
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(args[2], Path::new("/etc/pacman.conf").as_os_str());
        assert_eq!(args[4], cwd.join("relative target").as_os_str());
        assert_eq!(args[6], cwd.join("relative db").as_os_str());
    }
}

pub(crate) fn check_root(allow_root: bool) {
    let is_root = unsafe { libc::geteuid() } == 0;
    let has_sudo_user = std::env::var("SUDO_USER").is_ok();

    if is_root && !has_sudo_user {
        if allow_root {
            eprintln!("warning: building as root is strongly discouraged, proceeding anyway");
        } else {
            eprintln!("error: building AUR packages as root is strongly discouraged");
            eprintln!("  makepkg does not allow running as root by default.");
            eprintln!("  Use --allow-root to override this check.");
            std::process::exit(1);
        }
    }
}
