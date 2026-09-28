use std::collections::HashSet;

use anyhow::Result;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_aur::{aur_info, clone_and_build, resolve_aur_targets};
use pax_core::version::Version;

use super::{confirm, dirs_build_base};

pub fn run(db: &mut DatabaseHandle, skip_review: bool, noconfirm: bool, allow_root: bool) -> Result<()> {
    super::aur::check_root(allow_root);

    db.ensure_both()?;

    println!(":: Checking for AUR updates...");

    let sync_names: HashSet<String> = db
        .sync_packages_with_repo_index()?
        .iter()
        .map(|(p, _)| p.info.name.clone())
        .collect();

    let installed_names: HashSet<String> = db
        .installed_packages()?
        .iter()
        .map(|p| p.info.name.clone())
        .collect();

    let foreign: Vec<_> = db
        .installed_packages()?
        .into_iter()
        .filter(|p| !sync_names.contains(&p.info.name))
        .collect();

    if foreign.is_empty() {
        println!("No foreign packages found.");
        return Ok(());
    }

    let names: Vec<&str> = foreign.iter().map(|p| p.info.name.as_str()).collect();

    let aur_pkgs = aur_info(&names).map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut upgrade_names: Vec<String> = Vec::new();

    for aur_pkg in &aur_pkgs {
        let Some(local) = foreign.iter().find(|p| p.info.name == aur_pkg.name) else {
            continue;
        };

        let Ok(new_ver) = Version::parse(&aur_pkg.version) else {
            continue;
        };

        if new_ver > local.info.version {
            upgrade_names.push(aur_pkg.name.clone());
        }
    }

    if upgrade_names.is_empty() {
        println!("All AUR packages are up to date.");
        return Ok(());
    }

    println!(":: Resolving AUR dependencies...");
    let upgrade_refs: Vec<&str> = upgrade_names.iter().map(|s| s.as_str()).collect();
    let aur_targets = resolve_aur_targets(&upgrade_refs, &installed_names, &sync_names)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut all_repo_deps: Vec<String> = Vec::new();
    for target in &aur_targets {
        all_repo_deps.extend(target.repo_depends.iter().cloned());
        all_repo_deps.extend(target.make_depends.iter().cloned());
    }
    all_repo_deps.sort();
    all_repo_deps.dedup();

    println!("\n{}", "AUR packages to upgrade:".bold());
    for target in &aur_targets {
        let local_ver = foreign
            .iter()
            .find(|p| p.info.name == target.package.name)
            .map(|p| p.info.version.to_string());
        if let Some(old) = local_ver {
            println!(
                "  {}/{} {} -> {}",
                "aur".magenta(),
                target.package.name.bold(),
                old.red(),
                target.package.version.green(),
            );
        } else {
            println!(
                "  {}/{} {} {}",
                "aur".magenta(),
                target.package.name.bold(),
                target.package.version.green(),
                "(new dependency)".dimmed(),
            );
        }
    }

    if !all_repo_deps.is_empty() {
        println!("\n{}", "Repo dependencies to install:".bold());
        for dep in &all_repo_deps {
            println!("  {dep}");
        }
    }

    println!("\nTotal packages: {}", aur_targets.len().to_string().bold());

    if !noconfirm && !confirm("\nProceed? [Y/n]")? {
        println!("Cancelled.");
        return Ok(());
    }

    if !all_repo_deps.is_empty() {
        println!("\n:: Installing repo dependencies...");
        super::aur::install_repo_deps(db, &all_repo_deps)?;
    }

    let build_base = dirs_build_base();
    std::fs::create_dir_all(&build_base)?;

    for target in &aur_targets {
        println!(
            "\n:: Building {} {}...",
            target.package.name.bold(),
            target.package.version.green()
        );

        let result = clone_and_build(&target.package, &build_base, skip_review, allow_root, noconfirm)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        println!(":: Installing {}...", target.package.name.bold());

        super::aur::install_as_root(db, &result.package_path, &target.package.name)?;
    }

    println!(
        "\n{} AUR package(s) upgraded successfully.",
        aur_targets.len()
    );

    Ok(())
}
