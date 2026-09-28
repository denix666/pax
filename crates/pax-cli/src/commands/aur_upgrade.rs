use std::collections::HashSet;

use anyhow::Result;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_aur::{aur_info, clone_and_build, AurPackage};
use pax_core::version::Version;

use super::{confirm, dirs_build_base};

struct AurUpgradeTarget {
    package: AurPackage,
    local_version: Version,
    new_version: Version,
}

pub fn run(db: &mut DatabaseHandle, skip_review: bool, noconfirm: bool, allow_root: bool) -> Result<()> {
    super::aur::check_root(allow_root);

    db.ensure_both()?;

    println!(":: Checking for AUR updates...");

    let sync_names: HashSet<String> = db
        .sync_packages_with_repo_index()?
        .iter()
        .map(|(p, _)| p.info.name.clone())
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

    let mut upgrades: Vec<AurUpgradeTarget> = Vec::new();

    for aur_pkg in aur_pkgs {
        let Some(local) = foreign.iter().find(|p| p.info.name == aur_pkg.name) else {
            continue;
        };

        let Ok(new_ver) = Version::parse(&aur_pkg.version) else {
            continue;
        };

        if new_ver > local.info.version {
            upgrades.push(AurUpgradeTarget {
                package: aur_pkg,
                local_version: local.info.version.clone(),
                new_version: new_ver,
            });
        }
    }

    if upgrades.is_empty() {
        println!("All AUR packages are up to date.");
        return Ok(());
    }

    println!("\n{}", "AUR packages to upgrade:".bold());
    for upg in &upgrades {
        println!(
            "  {}/{} {} -> {}",
            "aur".magenta(),
            upg.package.name.bold(),
            upg.local_version.red(),
            upg.new_version.green(),
        );
    }
    println!("\nTotal packages: {}", upgrades.len().to_string().bold());

    if !noconfirm && !confirm("\nProceed? [Y/n]")? {
        println!("Cancelled.");
        return Ok(());
    }

    let build_base = dirs_build_base();
    std::fs::create_dir_all(&build_base)?;

    for upg in &upgrades {
        println!(
            "\n:: Building {} {}...",
            upg.package.name.bold(),
            upg.new_version.green()
        );

        let result = clone_and_build(&upg.package, &build_base, skip_review, allow_root)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        println!(":: Installing {}...", upg.package.name.bold());

        super::aur::install_as_root(db, &result.package_path, &upg.package.name)?;
    }

    println!(
        "\n{} AUR package(s) upgraded successfully.",
        upgrades.len()
    );

    Ok(())
}

