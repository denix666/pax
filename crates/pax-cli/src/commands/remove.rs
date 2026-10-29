use std::collections::HashSet;

use anyhow::Result;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_core::package::{InstallReason, PackageInfo};
use pax_exec::hooks::{HookWhen, TransactionPackages, load_hooks, run_hooks};
use pax_exec::{RemovalTarget, remove_package};
use pax_resolver::pool::package_satisfies_dependency;

use super::{confirm, confirm_default_no};

pub fn run(
    db: &mut DatabaseHandle,
    packages: &[String],
    noconfirm: bool,
    recursive: bool,
) -> Result<()> {
    super::ensure_root();

    if packages.is_empty() {
        anyhow::bail!("no targets specified");
    }

    let _lock = pax_alpm::DbLock::acquire(&db.config.db_path)
        .map_err(|e| anyhow::anyhow!("failed to acquire db lock: {e}"))?;

    db.invalidate();
    db.local()?;

    let mut targets: Vec<RemovalTarget> = Vec::new();

    for name in packages {
        if targets.iter().any(|target| target.name == *name) {
            continue;
        }
        let Some(pkg) = db.local_info(name)? else {
            anyhow::bail!("target not found: {name}");
        };
        targets.push(RemovalTarget {
            name: pkg.info.name.clone(),
            version: pkg.info.version.to_string(),
        });
    }

    if recursive {
        let orphan_targets = find_recursive_orphans(db, &targets)?;
        for t in orphan_targets {
            if !targets.iter().any(|existing| existing.name == t.name) {
                targets.push(t);
            }
        }
    }

    let removed: HashSet<String> = targets.iter().map(|target| target.name.clone()).collect();
    let installed: Vec<PackageInfo> = db
        .installed_packages()?
        .iter()
        .map(|pkg| pkg.info.clone())
        .collect();
    validate_retained_dependencies(&installed, &removed)?;

    println!("{}", "Packages to remove:".bold());
    for target in &targets {
        let is_dep = !packages.contains(&target.name);
        if is_dep {
            println!(
                "  {}-{} {}",
                target.name.bold(),
                target.version.green(),
                "(dependency)".dimmed()
            );
        } else {
            println!("  {}-{}", target.name.bold(), target.version.green());
        }
    }
    println!("\nTotal packages: {}", targets.len().bold());

    if !db.config.hold_pkgs.is_empty() {
        let hold: HashSet<&str> = db.config.hold_pkgs.iter().map(|s| s.as_str()).collect();
        for target in &targets {
            if hold.contains(target.name.as_str()) {
                eprintln!(
                    "{}: {} is designated as a HoldPkg.",
                    "warning".yellow().bold(),
                    target.name.bold()
                );
                if !noconfirm
                    && !confirm_default_no(&format!(
                        "  Remove {} anyway? [y/N]",
                        target.name.bold()
                    ))?
                {
                    println!("Removal cancelled.");
                    return Ok(());
                }
            }
        }
    }

    if !noconfirm && !confirm("\nProceed with removal? [Y/n]")? {
        println!("Removal cancelled.");
        return Ok(());
    }

    let hooks = load_hooks(&db.config.hook_dirs);
    let mut logger = pax_exec::PaxLogger::open(&db.config.log_file);

    let removed_names: Vec<String> = targets.iter().map(|t| t.name.clone()).collect();
    let mut planned_removed_files = Vec::new();
    for target in &targets {
        planned_removed_files.extend(db.package_files(&target.name)?);
    }
    planned_removed_files.sort();
    planned_removed_files.dedup();
    let pre_tx = TransactionPackages {
        installed: vec![],
        upgraded: vec![],
        removed: removed_names.clone(),
        installed_files: vec![],
        upgraded_files: vec![],
        removed_files: planned_removed_files,
    };
    let pre_dependencies = |dep: &pax_core::package::Dependency| {
        installed
            .iter()
            .any(|pkg| package_satisfies_dependency(pkg, dep))
    };
    run_hooks(
        &hooks,
        &HookWhen::PreTransaction,
        &pre_tx,
        &db.config.root_dir,
        &pre_dependencies,
        &mut logger,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut all_removed_files = Vec::new();
    logger.log_transaction_start();

    for target in &targets {
        let result = remove_package(target, &db.config.root_dir, &db.config.db_path, &mut logger);
        db.invalidate();
        let removed_files = result.map_err(|e| anyhow::anyhow!("{e}"))?;
        logger.log_removed(&target.name, &target.version);
        all_removed_files.extend(removed_files);
    }

    logger.log_transaction_completed();

    let post_tx = TransactionPackages {
        installed: vec![],
        upgraded: vec![],
        removed: removed_names,
        installed_files: vec![],
        upgraded_files: vec![],
        removed_files: all_removed_files,
    };
    db.invalidate();
    let current: Vec<PackageInfo> = db
        .installed_packages()?
        .iter()
        .map(|pkg| pkg.info.clone())
        .collect();
    let post_dependencies = |dep: &pax_core::package::Dependency| {
        current
            .iter()
            .any(|pkg| package_satisfies_dependency(pkg, dep))
    };
    run_hooks(
        &hooks,
        &HookWhen::PostTransaction,
        &post_tx,
        &db.config.root_dir,
        &post_dependencies,
        &mut logger,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("{} package(s) removed.", targets.len());

    Ok(())
}

fn find_recursive_orphans(
    db: &mut DatabaseHandle,
    initial_targets: &[RemovalTarget],
) -> Result<Vec<RemovalTarget>> {
    let all_packages = db.installed_packages()?;

    let mut to_remove: HashSet<String> = initial_targets.iter().map(|t| t.name.clone()).collect();
    let mut changed = true;

    while changed {
        changed = false;

        for candidate in &all_packages {
            if to_remove.contains(&candidate.info.name)
                || candidate.reason != InstallReason::Dependency
            {
                continue;
            }
            let dependency_of_removed = all_packages
                .iter()
                .filter(|pkg| to_remove.contains(&pkg.info.name))
                .any(|pkg| {
                    pkg.info
                        .depends
                        .iter()
                        .any(|dep| package_satisfies_dependency(&candidate.info, dep))
                });
            if !dependency_of_removed {
                continue;
            }
            let still_needed = all_packages
                .iter()
                .filter(|pkg| {
                    !to_remove.contains(&pkg.info.name) && pkg.info.name != candidate.info.name
                })
                .any(|pkg| {
                    pkg.info.depends.iter().any(|dep| {
                        package_satisfies_dependency(&candidate.info, dep)
                            && !all_packages.iter().any(|other| {
                                other.info.name != candidate.info.name
                                    && !to_remove.contains(&other.info.name)
                                    && package_satisfies_dependency(&other.info, dep)
                            })
                    })
                });
            if !still_needed {
                to_remove.insert(candidate.info.name.clone());
                changed = true;
            }
        }
    }

    let mut result = Vec::new();
    for name in &to_remove {
        if initial_targets.iter().any(|t| &t.name == name) {
            continue;
        }
        if let Some(pkg) = all_packages.iter().find(|p| &p.info.name == name) {
            result.push(RemovalTarget {
                name: pkg.info.name.clone(),
                version: pkg.info.version.to_string(),
            });
        }
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(result)
}

fn validate_retained_dependencies(
    installed: &[PackageInfo],
    removed: &HashSet<String>,
) -> Result<()> {
    for pkg in installed.iter().filter(|pkg| !removed.contains(&pkg.name)) {
        for dep in &pkg.depends {
            let loses_provider = installed.iter().any(|provider| {
                removed.contains(&provider.name) && package_satisfies_dependency(provider, dep)
            });
            if loses_provider
                && !installed.iter().any(|provider| {
                    !removed.contains(&provider.name) && package_satisfies_dependency(provider, dep)
                })
            {
                anyhow::bail!("removal breaks dependency {dep} required by {}", pkg.name);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pax_core::package::Dependency;
    use pax_core::version::Version;

    fn package(name: &str, depends: &[&str], provides: &[&str]) -> PackageInfo {
        PackageInfo {
            name: name.into(),
            version: Version::parse("1-1").unwrap(),
            base: None,
            description: String::new(),
            url: None,
            arch: "any".into(),
            build_date: 0,
            packager: String::new(),
            licenses: vec![],
            groups: vec![],
            depends: depends
                .iter()
                .map(|dep| Dependency::parse(dep).unwrap())
                .collect(),
            optdepends: vec![],
            provides: provides
                .iter()
                .map(|dep| Dependency::parse(dep).unwrap())
                .collect(),
            conflicts: vec![],
            replaces: vec![],
            xdata: vec![],
        }
    }

    #[test]
    fn removal_requires_a_retained_provider_with_sufficient_version() {
        let app = package("app", &["virtual>=2"], &[]);
        let provider = package("provider", &[], &["virtual=2"]);
        let removed = HashSet::from(["provider".to_string()]);
        assert!(
            validate_retained_dependencies(&[app.clone(), provider.clone()], &removed).is_err()
        );
        let old = package("old", &[], &["virtual=1"]);
        assert!(
            validate_retained_dependencies(&[app.clone(), provider.clone(), old], &removed)
                .is_err()
        );
        let alternative = package("alternative", &[], &["virtual=3"]);
        assert!(validate_retained_dependencies(&[app, provider, alternative], &removed).is_ok());
    }

    #[test]
    fn removal_checks_only_retained_packages_and_newly_broken_dependencies() {
        let packages = [
            package("app", &["library", "already-missing"], &[]),
            package("library", &[], &[]),
        ];
        assert!(
            validate_retained_dependencies(&packages, &HashSet::from(["library".into()])).is_err()
        );
        assert!(
            validate_retained_dependencies(
                &packages,
                &HashSet::from(["app".into(), "library".into()])
            )
            .is_ok()
        );
        assert!(validate_retained_dependencies(&packages, &HashSet::new()).is_ok());
    }
}
