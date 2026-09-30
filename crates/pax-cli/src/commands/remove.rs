use std::collections::HashSet;

use anyhow::Result;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_core::package::InstallReason;
use pax_exec::hooks::{load_hooks, run_hooks, HookWhen, TransactionPackages};
use pax_exec::{remove_package, RemovalTarget};

use super::{confirm, confirm_default_no};

pub fn run(
    db: &mut DatabaseHandle,
    packages: &[String],
    noconfirm: bool,
    recursive: bool,
) -> Result<()> {
    super::ensure_root();

    let _lock = pax_alpm::DbLock::acquire(&db.config.db_path)
        .map_err(|e| anyhow::anyhow!("failed to acquire db lock: {e}"))?;

    if packages.is_empty() {
        anyhow::bail!("no targets specified");
    }

    db.local()?;

    let mut targets: Vec<RemovalTarget> = Vec::new();

    for name in packages {
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
                if !noconfirm && !confirm_default_no(&format!("  Remove {} anyway? [y/N]", target.name.bold()))? {
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

    let removed_names: Vec<String> = targets.iter().map(|t| t.name.clone()).collect();
    let pre_tx = TransactionPackages {
        installed: vec![],
        upgraded: vec![],
        removed: removed_names.clone(),
        installed_files: vec![],
        upgraded_files: vec![],
        removed_files: vec![],
    };
    run_hooks(&hooks, &HookWhen::PreTransaction, &pre_tx)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut all_removed_files = Vec::new();

    for target in &targets {
        let removed_files = remove_package(target, &db.config.root_dir, &db.config.db_path)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        all_removed_files.extend(removed_files);
    }

    let post_tx = TransactionPackages {
        installed: vec![],
        upgraded: vec![],
        removed: removed_names,
        installed_files: vec![],
        upgraded_files: vec![],
        removed_files: all_removed_files,
    };
    run_hooks(&hooks, &HookWhen::PostTransaction, &post_tx)
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

        let deps_of_removed: HashSet<String> = all_packages
            .iter()
            .filter(|pkg| to_remove.contains(&pkg.info.name))
            .flat_map(|pkg| pkg.info.depends.iter().map(|d| d.name.clone()))
            .collect();

        for dep_name in &deps_of_removed {
            if to_remove.contains(dep_name) {
                continue;
            }

            let Some(dep_pkg) = all_packages.iter().find(|p| p.info.name == *dep_name) else {
                continue;
            };

            if dep_pkg.reason != InstallReason::Dependency {
                continue;
            }

            let still_needed = all_packages.iter().any(|pkg| {
                if to_remove.contains(&pkg.info.name) {
                    return false;
                }
                pkg.info
                    .depends
                    .iter()
                    .any(|d| d.name == *dep_name)
            });

            if !still_needed {
                let provides_needed = all_packages.iter().any(|pkg| {
                    if to_remove.contains(&pkg.info.name) {
                        return false;
                    }
                    dep_pkg.info.provides.iter().any(|prov| {
                        pkg.info.depends.iter().any(|d| d.name == prov.name)
                    })
                });

                if !provides_needed {
                    to_remove.insert(dep_name.clone());
                    changed = true;
                }
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
