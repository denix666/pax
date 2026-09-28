use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_core::package::{Dependency, LocalPackage};
use pax_core::version::Version;

struct ProviderEntry<'a> {
    pkg_version: &'a Version,
    provided_version: Option<&'a Version>,
}

fn build_provides_index<'a>(
    packages: &'a [&'a LocalPackage],
) -> HashMap<&'a str, Vec<ProviderEntry<'a>>> {
    let mut index: HashMap<&str, Vec<ProviderEntry>> = HashMap::new();

    for pkg in packages {
        index
            .entry(&pkg.info.name)
            .or_default()
            .push(ProviderEntry {
                pkg_version: &pkg.info.version,
                provided_version: None,
            });

        for prov in &pkg.info.provides {
            index
                .entry(&prov.name)
                .or_default()
                .push(ProviderEntry {
                    pkg_version: &pkg.info.version,
                    provided_version: prov.constraint.as_ref().map(|(_, v)| v),
                });
        }
    }

    index
}

fn is_dep_satisfied(dep: &Dependency, providers: &[ProviderEntry]) -> bool {
    if dep.constraint.is_none() {
        return true;
    }
    for p in providers {
        let check_ver = p.provided_version.unwrap_or(p.pkg_version);
        if dep.satisfies(check_ver) {
            return true;
        }
    }
    false
}

pub fn run_deps(db: &mut DatabaseHandle, packages: &[String]) -> Result<()> {
    db.local()?;

    let all_packages = db.installed_packages()?;
    let index = build_provides_index(&all_packages);

    let targets: Vec<&&LocalPackage> = if packages.is_empty() {
        all_packages.iter().collect()
    } else {
        let mut selected = Vec::new();
        for name in packages {
            match all_packages.iter().find(|p| p.info.name == *name) {
                Some(pkg) => selected.push(pkg),
                None => anyhow::bail!("package '{name}' is not installed"),
            }
        }
        selected
    };

    let checked = targets.len();
    let mut missing = 0u32;

    for pkg in &targets {
        for dep in &pkg.info.depends {
            match index.get(dep.name.as_str()) {
                Some(providers) if is_dep_satisfied(dep, providers) => {}
                _ => {
                    eprintln!(
                        "{}: {} requires {}",
                        "warning".yellow().bold(),
                        pkg.info.name,
                        dep,
                    );
                    missing += 1;
                }
            }
        }
    }

    if missing > 0 {
        println!(
            "Checked {} package(s), {} missing dependenc{}.",
            checked,
            missing.bold(),
            if missing == 1 { "y" } else { "ies" }
        );
    } else {
        println!("Checked {checked} package(s). No issues found.");
    }

    Ok(())
}

pub fn run_files(db: &mut DatabaseHandle, root_dir: &Path, packages: &[String]) -> Result<()> {
    db.local()?;

    let target_names: Vec<String> = if packages.is_empty() {
        db.installed_packages()?.iter().map(|p| p.info.name.clone()).collect()
    } else {
        for name in packages {
            if db.local_info(name)?.is_none() {
                anyhow::bail!("package '{name}' is not installed");
            }
        }
        packages.to_vec()
    };

    let checked = target_names.len();
    let mut missing = 0u32;

    for name in &target_names {
        let files = match db.package_files(name) {
            Ok(f) => f,
            Err(e) => {
                eprintln!(
                    "{}: {name}: could not read file list: {e}",
                    "warning".yellow().bold(),
                );
                continue;
            }
        };

        for file in &files {
            let abs_path = root_dir.join(file);
            if !abs_path.exists() {
                eprintln!(
                    "{name}: /{file} (No such file or directory)",
                );
                missing += 1;
            }
        }
    }

    if missing > 0 {
        println!(
            "Checked {} package(s), {} missing file(s).",
            checked,
            missing.bold(),
        );
    } else {
        println!("Checked {checked} package(s). No issues found.");
    }

    Ok(())
}
