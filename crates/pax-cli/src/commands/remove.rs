use std::io::Write;

use anyhow::Result;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_exec::hooks::{load_hooks, run_hooks, HookWhen, TransactionPackages};
use pax_exec::{remove_package, RemovalTarget};

pub fn run(
    db: &mut DatabaseHandle,
    packages: &[String],
    noconfirm: bool,
    _recursive: bool,
) -> Result<()> {
    if packages.is_empty() {
        eprintln!("error: no targets specified");
        std::process::exit(1);
    }

    db.local()?;

    let mut targets: Vec<RemovalTarget> = Vec::new();

    for name in packages {
        let Some(pkg) = db.local_info(name)? else {
            eprintln!("error: target not found: {name}");
            std::process::exit(1);
        };
        targets.push(RemovalTarget {
            name: pkg.info.name.clone(),
            version: pkg.info.version.to_string(),
        });
    }

    println!("{}", "Packages to remove:".bold());
    for target in &targets {
        println!("  {}-{}", target.name.bold(), target.version.green());
    }
    println!("\nTotal packages: {}", targets.len().bold());

    if !noconfirm {
        print!("\nProceed with removal? [Y/n] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Removal cancelled.");
            return Ok(());
        }
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
