mod cli;
mod commands;
mod completions;
mod output;

use anyhow::Result;
use clap::Parser;

use pax_alpm::db::DatabaseHandle;
use pax_core::config::PacmanConfig;

use cli::{Cli, Command};

fn reset_sigpipe() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

fn main() -> Result<()> {
    reset_sigpipe();
    let cli = Cli::parse();

    if let Some(ref shell) = cli.completions {
        return completions::generate(shell);
    }

    if let Some(ref source) = cli.pkg_list {
        return completions::list_packages(&cli.config, source, cli.dbpath.as_deref(), cli.root.as_deref());
    }

    let Some(ref command) = cli.command else {
        eprintln!("error: no command specified (use --help for usage)");
        std::process::exit(1);
    };

    let mut config = PacmanConfig::load(&cli.config)?;

    if let Some(ref dbpath) = cli.dbpath {
        config.db_path = dbpath.clone();
    }
    if let Some(ref root) = cli.root {
        config.root_dir = root.clone();
    }

    let mut db = DatabaseHandle::new(config);

    // The journal gate must precede logging and even the missing-lock fast path.
    if matches!(command, Command::RemoveLock) {
        commands::ensure_root();
        pax_alpm::lock::ensure_no_active_transaction(&db.config.db_path)?;
    }

    if !matches!(command, Command::TransactionStatus) {
        let mut logger = pax_exec::PaxLogger::open(&db.config.log_file);
        let args: Vec<String> = std::env::args().skip(1).collect();
        logger.log_command(&args);
    }

    match command {
        Command::Downgrade(args) => commands::downgrade::run(&mut db, &cli.config, args),
        Command::Search { query } => commands::search::run(&mut db, query),
        Command::Info { package, local } => commands::info::run(&mut db, package, *local),
        Command::Query {
            explicit,
            orphans,
            filter,
        } => commands::query::run(&mut db, *explicit, *orphans, filter.as_deref()),
        Command::Files { package } => commands::files::run(&mut db, package),
        Command::Owner { file } => commands::owner::run(&mut db, file),
        Command::Remove {
            packages,
            noconfirm,
            recursive,
        } => commands::remove::run(&mut db, packages, *noconfirm, *recursive),
        Command::LocalInstall {
            files,
            noconfirm,
        } => commands::localinstall::run(&mut db, files, *noconfirm),
        Command::Install {
            packages,
            dry_run,
            download_only,
            noconfirm,
            needed,
            reinstall,
            asdeps,
        } => commands::install::run(&mut db, packages, *dry_run, *download_only, *noconfirm, *needed, *reinstall, *asdeps),
        Command::AurInstall {
            packages,
            skip_review,
            noconfirm,
            allow_root,
            reinstall,
        } => commands::aur::run(&mut db, packages, *skip_review, *noconfirm, *allow_root, *reinstall),
        Command::AurUpgrade {
            skip_review,
            noconfirm,
            allow_root,
        } => commands::aur_upgrade::run(&mut db, *skip_review, *noconfirm, *allow_root),
        Command::AurSearch { query } => commands::aur_search::run(query),
        Command::Check { packages } => commands::check::run_deps(&mut db, packages),
        Command::CheckFiles { packages } => {
            let root_dir = db.config.root_dir.clone();
            commands::check::run_files(&mut db, &root_dir, packages)
        }
        Command::Clean { all, noconfirm } => commands::clean::run(&mut db, *all, *noconfirm),
        Command::Sync => commands::sync::run(&mut db),
        Command::Upgrade { dry_run, download_only, noconfirm } => {
            commands::upgrade::run(&mut db, *dry_run, *download_only, *noconfirm)
        }
        Command::TransactionStatus => {
            commands::ensure_root();
            let record = pax_exec::journal::inspect(&db.config.db_path)?;
            println!("Diagnostic only; no automatic recovery is performed.");
            if let Some(record) = record {
                println!("Transaction ID: {}", record.id);
                println!("Root: {}", record.root.display());
                println!("Database: {}", record.db_path.display());
                println!("State: {:?}", record.state);
                println!(
                    "Current operation: {}",
                    record.current_operation.as_deref().unwrap_or("none recorded")
                );
                println!("Planned operations ({}):", record.planned_operations.len());
                if record.planned_operations.is_empty() {
                    println!("  none recorded");
                }
                for operation in &record.planned_operations {
                    println!("  - {operation}");
                }
                println!("Completed operations ({}):", record.completed_operations.len());
                if record.completed_operations.is_empty() {
                    println!("  none recorded");
                }
                for operation in &record.completed_operations {
                    println!("  - {operation}");
                }
                println!("Failure:");
                for line in record.failure.as_deref().unwrap_or("none recorded").lines() {
                    println!("  {line}");
                }
            } else {
                println!(
                    "No unfinished journal found for {} (no active journal).",
                    db.config.db_path.display()
                );
            }
            println!("Journal status does not guarantee package, database, or system health.");
            Ok(())
        }
        Command::RemoveLock => {
            let lock_path = db.config.db_path.join("db.lck");
            if !lock_path.exists() {
                println!("No lock file found.");
                return Ok(());
            }
            eprintln!("warning: removing {}", lock_path.display());
            eprintln!("  This is dangerous if another package manager is currently running.");
            eprintln!("  Only proceed if you are sure no other instance is active.");
            if commands::confirm_default_no("  Remove lock file? [y/N]")? {
                std::fs::remove_file(&lock_path)?;
                println!("Lock file removed.");
            } else {
                println!("Cancelled.");
            }
            Ok(())
        }
    }
}
