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
        return completions::list_packages(&cli.config, source);
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

    match command {
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
        } => commands::install::run(&mut db, packages, *dry_run, *download_only, *noconfirm, *needed, *reinstall),
        Command::AurInstall {
            packages,
            skip_review,
            noconfirm,
            allow_root,
        } => commands::aur::run(&mut db, packages, *skip_review, *noconfirm, *allow_root),
        Command::AurUpgrade {
            skip_review,
            noconfirm,
            allow_root,
        } => commands::aur_upgrade::run(&mut db, *skip_review, *noconfirm, *allow_root),
        Command::AurSearch { query } => commands::aur_search::run(query),
        Command::Clean { all, noconfirm } => commands::clean::run(&mut db, *all, *noconfirm),
        Command::Sync => commands::sync::run(&mut db),
        Command::Upgrade { dry_run, download_only, noconfirm } => {
            commands::upgrade::run(&mut db, *dry_run, *download_only, *noconfirm)
        }
    }
}
