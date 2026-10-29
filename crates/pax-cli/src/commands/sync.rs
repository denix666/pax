use anyhow::Result;
use indicatif::MultiProgress;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_exec::SyncTarget;

pub fn run(db: &mut DatabaseHandle) -> Result<()> {
    super::ensure_root();

    let _lock = pax_alpm::DbLock::acquire(&db.config.db_path)
        .map_err(|e| anyhow::anyhow!("failed to acquire db lock: {e}"))?;
    db.invalidate();

    let mut logger = pax_exec::PaxLogger::open(&db.config.log_file);
    logger.log_sync();

    let sync_dir = db.config.db_path.join("sync");

    let targets: Vec<SyncTarget> = db
        .config
        .repos
        .iter()
        .map(|repo| SyncTarget {
            repo_name: repo.name.clone(),
            mirrors: repo.servers.clone(),
            sig_level: repo.sig_level.unwrap_or(db.config.sig_level).database,
            sig_trust: repo.sig_level.unwrap_or(db.config.sig_level).database_trust,
            gpg_dir: db.config.gpg_dir.clone(),
        })
        .collect();

    if targets.is_empty() {
        println!("no repositories configured");
        return Ok(());
    }

    println!(
        ":: {} {} repository database(s)...",
        "Synchronizing".bold(),
        targets.len()
    );

    let multi = MultiProgress::new();
    let result =
        pax_exec::sync_databases(&targets, &sync_dir, db.config.parallel_downloads, &multi);
    db.invalidate();
    result?;

    println!("\ndatabase synchronization complete.");

    Ok(())
}
