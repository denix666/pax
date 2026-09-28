use anyhow::Result;
use indicatif::MultiProgress;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;
use pax_exec::SyncTarget;

pub fn run(db: &mut DatabaseHandle) -> Result<()> {
    super::ensure_root();

    let sync_dir = db.config.db_path.join("sync");

    let targets: Vec<SyncTarget> = db
        .config
        .repos
        .iter()
        .map(|repo| SyncTarget {
            repo_name: repo.name.clone(),
            mirrors: repo.servers.clone(),
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
    pax_exec::sync_databases(&targets, &sync_dir, db.config.parallel_downloads, &multi)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("\ndatabase synchronization complete.");

    Ok(())
}
