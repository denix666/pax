use anyhow::Result;
use pax_alpm::db::DatabaseHandle;
use pax_core::package::SyncPackage;

use crate::output::print_sync_search_result;

pub fn run(db: &mut DatabaseHandle, query: &str) -> Result<()> {
    db.ensure_both()?;

    let results: Vec<SyncPackage> = db
        .search_sync(query)?
        .into_iter()
        .cloned()
        .collect();

    if results.is_empty() {
        eprintln!("error: no results for '{query}'");
        std::process::exit(1);
    }

    for pkg in &results {
        let installed = db.is_installed(&pkg.info.name);
        print_sync_search_result(pkg, installed);
    }

    Ok(())
}
