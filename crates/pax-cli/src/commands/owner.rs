use std::path::Path;

use anyhow::Result;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;

pub fn run(db: &mut DatabaseHandle, file: &Path) -> Result<()> {
    let file_str = file.to_string_lossy();
    let results = db.file_owner(&file_str).map_err(|e| anyhow::anyhow!("{e}"))?;

    if results.is_empty() {
        anyhow::bail!("no package owns {file_str}");
    }

    for (pkg, owned_file) in &results {
        println!(
            "/{owned_file} is owned by {} {}",
            pkg.info.name.bold(),
            pkg.info.version.green()
        );
    }

    Ok(())
}
