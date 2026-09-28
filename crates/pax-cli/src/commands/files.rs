use anyhow::Result;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;

pub fn run(db: &mut DatabaseHandle, package: &str) -> Result<()> {
    let files = db.package_files(package).map_err(|e| anyhow::anyhow!("{e}"))?;

    if files.is_empty() {
        anyhow::bail!("package '{package}' has no files or was not found");
    }

    for file in &files {
        println!("{} {}", package.bold(), format!("/{file}"));
    }

    Ok(())
}
