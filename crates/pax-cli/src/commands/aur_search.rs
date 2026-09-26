use anyhow::Result;
use owo_colors::OwoColorize;

pub fn run(query: &str) -> Result<()> {
    let results = pax_aur::aur_search(query).map_err(|e| anyhow::anyhow!("{e}"))?;

    if results.is_empty() {
        println!("no results found");
        return Ok(());
    }

    for pkg in &results {
        print!(
            "{}/{} {}",
            "aur".magenta(),
            pkg.name.bold(),
            pkg.version.green()
        );
        if pkg.out_of_date.is_some() {
            print!(" {}", "[out-of-date]".red());
        }
        println!(
            " (+{} {})",
            pkg.num_votes,
            format!("{:.2}", pkg.popularity).dimmed()
        );
        if let Some(ref desc) = pkg.description {
            println!("    {desc}");
        }
    }

    Ok(())
}
