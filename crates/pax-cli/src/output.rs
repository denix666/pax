use std::collections::HashMap;

use owo_colors::OwoColorize;

use pax_core::package::{LocalPackage, SyncPackage};
use pax_core::version::Version;
use pax_resolver::Transaction;

pub fn print_local_package_short(pkg: &LocalPackage) {
    println!("{} {}", pkg.info.name.bold(), pkg.info.version.green());
}

pub fn print_sync_search_result(pkg: &SyncPackage, installed: bool) {
    print!(
        "{}/{} {}",
        pkg.repository.purple(),
        pkg.info.name.bold(),
        pkg.info.version.green()
    );

    if !pkg.info.groups.is_empty() {
        print!(" ({})", pkg.info.groups.join(" "));
    }

    if installed {
        print!(" {}", "[installed]".cyan());
    }

    println!();

    if !pkg.info.description.is_empty() {
        println!("    {}", pkg.info.description);
    }
}

pub fn print_sync_info(pkg: &SyncPackage, installed_version: Option<&Version>) {
    let w = 18;
    println!("{:<w$}: {}", "Repository".bold(), pkg.repository);
    println!("{:<w$}: {}", "Name".bold(), pkg.info.name);
    println!("{:<w$}: {}", "Version".bold(), pkg.info.version);
    if let Some(ref desc) = pkg.info.base {
        println!("{:<w$}: {desc}", "Package Base".bold());
    }
    println!("{:<w$}: {}", "Description".bold(), pkg.info.description);
    println!("{:<w$}: {}", "Architecture".bold(), pkg.info.arch);
    if let Some(ref url) = pkg.info.url {
        println!("{:<w$}: {url}", "URL".bold());
    }
    println!(
        "{:<w$}: {}",
        "Licenses".bold(),
        if pkg.info.licenses.is_empty() {
            "None".to_string()
        } else {
            pkg.info.licenses.join("  ")
        }
    );
    println!(
        "{:<w$}: {}",
        "Groups".bold(),
        if pkg.info.groups.is_empty() {
            "None".to_string()
        } else {
            pkg.info.groups.join("  ")
        }
    );
    println!(
        "{:<w$}: {}",
        "Provides".bold(),
        if pkg.info.provides.is_empty() {
            "None".to_string()
        } else {
            pkg.info
                .provides
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("  ")
        }
    );
    println!(
        "{:<w$}: {}",
        "Depends On".bold(),
        if pkg.info.depends.is_empty() {
            "None".to_string()
        } else {
            pkg.info
                .depends
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("  ")
        }
    );
    println!(
        "{:<w$}: {}",
        "Optional Deps".bold(),
        if pkg.info.optdepends.is_empty() {
            "None".to_string()
        } else {
            let first = pkg.info.optdepends[0].to_string();
            let rest: Vec<String> = pkg.info.optdepends[1..]
                .iter()
                .map(|d| format!("{:<w$}  {d}", ""))
                .collect();
            if rest.is_empty() {
                first
            } else {
                format!("{first}\n{}", rest.join("\n"))
            }
        }
    );
    println!(
        "{:<w$}: {}",
        "Conflicts With".bold(),
        if pkg.info.conflicts.is_empty() {
            "None".to_string()
        } else {
            pkg.info
                .conflicts
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("  ")
        }
    );
    println!(
        "{:<w$}: {}",
        "Replaces".bold(),
        if pkg.info.replaces.is_empty() {
            "None".to_string()
        } else {
            pkg.info
                .replaces
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("  ")
        }
    );
    println!(
        "{:<w$}: {}",
        "Download Size".bold(),
        format_size(pkg.compressed_size)
    );
    println!(
        "{:<w$}: {}",
        "Installed Size".bold(),
        format_size(pkg.installed_size)
    );
    println!("{:<w$}: {}", "Packager".bold(), pkg.info.packager);
    println!(
        "{:<w$}: {}",
        "Build Date".bold(),
        format_timestamp(pkg.info.build_date)
    );
    match installed_version {
        Some(ver) => println!("{:<w$}: {}", "Install Status".bold(), format!("installed ({ver})").green()),
        None => println!("{:<w$}: {}", "Install Status".bold(), "not installed".red()),
    }
    if let Some(ref md5) = pkg.md5sum {
        println!("{:<w$}: {md5}", "MD5 Sum".bold());
    }
    if let Some(ref sha) = pkg.sha256sum {
        println!("{:<w$}: {sha}", "SHA-256 Sum".bold());
    }
    println!();
}

pub fn print_local_info(pkg: &LocalPackage) {
    let w = 18;
    println!("{:<w$}: {}", "Name".bold(), pkg.info.name);
    println!("{:<w$}: {}", "Version".bold(), pkg.info.version);
    if let Some(ref desc) = pkg.info.base {
        println!("{:<w$}: {desc}", "Package Base".bold());
    }
    println!("{:<w$}: {}", "Description".bold(), pkg.info.description);
    println!("{:<w$}: {}", "Architecture".bold(), pkg.info.arch);
    if let Some(ref url) = pkg.info.url {
        println!("{:<w$}: {url}", "URL".bold());
    }
    println!(
        "{:<w$}: {}",
        "Licenses".bold(),
        if pkg.info.licenses.is_empty() {
            "None".to_string()
        } else {
            pkg.info.licenses.join("  ")
        }
    );
    println!(
        "{:<w$}: {}",
        "Groups".bold(),
        if pkg.info.groups.is_empty() {
            "None".to_string()
        } else {
            pkg.info.groups.join("  ")
        }
    );
    println!(
        "{:<w$}: {}",
        "Provides".bold(),
        if pkg.info.provides.is_empty() {
            "None".to_string()
        } else {
            pkg.info
                .provides
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("  ")
        }
    );
    println!(
        "{:<w$}: {}",
        "Depends On".bold(),
        if pkg.info.depends.is_empty() {
            "None".to_string()
        } else {
            pkg.info
                .depends
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("  ")
        }
    );
    println!(
        "{:<w$}: {}",
        "Optional Deps".bold(),
        if pkg.info.optdepends.is_empty() {
            "None".to_string()
        } else {
            let first = pkg.info.optdepends[0].to_string();
            let rest: Vec<String> = pkg.info.optdepends[1..]
                .iter()
                .map(|d| format!("{:<w$}  {d}", ""))
                .collect();
            if rest.is_empty() {
                first
            } else {
                format!("{first}\n{}", rest.join("\n"))
            }
        }
    );
    println!("{:<w$}: {}", "Install Reason".bold(), pkg.reason);
    println!(
        "{:<w$}: {}",
        "Install Date".bold(),
        format_timestamp(pkg.install_date)
    );
    println!(
        "{:<w$}: {}",
        "Installed Size".bold(),
        format_size(pkg.size)
    );
    println!("{:<w$}: {}", "Packager".bold(), pkg.info.packager);
    println!(
        "{:<w$}: {}",
        "Build Date".bold(),
        format_timestamp(pkg.info.build_date)
    );
    println!(
        "{:<w$}: {}",
        "Validated By".bold(),
        if pkg.validation.is_empty() {
            "None".to_string()
        } else {
            pkg.validation
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("  ")
        }
    );
    println!();
}

pub fn print_transaction(tx: &Transaction, sync_sizes: &HashMap<String, (u64, u64, String)>) {
    if !tx.installs.is_empty() {
        println!("\n{}", "Packages to install:".bold());
        for inst in &tx.installs {
            let repo = sync_sizes
                .get(&inst.name)
                .map(|(_, _, r)| r.as_str())
                .unwrap_or("unknown");
            let tag = if inst.explicit { "" } else { " (dep)" };
            println!(
                "  {}/{} {} {}{}",
                repo.purple(),
                inst.name.bold(),
                inst.version.green(),
                format_size(inst.download_size),
                tag.dimmed()
            );
        }
    }

    if !tx.upgrades.is_empty() {
        println!("\n{}", "Packages to upgrade:".bold());
        for upg in &tx.upgrades {
            let repo = sync_sizes
                .get(&upg.name)
                .map(|(_, _, r)| r.as_str())
                .unwrap_or("unknown");
            println!(
                "  {}/{} {} -> {} {}",
                repo.purple(),
                upg.name.bold(),
                upg.old_version.red(),
                upg.new_version.green(),
                format_size(upg.download_size),
            );
        }
    }

    if !tx.removals.is_empty() {
        println!("\n{}", "Packages to remove:".bold());
        for rem in &tx.removals {
            println!(
                "  {} {} ({})",
                rem.name.bold(),
                rem.version.red(),
                rem.reason
            );
        }
    }

    println!();
    let total_count = tx.installs.len() + tx.upgrades.len();
    println!(
        "Total packages: {}  Download size: {}  Installed size: {}",
        total_count.to_string().bold(),
        format_size(tx.total_download_size).bold(),
        format_size(tx.total_installed_size).bold()
    );
}

pub fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;

    let b = bytes as f64;
    if b >= GIB {
        format!("{:.2} GiB", b / GIB)
    } else if b >= MIB {
        format!("{:.2} MiB", b / MIB)
    } else if b >= KIB {
        format!("{:.2} KiB", b / KIB)
    } else {
        format!("{b:.0} B")
    }
}

fn format_timestamp(ts: i64) -> String {
    // Simple UTC formatting without external crate
    let secs = ts;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;

    // Approximate date calculation from Unix epoch
    let mut y = 1970i64;
    let mut remaining_days = days;

    loop {
        let days_in_year = if is_leap_year(y) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        y += 1;
    }

    let month_days = if is_leap_year(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut m = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if remaining_days < md {
            m = i;
            break;
        }
        remaining_days -= md;
    }

    format!(
        "{y:04}-{:02}-{:02} {hours:02}:{minutes:02} UTC",
        m + 1,
        remaining_days + 1
    )
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}
