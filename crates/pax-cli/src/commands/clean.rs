use std::io::Write;
use std::path::Path;

use anyhow::Result;
use owo_colors::OwoColorize;
use pax_alpm::db::DatabaseHandle;

pub fn run(db: &mut DatabaseHandle, all: bool, noconfirm: bool) -> Result<()> {
    let cache_dirs = db.config.cache_dirs.clone();

    if all {
        clean_all(&cache_dirs, noconfirm)
    } else {
        db.local()?;
        clean_uninstalled(db, &cache_dirs, noconfirm)
    }
}

fn clean_uninstalled(db: &mut DatabaseHandle, cache_dirs: &[std::path::PathBuf], noconfirm: bool) -> Result<()> {
    let mut to_remove = Vec::new();
    let mut total_size: u64 = 0;

    for cache_dir in cache_dirs {
        if !cache_dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(cache_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !is_pkg_file(&path) {
                continue;
            }

            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            if let Some(name) = extract_pkg_name(&filename) {
                if !db.is_installed(&name) {
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    total_size += size;
                    to_remove.push(path);
                }
            }
        }
    }

    if to_remove.is_empty() {
        println!("Cache is clean, nothing to do.");
        return Ok(());
    }

    println!(
        "Packages to remove from cache: {}  Disk space to free: {}",
        to_remove.len().to_string().bold(),
        format_size(total_size).bold()
    );

    if !noconfirm {
        print!("\nProceed? [Y/n] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_lowercase();
        if !answer.is_empty() && answer != "y" && answer != "yes" {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let mut removed = 0;
    for path in &to_remove {
        if std::fs::remove_file(path).is_ok() {
            removed += 1;
        }
    }

    println!("{removed} package(s) removed from cache.");
    Ok(())
}

fn clean_all(cache_dirs: &[std::path::PathBuf], noconfirm: bool) -> Result<()> {
    let mut total_files = 0u64;
    let mut total_size = 0u64;

    for cache_dir in cache_dirs {
        if !cache_dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(cache_dir)? {
            let entry = entry?;
            if is_pkg_file(&entry.path()) {
                total_files += 1;
                total_size += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }

    if total_files == 0 {
        println!("Cache is empty, nothing to do.");
        return Ok(());
    }

    println!(
        "All cached packages: {}  Disk space to free: {}",
        total_files.to_string().bold(),
        format_size(total_size).bold()
    );

    if !noconfirm {
        print!("\nRemove ALL cached packages? [y/N] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        let answer = answer.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            println!("Cancelled.");
            return Ok(());
        }
    }

    let mut removed = 0;
    for cache_dir in cache_dirs {
        if !cache_dir.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(cache_dir)? {
            let entry = entry?;
            if is_pkg_file(&entry.path()) {
                if std::fs::remove_file(entry.path()).is_ok() {
                    removed += 1;
                }
            }
        }
    }

    println!("{removed} package(s) removed from cache.");
    Ok(())
}

fn is_pkg_file(path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    name.ends_with(".pkg.tar.zst")
        || name.ends_with(".pkg.tar.xz")
        || name.ends_with(".pkg.tar.gz")
        || name.ends_with(".pkg.tar.zst.sig")
        || name.ends_with(".pkg.tar.xz.sig")
        || name.ends_with(".pkg.tar.gz.sig")
}

fn extract_pkg_name(filename: &str) -> Option<String> {
    let base = filename
        .strip_suffix(".pkg.tar.zst.sig")
        .or_else(|| filename.strip_suffix(".pkg.tar.xz.sig"))
        .or_else(|| filename.strip_suffix(".pkg.tar.gz.sig"))
        .or_else(|| filename.strip_suffix(".pkg.tar.zst"))
        .or_else(|| filename.strip_suffix(".pkg.tar.xz"))
        .or_else(|| filename.strip_suffix(".pkg.tar.gz"))?;

    // Format: name-version-rel-arch
    // Split from right: arch, rel, version components, then name is the rest
    let mut parts: Vec<&str> = base.rsplitn(4, '-').collect();
    parts.reverse();
    if parts.len() >= 4 {
        // parts[0..len-3] = name segments, parts[len-3] = version, parts[len-2] = rel, parts[len-1] = arch
        let name_end = parts.len() - 3;
        Some(parts[..name_end].join("-"))
    } else {
        None
    }
}

fn format_size(bytes: u64) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_pkg_name() {
        assert_eq!(
            extract_pkg_name("nginx-1.30.4-1-x86_64.pkg.tar.zst"),
            Some("nginx".to_string())
        );
        assert_eq!(
            extract_pkg_name("lib32-glibc-2.41-2-x86_64.pkg.tar.zst"),
            Some("lib32-glibc".to_string())
        );
        assert_eq!(
            extract_pkg_name("python-3.12.4-1-x86_64.pkg.tar.xz"),
            Some("python".to_string())
        );
        assert_eq!(
            extract_pkg_name("nginx-1.30.4-1-x86_64.pkg.tar.zst.sig"),
            Some("nginx".to_string())
        );
    }

    #[test]
    fn test_is_pkg_file() {
        assert!(is_pkg_file(Path::new("nginx-1.30.4-1-x86_64.pkg.tar.zst")));
        assert!(is_pkg_file(Path::new("foo.pkg.tar.xz")));
        assert!(is_pkg_file(Path::new("foo.pkg.tar.gz.sig")));
        assert!(!is_pkg_file(Path::new("core.db")));
        assert!(!is_pkg_file(Path::new("readme.txt")));
    }
}
