use anyhow::Result;
use pax_alpm::db::DatabaseHandle;

use crate::output::print_local_package_short;

pub fn run(
    db: &mut DatabaseHandle,
    explicit: bool,
    orphans: bool,
    filter: Option<&str>,
) -> Result<()> {
    let packages = if orphans {
        db.orphan_packages()?
    } else if explicit {
        db.explicit_packages()?
    } else {
        db.installed_packages()?
    };

    let packages: Vec<_> = match filter {
        Some(f) => {
            let f_lower = f.to_lowercase();
            packages
                .into_iter()
                .filter(|p| p.info.name.to_lowercase().contains(&f_lower))
                .collect()
        }
        None => packages,
    };

    if packages.is_empty() {
        eprintln!("error: no packages found");
        std::process::exit(1);
    }

    for pkg in &packages {
        print_local_package_short(pkg);
    }

    Ok(())
}
