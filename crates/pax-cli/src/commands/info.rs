use anyhow::Result;
use pax_alpm::db::DatabaseHandle;
use pax_alpm::sync::SyncDb;

use crate::output::{print_local_info, print_sync_info};

pub fn run(db: &mut DatabaseHandle, package: &str, local: bool) -> Result<()> {
    if local {
        match db.local_info(package)? {
            Some(pkg) => print_local_info(pkg),
            None => {
                eprintln!("error: package '{package}' was not found in local database");
                std::process::exit(1);
            }
        }
    } else {
        match SyncDb::find_single(&db.config.db_path, &db.config.repos, package)? {
            Some(pkg) => {
                let installed_ver = db.local_info(package)?.map(|p| p.info.version.clone());
                print_sync_info(&pkg, installed_ver.as_ref());
            }
            None => match db.local_info(package)? {
                Some(pkg) => print_local_info(pkg),
                None => {
                    eprintln!("error: package '{package}' was not found");
                    std::process::exit(1);
                }
            },
        }
    }

    Ok(())
}
