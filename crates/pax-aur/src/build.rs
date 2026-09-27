use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{AurError, Result};
use crate::rpc::AurPackage;

pub struct BuildResult {
    pub name: String,
    pub package_path: PathBuf,
    pub build_dir: PathBuf,
}

struct BuildUser {
    uid: u32,
    gid: u32,
    home: PathBuf,
}

fn build_user(allow_root: bool) -> Option<BuildUser> {
    if let Ok(user) = std::env::var("SUDO_USER") {
        let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
        let gid: u32 = std::env::var("SUDO_GID").ok()?.parse().ok()?;
        return Some(BuildUser {
            home: PathBuf::from(format!("/home/{user}")),
            uid,
            gid,
        });
    }

    if allow_root && unsafe { libc::geteuid() } == 0 {
        return Some(BuildUser {
            uid: 65534,
            gid: 65534,
            home: PathBuf::from("/var/tmp/pax-aur"),
        });
    }

    None
}

fn as_build_user(cmd: &mut Command, user: &BuildUser) {
    cmd.env("HOME", &user.home)
        .uid(user.uid)
        .gid(user.gid);
}

fn chown_recursive(path: &Path, uid: u32, gid: u32) {
    let c_path = match std::ffi::CString::new(path.to_string_lossy().as_bytes()) {
        Ok(p) => p,
        Err(_) => return,
    };
    unsafe { libc::chown(c_path.as_ptr(), uid, gid); }

    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            let c = match std::ffi::CString::new(p.to_string_lossy().as_bytes()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            unsafe { libc::chown(c.as_ptr(), uid, gid); }
            if p.is_dir() {
                chown_recursive(&p, uid, gid);
            }
        }
    }
}

pub fn clone_and_build(
    pkg: &AurPackage,
    build_base: &Path,
    skip_review: bool,
    allow_root: bool,
) -> Result<BuildResult> {
    let user = build_user(allow_root);

    let effective_base = match user.as_ref() {
        Some(u) if u.uid == 65534 => u.home.as_path(),
        _ => build_base,
    };

    if let Some(ref u) = user {
        std::fs::create_dir_all(effective_base)?;
        chown_recursive(effective_base, u.uid, u.gid);
    }

    let build_dir = effective_base.join(&pkg.package_base);

    if build_dir.exists() {
        pull_updates(&build_dir, &pkg.name, user.as_ref())?;
    } else {
        clone_repo(&pkg.package_base, &build_dir, user.as_ref())?;
    }

    if !skip_review {
        show_pkgbuild(&build_dir, &pkg.name)?;
    }

    let pkg_path = run_makepkg(&build_dir, &pkg.name, user.as_ref())?;

    Ok(BuildResult {
        name: pkg.name.clone(),
        package_path: pkg_path,
        build_dir,
    })
}

fn clone_repo(package_base: &str, dest: &Path, user: Option<&BuildUser>) -> Result<()> {
    let url = format!("https://aur.archlinux.org/{package_base}.git");

    let mut cmd = Command::new("git");
    cmd.args(["clone", "--depth=1", &url])
        .arg(dest)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    if let Some(u) = user {
        as_build_user(&mut cmd, u);
    }
    let output = cmd.output()?;

    if !output.status.success() {
        return Err(AurError::GitFailed {
            pkg: package_base.to_string(),
            message: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    Ok(())
}

fn pull_updates(build_dir: &Path, pkg_name: &str, user: Option<&BuildUser>) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.args(["pull", "--ff-only"])
        .current_dir(build_dir)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    if let Some(u) = user {
        as_build_user(&mut cmd, u);
    }
    let output = cmd.output()?;

    if !output.status.success() {
        return Err(AurError::GitFailed {
            pkg: pkg_name.to_string(),
            message: "git pull failed".to_string(),
        });
    }

    Ok(())
}

fn show_pkgbuild(build_dir: &Path, pkg_name: &str) -> Result<()> {
    let pkgbuild = build_dir.join("PKGBUILD");
    if pkgbuild.exists() {
        eprintln!("==> PKGBUILD for {pkg_name}:");
        eprintln!("---");
        let content = std::fs::read_to_string(&pkgbuild)?;
        for line in content.lines().take(50) {
            eprintln!("  {line}");
        }
        if content.lines().count() > 50 {
            eprintln!("  ... (truncated, full PKGBUILD at {})", pkgbuild.display());
        }
        eprintln!("---");
    }
    Ok(())
}

fn run_makepkg(build_dir: &Path, pkg_name: &str, user: Option<&BuildUser>) -> Result<PathBuf> {
    let mut cmd = Command::new("makepkg");
    cmd.args(["-sf", "--noconfirm", "--needed"])
        .current_dir(build_dir)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    if let Some(u) = user {
        as_build_user(&mut cmd, u);
    }
    let output = cmd.output()?;

    if !output.status.success() {
        return Err(AurError::BuildFailed {
            pkg: pkg_name.to_string(),
            message: format!("makepkg exited with {}", output.status),
        });
    }

    // Find the built package
    let entries = std::fs::read_dir(build_dir)?;
    let mut candidates: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.to_string_lossy().contains(".pkg.tar")
                && !p.to_string_lossy().ends_with(".sig")
        })
        .collect();

    candidates.sort_by(|a, b| {
        let ma = std::fs::metadata(a).and_then(|m| m.modified()).ok();
        let mb = std::fs::metadata(b).and_then(|m| m.modified()).ok();
        mb.cmp(&ma)
    });

    candidates.into_iter().next().ok_or_else(|| AurError::BuildFailed {
        pkg: pkg_name.to_string(),
        message: "no .pkg.tar.* file found after build".to_string(),
    })
}
