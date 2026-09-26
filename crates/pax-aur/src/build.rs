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

fn real_user() -> Option<(String, u32, u32)> {
    let user = std::env::var("SUDO_USER").ok()?;
    let uid: u32 = std::env::var("SUDO_UID").ok()?.parse().ok()?;
    let gid: u32 = std::env::var("SUDO_GID").ok()?.parse().ok()?;
    Some((user, uid, gid))
}

fn as_real_user(cmd: &mut Command) {
    if let Some((user, uid, gid)) = real_user() {
        cmd.env("HOME", format!("/home/{user}"))
            .uid(uid)
            .gid(gid);
    }
}

pub fn clone_and_build(
    pkg: &AurPackage,
    build_base: &Path,
    skip_review: bool,
) -> Result<BuildResult> {
    if let Some((_, uid, gid)) = real_user() {
        std::fs::create_dir_all(build_base)?;
        unsafe {
            libc::chown(
                std::ffi::CString::new(build_base.to_string_lossy().as_bytes())
                    .unwrap()
                    .as_ptr(),
                uid,
                gid,
            );
        }
    }

    let build_dir = build_base.join(&pkg.package_base);

    if build_dir.exists() {
        pull_updates(&build_dir, &pkg.name)?;
    } else {
        clone_repo(&pkg.package_base, &build_dir)?;
    }

    if !skip_review {
        show_pkgbuild(&build_dir, &pkg.name)?;
    }

    let pkg_path = run_makepkg(&build_dir, &pkg.name)?;

    Ok(BuildResult {
        name: pkg.name.clone(),
        package_path: pkg_path,
        build_dir,
    })
}

fn clone_repo(package_base: &str, dest: &Path) -> Result<()> {
    let url = format!("https://aur.archlinux.org/{package_base}.git");

    let mut cmd = Command::new("git");
    cmd.args(["clone", "--depth=1", &url])
        .arg(dest)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    as_real_user(&mut cmd);
    let output = cmd.output()?;

    if !output.status.success() {
        return Err(AurError::GitFailed {
            pkg: package_base.to_string(),
            message: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    Ok(())
}

fn pull_updates(build_dir: &Path, pkg_name: &str) -> Result<()> {
    let mut cmd = Command::new("git");
    cmd.args(["pull", "--ff-only"])
        .current_dir(build_dir)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    as_real_user(&mut cmd);
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

fn run_makepkg(build_dir: &Path, pkg_name: &str) -> Result<PathBuf> {
    let mut cmd = Command::new("makepkg");
    cmd.args(["-sf", "--noconfirm", "--needed"])
        .current_dir(build_dir)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    as_real_user(&mut cmd);
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
