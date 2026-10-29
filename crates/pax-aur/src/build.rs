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
    cmd.env("HOME", &user.home).uid(user.uid).gid(user.gid);
}

fn chown_recursive(path: &Path, uid: u32, gid: u32) {
    let c_path = match std::ffi::CString::new(path.to_string_lossy().as_bytes()) {
        Ok(p) => p,
        Err(_) => return,
    };
    unsafe {
        libc::chown(c_path.as_ptr(), uid, gid);
    }

    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            let c = match std::ffi::CString::new(p.to_string_lossy().as_bytes()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            unsafe {
                libc::chown(c.as_ptr(), uid, gid);
            }
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
    noconfirm: bool,
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
        show_pkgbuild(&build_dir, &pkg.name, noconfirm)?;
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

    clean_cached_sources(build_dir);

    Ok(())
}

/// Remove cached source files so makepkg re-downloads them.
/// Needed when PKGBUILD version changes but source filename stays the same.
fn clean_cached_sources(build_dir: &Path) {
    let src_dir = build_dir.join("src");
    if src_dir.exists() {
        let _ = std::fs::remove_dir_all(&src_dir);
    }
    if let Ok(entries) = std::fs::read_dir(build_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.contains(".tar") && !name.contains(".pkg.tar") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

fn show_pkgbuild(build_dir: &Path, pkg_name: &str, noconfirm: bool) -> Result<()> {
    let pkgbuild = build_dir.join("PKGBUILD");
    if pkgbuild.exists() {
        eprintln!("==> PKGBUILD for {pkg_name}:");
        eprintln!("---");
        let content = std::fs::read_to_string(&pkgbuild)?;
        let line_count = content.lines().count();
        for line in content.lines().take(50) {
            eprintln!("  {line}");
        }
        if line_count > 50 {
            eprintln!("  ... (truncated, full PKGBUILD at {})", pkgbuild.display());
        }
        eprintln!("---");

        if !noconfirm {
            eprint!("==> Proceed with building {pkg_name}? [Y/n] ");
            use std::io::Write;
            std::io::stderr().flush()?;
            let mut answer = String::new();
            std::io::stdin().read_line(&mut answer)?;
            let answer = answer.trim().to_lowercase();
            if !answer.is_empty() && answer != "y" && answer != "yes" {
                return Err(AurError::BuildFailed {
                    pkg: pkg_name.to_string(),
                    message: "user aborted after PKGBUILD review".to_string(),
                });
            }
        }
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

    // makepkg knows PKGDEST and the current version of every split package.
    let mut cmd = Command::new("makepkg");
    cmd.arg("--packagelist").current_dir(build_dir);
    if let Some(u) = user {
        as_build_user(&mut cmd, u);
    }
    let output = cmd.output()?;
    if !output.status.success() {
        return Err(AurError::BuildFailed {
            pkg: pkg_name.to_string(),
            message: format!(
                "makepkg --packagelist exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    let package_list = String::from_utf8(output.stdout).map_err(|e| AurError::BuildFailed {
        pkg: pkg_name.to_string(),
        message: format!("invalid UTF-8 in makepkg --packagelist: {e}"),
    })?;
    select_package(build_dir, pkg_name, &package_list, read_package_name)
}

fn read_package_name(path: &Path) -> Result<String> {
    let output = Command::new("bsdtar")
        .arg("-xOf")
        .arg(path)
        .args(["--include", ".PKGINFO", "--include", "./.PKGINFO"])
        .output()?;
    if !output.status.success() {
        return Err(AurError::BuildFailed {
            pkg: path.display().to_string(),
            message: format!(
                "cannot read .PKGINFO: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    let metadata = String::from_utf8(output.stdout).map_err(|e| AurError::BuildFailed {
        pkg: path.display().to_string(),
        message: format!("invalid UTF-8 in .PKGINFO: {e}"),
    })?;
    package_name_from_metadata(&metadata)
        .map(str::to_owned)
        .ok_or_else(|| AurError::BuildFailed {
            pkg: path.display().to_string(),
            message: "missing or ambiguous pkgname in .PKGINFO".to_string(),
        })
}

fn package_name_from_metadata(metadata: &str) -> Option<&str> {
    let mut names = metadata.lines().filter_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "pkgname").then(|| value.trim())
    });
    let name = names.next()?;
    (names.next().is_none() && !name.is_empty()).then_some(name)
}

fn select_package(
    build_dir: &Path,
    pkg_name: &str,
    package_list: &str,
    mut read_name: impl FnMut(&Path) -> Result<String>,
) -> Result<PathBuf> {
    let mut selected = None;
    for line in package_list.lines().filter(|line| !line.is_empty()) {
        let path = build_dir.join(line);
        if read_name(&path)? != pkg_name {
            continue;
        }
        if selected.is_some() {
            return Err(AurError::BuildFailed {
                pkg: pkg_name.to_string(),
                message: "multiple artifacts have the requested package identity".to_string(),
            });
        }
        selected = Some(path);
    }
    selected.ok_or_else(|| AurError::BuildFailed {
        pkg: pkg_name.to_string(),
        message: "makepkg --packagelist contains no artifact with the requested package identity"
            .to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_exact_split_package_from_packagelist() {
        let base = Path::new("/build/base");
        let selected = select_package(
            base,
            "foo",
            "foo-docs.pkg.tar.zst\n/output with spaces/foo.pkg.tar.xz\nfoo-debug.pkg.tar.zst\n",
            |path| {
                Ok(match path.file_name().unwrap().to_str().unwrap() {
                    "foo-docs.pkg.tar.zst" => "foo-docs",
                    "foo-debug.pkg.tar.zst" => "foo-debug",
                    _ => "foo",
                }
                .to_string())
            },
        )
        .unwrap();
        assert_eq!(selected, Path::new("/output with spaces/foo.pkg.tar.xz"));
    }

    #[test]
    fn selects_every_requested_subpackage_from_the_same_build() {
        let names = ["foo", "foo-docs", "foo-debug"];
        let package_list = "foo.pkg.tar.zst\nfoo-docs.pkg.tar.zst\nfoo-debug.pkg.tar.zst\n";
        let selected: Vec<PathBuf> = names
            .iter()
            .map(|requested| {
                select_package(Path::new("/build/base"), requested, package_list, |path| {
                    let filename = path.file_name().unwrap().to_str().unwrap();
                    Ok(filename.strip_suffix(".pkg.tar.zst").unwrap().to_string())
                })
                .unwrap()
            })
            .collect();
        assert_eq!(
            selected,
            vec![
                PathBuf::from("/build/base/foo.pkg.tar.zst"),
                PathBuf::from("/build/base/foo-docs.pkg.tar.zst"),
                PathBuf::from("/build/base/foo-debug.pkg.tar.zst"),
            ]
        );
    }

    #[test]
    fn uses_metadata_identity_and_resolves_relative_paths() {
        let selected = select_package(
            Path::new("/build"),
            "foo",
            "misleading-name.pkg.tar.zst\n",
            |path| {
                assert_eq!(path, Path::new("/build/misleading-name.pkg.tar.zst"));
                Ok("foo".to_string())
            },
        )
        .unwrap();
        assert_eq!(selected, Path::new("/build/misleading-name.pkg.tar.zst"));
    }

    #[test]
    fn rejects_missing_ambiguous_and_unreadable_artifacts() {
        for list in ["", "one\n", "one\ntwo\n"] {
            assert!(
                select_package(Path::new("/build"), "foo", list, |_| {
                    Ok(if list == "one\n" { "foo-docs" } else { "foo" }.to_string())
                })
                .is_err()
            );
        }
        assert!(
            select_package(Path::new("/build"), "foo", "missing\n", |_| {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound).into())
            })
            .is_err()
        );
    }

    #[test]
    fn reads_only_exact_unambiguous_pkgname_metadata() {
        assert_eq!(
            package_name_from_metadata("pkgbase = foo\npkgname = foo-docs\npkgver = 1-1\n"),
            Some("foo-docs")
        );
        assert_eq!(package_name_from_metadata("pkgname=foo\n"), Some("foo"));
        assert_eq!(package_name_from_metadata("pkgbase = foo\n"), None);
        assert_eq!(package_name_from_metadata("pkgname = \n"), None);
        assert_eq!(
            package_name_from_metadata("pkgname = foo\npkgname = bar\n"),
            None
        );
    }
}
