use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use pax_core::config::PacmanConfig;
use tempfile::NamedTempFile;

/// Add approved package names to the main configuration's `[options]` section.
///
/// The caller handles prompting and must hold its writer lock throughout this
/// call. We reload the configuration under that lock; atomic replacement alone
/// does not serialize concurrent writers, including external configuration editors.
/// Included files are never edited, and no backup file is created. A symlink is
/// followed and its target is replaced, preserving the symlink itself.
///
/// Failures before replacement leave the original intact. A directory-sync error
/// after replacement means the complete update is visible but its durability
/// could not be confirmed.
pub fn add_ignored_packages(config_path: &Path, packages: &[String]) -> Result<()> {
    for name in packages {
        ensure!(
            !name.is_empty()
                && !matches!(name.as_bytes()[0], b'.' | b'-')
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"@._+-".contains(&byte)),
            "invalid package name: {name:?}"
        );
    }
    if packages.is_empty() {
        return Ok(());
    }

    let target = fs::canonicalize(config_path)
        .with_context(|| format!("failed to resolve {}", config_path.display()))?;
    // Use the requested path so relative Include paths retain loader semantics.
    let config = PacmanConfig::load(config_path)
        .with_context(|| format!("failed to load {}", config_path.display()))?;
    let mut ignored: HashSet<String> = config.ignore_pkgs.into_iter().collect();
    let missing: Vec<&str> = packages
        .iter()
        .filter(|name| ignored.insert((*name).clone()))
        .map(String::as_str)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }

    let mut original =
        File::open(&target).with_context(|| format!("failed to open {}", target.display()))?;
    let metadata = original.metadata()?;
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        target.display()
    );
    let mut content = String::new();
    original
        .read_to_string(&mut content)
        .with_context(|| format!("failed to read {}", target.display()))?;
    let updated = insert_ignore_directive(&content, &missing);
    let parent = target
        .parent()
        .context("configuration has no parent directory")?;
    let directory = File::open(parent).with_context(|| {
        format!(
            "failed to open configuration directory {}",
            parent.display()
        )
    })?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary file in {}", parent.display()))?;
    temporary.write_all(updated.as_bytes())?;
    verify_ignored_packages(config_path, temporary.path(), &updated, packages)?;

    let temporary_metadata = temporary.as_file().metadata()?;
    if temporary_metadata.uid() != metadata.uid() || temporary_metadata.gid() != metadata.gid() {
        // Preserve the original owner even when root edits a user-owned config.
        // SAFETY: the file descriptor is live and uid/gid come from file metadata.
        let result = unsafe {
            libc::fchown(
                temporary.as_file().as_raw_fd(),
                metadata.uid(),
                metadata.gid(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to preserve configuration ownership");
        }
    }
    // chown may clear set-ID bits, so restore permissions afterwards.
    temporary
        .as_file()
        .set_permissions(metadata.permissions())?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(&target)
        .with_context(|| format!("failed to replace {}", target.display()))?;
    directory
        .sync_all()
        .context("configuration updated, but failed to sync its directory")?;
    Ok(())
}

// Validate the complete candidate before committing it, using the requested
// config's directory for relative Includes even when its target is elsewhere.
fn verify_ignored_packages(
    config_path: &Path,
    candidate_path: &Path,
    content: &str,
    packages: &[String],
) -> Result<()> {
    let config_parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let config_parent = fs::canonicalize(config_parent)?;
    let mut validation_file = None;
    let validation_path = if candidate_path.parent() == Some(config_parent.as_path()) {
        candidate_path
    } else {
        let mut file = NamedTempFile::new_in(&config_parent)
            .context("failed to stage configuration verification beside the requested path")?;
        file.write_all(content.as_bytes())?;
        validation_file.insert(file).path()
    };
    let config = PacmanConfig::load(validation_path)
        .context("failed to load updated configuration before replacement")?;
    let ignored: HashSet<&str> = config.ignore_pkgs.iter().map(String::as_str).collect();
    for name in packages {
        ensure!(
            ignored.contains(name.as_str()),
            "updated configuration does not effectively ignore package {name:?}"
        );
    }
    Ok(())
}

fn insert_ignore_directive(content: &str, packages: &[&str]) -> String {
    let newline = if content.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut offset = 0;
    let mut first_section = None;
    let mut options_found = false;
    let mut insertion = content.len();
    for raw_line in content.split_inclusive('\n') {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            first_section.get_or_insert(offset);
            if line == "[options]" {
                options_found = true;
                // Includes can change the current section. Insert before any
                // existing directives so these names stay in [options].
                insertion = offset + raw_line.len();
                break;
            }
        }
        offset += raw_line.len();
    }
    if !options_found {
        insertion = first_section.unwrap_or(content.len());
    }

    let mut updated = String::with_capacity(content.len() + 32 + packages.join(" ").len());
    updated.push_str(&content[..insertion]);
    if insertion > 0 && !content[..insertion].ends_with('\n') {
        updated.push_str(newline);
    }
    if !options_found {
        updated.push_str("[options]");
        updated.push_str(newline);
    }
    updated.push_str("IgnorePkg = ");
    updated.push_str(&packages.join(" "));
    updated.push_str(newline);
    updated.push_str(&content[insertion..]);
    updated
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::tempdir;

    fn names(packages: &[&str]) -> Vec<String> {
        packages.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn preserves_comments_directives_and_repositories() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pacman.conf");
        let original = "# main config\n[options] # settings\n# IgnorePkg = commented\nIgnorePkg = linux # kernel\nIgnorePkg = bash\nInclude = options.conf\n\n# repositories\n[core]\nInclude = mirrors\nIgnorePkg = repo-only\n";
        fs::write(&path, original).unwrap();
        fs::write(directory.path().join("options.conf"), "# options\n").unwrap();
        fs::write(directory.path().join("mirrors"), "# mirrors\n").unwrap();

        add_ignored_packages(&path, &names(&["linux", "bash", "git", "git", "repo-only"])).unwrap();

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            original.replace(
                "[options] # settings\n",
                "[options] # settings\nIgnorePkg = git repo-only\n"
            )
        );
        let config = PacmanConfig::load(&path).unwrap();
        assert_eq!(
            config.ignore_pkgs,
            names(&["git", "repo-only", "linux", "bash"])
        );
    }

    #[test]
    fn uses_loader_for_includes_and_never_edits_included_files() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pacman.conf");
        let options = directory.path().join("options.conf");
        let mirrors = directory.path().join("mirrors");
        let original = "[options]\nInclude = options.conf\n[core]\nInclude = mirrors\n";
        // The included file inherits [options] without its own header.
        let included = "# inherited options\nIgnorePkg = linux\n";
        let mirror_content = "# mirrors\nServer = https://example.org/$repo/os/$arch\n";
        fs::write(&path, original).unwrap();
        fs::write(&options, included).unwrap();
        fs::write(&mirrors, mirror_content).unwrap();
        assert_eq!(
            PacmanConfig::load(&path).unwrap().ignore_pkgs,
            names(&["linux"])
        );

        add_ignored_packages(&path, &names(&["linux", "git"])).unwrap();

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            original.replace("[options]\n", "[options]\nIgnorePkg = git\n")
        );
        assert_eq!(
            PacmanConfig::load(&path).unwrap().ignore_pkgs,
            names(&["git", "linux"])
        );
        assert_eq!(fs::read_to_string(options).unwrap(), included);
        assert_eq!(fs::read_to_string(mirrors).unwrap(), mirror_content);
    }

    #[test]
    fn inserts_before_nested_includes_that_change_the_section() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pacman.conf");
        let include = directory.path().join("options.conf");
        let nested = directory.path().join("nested.conf");
        let original = "# main\n[options] # keep\n# includes follow\nInclude = options.conf\nIgnorePkg = repository-only\n[extra]\n";
        let included = "IgnorePkg = linux\nInclude = nested.conf\n";
        let nested_content =
            "# changes caller section\n[core]\nServer = https://example.org/$repo/os/$arch\n";
        fs::write(&path, original).unwrap();
        fs::write(&include, included).unwrap();
        fs::write(&nested, nested_content).unwrap();
        assert_eq!(
            PacmanConfig::load(&path).unwrap().ignore_pkgs,
            names(&["linux"])
        );

        add_ignored_packages(&path, &names(&["linux", "git", "repository-only"])).unwrap();

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            original.replace(
                "[options] # keep\n",
                "[options] # keep\nIgnorePkg = git repository-only\n"
            )
        );
        assert_eq!(
            PacmanConfig::load(&path).unwrap().ignore_pkgs,
            names(&["git", "repository-only", "linux"])
        );
        assert_eq!(fs::read_to_string(include).unwrap(), included);
        assert_eq!(fs::read_to_string(nested).unwrap(), nested_content);
    }

    #[test]
    fn validates_symlink_candidates_with_the_requested_include_directory() {
        let directory = tempdir().unwrap();
        let target_directory = directory.path().join("target");
        fs::create_dir(&target_directory).unwrap();
        let target = target_directory.join("actual.conf");
        let path = directory.path().join("pacman.conf");
        let original = "[options]\nInclude = options.conf\n";
        fs::write(&target, original).unwrap();
        fs::write(directory.path().join("options.conf"), "IgnorePkg = linux\n").unwrap();
        symlink("target/actual.conf", &path).unwrap();

        add_ignored_packages(&path, &names(&["linux", "git"])).unwrap();

        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "[options]\nIgnorePkg = git\nInclude = options.conf\n"
        );
        assert_eq!(
            PacmanConfig::load(&path).unwrap().ignore_pkgs,
            names(&["git", "linux"])
        );
        assert_eq!(
            fs::read_link(&path).unwrap(),
            Path::new("target/actual.conf")
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 3);
        assert_eq!(fs::read_dir(target_directory).unwrap().count(), 1);
    }

    #[test]
    fn verification_rejects_ineffective_names_without_replacing_the_original() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pacman.conf");
        let original = "[options]\n# unchanged\n";
        fs::write(&path, original).unwrap();
        let before = fs::metadata(&path).unwrap();
        let mut candidate = NamedTempFile::new_in(directory.path()).unwrap();
        let content = "[options]\n[core]\nIgnorePkg = git\n";
        candidate.write_all(content.as_bytes()).unwrap();

        assert!(
            verify_ignored_packages(&path, candidate.path(), content, &names(&["git"])).is_err()
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
        assert_eq!(fs::metadata(&path).unwrap().ino(), before.ino());
    }

    #[test]
    fn already_ignored_packages_do_not_replace_the_file() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pacman.conf");
        let original = "[options]\nIgnorePkg = linux git # keep\n";
        fs::write(&path, original).unwrap();
        let before = fs::metadata(&path).unwrap();

        add_ignored_packages(&path, &names(&["git", "linux", "git"])).unwrap();

        assert_eq!(fs::metadata(&path).unwrap().ino(), before.ino());
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn preserves_symlink_target_permissions_and_ownership() {
        let directory = tempdir().unwrap();
        let target = directory.path().join("actual.conf");
        let link = directory.path().join("pacman.conf");
        fs::write(&target, "[options]\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        symlink("actual.conf", &link).unwrap();
        let before = fs::metadata(&target).unwrap();

        add_ignored_packages(&link, &names(&["linux"])).unwrap();

        assert_eq!(fs::read_link(&link).unwrap(), Path::new("actual.conf"));
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "[options]\nIgnorePkg = linux\n"
        );
        let after = fs::metadata(&target).unwrap();
        assert_eq!(after.mode(), before.mode());
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_ne!(after.ino(), before.ino());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn root_preserves_a_user_owned_configuration() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let directory = tempdir().unwrap();
        let path = directory.path().join("pacman.conf");
        fs::write(&path, "[options]\n").unwrap();
        let file = File::open(&path).unwrap();
        // SAFETY: file is live; these are ordinary numeric uid/gid values.
        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 65534, 65534) }, 0);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        add_ignored_packages(&path, &names(&["linux"])).unwrap();

        let metadata = fs::metadata(&path).unwrap();
        assert_eq!((metadata.uid(), metadata.gid()), (65534, 65534));
        assert_eq!(metadata.mode() & 0o7777, 0o640);
    }

    #[test]
    fn invalid_names_leave_configuration_untouched() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pacman.conf");
        let original = "[options]\n# unchanged\n";
        fs::write(&path, original).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        for invalid in [
            "",
            "-linux",
            ".linux",
            "two names",
            "linux\n[core]",
            "pkg#comment",
            "a=b",
            "a/b",
            "pkg*",
            "café",
        ] {
            assert!(add_ignored_packages(&path, &names(&["git", invalid])).is_err());
            assert_eq!(fs::read_to_string(&path).unwrap(), original);
            assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        }
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn handles_line_endings_missing_options_and_repeated_sections() {
        for (original, expected) in [
            ("[options]", "[options]\nIgnorePkg = git\n"),
            (
                "[options]\r\n# keep\r\n[core]\r\n",
                "[options]\r\nIgnorePkg = git\r\n# keep\r\n[core]\r\n",
            ),
            (
                "# preamble\n[core]\n",
                "# preamble\n[options]\nIgnorePkg = git\n[core]\n",
            ),
            ("# preamble", "# preamble\n[options]\nIgnorePkg = git\n"),
            ("", "[options]\nIgnorePkg = git\n"),
            (
                "[options]\n[core]\n[options]\n",
                "[options]\nIgnorePkg = git\n[core]\n[options]\n",
            ),
        ] {
            assert_eq!(insert_ignore_directive(original, &["git"]), expected);
        }
    }

    #[test]
    fn accepts_package_name_punctuation_and_empty_requests() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pacman.conf");
        add_ignored_packages(&path, &[]).unwrap();
        assert!(!path.exists());
        fs::write(&path, "[options]\n").unwrap();
        let packages = names(&["libc++", "python-foo", "foo_bar", "foo.bar", "foo@bar"]);
        add_ignored_packages(&path, &packages).unwrap();
        assert_eq!(PacmanConfig::load(&path).unwrap().ignore_pkgs, packages);
    }

    #[test]
    fn read_failures_do_not_change_the_configuration() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("pacman.conf");
        let original = b"[options]\n# invalid UTF-8: \xff\n";
        fs::write(&path, original).unwrap();
        assert!(add_ignored_packages(&path, &names(&["linux"])).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
