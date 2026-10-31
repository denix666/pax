use crate::error::{PaxError, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigLevel {
    Required,
    Optional,
    Never,
}

impl Default for SigLevel {
    fn default() -> Self {
        SigLevel::Optional
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigTrust {
    #[default]
    TrustedOnly,
    TrustAll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigConfig {
    pub package: SigLevel,
    pub database: SigLevel,
    pub package_trust: SigTrust,
    pub database_trust: SigTrust,
}

impl Default for SigConfig {
    fn default() -> Self {
        SigConfig {
            package: SigLevel::Optional,
            database: SigLevel::Optional,
            package_trust: SigTrust::TrustedOnly,
            database_trust: SigTrust::TrustedOnly,
        }
    }
}

pub fn parse_sig_level(value: &str) -> SigConfig {
    parse_sig_level_with_base(value, SigConfig::default())
}

pub fn parse_sig_level_with_base(value: &str, mut cfg: SigConfig) -> SigConfig {
    for token in value.split_whitespace() {
        match token {
            "Required" => {
                cfg.package = SigLevel::Required;
                cfg.database = SigLevel::Required;
            }
            "Optional" => {
                cfg.package = SigLevel::Optional;
                cfg.database = SigLevel::Optional;
            }
            "Never" => {
                cfg.package = SigLevel::Never;
                cfg.database = SigLevel::Never;
            }
            "PackageRequired" => cfg.package = SigLevel::Required,
            "PackageOptional" => cfg.package = SigLevel::Optional,
            "PackageNever" => cfg.package = SigLevel::Never,
            "DatabaseRequired" => cfg.database = SigLevel::Required,
            "DatabaseOptional" => cfg.database = SigLevel::Optional,
            "DatabaseNever" => cfg.database = SigLevel::Never,
            "TrustAll" => {
                cfg.package_trust = SigTrust::TrustAll;
                cfg.database_trust = SigTrust::TrustAll;
            }
            "TrustedOnly" => {
                cfg.package_trust = SigTrust::TrustedOnly;
                cfg.database_trust = SigTrust::TrustedOnly;
            }
            "PackageTrustAll" => cfg.package_trust = SigTrust::TrustAll,
            "PackageTrustedOnly" => cfg.package_trust = SigTrust::TrustedOnly,
            "DatabaseTrustAll" => cfg.database_trust = SigTrust::TrustAll,
            "DatabaseTrustedOnly" => cfg.database_trust = SigTrust::TrustedOnly,
            _ => {}
        }
    }
    cfg
}

#[derive(Debug, Clone)]
pub struct PacmanConfig {
    pub root_dir: PathBuf,
    pub db_path: PathBuf,
    pub cache_dirs: Vec<PathBuf>,
    pub log_file: PathBuf,
    pub gpg_dir: PathBuf,
    pub hook_dirs: Vec<PathBuf>,
    pub hold_pkgs: Vec<String>,
    pub ignore_pkgs: Vec<String>,
    pub ignore_groups: Vec<String>,
    pub architecture: String,
    pub color: bool,
    pub check_space: bool,
    pub parallel_downloads: u32,
    pub sig_level: SigConfig,
    pub local_file_sig_level: SigConfig,
    pub repos: Vec<Repository>,
    cache_dirs_overridden: bool,
}

#[derive(Debug, Clone)]
pub struct Repository {
    pub name: String,
    pub servers: Vec<String>,
    pub sig_level: Option<SigConfig>,
}

impl Default for PacmanConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from("/"),
            db_path: PathBuf::from("/var/lib/pacman/"),
            cache_dirs: vec![PathBuf::from("/var/cache/pacman/pkg/")],
            log_file: PathBuf::from("/var/log/pax.log"),
            gpg_dir: PathBuf::from("/etc/pacman.d/gnupg/"),
            hook_dirs: vec![],
            hold_pkgs: vec![],
            ignore_pkgs: vec![],
            ignore_groups: vec![],
            architecture: String::new(),
            color: false,
            check_space: false,
            parallel_downloads: 1,
            sig_level: SigConfig::default(),
            local_file_sig_level: SigConfig::default(),
            repos: vec![],
            cache_dirs_overridden: false,
        }
    }
}

impl PacmanConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(PaxError::Io)?;
        Self::parse(&content, path)
    }

    fn parse(content: &str, config_path: &Path) -> Result<Self> {
        let mut config = PacmanConfig::default();
        let mut current_repo: Option<String> = None;
        let mut current_servers: Vec<String> = Vec::new();
        let mut current_sig_level: Option<SigConfig> = None;
        let mut repo_sig_overrides: Vec<String> = Vec::new();
        let mut local_sig_override = String::new();

        if config.architecture.is_empty() {
            config.architecture = detect_arch();
        }

        let mut expanded = String::new();
        let mut include_stack =
            vec![std::fs::canonicalize(config_path).unwrap_or_else(|_| config_path.to_path_buf())];
        expand_includes(content, config_path, &mut include_stack, &mut expanded)?;

        for raw_line in expanded.lines() {
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                // Flush previous repo
                if let Some(repo_name) = current_repo.take() {
                    if repo_name != "options" {
                        config.repos.push(Repository {
                            name: repo_name,
                            servers: std::mem::take(&mut current_servers),
                            sig_level: current_sig_level.take(),
                        });
                    }
                }

                let section = &line[1..line.len() - 1];
                current_repo = Some(section.to_string());
                current_servers.clear();
                current_sig_level = None;
                continue;
            }

            let section = current_repo.as_deref().unwrap_or("");

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                if section == "options" {
                    match key {
                        "RootDir" => config.root_dir = PathBuf::from(value),
                        "DBPath" => config.db_path = PathBuf::from(value),
                        "CacheDir" => {
                            if !config.cache_dirs_overridden {
                                config.cache_dirs.clear();
                                config.cache_dirs_overridden = true;
                            }
                            config.cache_dirs.push(PathBuf::from(value));
                        }
                        "LogFile" => config.log_file = PathBuf::from(value),
                        "GPGDir" => config.gpg_dir = PathBuf::from(value),
                        "HookDir" => config.hook_dirs.push(PathBuf::from(value)),
                        "HoldPkg" => {
                            config
                                .hold_pkgs
                                .extend(value.split_whitespace().map(String::from));
                        }
                        "IgnorePkg" => {
                            config
                                .ignore_pkgs
                                .extend(value.split_whitespace().map(String::from));
                        }
                        "IgnoreGroup" => {
                            config
                                .ignore_groups
                                .extend(value.split_whitespace().map(String::from));
                        }
                        "Architecture" => {
                            config.architecture = if value == "auto" {
                                detect_arch()
                            } else {
                                value.to_string()
                            };
                        }
                        "ParallelDownloads" => {
                            config.parallel_downloads = value.parse().unwrap_or(1);
                        }
                        "SigLevel" => {
                            config.sig_level = parse_sig_level_with_base(value, config.sig_level);
                        }
                        "LocalFileSigLevel" => {
                            local_sig_override.push_str(value);
                            local_sig_override.push(' ');
                        }
                        _ => {}
                    }
                } else {
                    match key {
                        "SigLevel" => {
                            let index = config.repos.len();
                            repo_sig_overrides.resize(index + 1, String::new());
                            repo_sig_overrides[index].push_str(value);
                            repo_sig_overrides[index].push(' ');
                            current_sig_level = Some(SigConfig::default());
                        }
                        "Server" => {
                            let url = value
                                .replace("$repo", section)
                                .replace("$arch", &config.architecture);
                            current_servers.push(url);
                        }

                        _ => {}
                    }
                }
            } else if section == "options" {
                match line {
                    "Color" => config.color = true,
                    "CheckSpace" => config.check_space = true,
                    _ => {}
                }
            }
        }

        // Flush last repo
        if let Some(repo_name) = current_repo {
            if repo_name != "options" {
                config.repos.push(Repository {
                    name: repo_name,
                    servers: current_servers,
                    sig_level: current_sig_level,
                });
            }
        }

        for (index, repo) in config.repos.iter_mut().enumerate() {
            if repo.sig_level.is_some() {
                repo.sig_level = Some(parse_sig_level_with_base(
                    &repo_sig_overrides[index],
                    config.sig_level,
                ));
            }
        }
        config.local_file_sig_level =
            parse_sig_level_with_base(&local_sig_override, config.sig_level);
        Ok(config)
    }
}

const MAX_INCLUDE_DEPTH: usize = 64;

fn expand_includes(
    content: &str,
    config_path: &Path,
    include_stack: &mut Vec<PathBuf>,
    expanded: &mut String,
) -> Result<()> {
    let config_dir = config_path.parent().unwrap_or(Path::new("/etc"));
    for (index, raw_line) in content.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        let Some(("Include", value)) = line.split_once('=').map(|(k, v)| (k.trim(), v.trim()))
        else {
            expanded.push_str(raw_line);
            expanded.push('\n');
            continue;
        };
        let error = |message: String| PaxError::ConfigParse {
            path: config_path.to_path_buf(),
            line: index + 1,
            message,
        };
        if value.is_empty() {
            return Err(error("empty Include path".to_string()));
        }
        let pattern = config_dir.join(value);
        let paths = include_paths(&pattern)
            .map_err(|e| error(format!("Include {}: {e}", pattern.display())))?;
        if paths.is_empty() {
            return Err(error(format!(
                "Include {} matched no files",
                pattern.display()
            )));
        }
        for path in paths {
            let canonical = std::fs::canonicalize(&path)
                .map_err(|e| error(format!("Include {}: {e}", path.display())))?;
            if include_stack.contains(&canonical) {
                return Err(error(format!("Include cycle at {}", path.display())));
            }
            if include_stack.len() >= MAX_INCLUDE_DEPTH {
                return Err(error(format!(
                    "Include depth exceeds {MAX_INCLUDE_DEPTH} files at {}",
                    path.display()
                )));
            }
            let content = std::fs::read_to_string(&path)
                .map_err(|e| error(format!("Include {}: {e}", path.display())))?;
            include_stack.push(canonical);
            let result = expand_includes(&content, &path, include_stack, expanded);
            include_stack.pop();
            result?;
        }
    }
    Ok(())
}

fn include_paths(pattern: &Path) -> std::io::Result<Vec<PathBuf>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    unsafe extern "C" {
        fn fnmatch(
            pattern: *const std::ffi::c_char,
            name: *const std::ffi::c_char,
            flags: std::ffi::c_int,
        ) -> std::ffi::c_int;
    }

    let mut paths = vec![PathBuf::new()];
    for component in pattern.components() {
        let Component::Normal(part) = component else {
            for path in &mut paths {
                path.push(component.as_os_str());
            }
            continue;
        };
        let bytes = part.as_bytes();
        if !bytes
            .iter()
            .any(|&b| matches!(b, b'*' | b'?' | b'[' | b'\\'))
        {
            for path in &mut paths {
                path.push(part);
            }
            continue;
        }
        let pattern = CString::new(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut matches = Vec::new();
        for path in paths {
            let directory = if path.as_os_str().is_empty() {
                Path::new(".")
            } else {
                &path
            };
            let entries = match std::fs::read_dir(directory) {
                Ok(entries) => entries,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            };
            for entry in entries {
                let entry = entry?;
                let name = CString::new(entry.file_name().as_bytes())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                // Linux FNM_PERIOD: wildcards must not match a leading dot.
                // SAFETY: both pointers refer to live, NUL-terminated C strings.
                if unsafe { fnmatch(pattern.as_ptr(), name.as_ptr(), 4) } == 0 {
                    matches.push(entry.path());
                }
            }
        }
        paths = matches;
    }
    paths.sort();
    Ok(paths)
}

fn detect_arch() -> String {
    std::process::Command::new("uname")
        .arg("-m")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "x86_64".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ConfigFixture(PathBuf);

    impl ConfigFixture {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
            loop {
                let path = std::env::temp_dir().join(format!(
                    "pax-config-{}-{}",
                    std::process::id(),
                    NEXT_ID.fetch_add(1, Ordering::Relaxed)
                ));
                match std::fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(e) => panic!("cannot create config fixture: {e}"),
                }
            }
        }

        fn write(&self, name: &str, content: &str) {
            let path = self.0.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }

        fn load(&self) -> Result<PacmanConfig> {
            PacmanConfig::load(&self.0.join("pacman.conf"))
        }
    }

    impl Drop for ConfigFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn includes_inherit_options_and_propagate_nested_section_changes() {
        let files = ConfigFixture::new();
        files.write(
            "pacman.conf",
            "[options]\nArchitecture = testarch\nInclude = conf/options\nServer = https://parent/$repo/$arch\n",
        );
        files.write(
            "conf/options",
            "IgnorePkg = pinned\nSigLevel = Required TrustAll\nLocalFileSigLevel = PackageOptional\nInclude = nested/repos\nServer = https://included/$repo/$arch\n",
        );
        files.write(
            "conf/nested/repos",
            "IgnorePkg = also-pinned\n[core]\nSigLevel = DatabaseOptional\nServer = https://nested/$repo/$arch\n",
        );
        let config = files.load().unwrap();
        assert_eq!(config.ignore_pkgs, ["pinned", "also-pinned"]);
        assert_eq!(config.sig_level, parse_sig_level("Required TrustAll"));
        assert_eq!(config.local_file_sig_level.package, SigLevel::Optional);
        assert_eq!(config.local_file_sig_level.database, SigLevel::Required);
        assert_eq!(
            config.local_file_sig_level.package_trust,
            SigTrust::TrustAll
        );
        assert_eq!(config.repos.len(), 1);
        assert_eq!(config.repos[0].name, "core");
        assert_eq!(
            config.repos[0].sig_level,
            Some(parse_sig_level("Required TrustAll DatabaseOptional"))
        );
        assert_eq!(
            config.repos[0].servers,
            [
                "https://nested/core/testarch",
                "https://included/core/testarch",
                "https://parent/core/testarch",
            ]
        );
    }

    #[test]
    fn repository_includes_can_switch_back_to_options() {
        let files = ConfigFixture::new();
        files.write(
            "pacman.conf",
            "[options]\nArchitecture = testarch\n[core]\nInclude = mirrorlist\nIgnorePkg = parent-pin\n[extra]\nSigLevel = DatabaseOptional\n",
        );
        files.write(
            "mirrorlist",
            "Server = https://mirror/$repo/$arch\nSigLevel = PackageOptional\n[options]\nSigLevel = Required TrustedOnly\nIgnorePkg = included-pin\n",
        );
        let config = files.load().unwrap();
        assert_eq!(config.ignore_pkgs, ["included-pin", "parent-pin"]);
        assert_eq!(config.repos.len(), 2);
        assert_eq!(config.repos[0].servers, ["https://mirror/core/testarch"]);
        assert_eq!(
            config.repos[0].sig_level,
            Some(parse_sig_level("Required PackageOptional"))
        );
        assert_eq!(
            config.repos[1].sig_level,
            Some(parse_sig_level("Required DatabaseOptional"))
        );
    }

    #[test]
    fn include_globs_are_sorted_and_preserve_section_state_between_matches() {
        let files = ConfigFixture::new();
        files.write(
            "pacman.conf",
            "[options]\nInclude = conf.d/[12]?-*.conf\nServer = https://parent/$repo/$arch\n",
        );
        files.write("conf.d/20-repo.conf", "[core]\n");
        files.write(
            "conf.d/10-options.conf",
            "Architecture = testarch\nIgnorePkg = pinned\nSigLevel = Required\n",
        );
        files.write("conf.d/.hidden.conf", "IgnorePkg = hidden\n");
        files.write("conf.d/30-unused.conf", "[unused]\n");
        let config = files.load().unwrap();
        assert_eq!(config.ignore_pkgs, ["pinned"]);
        assert_eq!(config.sig_level.package, SigLevel::Required);
        assert_eq!(config.repos.len(), 1);
        assert_eq!(config.repos[0].servers, ["https://parent/core/testarch"]);
    }

    #[test]
    fn include_globs_support_directory_components_and_skip_hidden_files() {
        let files = ConfigFixture::new();
        files.write("pacman.conf", "[options]\nInclude = fragments/*/*.conf\n");
        files.write("fragments/b/20.conf", "IgnorePkg = second\n");
        files.write("fragments/a/10.conf", "IgnorePkg = first\n");
        files.write("fragments/a/.hidden.conf", "IgnorePkg = hidden\n");
        files.write("fragments/plain-file", "");
        let config = files.load().unwrap();
        assert_eq!(config.ignore_pkgs, ["first", "second"]);
    }

    #[test]
    fn absolute_and_repeated_includes_are_allowed() {
        let files = ConfigFixture::new();
        files.write("shared", "IgnorePkg = pinned\n");
        files.write(
            "pacman.conf",
            &format!(
                "[options]\nInclude = {}\nInclude = shared\n",
                files.0.join("shared").display()
            ),
        );
        assert_eq!(files.load().unwrap().ignore_pkgs, ["pinned", "pinned"]);
    }

    #[test]
    fn include_cycles_report_the_directive_location() {
        let files = ConfigFixture::new();
        files.write("pacman.conf", "[options]\nInclude = nested/options\n");
        files.write(
            "nested/options",
            "IgnorePkg = pinned\nInclude = ../pacman.conf\n",
        );
        let error = files.load().unwrap_err();
        match error {
            PaxError::ConfigParse {
                path,
                line,
                message,
            } => {
                assert_eq!(path, files.0.join("nested/options"));
                assert_eq!(line, 2);
                assert!(message.contains("Include cycle"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn include_depth_is_bounded() {
        let files = ConfigFixture::new();
        files.write("pacman.conf", "[options]\nInclude = depth-0\n");
        for index in 0..MAX_INCLUDE_DEPTH {
            files.write(
                &format!("depth-{index}"),
                &format!("Include = depth-{}\n", index + 1),
            );
        }
        let error = files.load().unwrap_err().to_string();
        assert!(error.contains("Include depth exceeds"), "{error}");
    }

    #[test]
    fn missing_unmatched_and_empty_includes_are_errors() {
        let files = ConfigFixture::new();
        for value in ["missing", "*.missing", ""] {
            files.write("pacman.conf", &format!("[options]\nInclude = {value}\n"));
            match files.load().unwrap_err() {
                PaxError::ConfigParse { path, line, .. } => {
                    assert_eq!(path, files.0.join("pacman.conf"));
                    assert_eq!(line, 2);
                }
                other => panic!("unexpected error: {other}"),
            }
        }
    }

    #[test]
    fn partial_repository_and_local_policies_inherit_global_fields() {
        let config = PacmanConfig::parse(
            r#"
[options]
SigLevel = Required TrustedOnly
LocalFileSigLevel = PackageOptional
[core]
SigLevel = DatabaseOptional
[extra]
SigLevel = PackageTrustAll
[options]
SigLevel = DatabaseTrustAll
"#,
            Path::new("/etc/pacman.conf"),
        )
        .unwrap();
        let core = config.repos[0].sig_level.unwrap();
        assert_eq!(core.package, SigLevel::Required);
        assert_eq!(core.database, SigLevel::Optional);
        assert_eq!(core.package_trust, SigTrust::TrustedOnly);
        assert_eq!(core.database_trust, SigTrust::TrustAll);
        let extra = config.repos[1].sig_level.unwrap();
        assert_eq!(extra.package, SigLevel::Required);
        assert_eq!(extra.database, SigLevel::Required);
        assert_eq!(extra.package_trust, SigTrust::TrustAll);
        assert_eq!(config.local_file_sig_level.package, SigLevel::Optional);
        assert_eq!(
            config.local_file_sig_level.package_trust,
            SigTrust::TrustedOnly
        );
        assert_eq!(
            config.local_file_sig_level.database_trust,
            SigTrust::TrustAll
        );
    }

    #[test]
    fn signature_tokens_scope_trust_and_requirement_independently() {
        let policy = parse_sig_level("Required TrustAll PackageTrustedOnly DatabaseNever");
        assert_eq!(policy.package, SigLevel::Required);
        assert_eq!(policy.database, SigLevel::Never);
        assert_eq!(policy.package_trust, SigTrust::TrustedOnly);
        assert_eq!(policy.database_trust, SigTrust::TrustAll);
        let policy = parse_sig_level("Never TrustedOnly PackageOptional DatabaseTrustAll");
        assert_eq!(policy.package, SigLevel::Optional);
        assert_eq!(policy.database, SigLevel::Never);
        assert_eq!(policy.package_trust, SigTrust::TrustedOnly);
        assert_eq!(policy.database_trust, SigTrust::TrustAll);
    }

    #[test]
    fn local_signature_policy_defaults_to_global_and_accumulates_overrides() {
        let config = PacmanConfig::parse(
            "[options]\nSigLevel = Required TrustAll\n",
            Path::new("/etc/pacman.conf"),
        )
        .unwrap();
        assert_eq!(config.local_file_sig_level, config.sig_level);
        let config = PacmanConfig::parse("[options]\nSigLevel = Required TrustAll\nLocalFileSigLevel = Optional\nLocalFileSigLevel = TrustedOnly\n", Path::new("/etc/pacman.conf")).unwrap();
        assert_eq!(config.local_file_sig_level.package, SigLevel::Optional);
        assert_eq!(
            config.local_file_sig_level.package_trust,
            SigTrust::TrustedOnly
        );
    }

    #[test]
    fn test_parse_minimal_config() {
        let content = r#"
[options]
Architecture = auto
Color
CheckSpace

[core]
Server = https://mirror.example.com/$repo/$arch

[extra]
Server = https://mirror.example.com/$repo/$arch
"#;
        let config = PacmanConfig::parse(content, Path::new("/etc/pacman.conf")).unwrap();
        assert!(config.color);
        assert!(config.check_space);
        assert_eq!(config.repos.len(), 2);
        assert_eq!(config.repos[0].name, "core");
        assert_eq!(config.repos[1].name, "extra");
        assert!(!config.repos[0].servers.is_empty());
    }
}
