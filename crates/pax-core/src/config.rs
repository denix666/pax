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

        let config_dir = config_path.parent().unwrap_or(Path::new("/etc"));

        for raw_line in content.lines() {
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
                        "Include" => {
                            let include_path = if value.starts_with('/') {
                                PathBuf::from(value)
                            } else {
                                config_dir.join(value)
                            };
                            if let Ok(mirrors) =
                                parse_mirrorlist(&include_path, section, &config.architecture)
                            {
                                current_servers.extend(mirrors);
                            }
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

fn parse_mirrorlist(path: &Path, repo: &str, arch: &str) -> Result<Vec<String>> {
    let content = std::fs::read_to_string(path)?;
    let mut servers = Vec::new();

    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "Server" {
                let url = value.trim().replace("$repo", repo).replace("$arch", arch);
                servers.push(url);
            }
        }
    }

    Ok(servers)
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
