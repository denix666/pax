use crate::error::Result;
use crate::version::Version;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionConstraint {
    Eq,
    Ge,
    Le,
    Gt,
    Lt,
}

impl fmt::Display for VersionConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eq => write!(f, "="),
            Self::Ge => write!(f, ">="),
            Self::Le => write!(f, "<="),
            Self::Gt => write!(f, ">"),
            Self::Lt => write!(f, "<"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub constraint: Option<(VersionConstraint, Version)>,
}

impl Dependency {
    pub fn parse(s: &str) -> Result<Self> {
        let ops: &[(&str, VersionConstraint)] = &[
            (">=", VersionConstraint::Ge),
            ("<=", VersionConstraint::Le),
            ("=", VersionConstraint::Eq),
            (">", VersionConstraint::Gt),
            ("<", VersionConstraint::Lt),
        ];

        for &(op_str, op) in ops {
            if let Some(pos) = s.find(op_str) {
                let name = s[..pos].to_string();
                let ver_str = &s[pos + op_str.len()..];
                let version = Version::parse(ver_str)?;
                return Ok(Dependency {
                    name,
                    constraint: Some((op, version)),
                });
            }
        }

        Ok(Dependency {
            name: s.to_string(),
            constraint: None,
        })
    }

    pub fn satisfies(&self, version: &Version) -> bool {
        match &self.constraint {
            None => true,
            Some((op, required)) => {
                let ord = if required.pkgrel.is_empty() {
                    version.cmp_no_pkgrel(required)
                } else {
                    version.cmp(required)
                };
                match op {
                    VersionConstraint::Eq => ord == std::cmp::Ordering::Equal,
                    VersionConstraint::Ge => ord != std::cmp::Ordering::Less,
                    VersionConstraint::Le => ord != std::cmp::Ordering::Greater,
                    VersionConstraint::Gt => ord == std::cmp::Ordering::Greater,
                    VersionConstraint::Lt => ord == std::cmp::Ordering::Less,
                }
            }
        }
    }
}

impl fmt::Display for Dependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some((op, ver)) = &self.constraint {
            write!(f, "{op}{ver}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalDependency {
    pub dep: Dependency,
    pub description: String,
}

impl OptionalDependency {
    pub fn parse(s: &str) -> Result<Self> {
        let (dep_str, description) = match s.find(": ") {
            Some(pos) => (&s[..pos], s[pos + 2..].to_string()),
            None => (s, String::new()),
        };
        Ok(OptionalDependency {
            dep: Dependency::parse(dep_str)?,
            description,
        })
    }
}

impl fmt::Display for OptionalDependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.dep)?;
        if !self.description.is_empty() {
            write!(f, ": {}", self.description)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallReason {
    Explicit,
    Dependency,
}

impl fmt::Display for InstallReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Explicit => write!(f, "Explicitly installed"),
            Self::Dependency => write!(f, "Installed as a dependency for another package"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Validation {
    None,
    Pgp,
    Sha256,
    Md5,
    Unknown(String),
}

impl fmt::Display for Validation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Pgp => write!(f, "PGP Signature"),
            Self::Sha256 => write!(f, "SHA-256"),
            Self::Md5 => write!(f, "MD5"),
            Self::Unknown(s) => write!(f, "{s}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupFile {
    pub path: String,
    pub md5: String,
}

#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub version: Version,
    pub base: Option<String>,
    pub description: String,
    pub url: Option<String>,
    pub arch: String,
    pub build_date: i64,
    pub packager: String,
    pub licenses: Vec<String>,
    pub groups: Vec<String>,
    pub depends: Vec<Dependency>,
    pub optdepends: Vec<OptionalDependency>,
    pub provides: Vec<Dependency>,
    pub conflicts: Vec<Dependency>,
    pub replaces: Vec<Dependency>,
    pub xdata: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LocalPackage {
    pub info: PackageInfo,
    pub install_date: i64,
    pub size: u64,
    pub reason: InstallReason,
    pub validation: Vec<Validation>,
}

#[derive(Debug, Clone)]
pub struct SyncPackage {
    pub info: PackageInfo,
    pub filename: String,
    pub compressed_size: u64,
    pub installed_size: u64,
    pub md5sum: Option<String>,
    pub sha256sum: Option<String>,
    pub pgpsig: Option<String>,
    pub makedepends: Vec<Dependency>,
    pub checkdepends: Vec<Dependency>,
    pub repository: String,
}
