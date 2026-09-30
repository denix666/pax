use pax_core::package::Dependency;
use pax_core::version::Version;

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("target not found: {name} is not available in any repository")]
    TargetNotFound { name: String },

    #[error("unresolvable dependency: {dep}\n  required by: {}", format_chain(chain))]
    DependencyNotFound {
        dep: Dependency,
        chain: Vec<String>,
    },

    #[error("version conflict: {pkg} {installed} is installed, but {dep} is required\n  required by: {}", format_chain(chain))]
    VersionConflict {
        pkg: String,
        installed: Version,
        dep: Dependency,
        chain: Vec<String>,
    },

    #[error("conflict: {pkg_a} and {pkg_b} conflict with each other\n  {pkg_a} required by: {}\n  {pkg_b} required by: {}\n  cannot remove {pkg_b} automatically: required by {blocked_by}", format_chain(chain_a), format_chain(chain_b))]
    PackageConflict {
        pkg_a: String,
        pkg_b: String,
        chain_a: Vec<String>,
        chain_b: Vec<String>,
        blocked_by: String,
    },

    #[error(transparent)]
    Core(#[from] pax_core::error::PaxError),
}

fn format_chain(chain: &[String]) -> String {
    if chain.is_empty() {
        "target".to_string()
    } else {
        chain.join(" -> ")
    }
}

pub type Result<T> = std::result::Result<T, ResolveError>;
