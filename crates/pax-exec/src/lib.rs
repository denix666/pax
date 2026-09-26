pub mod download;
pub mod error;
pub mod execute;
pub mod extract;
pub mod hooks;
pub mod register;
pub mod removal;
pub mod scriptlet;
pub mod sync_db;
pub mod verify;

pub use download::{download_packages, DownloadTarget, DownloadedPackage};
pub use error::ExecError;
pub use execute::{execute_transaction, InstallContext};
pub use extract::{extract_package, read_pkginfo, PackageMetadata, PkgFileInfo};
pub use hooks::{load_hooks, run_hooks, HookWhen, TransactionPackages};
pub use register::register_package;
pub use removal::{remove_package, RemovalTarget};
pub use scriptlet::{run_scriptlet, ScriptletOp};
pub use sync_db::{sync_databases, SyncTarget};

pub(crate) fn http_agent() -> ureq::Agent {
    use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
    ureq::Agent::config_builder()
        .tls_config(
            TlsConfig::builder()
                .provider(TlsProvider::NativeTls)
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .new_agent()
}
