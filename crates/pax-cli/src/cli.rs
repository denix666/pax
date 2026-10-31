use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum IgnoreMode {
    Prompt,
    Always,
    Never,
}

#[derive(Args)]
pub struct DowngradeArgs {
    /// Installed package names, optionally followed by =VERSION
    #[arg(required = true)]
    pub packages: Vec<String>,
    /// Search only local caches
    #[arg(long, conflicts_with_all = ["ala_only", "with_ala", "ala_url"])]
    pub cached_only: bool,
    /// Search only Arch Linux Archive
    #[arg(long, conflicts_with_all = ["with_ala", "prefer_cache"])]
    pub ala_only: bool,
    /// Include ALA even on Manjaro (whose default is cache only)
    #[arg(long)]
    pub with_ala: bool,
    /// Archive server URL; specifying it also enables archive search
    #[arg(long)]
    pub ala_url: Option<String>,
    /// Query ALA only if the cache has no matching older version
    #[arg(long)]
    pub prefer_cache: bool,
    /// Additional package cache directory (repeatable)
    #[arg(long = "cache-dir")]
    pub cache_dirs: Vec<PathBuf>,
    /// List older versions without installing
    #[arg(long)]
    pub list: bool,
    /// Select the newest matching version older than the installed version
    #[arg(long)]
    pub latest: bool,
    /// Skip transaction confirmation; requires an exact version or --latest
    #[arg(long)]
    pub noconfirm: bool,
    /// Add successfully downgraded packages to IgnorePkg
    #[arg(long, value_enum, default_value = "prompt")]
    pub ignore: IgnoreMode,
}

#[derive(Parser)]
#[command(
    name = "pax",
    version,
    about = "A modern and fast package manager for Arch-based systems"
)]
pub struct Cli {
    /// Path to pacman.conf
    #[arg(long, default_value = "/etc/pacman.conf")]
    pub config: PathBuf,

    /// Alternate database path
    #[arg(long)]
    pub dbpath: Option<PathBuf>,

    /// Alternate root directory
    #[arg(long)]
    pub root: Option<PathBuf>,

    /// Generate shell completions (bash, zsh, fish)
    #[arg(long)]
    pub completions: Option<String>,

    /// List package names for shell completion (sync, local, all)
    #[arg(long, hide = true)]
    pub pkg_list: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Downgrade installed packages using the cache or Arch Linux Archive
    Downgrade(DowngradeArgs),
    /// Search sync databases for packages
    #[command(alias = "s")]
    Search {
        /// Search query (matches name and description)
        query: String,
    },

    /// Show detailed package information
    #[command(alias = "i")]
    Info {
        /// Package name
        package: String,

        /// Query local database instead of sync
        #[arg(short, long)]
        local: bool,
    },

    /// Query installed packages
    #[command(alias = "q")]
    Query {
        /// Show only explicitly installed packages
        #[arg(short, long)]
        explicit: bool,

        /// Show orphan packages (unused dependencies)
        #[arg(short, long)]
        orphans: bool,

        /// Filter by package name (substring match)
        filter: Option<String>,
    },

    /// List files owned by a package
    #[command(alias = "f")]
    Files {
        /// Package name
        package: String,
    },

    /// Find which package owns a file
    #[command(alias = "o")]
    Owner {
        /// File path
        file: PathBuf,
    },

    /// Install local package files (.pkg.tar.zst, .pkg.tar.xz, .pkg.tar.gz)
    #[command(alias = "U")]
    LocalInstall {
        /// Paths to package files
        files: Vec<PathBuf>,

        /// Skip confirmation prompt
        #[arg(long)]
        noconfirm: bool,
    },

    /// Install packages (resolves dependencies)
    #[command(alias = "S")]
    Install {
        /// Package names to install
        packages: Vec<String>,

        /// Only show what would be installed, don't actually install
        #[arg(long)]
        dry_run: bool,

        /// Download packages without installing
        #[arg(short = 'w', long)]
        download_only: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        noconfirm: bool,

        /// Skip already installed up-to-date packages
        #[arg(long)]
        needed: bool,

        /// Reinstall already installed packages
        #[arg(long)]
        reinstall: bool,

        /// Install packages as dependencies (non-explicit)
        #[arg(long)]
        asdeps: bool,
    },

    /// Remove packages
    #[command(alias = "R")]
    Remove {
        /// Package names to remove
        packages: Vec<String>,

        /// Skip confirmation prompt
        #[arg(long)]
        noconfirm: bool,

        /// Remove unneeded dependencies too
        #[arg(short = 's', long)]
        recursive: bool,
    },

    /// Install packages from AUR
    AurInstall {
        /// Package names to install from AUR
        packages: Vec<String>,

        /// Skip PKGBUILD review
        #[arg(long)]
        skip_review: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        noconfirm: bool,

        /// Allow running as root (not recommended)
        #[arg(long)]
        allow_root: bool,

        /// Reinstall already installed packages
        #[arg(long)]
        reinstall: bool,
    },

    /// Upgrade installed AUR packages
    AurUpgrade {
        /// Skip PKGBUILD review
        #[arg(long)]
        skip_review: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        noconfirm: bool,

        /// Allow running as root (not recommended)
        #[arg(long)]
        allow_root: bool,
    },

    /// Search AUR for packages
    AurSearch {
        /// Search query
        query: String,
    },

    /// Clean package cache
    #[command(alias = "c")]
    Clean {
        /// Remove all cached packages, not just outdated ones
        #[arg(long)]
        all: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        noconfirm: bool,
    },

    /// Check for missing dependencies
    Check {
        /// Only check specific packages
        packages: Vec<String>,
    },

    /// Check that all package files exist on disk
    CheckFiles {
        /// Only check specific packages
        packages: Vec<String>,
    },

    /// Synchronize package databases
    #[command(alias = "y")]
    Sync,

    /// Upgrade installed packages
    #[command(alias = "u")]
    Upgrade {
        /// Only show what would be upgraded, don't actually upgrade
        #[arg(long)]
        dry_run: bool,

        /// Download packages without installing
        #[arg(short = 'w', long)]
        download_only: bool,

        /// Skip confirmation prompt
        #[arg(long)]
        noconfirm: bool,
    },

    /// Remove a stale database lock file
    RemoveLock,
}
