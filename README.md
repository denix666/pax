# pax

A modern and fast package manager for Arch-based systems, written in Rust.

Drop-in replacement for pacman with AUR support, dependency resolution, parallel downloads, and shell completions.

## Disclaimer

This program comes with no warranty. You must use this program at your own risk.

## Features

- **Full pacman compatibility** — reads pacman.conf, uses the same database format and mirrors
- **Dependency resolution** — automatic dependency resolution with topological sorting
- **Parallel downloads** — concurrent package downloads with multi-mirror fallback
- **AUR support** — search, install, and build AUR packages via makepkg
- **Shell completions** — dynamic completions for bash, zsh, and fish with `[installed]` markers
- **Transaction hooks** — supports alpm hooks (PreTransaction / PostTransaction)
- **Scriptlets** — runs pre/post install/upgrade/remove scriptlets
- **Backup file handling** — preserves user-modified config files (`.pacnew` / `.pacsave`)
- **PGP signature verification** — verifies package signatures respecting SigLevel settings (global and per-repo)
- **File conflict detection** — checks for file conflicts between packages before extraction
- **Disk space checking** — verifies sufficient disk space before installation (when `CheckSpace` is enabled)
- **Privilege escalation** — automatically requests root via sudo/doas when needed
- **System integrity checks** — verify dependency completeness and file existence (like `pacman -Dk` / `-Dkk`)
- **IgnoreGroup / HoldPkg** — respects `IgnoreGroup` and `HoldPkg` from pacman.conf

## Installation

Requires Rust 1.85+ (edition 2024).

```bash
git clone https://github.com/denix666/pax.git
cd pax
cargo build --release
sudo cp target/release/pax /usr/local/bin/
```

## Usage

```
pax [OPTIONS] [COMMAND]
```

Most commands that modify the system (install, remove, upgrade, sync) will automatically request root privileges via sudo or doas if not already running as root.

### Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `sync` | `y` | Synchronize package databases |
| `install` | `S` | Install packages (resolves dependencies) |
| `remove` | `R` | Remove packages |
| `upgrade` | `u` | Upgrade installed packages |
| `search` | `s` | Search sync databases for packages |
| `info` | `i` | Show detailed package information |
| `query` | `q` | Query installed packages |
| `files` | `f` | List files owned by a package |
| `owner` | `o` | Find which package owns a file |
| `local-install` | `U` | Install local package files (`.pkg.tar.zst`, `.pkg.tar.xz`, `.pkg.tar.gz`) |
| `clean` | `c` | Clean package cache |
| `check` | — | Check for missing dependencies |
| `check-files` | — | Check that all package files exist on disk |
| `aur-install` | — | Install packages from AUR |
| `aur-upgrade` | — | Upgrade installed AUR packages |
| `aur-search` | — | Search AUR for packages |

### Examples

```bash
# Synchronize databases
pax sync

# Install a package
pax install nginx

# Install with dry-run (no root needed)
pax install nginx --dry-run

# Download packages without installing
pax install nginx --download-only

# Reinstall a package
pax install nginx --reinstall

# Remove a package and its unused dependencies
pax remove nginx --recursive

# Upgrade all packages
pax upgrade

# Download upgrades without installing
pax upgrade --download-only

# Search for packages
pax search firefox

# Show package info (with install status)
pax info cowsay

# Query explicitly installed packages
pax query --explicit

# Find orphan packages
pax query --orphans

# Find which package owns a file
pax owner /usr/bin/vim

# Install a package from AUR
pax aur-install resistor

# Reinstall / update a specific AUR package
pax aur-install resistor --reinstall

# Install AUR package as root (not recommended)
pax aur-install resistor --allow-root

# Install a local package file
pax local-install ./package-1.0-1-x86_64.pkg.tar.zst

# Install multiple local packages at once
pax local-install pkg1.pkg.tar.zst pkg2.pkg.tar.zst

# Clean uninstalled packages from cache
pax clean

# Remove all cached packages
pax clean --all

# Upgrade all AUR packages
pax aur-upgrade

# Search AUR
pax aur-search telegram

# Check for missing dependencies (all packages)
pax check

# Check specific packages only
pax check vlc bash

# Check that all package files exist on disk
pax check-files

# Check files for specific packages
pax check-files bash glibc
```

### Global Options

| Option | Description |
|--------|-------------|
| `--config <PATH>` | Path to pacman.conf (default: `/etc/pacman.conf`) |
| `--dbpath <PATH>` | Alternate database path |
| `--root <PATH>` | Alternate root directory |
| `--completions <SHELL>` | Generate shell completions (`bash`, `zsh`, `fish`) |

### Install / Upgrade Flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would be installed/upgraded without doing it |
| `-w`, `--download-only` | Download packages to cache without installing |
| `--noconfirm` | Skip confirmation prompt |
| `--needed` | Skip already installed up-to-date packages (install only) |
| `--reinstall` | Reinstall already installed packages (install only) |

### Remove Flags

| Flag | Description |
|------|-------------|
| `-s`, `--recursive` | Also remove unneeded dependencies |
| `--noconfirm` | Skip confirmation prompt |

### AUR Flags

| Flag | Description |
|------|-------------|
| `--skip-review` | Skip PKGBUILD review before building |
| `--noconfirm` | Skip confirmation prompt |
| `--reinstall` | Reinstall already installed AUR packages (`aur-install` only) |
| `--allow-root` | Allow building as root (not recommended) |

### Privilege Escalation

pax automatically detects and uses the available privilege escalation tool:

1. `PAX_SUDO` environment variable — if set, uses the specified tool
2. `sudo` — if available in PATH
3. `doas` — if available in PATH

Example: `PAX_SUDO=doas pax install nginx`

### pacman.conf Support

pax reads and respects the following pacman.conf directives:

| Directive | Description |
|-----------|-------------|
| `IgnorePkg` | Packages to skip during upgrades |
| `IgnoreGroup` | Package groups to skip during upgrades |
| `HoldPkg` | Packages that require extra confirmation before removal |
| `CheckSpace` | Verify sufficient disk space before installing |
| `SigLevel` | PGP signature verification level (global and per-repo) |
| `ParallelDownloads` | Number of concurrent downloads |
| `CacheDir` | Package cache directory |

## Shell Completions

Generate and install completion scripts for your shell:

```bash
# Bash
pax --completions bash > ~/.local/share/bash-completion/completions/pax

# Zsh
pax --completions zsh > ~/.local/share/zsh/site-functions/_pax

# Fish
pax --completions fish > ~/.config/fish/completions/pax.fish
```

Completions include:
- Subcommands and flags
- Dynamic package name suggestions from sync databases, local database, and AUR
- `[installed]` markers next to already installed packages

## Architecture

The project is organized as a Cargo workspace with modular library crates:

```
crates/
├── pax-core       Core types, version parsing, config parser
├── pax-alpm       ALPM database readers (local and sync)
├── pax-resolver   Dependency resolver and transaction builder
├── pax-exec       Execution engine (download, extract, install, hooks)
├── pax-aur        AUR RPC client and build engine
└── pax-cli        CLI binary (thin wrapper over library crates)
```

All core logic lives in library crates. The CLI is a thin wrapper, making the architecture suitable for alternative frontends.

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request.

## License

[MIT License](https://opensource.org/licenses/MIT)
