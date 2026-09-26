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
| `aur-install` | — | Install packages from AUR |
| `aur-search` | — | Search AUR for packages |

### Examples

```bash
# Synchronize databases
sudo pax sync

# Install a package
sudo pax install nginx

# Install with dry-run
pax install nginx --dry-run

# Download package without installing
sudo pax install nginx --download-only

# Reinstall a package
sudo pax install nginx --reinstall

# Remove a package and its unused dependencies
sudo pax remove nginx --recursive

# Upgrade all packages
sudo pax upgrade

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
sudo pax aur-install resistor

# Install a local package file
sudo pax local-install ./package-1.0-1-x86_64.pkg.tar.zst

# Install multiple local packages at once
sudo pax local-install pkg1.pkg.tar.zst pkg2.pkg.tar.zst

# Search AUR
pax aur-search telegram
```

### Global Options

| Option | Description |
|--------|-------------|
| `--config <PATH>` | Path to pacman.conf (default: `/etc/pacman.conf`) |
| `--dbpath <PATH>` | Alternate database path |
| `--root <PATH>` | Alternate root directory |
| `--completions <SHELL>` | Generate shell completions (`bash`, `zsh`, `fish`) |

### Install Flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Show what would be installed without installing |
| `-w`, `--download-only` | Download packages to cache without installing |
| `--noconfirm` | Skip confirmation prompt |
| `--needed` | Skip already installed up-to-date packages |
| `--reinstall` | Reinstall already installed packages |

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
