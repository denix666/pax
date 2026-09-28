use std::path::Path;

use anyhow::{Result, bail};
use pax_alpm::db::DatabaseHandle;
use pax_core::config::PacmanConfig;

pub fn generate(shell: &str) -> Result<()> {
    match shell {
        "bash" => print!("{}", BASH),
        "zsh" => print!("{}", ZSH),
        "fish" => print!("{}", FISH),
        _ => bail!("unsupported shell: {shell} (use bash, zsh, or fish)"),
    }
    Ok(())
}

pub fn list_packages(config_path: &Path, source: &str) -> Result<()> {
    let config = PacmanConfig::load(config_path)?;
    let mut db = DatabaseHandle::new(config);

    match source {
        "local" => {
            for pkg in db.installed_packages()? {
                println!("{}", pkg.info.name);
            }
        }
        "sync" => {
            for (pkg, _) in db.sync_packages_with_repo_index()? {
                println!("{}", pkg.info.name);
            }
        }
        "all" => {
            let mut names = std::collections::BTreeSet::new();
            for pkg in db.installed_packages()? {
                names.insert(pkg.info.name.clone());
            }
            for (pkg, _) in db.sync_packages_with_repo_index()? {
                names.insert(pkg.info.name.clone());
            }
            for name in &names {
                println!("{name}");
            }
        }
        "sync-desc" | "all-desc" => {
            let mut installed = std::collections::HashSet::new();
            for pkg in db.installed_packages()? {
                installed.insert(pkg.info.name.clone());
            }
            let mut seen = std::collections::BTreeSet::new();
            if source == "all-desc" {
                for name in &installed {
                    seen.insert(name.clone());
                }
            }
            for (pkg, _) in db.sync_packages_with_repo_index()? {
                seen.insert(pkg.info.name.clone());
            }
            let mut installed_names = Vec::new();
            let mut other_names = Vec::new();
            for name in &seen {
                if installed.contains(name) {
                    installed_names.push(name);
                } else {
                    other_names.push(name);
                }
            }
            for name in &installed_names {
                println!("{name}\t[installed]");
            }
            for name in &other_names {
                println!("{name}");
            }
        }
        _ if source.starts_with("aur:") => {
            let prefix = &source[4..];
            if prefix.len() >= 2 {
                if let Ok(names) = pax_aur::aur_suggest(prefix) {
                    let mut installed = std::collections::HashSet::new();
                    if let Ok(pkgs) = db.installed_packages() {
                        for pkg in pkgs {
                            installed.insert(pkg.info.name.clone());
                        }
                    }
                    let mut installed_names = Vec::new();
                    let mut other_names = Vec::new();
                    for name in &names {
                        if installed.contains(name) {
                            installed_names.push(name);
                        } else {
                            other_names.push(name);
                        }
                    }
                    for name in installed_names {
                        println!("{name}\t[installed]");
                    }
                    for name in other_names {
                        println!("{name}");
                    }
                }
            }
        }
        _ => bail!("unsupported source: {source} (use sync, local, all, sync-desc, all-desc, aur:<prefix>)"),
    }
    Ok(())
}

const BASH: &str = r#"
_pax_complete_packages() {
    local desc_source="$1"
    local plain_source="$2"
    if [[ -n "$_FZF_COMPLETION_SEP" ]]; then
        local sel
        sel=$(pax --pkg-list "$desc_source" 2>/dev/null | \
            awk -F'\t' '{
                if ($2) printf "%s\t\033[32m%s\033[0m\n", $1, $2
                else print $1
            }' | \
            fzf --ansi --select-1 --exit-0 -q "$cur" \
                --height=~40% --layout=reverse --no-sort \
                -d '\t' --nth=1 --with-nth=.. | \
            cut -f1)
        [[ -n "$sel" ]] && COMPREPLY=("$sel")
    else
        COMPREPLY=($(compgen -W "$(pax --pkg-list "$plain_source" 2>/dev/null)" -- "$cur"))
    fi
}

_pax() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local subcmds="search info query files owner install remove local-install aur-install aur-search aur-upgrade check check-files sync upgrade clean help"

    case "$prev" in
        --completions)
            COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur"))
            return 0
            ;;
        --config)
            compopt -o filenames
            COMPREPLY=($(compgen -f -- "$cur"))
            return 0
            ;;
        --dbpath|--root)
            compopt -o filenames
            COMPREPLY=($(compgen -d -- "$cur"))
            return 0
            ;;
    esac

    local subcmd=""
    for ((i=1; i < COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            search|s|info|i|query|q|files|f|owner|o|install|S|remove|R|local-install|U|aur-install|aur-search|aur-upgrade|check|check-files|sync|y|upgrade|u|clean|c)
                subcmd="${COMP_WORDS[i]}"
                break
                ;;
        esac
    done

    if [[ -z "$subcmd" ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=($(compgen -W "--help --version --config --dbpath --root --completions" -- "$cur"))
        else
            COMPREPLY=($(compgen -W "$subcmds" -- "$cur"))
        fi
        return 0
    fi

    case "$subcmd" in
        install|S)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--dry-run --noconfirm --needed --reinstall --help" -- "$cur"))
            else
                _pax_complete_packages sync-desc sync
            fi
            ;;
        remove|R)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--noconfirm --recursive -s --help" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "$(pax --pkg-list local 2>/dev/null)" -- "$cur"))
            fi
            ;;
        search|s)
            ;;
        info|i)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--local -l --help" -- "$cur"))
            else
                _pax_complete_packages all-desc all
            fi
            ;;
        query|q)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--explicit -e --orphans -o --help" -- "$cur"))
            fi
            ;;
        files|f)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--help" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "$(pax --pkg-list local 2>/dev/null)" -- "$cur"))
            fi
            ;;
        owner|o)
            compopt -o filenames
            COMPREPLY=($(compgen -f -- "$cur"))
            ;;
        aur-install)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--skip-review --noconfirm --help" -- "$cur"))
            elif [[ ${#cur} -ge 2 ]]; then
                _pax_complete_packages "aur:$cur" "aur:$cur"
            fi
            ;;
        aur-search)
            ;;
        local-install|U)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--noconfirm --help" -- "$cur"))
            else
                compopt -o filenames
                COMPREPLY=($(compgen -f -- "$cur"))
            fi
            ;;
        aur-upgrade)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--skip-review --noconfirm --allow-root --help" -- "$cur"))
            fi
            ;;
        clean|c)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--all --noconfirm --help" -- "$cur"))
            fi
            ;;
        check)
            COMPREPLY=($(compgen -W "$(pax --pkg-list local 2>/dev/null)" -- "$cur"))
            ;;
        check-files)
            COMPREPLY=($(compgen -W "$(pax --pkg-list local 2>/dev/null)" -- "$cur"))
            ;;
        upgrade|u)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--dry-run --noconfirm --help" -- "$cur"))
            fi
            ;;
    esac
}
complete -o bashdefault -F _pax pax
"#;

const ZSH: &str = r#"
#compdef pax

_pax_sync_packages() {
    local -a pkgs
    local name status
    while IFS=$'\t' read -r name status; do
        [[ -z "$name" ]] && continue
        if [[ -n "$status" ]]; then
            pkgs+=("${name}:${status}")
        else
            pkgs+=("$name")
        fi
    done < <(pax --pkg-list sync-desc 2>/dev/null)
    _describe 'package' pkgs
}

_pax_installed_packages() {
    local -a pkgs
    pkgs=(${(f)"$(pax --pkg-list local 2>/dev/null)"})
    compadd -a pkgs
}

_pax_aur_packages() {
    local -a pkgs
    local cur="${words[CURRENT]}"
    [[ ${#cur} -lt 2 ]] && return
    pkgs=(${(f)"$(pax --pkg-list "aur:$cur" 2>/dev/null)"})
    compadd -a pkgs
}

_pax_all_packages() {
    local -a pkgs
    local name status
    while IFS=$'\t' read -r name status; do
        [[ -z "$name" ]] && continue
        if [[ -n "$status" ]]; then
            pkgs+=("${name}:${status}")
        else
            pkgs+=("$name")
        fi
    done < <(pax --pkg-list all-desc 2>/dev/null)
    _describe 'package' pkgs
}

_pax() {
    local -a subcmds
    subcmds=(
        'search:Search sync databases for packages'
        'info:Show detailed package information'
        'query:Query installed packages'
        'files:List files owned by a package'
        'owner:Find which package owns a file'
        'install:Install packages'
        'remove:Remove packages'
        'local-install:Install local package files'
        'aur-install:Install packages from AUR'
        'aur-search:Search AUR for packages'
        'aur-upgrade:Upgrade installed AUR packages'
        'check:Check for missing dependencies'
        'check-files:Check that all package files exist'
        'sync:Synchronize package databases'
        'upgrade:Upgrade installed packages'
        'clean:Clean package cache'
    )

    _arguments -C \
        '--help[Show help]' \
        '--version[Show version]' \
        '--config[Path to pacman.conf]:config:_files' \
        '--dbpath[Alternate database path]:dbpath:_directories' \
        '--root[Alternate root directory]:root:_directories' \
        '--completions[Generate shell completions]:shell:(bash zsh fish)' \
        '1:command:->cmd' \
        '*::arg:->args'

    case "$state" in
        cmd)
            _describe 'command' subcmds
            ;;
        args)
            case "${words[1]}" in
                install|S)
                    _arguments \
                        '--dry-run[Show what would be installed]' \
                        '--noconfirm[Skip confirmation]' \
                        '--needed[Skip up-to-date packages]' \
                        '--reinstall[Reinstall packages]' \
                        '*:package:_pax_sync_packages'
                    ;;
                remove|R)
                    _arguments \
                        '--noconfirm[Skip confirmation]' \
                        '-s[Remove unneeded deps]' \
                        '--recursive[Remove unneeded deps]' \
                        '*:package:_pax_installed_packages'
                    ;;
                info|i)
                    _arguments \
                        '-l[Query local database]' \
                        '--local[Query local database]' \
                        ':package:_pax_all_packages'
                    ;;
                query|q)
                    _arguments \
                        '-e[Explicitly installed only]' \
                        '--explicit[Explicitly installed only]' \
                        '-o[Orphan packages]' \
                        '--orphans[Orphan packages]' \
                        ':filter:'
                    ;;
                files|f)
                    _arguments ':package:_pax_installed_packages'
                    ;;
                owner|o)
                    _arguments ':file:_files'
                    ;;
                aur-install)
                    _arguments \
                        '--skip-review[Skip PKGBUILD review]' \
                        '--noconfirm[Skip confirmation]' \
                        '*:package:_pax_aur_packages'
                    ;;
                local-install|U)
                    _arguments \
                        '--noconfirm[Skip confirmation]' \
                        '*:file:_files -g "*.pkg.tar.(zst|xz|gz)"'
                    ;;
                aur-upgrade)
                    _arguments \
                        '--skip-review[Skip PKGBUILD review]' \
                        '--noconfirm[Skip confirmation]' \
                        '--allow-root[Allow running as root]'
                    ;;
                check)
                    _arguments '*:package:_pax_installed_packages'
                    ;;
                check-files)
                    _arguments '*:package:_pax_installed_packages'
                    ;;
                clean|c)
                    _arguments \
                        '--all[Remove all cached packages]' \
                        '--noconfirm[Skip confirmation]'
                    ;;
                upgrade|u)
                    _arguments \
                        '--dry-run[Show what would be upgraded]' \
                        '--noconfirm[Skip confirmation]'
                    ;;
            esac
            ;;
    esac
}

_pax "$@"
"#;

const FISH: &str = r#"
set -l subcmds search info query files owner install remove local-install aur-install aur-search aur-upgrade check check-files sync upgrade clean

complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -l help -d "Show help"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -l version -d "Show version"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -l config -d "Path to pacman.conf" -rF
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -l dbpath -d "Alternate database path" -ra "(__fish_complete_directories)"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -l root -d "Alternate root directory" -ra "(__fish_complete_directories)"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -l completions -d "Generate completions" -x -a "bash zsh fish"

complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a search -d "Search sync databases"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a info -d "Show package information"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a query -d "Query installed packages"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a files -d "List files owned by a package"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a owner -d "Find which package owns a file"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a install -d "Install packages"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a remove -d "Remove packages"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a aur-install -d "Install packages from AUR"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a aur-search -d "Search AUR for packages"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a sync -d "Synchronize databases"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a local-install -d "Install local package files"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a aur-upgrade -d "Upgrade AUR packages"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a upgrade -d "Upgrade packages"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a check -d "Check for missing dependencies"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a check-files -d "Check that all package files exist"
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a clean -d "Clean package cache"

complete -c pax -n "__fish_seen_subcommand_from install" -l dry-run -d "Show what would be installed"
complete -c pax -n "__fish_seen_subcommand_from install" -l noconfirm -d "Skip confirmation"
complete -c pax -n "__fish_seen_subcommand_from install" -l needed -d "Skip up-to-date packages"
complete -c pax -n "__fish_seen_subcommand_from install" -l reinstall -d "Reinstall packages"
complete -c pax -n "__fish_seen_subcommand_from install" -a "(pax --pkg-list sync-desc 2>/dev/null | string replace \t '\t')" -d ""

complete -c pax -n "__fish_seen_subcommand_from remove" -l noconfirm -d "Skip confirmation"
complete -c pax -n "__fish_seen_subcommand_from remove" -s s -l recursive -d "Remove unneeded deps"
complete -c pax -n "__fish_seen_subcommand_from remove" -a "(pax --pkg-list local 2>/dev/null)" -d "Installed package"

complete -c pax -n "__fish_seen_subcommand_from info" -s l -l local -d "Query local database"
complete -c pax -n "__fish_seen_subcommand_from info" -a "(pax --pkg-list all-desc 2>/dev/null | string replace \t '\t')" -d ""

complete -c pax -n "__fish_seen_subcommand_from query" -s e -l explicit -d "Explicitly installed only"
complete -c pax -n "__fish_seen_subcommand_from query" -s o -l orphans -d "Orphan packages"

complete -c pax -n "__fish_seen_subcommand_from files" -a "(pax --pkg-list local 2>/dev/null)" -d "Installed package"

complete -c pax -n "__fish_seen_subcommand_from owner" -F -d "File path"

complete -c pax -n "__fish_seen_subcommand_from aur-install" -l skip-review -d "Skip PKGBUILD review"
complete -c pax -n "__fish_seen_subcommand_from aur-install" -l noconfirm -d "Skip confirmation"
complete -c pax -n "__fish_seen_subcommand_from aur-install" -a "(test (string length -- (commandline -ct)) -ge 2; and pax --pkg-list 'aur:'(commandline -ct) 2>/dev/null)" -d "AUR package"

complete -c pax -n "__fish_seen_subcommand_from local-install" -l noconfirm -d "Skip confirmation"
complete -c pax -n "__fish_seen_subcommand_from local-install" -F -d "Package file"

complete -c pax -n "__fish_seen_subcommand_from aur-upgrade" -l skip-review -d "Skip PKGBUILD review"
complete -c pax -n "__fish_seen_subcommand_from aur-upgrade" -l noconfirm -d "Skip confirmation"
complete -c pax -n "__fish_seen_subcommand_from aur-upgrade" -l allow-root -d "Allow running as root"

complete -c pax -n "__fish_seen_subcommand_from upgrade" -l dry-run -d "Show what would be upgraded"
complete -c pax -n "__fish_seen_subcommand_from upgrade" -l noconfirm -d "Skip confirmation"

complete -c pax -n "__fish_seen_subcommand_from check" -a "(pax --pkg-list local 2>/dev/null)" -d "Installed package"
complete -c pax -n "__fish_seen_subcommand_from check-files" -a "(pax --pkg-list local 2>/dev/null)" -d "Installed package"

complete -c pax -n "__fish_seen_subcommand_from clean" -l all -d "Remove all cached packages"
complete -c pax -n "__fish_seen_subcommand_from clean" -l noconfirm -d "Skip confirmation"
"#;
