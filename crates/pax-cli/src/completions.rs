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

pub fn list_packages(
    config_path: &Path,
    source: &str,
    dbpath: Option<&Path>,
    root: Option<&Path>,
) -> Result<()> {
    let mut config = PacmanConfig::load(config_path)?;
    if let Some(dbpath) = dbpath {
        config.db_path = dbpath.to_path_buf();
    }
    if let Some(root) = root {
        config.root_dir = root.to_path_buf();
    }
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
        _ => bail!(
            "unsupported source: {source} (use sync, local, all, sync-desc, all-desc, aur:<prefix>)"
        ),
    }
    Ok(())
}

const BASH: &str = r#"
_pax_pkg_list() {
    pax "${pax_global_args[@]}" --pkg-list "$1" 2>/dev/null
}

_pax_complete_packages() {
    local desc_source="$1"
    local plain_source="$2"
    if [[ -n "$_FZF_COMPLETION_SEP" ]]; then
        local sel
        sel=$(_pax_pkg_list "$desc_source" 2>/dev/null | \
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
        COMPREPLY=($(compgen -W "$(_pax_pkg_list "$plain_source" 2>/dev/null)" -- "$cur"))
    fi
}

_pax() {
    local cur prev i cword
    local -a words=() pax_global_args=()
    COMPREPLY=()
    # Reassemble words split at '=' by Bash's default COMP_WORDBREAKS.
    for ((i=0; i <= COMP_CWORD; i++)); do
        if (( ${#words[@]} > 0 )) &&
            [[ "${COMP_WORDS[i]}" == "=" || "${words[${#words[@]}-1]}" == *= ]]; then
            words[${#words[@]}-1]+="${COMP_WORDS[i]}"
        else
            words+=("${COMP_WORDS[i]}")
        fi
    done
    cword=$((${#words[@]} - 1))
    cur="${words[cword]}"
    prev="${words[cword-1]}"

    local subcmds="search info query files owner install downgrade remove local-install aur-install aur-search aur-upgrade check check-files sync upgrade clean remove-lock help"

    local value_prefix=""
    if [[ "$cur" == --*=* ]]; then
        prev="${cur%%=*}"
        [[ "$COMP_WORDBREAKS" != *=* ]] && value_prefix="$prev="
        cur="${cur#*=}"
    fi
    case "$prev" in
        --completions)
            COMPREPLY=($(compgen -P "$value_prefix" -W "bash zsh fish" -- "$cur"))
            return 0
            ;;
        --config)
            compopt -o filenames
            COMPREPLY=($(compgen -P "$value_prefix" -f -- "$cur"))
            return 0
            ;;
        --dbpath|--root)
            compopt -o filenames
            COMPREPLY=($(compgen -P "$value_prefix" -d -- "$cur"))
            return 0
            ;;
    esac

    local subcmd=""
    for ((i=1; i < cword; i++)); do
        case "${words[i]}" in
            --config|--dbpath|--root)
                pax_global_args+=("${words[i]}" "${words[i+1]}")
                ((i++))
                ;;
            --config=*|--dbpath=*|--root=*)
                pax_global_args+=("${words[i]}")
                ;;
            --completions|--pkg-list)
                ((i++))
                ;;
            search|s|info|i|query|q|files|f|owner|o|install|S|downgrade|remove|R|local-install|U|aur-install|aur-search|aur-upgrade|check|check-files|sync|y|upgrade|u|clean|c|remove-lock)
                subcmd="${words[i]}"
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
                COMPREPLY=($(compgen -W "--dry-run --download-only -w --noconfirm --needed --reinstall --asdeps --help" -- "$cur"))
            else
                _pax_complete_packages sync-desc sync
            fi
            ;;
        downgrade)
            case "$prev" in
                --ignore)
                    COMPREPLY=($(compgen -P "$value_prefix" -W "prompt always never" -- "$cur"))
                    return 0
                    ;;
                --cache-dir)
                    compopt -o filenames
                    COMPREPLY=($(compgen -P "$value_prefix" -d -- "$cur"))
                    return 0
                    ;;
                --ala-url)
                    return 0
                    ;;
            esac
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--cached-only --ala-only --with-ala --prefer-cache --ala-url --cache-dir --list --latest --noconfirm --ignore --help" -- "$cur"))
            elif [[ "${words[cword]}" != *=* ]]; then
                COMPREPLY=($(compgen -W "$(_pax_pkg_list local 2>/dev/null)" -- "$cur"))
            fi
            ;;
        remove|R)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--noconfirm --recursive -s --help" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "$(_pax_pkg_list local 2>/dev/null)" -- "$cur"))
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
                COMPREPLY=($(compgen -W "$(_pax_pkg_list local 2>/dev/null)" -- "$cur"))
            fi
            ;;
        owner|o)
            compopt -o filenames
            COMPREPLY=($(compgen -f -- "$cur"))
            ;;
        aur-install)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--skip-review --noconfirm --reinstall --allow-root --help" -- "$cur"))
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
            COMPREPLY=($(compgen -W "$(_pax_pkg_list local 2>/dev/null)" -- "$cur"))
            ;;
        check-files)
            COMPREPLY=($(compgen -W "$(_pax_pkg_list local 2>/dev/null)" -- "$cur"))
            ;;
        upgrade|u)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "--dry-run --download-only -w --noconfirm --help" -- "$cur"))
            fi
            ;;
    esac
}
complete -F _pax pax
"#;

const ZSH: &str = r#"
#compdef pax

_pax_pkg_list() {
    pax "${pax_global_args[@]}" --pkg-list "$1" 2>/dev/null
}

_pax_downgrade_packages() {
    [[ "$IPREFIX$PREFIX$SUFFIX$ISUFFIX" == *=* || "${words[CURRENT]}" == *=* ]] && return 0
    _pax_installed_packages
}

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
    done < <(_pax_pkg_list sync-desc 2>/dev/null)
    _describe 'package' pkgs
}

_pax_installed_packages() {
    local -a pkgs
    pkgs=(${(f)"$(_pax_pkg_list local 2>/dev/null)"})
    compadd -a pkgs
}

_pax_aur_packages() {
    local -a pkgs
    local cur="${words[CURRENT]}"
    [[ ${#cur} -lt 2 ]] && return
    pkgs=(${(f)"$(_pax_pkg_list "aur:$cur" 2>/dev/null)"})
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
    done < <(_pax_pkg_list all-desc 2>/dev/null)
    _describe 'package' pkgs
}

_pax() {
    local -a pax_global_args
    local i
    for ((i=2; i < CURRENT; i++)); do
        case "${words[i]}" in
            --config|--dbpath|--root)
                pax_global_args+=("${words[i]}" "${words[i+1]}")
                ((i++))
                ;;
            --config=*|--dbpath=*|--root=*)
                pax_global_args+=("${words[i]}")
                ;;
            --completions|--pkg-list)
                ((i++))
                ;;
            -*) ;;
            *) break ;;
        esac
    done

    local -a subcmds
    subcmds=(
        'search:Search sync databases for packages'
        'info:Show detailed package information'
        'query:Query installed packages'
        'files:List files owned by a package'
        'owner:Find which package owns a file'
        'install:Install packages'
        'downgrade:Downgrade installed packages'
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
        'remove-lock:Remove a stale database lock file'
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
                        '-w[Download without installing]' \
                        '--download-only[Download without installing]' \
                        '--noconfirm[Skip confirmation]' \
                        '--needed[Skip up-to-date packages]' \
                        '--reinstall[Reinstall packages]' \
                        '--asdeps[Install as dependencies]' \
                        '*:package:_pax_sync_packages'
                    ;;
                downgrade)
                    _arguments \
                        '--cached-only[Use only cached packages]' \
                        '--ala-only[Use only the Arch Linux Archive]' \
                        '--with-ala[Include the Arch Linux Archive]' \
                        '--prefer-cache[Prefer cached packages]' \
                        '--ala-url=[Arch Linux Archive base URL]:url:_urls' \
                        '*--cache-dir=[Package cache directory]:directory:_directories' \
                        '--list[List available versions]' \
                        '--latest[Select the latest available version]' \
                        '--noconfirm[Skip confirmation]' \
                        '--ignore=[Ignore policy]:policy:(prompt always never)' \
                        '--help[Show help]' \
                        '*:package or package=version:_pax_downgrade_packages'
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
                        '--reinstall[Reinstall already installed packages]' \
                        '--allow-root[Allow running as root]' \
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
                        '-w[Download without installing]' \
                        '--download-only[Download without installing]' \
                        '--noconfirm[Skip confirmation]'
                    ;;
            esac
            ;;
    esac
}

_pax "$@"
"#;

const FISH: &str = r#"
function __pax_pkg_list
    set -l tokens (commandline -opc)
    set -l global_args
    set -l i 2
    while test $i -le (count $tokens)
        switch $tokens[$i]
            case --config --dbpath --root
                set -l option $tokens[$i]
                set i (math $i + 1)
                if test $i -le (count $tokens)
                    set -a global_args $option "$tokens[$i]"
                end
            case '--config=*' '--dbpath=*' '--root=*'
                set -a global_args "$tokens[$i]"
            case --completions --pkg-list
                set i (math $i + 1)
            case '-*'
            case '*'
                break
        end
        set i (math $i + 1)
    end
    pax $global_args --pkg-list "$argv[1]" 2>/dev/null
end

set -l subcmds search s info i query q files f owner o install S downgrade remove R local-install U aur-install aur-search aur-upgrade check check-files sync y upgrade u clean c remove-lock

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
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a downgrade -d "Downgrade installed packages"
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
complete -c pax -n "not __fish_seen_subcommand_from $subcmds" -a remove-lock -d "Remove stale database lock"

complete -c pax -n "__fish_seen_subcommand_from install S" -l dry-run -d "Show what would be installed"
complete -c pax -n "__fish_seen_subcommand_from install S" -l noconfirm -d "Skip confirmation"
complete -c pax -n "__fish_seen_subcommand_from install S" -l needed -d "Skip up-to-date packages"
complete -c pax -n "__fish_seen_subcommand_from install S" -l reinstall -d "Reinstall packages"
complete -c pax -n "__fish_seen_subcommand_from install S" -l asdeps -d "Install as dependencies"
complete -c pax -n "__fish_seen_subcommand_from install S" -s w -l download-only -d "Download without installing"
complete -c pax -n "__fish_seen_subcommand_from install S" -a "(__pax_pkg_list sync-desc 2>/dev/null | string replace \t '\t')" -d ""

function __pax_downgrade_packages
    set -l tokens (commandline -opc)
    if contains -- $tokens[-1] --ala-url --cache-dir --ignore
        return
    end
    if string match -q '*=*' -- (commandline -ct)
        return
    end
    __pax_pkg_list local 2>/dev/null
end

complete -c pax -n "__fish_seen_subcommand_from downgrade" -f
complete -c pax -n "__fish_seen_subcommand_from downgrade" -l cached-only -d "Use only cached packages"
complete -c pax -n "__fish_seen_subcommand_from downgrade" -l ala-only -d "Use only the Arch Linux Archive"
complete -c pax -n "__fish_seen_subcommand_from downgrade" -l with-ala -d "Include the Arch Linux Archive"
complete -c pax -n "__fish_seen_subcommand_from downgrade" -l prefer-cache -d "Prefer cached packages"
complete -c pax -n "__fish_seen_subcommand_from downgrade" -l ala-url -x -d "Arch Linux Archive base URL"
complete -c pax -n "__fish_seen_subcommand_from downgrade" -l cache-dir -x -a "(__fish_complete_directories)" -d "Package cache directory"
complete -c pax -n "__fish_seen_subcommand_from downgrade" -l list -d "List available versions"
complete -c pax -n "__fish_seen_subcommand_from downgrade" -l latest -d "Select the latest available version"
complete -c pax -n "__fish_seen_subcommand_from downgrade" -l noconfirm -d "Skip confirmation"
complete -c pax -n "__fish_seen_subcommand_from downgrade" -l ignore -x -a "prompt always never" -d "Ignore policy"
complete -c pax -n "__fish_seen_subcommand_from downgrade" -l help -d "Show help"
complete -c pax -n "__fish_seen_subcommand_from downgrade" -a "(__pax_downgrade_packages)" -d "Installed package"

complete -c pax -n "__fish_seen_subcommand_from remove R" -l noconfirm -d "Skip confirmation"
complete -c pax -n "__fish_seen_subcommand_from remove R" -s s -l recursive -d "Remove unneeded deps"
complete -c pax -n "__fish_seen_subcommand_from remove R" -a "(__pax_pkg_list local 2>/dev/null)" -d "Installed package"

complete -c pax -n "__fish_seen_subcommand_from info i" -s l -l local -d "Query local database"
complete -c pax -n "__fish_seen_subcommand_from info i" -a "(__pax_pkg_list all-desc 2>/dev/null | string replace \t '\t')" -d ""

complete -c pax -n "__fish_seen_subcommand_from query q" -s e -l explicit -d "Explicitly installed only"
complete -c pax -n "__fish_seen_subcommand_from query q" -s o -l orphans -d "Orphan packages"

complete -c pax -n "__fish_seen_subcommand_from files f" -a "(__pax_pkg_list local 2>/dev/null)" -d "Installed package"

complete -c pax -n "__fish_seen_subcommand_from owner o" -F -d "File path"

complete -c pax -n "__fish_seen_subcommand_from aur-install" -l skip-review -d "Skip PKGBUILD review"
complete -c pax -n "__fish_seen_subcommand_from aur-install" -l noconfirm -d "Skip confirmation"
complete -c pax -n "__fish_seen_subcommand_from aur-install" -l reinstall -d "Reinstall already installed packages"
complete -c pax -n "__fish_seen_subcommand_from aur-install" -l allow-root -d "Allow running as root"
complete -c pax -n "__fish_seen_subcommand_from aur-install" -a "(test (string length -- (commandline -ct)) -ge 2; and __pax_pkg_list 'aur:'(commandline -ct) 2>/dev/null)" -d "AUR package"

complete -c pax -n "__fish_seen_subcommand_from local-install U" -l noconfirm -d "Skip confirmation"
complete -c pax -n "__fish_seen_subcommand_from local-install U" -F -d "Package file"

complete -c pax -n "__fish_seen_subcommand_from aur-upgrade" -l skip-review -d "Skip PKGBUILD review"
complete -c pax -n "__fish_seen_subcommand_from aur-upgrade" -l noconfirm -d "Skip confirmation"
complete -c pax -n "__fish_seen_subcommand_from aur-upgrade" -l allow-root -d "Allow running as root"

complete -c pax -n "__fish_seen_subcommand_from upgrade u" -l dry-run -d "Show what would be upgraded"
complete -c pax -n "__fish_seen_subcommand_from upgrade u" -s w -l download-only -d "Download without installing"
complete -c pax -n "__fish_seen_subcommand_from upgrade u" -l noconfirm -d "Skip confirmation"

complete -c pax -n "__fish_seen_subcommand_from check" -a "(__pax_pkg_list local 2>/dev/null)" -d "Installed package"
complete -c pax -n "__fish_seen_subcommand_from check-files" -a "(__pax_pkg_list local 2>/dev/null)" -d "Installed package"

complete -c pax -n "__fish_seen_subcommand_from clean c" -l all -d "Remove all cached packages"
complete -c pax -n "__fish_seen_subcommand_from clean c" -l noconfirm -d "Skip confirmation"
"#;
