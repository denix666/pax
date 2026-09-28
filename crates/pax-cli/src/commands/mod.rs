pub fn privilege_escalation_tool() -> Option<String> {
    if let Ok(tool) = std::env::var("PAX_SUDO") {
        return Some(tool);
    }
    for candidate in &["sudo", "doas"] {
        if std::process::Command::new("which")
            .arg(candidate)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(candidate.to_string());
        }
    }
    None
}

pub fn ensure_root() {
    if (unsafe { libc::geteuid() }) == 0 {
        return;
    }
    let Some(tool) = privilege_escalation_tool() else {
        eprintln!("error: this operation requires root privileges");
        eprintln!("  install sudo or doas, or set PAX_SUDO to your privilege escalation tool");
        std::process::exit(1);
    };
    let args: Vec<String> = std::env::args().collect();
    let status = std::process::Command::new(&tool)
        .args(&args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status();
    std::process::exit(match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(_) => 1,
    });
}

pub mod aur;
pub mod aur_search;
pub mod aur_upgrade;
pub mod clean;
pub mod files;
pub mod info;
pub mod install;
pub mod localinstall;
pub mod owner;
pub mod query;
pub mod remove;
pub mod search;
pub mod sync;
pub mod upgrade;
