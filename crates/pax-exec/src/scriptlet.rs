use std::path::Path;
use std::process::Command;

use crate::error::Result;
use crate::log::PaxLogger;

pub enum ScriptletOp {
    PreInstall,
    PostInstall,
    PreUpgrade,
    PostUpgrade,
    PreRemove,
    PostRemove,
}

impl ScriptletOp {
    fn function_name(&self) -> &'static str {
        match self {
            Self::PreInstall => "pre_install",
            Self::PostInstall => "post_install",
            Self::PreUpgrade => "pre_upgrade",
            Self::PostUpgrade => "post_upgrade",
            Self::PreRemove => "pre_remove",
            Self::PostRemove => "post_remove",
        }
    }
}

pub fn run_scriptlet(
    install_script: &str,
    op: ScriptletOp,
    new_version: &str,
    old_version: Option<&str>,
    root_dir: &Path,
    pkg_name: &str,
    logger: &mut PaxLogger,
) -> Result<()> {
    let func = op.function_name();

    if !install_script.contains(func) {
        return Ok(());
    }

    let args = match old_version {
        Some(old) => format!("{func} {new_version} {old}"),
        None => format!("{func} {new_version}"),
    };

    let script = format!("source /dev/stdin; {args}");

    let output = Command::new("bash")
        .arg("-c")
        .arg(&script)
        .current_dir(root_dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(install_script.as_bytes())?;
            }
            drop(child.stdin.take());
            child.wait_with_output()
        });

    match output {
        Ok(ref out) => {
            let stdout_str = String::from_utf8_lossy(&out.stdout);
            let stderr_str = String::from_utf8_lossy(&out.stderr);

            if !stdout_str.is_empty() {
                eprint!("{stdout_str}");
                logger.log_scriptlet_output(pkg_name, &stdout_str);
            }
            if !stderr_str.is_empty() {
                eprint!("{stderr_str}");
                logger.log_scriptlet_output(pkg_name, &stderr_str);
            }

            if !out.status.success() {
                let msg = format!(
                    "scriptlet failed for {}: exit code {}",
                    pkg_name,
                    out.status.code().unwrap_or(-1)
                );
                eprintln!("warning: {msg}");
                logger.log_warning(&msg);
            }
        }
        Err(e) => {
            let msg = format!("scriptlet failed for {}: {e}", pkg_name);
            eprintln!("warning: {msg}");
            logger.log_warning(&msg);
        }
    }

    Ok(())
}
