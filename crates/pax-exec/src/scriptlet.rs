use std::path::Path;
use std::process::Command;

use crate::error::{ExecError, Result};

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
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(install_script.as_bytes())?;
            }
            child.wait()
        })
        .map_err(|_| ExecError::Scriptlet {
            pkg: pkg_name.to_string(),
            code: -1,
        })?;

    if !output.success() {
        return Err(ExecError::Scriptlet {
            pkg: pkg_name.to_string(),
            code: output.code().unwrap_or(-1),
        });
    }

    Ok(())
}
