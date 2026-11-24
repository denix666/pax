use std::ffi::CString;

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use crate::error::{ExecError, Result};
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

/// Configure the child only: the parent must retain its original root and cwd.
pub(crate) fn command_in_root(program: &str, root_dir: &Path) -> io::Result<Command> {
    let root = std::fs::canonicalize(root_dir)?;
    let mut command = Command::new(program);
    command.current_dir("/");
    if root != Path::new("/") {
        let root = CString::new(root.as_os_str().as_bytes())?;
        // Only async-signal-safe operations are allowed between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if libc::chroot(root.as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::chdir(c"/".as_ptr()) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    Ok(command)
}

/// File-backed streams cannot deadlock on pipe capacity or on a descendant
/// retaining a pipe after the direct child exits. No execution deadline is imposed.
pub(crate) fn command_output(command: &mut Command, input: Option<&[u8]>) -> io::Result<Output> {
    if let Some(input) = input {
        let mut stdin = tempfile::tempfile()?;
        stdin.write_all(input)?;
        stdin.seek(SeekFrom::Start(0))?;
        command.stdin(Stdio::from(stdin));
    } else {
        command.stdin(Stdio::null());
    }
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    command.stdout(Stdio::from(stdout.try_clone()?));
    command.stderr(Stdio::from(stderr.try_clone()?));
    let status = command.status()?;
    // Read only the bytes present at child exit; a background descendant may
    // still be writing to its inherited file descriptor.
    let stdout_len = stdout.metadata()?.len();
    let stderr_len = stderr.metadata()?.len();
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut output = Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    stdout.take(stdout_len).read_to_end(&mut output.stdout)?;
    stderr.take(stderr_len).read_to_end(&mut output.stderr)?;
    Ok(output)
}

fn scriptlet_output(
    install_script: &str,
    op: ScriptletOp,
    new_version: &str,
    old_version: Option<&str>,
    root_dir: &Path,
) -> io::Result<Output> {
    let root = std::fs::canonicalize(root_dir)?;
    // Source a real file inside the target root, without requiring /dev/stdin.
    // The RAII guard removes it on every return path.
    let mut script = tempfile::Builder::new()
        .prefix(".pax-scriptlet-")
        .tempfile_in(root.join("tmp"))?;
    script.write_all(install_script.as_bytes())?;
    script.flush()?;
    let script_path = Path::new("/tmp").join(script.path().file_name().unwrap());
    let mut command = command_in_root("/bin/bash", &root)?;
    command.args([
        "-c",
        ". \"$1\" || exit $?; shift; if declare -F -- \"$1\" >/dev/null; then \"$@\"; fi",
        "pax-scriptlet",
    ]);
    command
        .arg(script_path)
        .arg(op.function_name())
        .arg(new_version);
    if let Some(old) = old_version {
        command.arg(old);
    }
    command_output(&mut command, None)
}

/// Logs script output and returns failures with package and operation context.
/// The caller decides whether to continue the transaction after a failure.
pub fn run_scriptlet(
    install_script: &str,
    op: ScriptletOp,
    new_version: &str,
    old_version: Option<&str>,
    root_dir: &Path,
    pkg_name: &str,
    logger: &mut PaxLogger,
) -> Result<()> {
    let operation = op.function_name();
    let message = match scriptlet_output(install_script, op, new_version, old_version, root_dir) {
        Ok(out) => {
            for bytes in [&out.stdout, &out.stderr] {
                let text = String::from_utf8_lossy(bytes);
                if !text.is_empty() {
                    eprint!("{text}");
                    logger.log_scriptlet_output(pkg_name, &text);
                }
            }
            if out.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&out.stderr);
            let mut message = format!("scriptlet failed: {}", out.status);
            if !stderr.trim().is_empty() {
                message.push_str(": ");
                message.push_str(stderr.trim());
            }
            message
        }
        Err(error) => format!(
            "could not execute scriptlet in {}: {error}",
            root_dir.display()
        ),
    };
    let error = ExecError::Hook {
        name: format!("{pkg_name}::{operation}"),
        message,
    };
    eprintln!("warning: {error}");
    logger.log_warning(&error.to_string());
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_literal_positional_arguments() {
        let output = scriptlet_output(
            "pre_upgrade() { printf '%s\\n' \"$#\" \"$1\" \"$2\"; pwd; }",
            ScriptletOp::PreUpgrade,
            "1; $(exit 89) ' \"",
            Some("old version *"),
            Path::new("/"),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "2\n1; $(exit 89) ' \"\nold version *\n/\n"
        );
    }

    #[test]
    fn missing_function_is_a_noop() {
        let output = scriptlet_output(
            "# post_install is absent",
            ScriptletOp::PostInstall,
            "1",
            None,
            Path::new("/"),
        )
        .unwrap();
        assert!(output.status.success());
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn successful_scriptlets_and_missing_functions_return_ok() {
        for script in ["post_install() { return 0; }", "# post_install is absent"] {
            run_scriptlet(
                script,
                ScriptletOp::PostInstall,
                "1",
                None,
                Path::new("/"),
                "test-package",
                &mut PaxLogger::none(),
            )
            .unwrap();
        }
    }

    #[test]
    fn failed_scriptlet_returns_context_and_keeps_output() {
        let log = tempfile::NamedTempFile::new().unwrap();
        let error = run_scriptlet(
            "post_upgrade() { printf 'stdout marker\\n'; printf 'original failure\\n' >&2; return 42; }",
            ScriptletOp::PostUpgrade,
            "2",
            Some("1"),
            Path::new("/"),
            "test-package",
            &mut PaxLogger::open(log.path()),
        )
        .unwrap_err();
        match &error {
            ExecError::Hook { name, message } => {
                assert_eq!(name, "test-package::post_upgrade");
                assert!(message.contains("exit status: 42"));
                assert!(message.contains("original failure"));
            }
            other => panic!("unexpected error: {other}"),
        }
        let content = std::fs::read_to_string(log.path()).unwrap();
        assert!(content.contains("[PAX-SCRIPTLET] [test-package] stdout marker"));
        assert!(content.contains("[PAX-SCRIPTLET] [test-package] original failure"));
        assert!(content.contains(&error.to_string()));
    }

    #[test]
    fn source_failure_is_not_masked_by_function_lookup_or_invocation() {
        for script in [
            "return 37",
            "post_install() { printf 'must not run\\n'; return 0; }\nreturn 37",
        ] {
            let log = tempfile::NamedTempFile::new().unwrap();
            let error = run_scriptlet(
                script,
                ScriptletOp::PostInstall,
                "1",
                None,
                Path::new("/"),
                "test-package",
                &mut PaxLogger::open(log.path()),
            )
            .unwrap_err();
            let message = error.to_string();
            assert!(message.contains("test-package::post_install"));
            assert!(message.contains("exit status: 37"));
            let content = std::fs::read_to_string(log.path()).unwrap();
            assert!(!content.contains("must not run"));
        }
    }

    #[test]
    fn source_syntax_error_preserves_shell_diagnostic() {
        let error = run_scriptlet(
            "post_install() {\n",
            ScriptletOp::PostInstall,
            "1",
            None,
            Path::new("/"),
            "test-package",
            &mut PaxLogger::none(),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("test-package::post_install"));
        assert!(message.contains("exit status: 2"));
        assert!(message.contains(".pax-scriptlet-"));
    }

    #[test]
    fn io_failure_preserves_package_operation_root_and_cause() {
        let temp = tempfile::tempdir().unwrap();
        let missing_root = temp.path().join("missing-root");
        let cause = std::fs::canonicalize(&missing_root).unwrap_err();
        let error = run_scriptlet(
            "pre_remove() { return 0; }",
            ScriptletOp::PreRemove,
            "1",
            None,
            &missing_root,
            "test-package",
            &mut PaxLogger::none(),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("test-package::pre_remove"));
        assert!(message.contains(&missing_root.display().to_string()));
        assert!(message.contains(&cause.to_string()));
    }

    #[test]
    fn large_input_and_output_do_not_use_pipes() {
        let input = vec![b'x'; 256 * 1024];
        let mut command = command_in_root("/bin/bash", Path::new("/")).unwrap();
        command.args(["-c", "printf '%131072s' x; printf '%131072s' y >&2; cat"]);
        let output = command_output(&mut command, Some(&input)).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 131072 + input.len());
        assert_eq!(output.stderr.len(), 131072);
        assert!(output.stdout.ends_with(&input));
    }

    #[test]
    fn missing_shell_in_alternate_root_never_falls_back_to_host() {
        let root = tempfile::tempdir().unwrap();
        let mut command = command_in_root("/bin/bash", root.path()).unwrap();
        command.args(["-c", "exit 0"]);
        assert!(command_output(&mut command, None).is_err());
    }
}
