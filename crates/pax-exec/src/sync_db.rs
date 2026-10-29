use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::verify;
use pax_core::config::{SigLevel, SigTrust};
use std::time::{Duration, Instant};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use tempfile::NamedTempFile;

use crate::error::{ExecError, Result};

const MIRROR_TIMEOUT: Duration = Duration::from_secs(60);
const REPOSITORY_TIMEOUT: Duration = Duration::from_secs(120);

pub struct SyncTarget {
    pub repo_name: String,
    pub mirrors: Vec<String>,
    pub sig_level: SigLevel,
    pub sig_trust: SigTrust,
    pub gpg_dir: PathBuf,
}

pub fn sync_databases(
    targets: &[SyncTarget],
    sync_dir: &Path,
    parallel: u32,
    multi_progress: &MultiProgress,
) -> Result<()> {
    sync_databases_with_agent(
        targets,
        sync_dir,
        parallel,
        multi_progress,
        &crate::http_agent(),
        REPOSITORY_TIMEOUT,
    )
}

fn sync_databases_with_agent(
    targets: &[SyncTarget],
    sync_dir: &Path,
    parallel: u32,
    multi_progress: &MultiProgress,
    agent: &ureq::Agent,
    repository_timeout: Duration,
) -> Result<()> {
    std::fs::create_dir_all(sync_dir)?;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(parallel.max(1) as usize)
        .build()
        .map_err(|e| ExecError::Download {
            pkg: String::new(),
            message: e.to_string(),
        })?;

    let results: Vec<std::result::Result<(), String>> = pool.install(|| {
        targets
            .par_iter()
            .map(|target| sync_one(target, sync_dir, multi_progress, agent, repository_timeout))
            .collect()
    });

    let failures: Vec<String> = results
        .into_iter()
        .filter_map(|result| result.err())
        .collect();
    if !failures.is_empty() {
        return Err(ExecError::RepositorySync { failures });
    }

    Ok(())
}

fn sync_one(
    target: &SyncTarget,
    sync_dir: &Path,
    multi_progress: &MultiProgress,
    agent: &ureq::Agent,
    repository_timeout: Duration,
) -> std::result::Result<(), String> {
    let started = Instant::now();
    let style = ProgressStyle::with_template(
        " {spinner:.green} {msg:<20} [{bar:25.cyan/dim}] {bytes}/{total_bytes} {bytes_per_sec}",
    )
    .unwrap()
    .progress_chars("=> ");

    let pb = multi_progress.add(ProgressBar::new(0));
    pb.set_style(style);
    pb.set_message(format!("{}.db", target.repo_name));

    let filename = format!("{}.db", target.repo_name);
    let mut last_error = "no mirrors configured".to_string();

    for mirror_url in &target.mirrors {
        let remaining = repository_timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            last_error = format!(
                "repository timeout after {}s; last error: {last_error}",
                repository_timeout.as_secs()
            );
            break;
        }
        let url = format!("{}/{filename}", mirror_url.trim_end_matches('/'));
        pb.set_position(0);
        pb.set_length(0);
        match try_download_db(
            &url,
            sync_dir,
            &filename,
            &pb,
            agent,
            remaining.min(MIRROR_TIMEOUT),
            target,
        ) {
            Ok(()) => {
                pb.finish_with_message(format!("{} ok", target.repo_name));
                return Ok(());
            }
            Err(e @ ExecError::SignatureFailure { .. }) => {
                pb.finish_with_message(format!("{} SIG FAIL", target.repo_name));
                return Err(format!(
                    "repository '{}' unavailable: {url}: {e}",
                    target.repo_name
                ));
            }
            Err(e) => {
                last_error = format!("{url}: {e}");
                let _ = multi_progress.println(format!(
                    "warning: repository '{}': {last_error}; trying next mirror if available",
                    target.repo_name
                ));
            }
        }
    }

    pb.finish_with_message(format!("{} FAILED", target.repo_name));
    Err(format!(
        "repository '{}' unavailable: {last_error}",
        target.repo_name
    ))
}

fn try_download_db(
    url: &str,
    sync_dir: &Path,
    filename: &str,
    pb: &ProgressBar,
    agent: &ureq::Agent,
    timeout: Duration,
    target: &SyncTarget,
) -> Result<()> {
    let started = Instant::now();
    let response = agent
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .map_err(|e| ExecError::Download {
            pkg: filename.to_string(),
            message: e.to_string(),
        })?;

    if let Some(len) = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        pb.set_length(len);
    }

    let mut tmp = NamedTempFile::new_in(sync_dir)?;
    let mut buf = [0u8; 65536];
    let mut body = response.into_body().into_reader();

    loop {
        let n = body.read(&mut buf).map_err(|e| ExecError::Download {
            pkg: filename.to_string(),
            message: e.to_string(),
        })?;
        if n == 0 {
            break;
        }
        tmp.write_all(&buf[..n])?;
        pb.inc(n as u64);
    }

    tmp.flush()?;

    let mut signature = None;
    if target.sig_level != SigLevel::Never {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(ExecError::Download {
                pkg: filename.to_string(),
                message: "signature download timeout".into(),
            });
        }
        if let Some(body) = verify::fetch_signature(agent, &format!("{url}.sig"), remaining)? {
            let mut file = NamedTempFile::new_in(sync_dir)?;
            file.write_all(&body)?;
            file.flush()?;
            signature = Some(file);
        }
    }
    verify::verify_signature(
        tmp.path(),
        signature.as_ref().map(|file| file.path()),
        &target.gpg_dir,
        target.sig_level,
        target.sig_trust,
    )?;

    let dest = sync_dir.join(filename);
    tmp.persist(&dest).map_err(|e| ExecError::Download {
        pkg: filename.to_string(),
        message: format!("failed to persist: {e}"),
    })?;

    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o644))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    struct TestServer {
        url: String,
        stop: mpsc::Sender<()>,
        thread: Option<thread::JoinHandle<()>>,
    }

    impl TestServer {
        fn new(response: &'static [u8], stall: bool) -> Self {
            Self::responses(vec![response], stall)
        }

        fn responses(responses: Vec<&'static [u8]>, stall: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            listener.set_nonblocking(true).unwrap();
            let (stop, stopped) = mpsc::channel();
            let thread = thread::spawn(move || {
                let mut responses = responses.into_iter();
                loop {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(2)))
                                .unwrap();
                            let mut request = [0; 4096];
                            stream.read(&mut request).unwrap();
                            let response = responses.next().unwrap();
                            stream.write_all(response).unwrap();
                            if stall && responses.len() == 0 {
                                let _ = stopped.recv_timeout(Duration::from_secs(5));
                            }
                            if responses.len() == 0 {
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if stopped.recv_timeout(Duration::from_millis(10)).is_ok() {
                                break;
                            }
                        }
                        Err(e) => panic!("test server accept failed: {e}"),
                    }
                }
            });
            Self {
                url,
                stop,
                thread: Some(thread),
            }
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            let _ = self.stop.send(());
            self.thread.take().unwrap().join().unwrap();
        }
    }

    fn agent() -> ureq::Agent {
        // Local fixtures must not use HTTP proxy settings from the environment.
        ureq::Agent::config_builder()
            .proxy(None)
            .build()
            .new_agent()
    }

    fn target(name: &str, mirrors: Vec<String>) -> SyncTarget {
        SyncTarget {
            repo_name: name.to_string(),
            mirrors,
            sig_level: SigLevel::Never,
            sig_trust: SigTrust::TrustedOnly,
            gpg_dir: PathBuf::new(),
        }
    }

    #[test]
    fn signature_policy_checks_temporary_database_before_replacement() {
        for (level, signature_response, succeeds) in [
            (
                SigLevel::Optional,
                &b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"[..],
                true,
            ),
            (
                SigLevel::Required,
                &b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"[..],
                false,
            ),
            (
                SigLevel::Optional,
                &b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ninvalid"[..],
                false,
            ),
            (
                SigLevel::Required,
                &b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ninvalid"[..],
                false,
            ),
            (
                SigLevel::Optional,
                &b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"[..],
                false,
            ),
        ] {
            let server = TestServer::responses(
                vec![
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ndatabase",
                    signature_response,
                ],
                false,
            );
            let dir = tempfile::tempdir().unwrap();
            let gpg = tempfile::tempdir().unwrap();
            let dest = dir.path().join("core.db");
            std::fs::write(&dest, b"old database").unwrap();
            let mut target = target("core", vec![server.url.clone()]);
            target.sig_level = level;
            target.gpg_dir = gpg.path().to_path_buf();
            let result = sync_databases_with_agent(
                &[target],
                dir.path(),
                1,
                &MultiProgress::new(),
                &agent(),
                Duration::from_secs(2),
            );
            assert_eq!(result.is_ok(), succeeds, "{result:?}");
            assert_eq!(
                std::fs::read(&dest).unwrap(),
                if succeeds {
                    &b"database"[..]
                } else {
                    &b"old database"[..]
                }
            );
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn signature_timeout_preserves_database_and_repository_budget() {
        let server = TestServer::responses(
            vec![b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ndatabase", b""],
            true,
        );
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("core.db");
        std::fs::write(&dest, b"old database").unwrap();
        let mut target = target("core", vec![server.url.clone()]);
        target.sig_level = SigLevel::Required;
        let started = Instant::now();
        let result = sync_databases_with_agent(
            &[target],
            dir.path(),
            1,
            &MultiProgress::new(),
            &agent(),
            Duration::from_millis(200),
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(std::fs::read(&dest).unwrap(), b"old database");
    }

    #[test]
    fn stalled_headers_and_body_timeout_preserving_database() {
        for response in [
            &b""[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial"[..],
        ] {
            let server = TestServer::new(response, true);
            let dir = tempfile::tempdir().unwrap();
            let dest = dir.path().join("core.db");
            std::fs::write(&dest, b"old database").unwrap();
            let started = Instant::now();
            let result = sync_databases_with_agent(
                &[target("core", vec![server.url.clone()])],
                dir.path(),
                1,
                &MultiProgress::new(),
                &agent(),
                Duration::from_millis(200),
            );
            let error = result.unwrap_err().to_string();
            assert!(error.contains("repository 'core' unavailable"), "{error}");
            assert!(error.to_lowercase().contains("timeout"), "{error}");
            assert!(started.elapsed() < Duration::from_secs(2));
            assert_eq!(std::fs::read(&dest).unwrap(), b"old database");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }

    #[test]
    fn failed_mirror_falls_back_to_working_mirror() {
        let failed = TestServer::new(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
            false,
        );
        let working = TestServer::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ndatabase",
            false,
        );
        let dir = tempfile::tempdir().unwrap();
        sync_databases_with_agent(
            &[target(
                "core",
                vec![failed.url.clone(), working.url.clone()],
            )],
            dir.path(),
            1,
            &MultiProgress::new(),
            &agent(),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("core.db")).unwrap(),
            b"database"
        );
    }

    #[test]
    fn stalled_mirror_falls_back_after_response_timeout() {
        let stalled = TestServer::new(b"", true);
        let working = TestServer::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ndatabase",
            false,
        );
        let dir = tempfile::tempdir().unwrap();
        let agent = ureq::Agent::config_builder()
            .proxy(None)
            .timeout_recv_response(Some(Duration::from_millis(100)))
            .build()
            .new_agent();
        sync_databases_with_agent(
            &[target(
                "core",
                vec![stalled.url.clone(), working.url.clone()],
            )],
            dir.path(),
            1,
            &MultiProgress::new(),
            &agent,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("core.db")).unwrap(),
            b"database"
        );
    }

    #[test]
    fn partial_failure_returns_error_and_updates_other_repository() {
        let stalled = TestServer::new(b"", true);
        let working = TestServer::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ndatabase",
            false,
        );
        let dir = tempfile::tempdir().unwrap();
        let error = sync_databases_with_agent(
            &[
                target("unavailable", vec![stalled.url.clone()]),
                target("working", vec![working.url.clone()]),
            ],
            dir.path(),
            2,
            &MultiProgress::new(),
            &agent(),
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("repository 'unavailable' unavailable")
        );
        assert_eq!(
            std::fs::read(dir.path().join("working.db")).unwrap(),
            b"database"
        );
        assert!(!dir.path().join("unavailable.db").exists());
    }

    #[test]
    fn repository_budget_stops_mirror_iteration() {
        let stalled = TestServer::new(b"", true);
        let working = TestServer::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\ndatabase",
            false,
        );
        let dir = tempfile::tempdir().unwrap();
        let error = sync_databases_with_agent(
            &[target(
                "core",
                vec![stalled.url.clone(), working.url.clone()],
            )],
            dir.path(),
            1,
            &MultiProgress::new(),
            &agent(),
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert!(error.to_string().contains("repository timeout"), "{error}");
        assert!(!dir.path().join("core.db").exists());
    }

    #[test]
    fn missing_mirrors_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let error = sync_databases(
            &[target("core", vec![])],
            dir.path(),
            1,
            &MultiProgress::new(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("repository 'core' unavailable: no mirrors configured")
        );
    }

    #[test]
    fn no_repositories_is_successful() {
        let dir = tempfile::tempdir().unwrap();
        sync_databases(&[], dir.path(), 1, &MultiProgress::new()).unwrap();
    }
}
