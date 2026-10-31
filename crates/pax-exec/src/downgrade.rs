//! Candidate discovery only; callers select, download, and verify packages.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pax_core::version::Version;
use rayon::prelude::*;

use crate::error::{ExecError, Result};
use crate::extract::read_pkginfo;

const INDEX_LIMIT: u64 = 8 * 1024 * 1024;
const INDEX_TIMEOUT: Duration = Duration::from_secs(30);
const METADATA_LIMIT: u64 = 4 * 1024 * 1024;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(60);
const PACKAGE_SUFFIXES: [&str; 4] = [".pkg.tar.zst", ".pkg.tar.xz", ".pkg.tar.gz", ".pkg.tar"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DowngradeCandidate {
    pub name: String,
    pub version: Version,
    pub arch: String,
    pub local_paths: Vec<PathBuf>,
    pub remote_url: Option<String>,
}

#[derive(Debug)]
pub struct CacheDiagnostic {
    pub path: PathBuf,
    pub message: String,
}

/// A bad archive or unreadable cache entry does not hide other candidates.
#[derive(Debug, Default)]
pub struct CachedVersions {
    pub candidates: Vec<DowngradeCandidate>,
    pub diagnostics: Vec<CacheDiagnostic>,
}

/// Inspect cache roots and their immediate subdirectories, without following symlinks.
/// Missing cache roots are normal. Other I/O and metadata failures are diagnostics.
/// Versions (including epochs) always come from .PKGINFO, never cache filenames.
/// The `pax-ala` child directory is excluded to preserve its archive provenance.
/// Callers may scan that directory explicitly under their archive signature policy.
pub fn cached_versions(name: &str, cache_dirs: &[PathBuf], arch: &str) -> Result<CachedVersions> {
    validate_request(name, arch)?;
    let mut report = CachedVersions::default();
    let prefix = format!("{name}-");
    for directory in cache_dirs {
        scan_cache(directory, &prefix, name, arch, true, &mut report);
    }
    report.candidates = merge_candidates(report.candidates, Vec::new());
    Ok(report)
}

fn scan_cache(
    directory: &Path,
    prefix: &str,
    name: &str,
    arch: &str,
    descend: bool,
    report: &mut CachedVersions,
) {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            diagnostic(report, directory.to_path_buf(), error);
            return;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                diagnostic(report, directory.to_path_buf(), error);
                continue;
            }
        };
        let path = entry.path();
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(error) => {
                diagnostic(report, path, error);
                continue;
            }
        };
        if kind.is_dir() && descend {
            if entry.file_name() == "pax-ala" {
                continue;
            }
            scan_cache(&path, prefix, name, arch, false, report);
            continue;
        }
        let filename = entry.file_name();
        let Some(filename) = filename.to_str() else {
            continue;
        };
        if !kind.is_file() || !filename.starts_with(prefix) || package_stem(filename).is_none() {
            continue;
        }
        match read_pkginfo(&path) {
            Ok(metadata)
                if metadata.info.name == name && compatible_arch(&metadata.info.arch, arch) =>
            {
                report.candidates.push(DowngradeCandidate {
                    name: metadata.info.name,
                    version: metadata.info.version,
                    arch: metadata.info.arch,
                    local_paths: vec![path],
                    remote_url: None,
                });
            }
            Ok(_) => {}
            Err(error) => diagnostic(report, path, error),
        }
    }
}

fn diagnostic(report: &mut CachedVersions, path: PathBuf, error: impl std::fmt::Display) {
    report.diagnostics.push(CacheDiagnostic {
        path,
        message: error.to_string(),
    });
}

/// Read an Arch Linux Archive index under `{base_url}/{first_letter}/{name}/`.
/// `base_url` is normally `https://archive.archlinux.org/packages`; HTTP is
/// accepted for custom archives and loopback tests. Redirects are disabled.
///
/// Archive filenames normally omit epochs. Such versions have epoch zero;
/// callers must hydrate candidates with `archive_package_version` before version
/// filtering or ranking, then verify downloaded packages before installing.
/// An explicit filename epoch is preserved; omitted epochs require metadata.
pub fn archive_versions(name: &str, arch: &str, base_url: &str) -> Result<Vec<DowngradeCandidate>> {
    archive_versions_inner(name, arch, base_url)
        .map_err(|error| discovery_error(name, format!("archive {base_url}: {error}")))
}

fn archive_versions_inner(
    name: &str,
    arch: &str,
    base_url: &str,
) -> Result<Vec<DowngradeCandidate>> {
    validate_request(name, arch)?;
    let index_url = archive_index_url(name, base_url)?;
    let mut response = crate::http_agent()
        .get(&index_url)
        .config()
        .max_redirects(0)
        .timeout_global(Some(INDEX_TIMEOUT))
        .timeout_recv_body(Some(Duration::from_secs(15)))
        .build()
        .call()
        .map_err(|error| discovery_error(name, error))?;
    if response.status() != 200 {
        return Err(discovery_error(
            name,
            format!("archive index returned {}", response.status()),
        ));
    }
    if response
        .headers()
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > INDEX_LIMIT)
    {
        return Err(discovery_error(name, "archive index exceeds 8 MiB"));
    }
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(INDEX_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| discovery_error(name, error))?;
    if bytes.len() as u64 > INDEX_LIMIT {
        return Err(discovery_error(name, "archive index exceeds 8 MiB"));
    }
    let html = String::from_utf8(bytes).map_err(|error| discovery_error(name, error))?;
    Ok(parse_archive_index(name, arch, &index_url, &html))
}

/// Decode the final package path segment for local storage. The original URL
/// must still be used for HTTP requests (including its encoded path).
/// This helper rejects credentials, queries, fragments, and unsafe path segments.
pub fn archive_filename(url: &str) -> Result<String> {
    let parse = || -> std::result::Result<String, String> {
        let uri: ureq::http::Uri = url.parse().map_err(|error| format!("{error}"))?;
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri.host().is_none_or(str::is_empty)
            || uri
                .authority()
                .is_some_and(|authority| authority.as_str().contains('@'))
            || uri.query().is_some()
            || url.contains(['#', '\\'])
            || url.chars().any(char::is_control)
        {
            return Err(
                "expected an HTTP(S) package URL without credentials, query, or fragment".into(),
            );
        }
        let mut filename = None;
        for segment in uri.path().split('/') {
            let decoded = percent_decode(segment).ok_or("invalid percent encoding")?;
            if matches!(decoded.as_str(), "." | "..")
                || decoded.contains(['/', '\\', '%', '?', '#'])
                || decoded.chars().any(char::is_control)
            {
                return Err("unsafe archive path segment".into());
            }
            filename = Some(decoded);
        }
        let filename = filename.ok_or("missing package filename")?;
        let stem = package_stem(&filename).ok_or("unsupported package suffix")?;
        let (identity, arch) = stem
            .rsplit_once('-')
            .ok_or("missing package architecture")?;
        let (identity, _) = identity.rsplit_once('-').ok_or("missing package release")?;
        let (name, _) = identity.rsplit_once('-').ok_or("missing package version")?;
        validate_request(name, arch).map_err(|error| error.to_string())?;
        if filename_candidate(name, arch, &filename).is_none() {
            return Err("invalid archive filename".into());
        }
        Ok(filename)
    };
    parse().map_err(|error| discovery_error(url, format!("archive {url}: {error}")))
}

/// Read only the initial archive stream through .PKGINFO, returning its actual
/// version including epoch. At most 4 MiB each of compressed and decoded data
/// may be consumed, with a total 30-second deadline and redirects disabled.
/// This is discovery metadata, not a replacement for package signature checks.
pub fn archive_package_version(candidate: &DowngradeCandidate) -> Result<Version> {
    archive_package_version_with_timeout(candidate, INDEX_TIMEOUT)
}

/// Hydrate every supplied archive candidate before filtering or ranking versions.
/// Callers should narrow exact pkgver requests before calling this function.
/// Uses at most four workers and a shared 60-second deadline, including queue
/// time. Any failure returns an error; incomplete results are never returned.
/// Successful results are merged and sorted using authoritative metadata versions.
pub fn resolve_archive_versions(
    candidates: Vec<DowngradeCandidate>,
) -> Result<Vec<DowngradeCandidate>> {
    resolve_archive_versions_with(
        candidates,
        RESOLVE_TIMEOUT,
        archive_package_version_with_timeout,
    )
}

fn resolve_archive_versions_with(
    candidates: Vec<DowngradeCandidate>,
    timeout: Duration,
    inspect: impl Fn(&DowngradeCandidate, Duration) -> Result<Version> + Sync,
) -> Result<Vec<DowngradeCandidate>> {
    let deadline = Instant::now() + timeout;
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(candidates.len().min(4))
        .build()
        .map_err(|error| discovery_error("archive metadata", error))?;
    let resolved: Result<Vec<_>> = pool.install(|| {
        candidates
            .into_par_iter()
            .map(|mut candidate| {
                let expired = || {
                    discovery_error(
                        &candidate.name,
                        format!(
                            "archive {}: total metadata discovery deadline exceeded",
                            candidate
                                .remote_url
                                .as_deref()
                                .unwrap_or("<missing remote URL>")
                        ),
                    )
                };
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(expired());
                }
                let version = inspect(&candidate, remaining.min(INDEX_TIMEOUT))?;
                if Instant::now() >= deadline {
                    return Err(expired());
                }
                candidate.version = version;
                Ok(candidate)
            })
            .collect()
    });
    let merged = merge_candidates(Vec::new(), resolved?);
    if Instant::now() >= deadline {
        return Err(discovery_error(
            "archive metadata",
            "total metadata discovery deadline exceeded",
        ));
    }
    Ok(merged)
}

fn archive_package_version_with_timeout(
    candidate: &DowngradeCandidate,
    timeout: Duration,
) -> Result<Version> {
    let deadline = Instant::now() + timeout.min(INDEX_TIMEOUT);
    let context = candidate
        .remote_url
        .as_deref()
        .unwrap_or("<missing remote URL>");
    let inspect = || -> Result<Version> {
        validate_request(&candidate.name, &candidate.arch)?;
        let url = candidate
            .remote_url
            .as_deref()
            .ok_or_else(|| discovery_error(&candidate.name, "candidate has no remote URL"))?;
        let filename = archive_filename(url)?;
        let identity = filename_candidate(&candidate.name, &candidate.arch, &filename)
            .ok_or_else(|| discovery_error(&candidate.name, "filename does not match candidate"))?;
        if identity.arch != candidate.arch
            || identity.version.pkgver != candidate.version.pkgver
            || identity.version.pkgrel != candidate.version.pkgrel
            || (filename_has_epoch(&filename) && identity.version.epoch != candidate.version.epoch)
        {
            return Err(discovery_error(
                &candidate.name,
                "filename does not match candidate version or architecture",
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(discovery_error(
                &candidate.name,
                "archive metadata deadline exceeded",
            ));
        }
        let mut response = crate::http_agent()
            .get(url)
            .config()
            .max_redirects(0)
            .timeout_global(Some(remaining))
            .timeout_recv_body(Some(remaining.min(Duration::from_secs(15))))
            .build()
            .call()
            .map_err(|error| discovery_error(&candidate.name, error))?;
        if response.status() != 200 {
            return Err(discovery_error(
                &candidate.name,
                format!("package returned {}", response.status()),
            ));
        }
        // A large Content-Length is normal: stop as soon as metadata is read.
        let compressed =
            MetadataReader::new(response.body_mut().as_reader(), deadline, "compressed");
        let decoded: Box<dyn Read + '_> = if filename.ends_with(".zst") {
            let mut decoder = zstd::Decoder::new(compressed)
                .map_err(|error| discovery_error(&candidate.name, error))?;
            // Arch packages commonly use zstd --long (128 MiB window).
            // Keep a finite decoder limit while accepting that package format.
            decoder
                .window_log_max(27)
                .map_err(|error| discovery_error(&candidate.name, error))?;
            Box::new(decoder)
        } else if filename.ends_with(".xz") {
            let stream = xz2::stream::Stream::new_stream_decoder(64 * 1024 * 1024, 0)
                .map_err(|error| discovery_error(&candidate.name, error))?;
            Box::new(xz2::read::XzDecoder::new_stream(compressed, stream))
        } else if filename.ends_with(".gz") {
            Box::new(flate2::read::GzDecoder::new(compressed))
        } else {
            Box::new(compressed)
        };
        let decoded = MetadataReader::new(decoded, deadline, "decoded");
        read_remote_pkginfo(candidate, &filename, decoded)
    };
    inspect()
        .map_err(|error| discovery_error(&candidate.name, format!("archive {context}: {error}")))
}

fn filename_has_epoch(filename: &str) -> bool {
    filename.contains(':')
}

struct MetadataReader<R> {
    inner: R,
    remaining: u64,
    deadline: Instant,
    stage: &'static str,
}

impl<R> MetadataReader<R> {
    fn new(inner: R, deadline: Instant, stage: &'static str) -> Self {
        Self {
            inner,
            remaining: METADATA_LIMIT,
            deadline,
            stage,
        }
    }
}

impl<R: Read> Read for MetadataReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "archive metadata deadline exceeded",
            ));
        }
        if self.remaining == 0 {
            return Err(std::io::Error::other(format!(
                "archive metadata {} limit exceeded (4 MiB)",
                self.stage
            )));
        }
        let length = buffer.len().min(self.remaining as usize);
        let count = self.inner.read(&mut buffer[..length])?;
        self.remaining -= count as u64;
        if Instant::now() >= self.deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "archive metadata deadline exceeded",
            ));
        }
        Ok(count)
    }
}

fn read_remote_pkginfo(
    candidate: &DowngradeCandidate,
    filename: &str,
    reader: impl Read,
) -> Result<Version> {
    let invalid = |message: String| discovery_error(&candidate.name, message);
    let mut archive = tar::Archive::new(reader);
    let entries = archive
        .entries()
        .map_err(|error| invalid(error.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|error| invalid(error.to_string()))?;
        let path = entry.path().map_err(|error| invalid(error.to_string()))?;
        if path.as_ref() != Path::new(".PKGINFO") && path.as_ref() != Path::new("./.PKGINFO") {
            continue;
        }
        if !entry.header().entry_type().is_file() || entry.size() > METADATA_LIMIT {
            return Err(invalid("invalid or oversized .PKGINFO".into()));
        }
        let mut metadata = String::new();
        entry
            .read_to_string(&mut metadata)
            .map_err(|error| invalid(error.to_string()))?;
        let field = |key: &str| -> Result<&str> {
            let mut values = metadata.lines().filter_map(|line| {
                let (name, value) = line.split_once('=')?;
                (name.trim() == key).then_some(value.trim())
            });
            let value = values
                .next()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid(format!("missing {key} in .PKGINFO")))?;
            if values.next().is_some() {
                return Err(invalid(format!("duplicate {key} in .PKGINFO")));
            }
            Ok(value)
        };
        if field("pkgname")? != candidate.name || field("arch")? != candidate.arch {
            return Err(invalid(
                ".PKGINFO name or architecture differs from archive candidate".into(),
            ));
        }
        let value = field("pkgver")?;
        let version = Version::parse(value).map_err(|error| invalid(error.to_string()))?;
        let expected = filename_candidate(&candidate.name, &candidate.arch, filename)
            .ok_or_else(|| invalid("invalid package filename".into()))?;
        if version.pkgver != expected.version.pkgver
            || version.pkgrel != expected.version.pkgrel
            || (filename_has_epoch(filename) && version.epoch != expected.version.epoch)
        {
            return Err(invalid(format!(
                ".PKGINFO version {value} differs from filename {filename}"
            )));
        }
        return Ok(version);
    }
    Err(invalid(
        "missing .PKGINFO within archive metadata limits".into(),
    ))
}

fn discovery_error(name: &str, message: impl std::fmt::Display) -> ExecError {
    ExecError::Download {
        pkg: name.to_owned(),
        message: message.to_string(),
    }
}

fn validate_request(name: &str, arch: &str) -> Result<()> {
    let valid_name = !name.is_empty()
        && !matches!(name.as_bytes()[0], b'.' | b'-')
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@._+-".contains(&byte));
    let valid_arch = !arch.is_empty()
        && arch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if !valid_name || !valid_arch {
        return Err(discovery_error(
            name,
            "invalid package name or architecture",
        ));
    }
    Ok(())
}

fn archive_index_url(name: &str, base_url: &str) -> Result<String> {
    let uri: ureq::http::Uri = base_url
        .parse()
        .map_err(|error| discovery_error(name, error))?;
    if !matches!(uri.scheme_str(), Some("http" | "https"))
        || uri.authority().is_none()
        || uri.host().is_none_or(str::is_empty)
        || uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        || uri.query().is_some()
        || base_url.contains('#')
        || base_url.contains('\\')
        || base_url.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(discovery_error(
            name,
            "archive base URL must be an HTTP(S) URL without credentials, query, or fragment",
        ));
    }
    // Decode once to reject traversal and ambiguous encoded path separators.
    let path = percent_decode(uri.path())
        .ok_or_else(|| discovery_error(name, "invalid archive base path"))?;
    if path.split('/').any(|part| matches!(part, "." | ".."))
        || path.contains(['\\', '%', '?', '#'])
        || path.chars().any(char::is_control)
    {
        return Err(discovery_error(name, "unsafe archive base path"));
    }
    Ok(format!(
        "{}/{}/{}/",
        base_url.trim_end_matches('/'),
        &name[..1],
        encode_segment(name)
    ))
}

fn compatible_arch(candidate: &str, requested: &str) -> bool {
    candidate == requested || candidate == "any"
}

fn package_stem(filename: &str) -> Option<&str> {
    PACKAGE_SUFFIXES
        .iter()
        .find_map(|suffix| filename.strip_suffix(suffix))
}

fn filename_candidate(name: &str, arch: &str, filename: &str) -> Option<DowngradeCandidate> {
    let stem = package_stem(filename)?;
    let (identity, candidate_arch) = stem.rsplit_once('-')?;
    if !compatible_arch(candidate_arch, arch) {
        return None;
    }
    let version = identity.strip_prefix(name)?.strip_prefix('-')?;
    let (pkgver, pkgrel) = version.rsplit_once('-')?;
    if pkgver.is_empty()
        || pkgrel.is_empty()
        || !pkgver
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+:~".contains(&byte))
        || !pkgrel
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
    {
        return None;
    }
    Some(DowngradeCandidate {
        name: name.to_owned(),
        version: Version::parse(version).ok()?,
        arch: candidate_arch.to_owned(),
        local_paths: Vec::new(),
        remote_url: None,
    })
}

fn parse_archive_index(
    name: &str,
    arch: &str,
    index_url: &str,
    html: &str,
) -> Vec<DowngradeCandidate> {
    let index_path = index_url
        .parse::<ureq::http::Uri>()
        .expect("validated index URL")
        .path()
        .to_owned();
    let mut candidates = Vec::new();
    for href in anchor_hrefs(html) {
        let Some(href) = decode_entities(href) else {
            continue;
        };
        // Accept basenames, ./basenames, and links to this exact directory.
        // Never resolve arbitrary URLs or dot segments from untrusted HTML.
        let filename = href
            .strip_prefix(index_url)
            .or_else(|| href.strip_prefix(&index_path))
            .or_else(|| href.strip_prefix("./"))
            .unwrap_or(&href);
        let Some(filename) = percent_decode(filename) else {
            continue;
        };
        if filename.contains(['/', '\\', '?', '#', '%']) || filename.chars().any(char::is_control) {
            continue;
        }
        let Some(mut candidate) = filename_candidate(name, arch, &filename) else {
            continue;
        };
        candidate.remote_url = Some(format!("{index_url}{}", encode_segment(&filename)));
        candidates.push(candidate);
    }
    merge_candidates(Vec::new(), candidates)
}

/// Combine sources by exact package name, Version, and architecture. Local
/// paths take priority for callers; the remote URL remains available as fallback.
/// Sorting uses libalpm version ordering, newest first, with deterministic ties.
pub fn merge_candidates(
    local: Vec<DowngradeCandidate>,
    remote: Vec<DowngradeCandidate>,
) -> Vec<DowngradeCandidate> {
    let mut candidates = local;
    candidates.extend(remote);
    candidates.sort_by(|left, right| {
        right
            .version
            .cmp(&left.version)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.arch.cmp(&right.arch))
            .then_with(|| left.version.to_string().cmp(&right.version.to_string()))
            .then_with(|| {
                left.local_paths
                    .is_empty()
                    .cmp(&right.local_paths.is_empty())
            })
            .then_with(|| left.remote_url.cmp(&right.remote_url))
    });
    let mut merged: Vec<DowngradeCandidate> = Vec::new();
    for mut candidate in candidates {
        if let Some(previous) = merged.last_mut().filter(|previous| {
            previous.name == candidate.name
                && previous.version == candidate.version
                && previous.arch == candidate.arch
        }) {
            previous.local_paths.append(&mut candidate.local_paths);
            if previous.remote_url.is_none() {
                previous.remote_url = candidate.remote_url;
            }
        } else {
            merged.push(candidate);
        }
    }
    for candidate in &mut merged {
        candidate.local_paths.sort();
        candidate.local_paths.dedup();
    }
    merged
}

fn percent_decode(value: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = (bytes.next()? as char).to_digit(16)?;
            let low = (bytes.next()? as char).to_digit(16)?;
            decoded.push((high * 16 + low) as u8);
        } else {
            decoded.push(byte);
        }
    }
    String::from_utf8(decoded).ok()
}

fn encode_segment(value: &str) -> String {
    use std::fmt::Write;
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            encoded.push(byte as char);
        } else {
            write!(encoded, "%{byte:02X}").expect("writing to String");
        }
    }
    encoded
}

fn decode_entities(value: &str) -> Option<String> {
    let mut result = String::new();
    let mut rest = value;
    while let Some(start) = rest.find('&') {
        result.push_str(&rest[..start]);
        let end = rest[start..].find(';')? + start;
        let entity = &rest[start + 1..end];
        let character = match entity {
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            "lt" => '<',
            "gt" => '>',
            _ => {
                let number = if let Some(hex) = entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                {
                    u32::from_str_radix(hex, 16).ok()?
                } else {
                    entity.strip_prefix('#')?.parse().ok()?
                };
                char::from_u32(number)?
            }
        };
        result.push(character);
        rest = &rest[end + 1..];
    }
    result.push_str(rest);
    Some(result)
}

// Small tokenizer for directory listings: match actual anchor attributes,
// respecting quotes, comments, and raw script/style text. No HTML dependency.
fn anchor_hrefs(html: &str) -> Vec<&str> {
    let mut hrefs = Vec::new();
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        if let Some(comment) = rest.strip_prefix("!--") {
            let Some(end) = comment.find("-->") else {
                break;
            };
            rest = &comment[end + 3..];
            continue;
        }
        let mut quote = None;
        let end = rest.bytes().position(|byte| {
            match (quote, byte) {
                (Some(active), byte) if active == byte => quote = None,
                (None, b'\'' | b'"') => quote = Some(byte),
                (None, b'>') => return true,
                _ => {}
            }
            false
        });
        let Some(end) = end else { break };
        let tag = &rest[..end];
        rest = &rest[end + 1..];
        let name_end = tag
            .find(|character: char| character.is_ascii_whitespace() || character == '/')
            .unwrap_or(tag.len());
        let tag_name = &tag[..name_end];
        if tag_name.eq_ignore_ascii_case("script") || tag_name.eq_ignore_ascii_case("style") {
            let closing = format!("</{tag_name}");
            if let Some(end) = rest
                .as_bytes()
                .windows(closing.len())
                .position(|bytes| bytes.eq_ignore_ascii_case(closing.as_bytes()))
            {
                rest = &rest[end..];
            } else {
                break;
            }
            continue;
        }
        if !tag_name.eq_ignore_ascii_case("a") {
            continue;
        }
        let mut attributes = &tag[name_end..];
        loop {
            attributes = attributes.trim_start_matches(|character: char| {
                character.is_ascii_whitespace() || character == '/'
            });
            if attributes.is_empty() {
                break;
            }
            let end = attributes
                .find(|character: char| character.is_ascii_whitespace() || character == '=')
                .unwrap_or(attributes.len());
            let attribute = &attributes[..end];
            attributes = attributes[end..].trim_start();
            let Some(value) = attributes.strip_prefix('=') else {
                continue;
            };
            attributes = value.trim_start();
            let value;
            if attributes.starts_with(['\'', '"']) {
                let quote = attributes.as_bytes()[0] as char;
                let Some(end) = attributes[1..].find(quote) else {
                    break;
                };
                value = &attributes[1..end + 1];
                attributes = &attributes[end + 2..];
            } else {
                let end = attributes
                    .find(|character: char| character.is_ascii_whitespace())
                    .unwrap_or(attributes.len());
                value = &attributes[..end];
                attributes = &attributes[end..];
            }
            if attribute.eq_ignore_ascii_case("href") {
                hrefs.push(value);
                break;
            }
        }
    }
    hrefs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const INDEX: &str = "https://archive.archlinux.org/packages/f/foo/";

    fn package(path: &Path, name: &str, version: &str, arch: &str) {
        let info = format!("pkgname = {name}\npkgver = {version}\narch = {arch}\nsize = 1\n");
        let mut archive = tar::Builder::new(std::fs::File::create(path).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(info.len() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, ".PKGINFO", info.as_bytes())
            .unwrap();
        archive.finish().unwrap();
    }

    #[test]
    fn cache_reads_metadata_filters_identity_and_stops_at_depth_two() {
        let temp = tempfile::tempdir().unwrap();
        let nested = temp.path().join("nested");
        let deep = nested.join("deep");
        std::fs::create_dir_all(&deep).unwrap();
        package(
            &temp.path().join("foo-1-1-x86_64.pkg.tar"),
            "foo",
            "3:1-2",
            "x86_64",
        );
        package(&nested.join("foo-2-1-any.pkg.tar"), "foo", "2-1", "any");
        package(&deep.join("foo-9-1-any.pkg.tar"), "foo", "9-1", "any");
        package(
            &temp.path().join("foo-tools-8-1-any.pkg.tar"),
            "foo-tools",
            "8-1",
            "any",
        );
        package(
            &temp.path().join("foo-7-1-aarch64.pkg.tar"),
            "foo",
            "7-1",
            "aarch64",
        );
        std::fs::write(temp.path().join("foo-broken.pkg.tar.zst"), b"broken").unwrap();
        std::fs::write(temp.path().join("foo-1-1-x86_64.pkg.tar.sig"), b"signature").unwrap();
        std::fs::write(temp.path().join("other-broken.pkg.tar"), b"ignored").unwrap();
        std::os::unix::fs::symlink(&deep, temp.path().join("link")).unwrap();
        let report = cached_versions(
            "foo",
            &[temp.path().to_path_buf(), temp.path().join("missing")],
            "x86_64",
        )
        .unwrap();
        assert_eq!(report.candidates.len(), 2);
        assert_eq!(report.candidates[0].version.to_string(), "3:1-2");
        assert_eq!(report.candidates[1].arch, "any");
        assert_eq!(report.diagnostics.len(), 1);
        assert!(
            report.diagnostics[0]
                .path
                .ends_with("foo-broken.pkg.tar.zst")
        );
    }

    #[test]
    fn cache_accepts_all_compression_formats_and_metadata_epochs() {
        let temp = tempfile::tempdir().unwrap();
        let plain = temp.path().join("foo-1-1-any.pkg.tar");
        package(&plain, "foo", "5:1-1", "any");
        let bytes = std::fs::read(&plain).unwrap();
        let gzip_path = temp.path().join("foo-1-1-any.pkg.tar.gz");
        let mut gzip = flate2::write::GzEncoder::new(
            std::fs::File::create(gzip_path).unwrap(),
            flate2::Compression::default(),
        );
        gzip.write_all(&bytes).unwrap();
        gzip.finish().unwrap();
        let xz_path = temp.path().join("foo-1-1-any.pkg.tar.xz");
        let mut xz = xz2::write::XzEncoder::new(std::fs::File::create(xz_path).unwrap(), 1);
        xz.write_all(&bytes).unwrap();
        xz.finish().unwrap();
        std::fs::write(
            temp.path().join("foo-1-1-any.pkg.tar.zst"),
            zstd::encode_all(bytes.as_slice(), 1).unwrap(),
        )
        .unwrap();
        let report = cached_versions("foo", &[temp.path().to_path_buf()], "x86_64").unwrap();
        assert!(report.diagnostics.is_empty());
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].version.epoch, 5);
        assert_eq!(report.candidates[0].local_paths.len(), 4);
    }

    #[test]
    fn parses_html_attributes_entities_encodings_and_all_archive_formats() {
        let html = r#"
            <!-- <a href="foo-99-1-any.pkg.tar"> -->
            <script>const x = '<a href="foo-98-1-any.pkg.tar">';</script>
            <A title='a > b' HREF = 'foo-2%3A1.2%2B3-1-x86_64.pkg.tar.zst'>one</A>
            <a data-href="foo-99-1-any.pkg.tar" href=./foo-4-1-any.pkg.tar.xz>two</a>
            <a href="/packages/f/foo/foo-3-1-any.pkg.tar.gz">three</a>
            <a href="https://archive.archlinux.org/packages/f/foo/foo-2-1-any.pkg.tar">four</a>
            <a href="foo-&#49;-1-any.pkg.tar">five</a>
            <a href="foo-1-1-any.pkg.tar">duplicate</a>
        "#;
        let candidates = parse_archive_index("foo", "x86_64", INDEX, html);
        assert_eq!(candidates.len(), 5);
        assert_eq!(candidates[0].version.to_string(), "2:1.2+3-1");
        assert_eq!(
            candidates[0].remote_url.as_deref(),
            Some(
                "https://archive.archlinux.org/packages/f/foo/foo-2%3A1.2%2B3-1-x86_64.pkg.tar.zst"
            )
        );
        assert_eq!(candidates[1].version.to_string(), "4-1");
        assert_eq!(candidates[4].version.epoch, 0);
    }

    #[test]
    fn rejects_foreign_links_traversal_signatures_wrong_names_and_architectures() {
        let links = [
            "https://evil.test/foo-1-1-any.pkg.tar",
            "//evil.test/foo-1-1-any.pkg.tar",
            "../foo-1-1-any.pkg.tar",
            "%2e%2e%2ffoo-1-1-any.pkg.tar",
            "foo-1-1-any.pkg.tar?x",
            "foo-1-1-any.pkg.tar#x",
            "foo-1-1-any.pkg.tar.sig",
            "foo-tools-1-1-any.pkg.tar",
            "foo-1-1-aarch64.pkg.tar",
            "foo-%252f-1-any.pkg.tar",
            "foo-1%00-1-any.pkg.tar",
            "foo-%GG-1-any.pkg.tar",
            "https://archive.archlinux.org.evil/packages/f/foo/foo-1-1-any.pkg.tar",
        ];
        for link in links {
            assert!(
                parse_archive_index("foo", "x86_64", INDEX, &format!("<a href='{link}'>x</a>"))
                    .is_empty(),
                "{link}"
            );
        }
    }

    #[test]
    fn merge_keeps_local_paths_and_remote_fallback_and_sorts_by_version() {
        let mut local = filename_candidate("foo", "x86_64", "foo-1-1-any.pkg.tar").unwrap();
        local.local_paths = vec![
            PathBuf::from("/b"),
            PathBuf::from("/a"),
            PathBuf::from("/b"),
        ];
        let remote = parse_archive_index(
            "foo",
            "x86_64",
            INDEX,
            "<a href='foo-1-1-any.pkg.tar'><a href='foo-2-1-any.pkg.tar'><a href='foo-1-1-x86_64.pkg.tar'>",
        );
        let merged = merge_candidates(vec![local.clone(), local], remote);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].version.to_string(), "2-1");
        assert_eq!(
            merged[1].local_paths,
            [PathBuf::from("/a"), PathBuf::from("/b")]
        );
        assert!(merged[1].remote_url.is_some());
    }

    #[test]
    fn validates_inputs_and_builds_custom_archive_urls() {
        for name in ["", "../foo", "-foo", "foo/bar", "foo?x", "foo%2f", "foo\n"] {
            assert!(cached_versions(name, &[], "x86_64").is_err());
        }
        assert!(cached_versions("foo", &[], "../any").is_err());
        for url in [
            "file:///tmp",
            "https://user@host/packages",
            "https://host/packages?x",
            "https://host/packages#x",
            "https://host/../packages",
            "https://host/%2e%2e/packages",
        ] {
            assert!(archive_index_url("foo", url).is_err(), "{url}");
        }
        assert_eq!(
            archive_index_url("foo+bar", "http://127.0.0.1:1234/packages/").unwrap(),
            "http://127.0.0.1:1234/packages/f/foo%2Bbar/"
        );
    }

    fn serve(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/packages", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0; 4096];
            let count = stream.read(&mut request).unwrap();
            assert!(
                String::from_utf8_lossy(&request[..count]).starts_with("GET /packages/f/foo/ ")
            );
            // Limit tests may deliberately close the connection early.
            let _ = stream.write_all(&response);
        });
        (url, handle)
    }

    #[test]
    fn resolver_hydrates_in_parallel_and_sorts_authoritative_versions() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let active = AtomicUsize::new(0);
        let maximum = AtomicUsize::new(0);
        let barrier = std::sync::Barrier::new(4);
        let candidates: Vec<_> = (1..=8)
            .map(|number| {
                filename_candidate("foo", "any", &format!("foo-{number}-1-any.pkg.tar")).unwrap()
            })
            .collect();
        let resolved =
            resolve_archive_versions_with(candidates, RESOLVE_TIMEOUT, |candidate, timeout| {
                assert!(!timeout.is_zero() && timeout <= INDEX_TIMEOUT);
                let count = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(count, Ordering::SeqCst);
                barrier.wait();
                active.fetch_sub(1, Ordering::SeqCst);
                Version::parse(&format!(
                    "{}:{}-1",
                    9 - candidate.version.pkgver.parse::<u32>().unwrap(),
                    candidate.version.pkgver
                ))
                .map_err(ExecError::from)
            })
            .unwrap();
        assert_eq!(maximum.load(Ordering::SeqCst), 4);
        assert_eq!(resolved.len(), 8);
        assert_eq!(resolved[0].version.to_string(), "8:1-1");
        assert_eq!(resolved[7].version.to_string(), "1:8-1");
    }

    #[test]
    fn resolver_rejects_partial_results_and_expired_queue_budget() {
        let candidate = filename_candidate("foo", "any", "foo-1-1-any.pkg.tar").unwrap();
        assert!(
            resolve_archive_versions_with(vec![candidate.clone(); 8], Duration::ZERO, |_, _| {
                panic!("expired work must not start an HTTP request")
            })
            .is_err()
        );
        assert!(
            resolve_archive_versions_with(vec![candidate; 8], RESOLVE_TIMEOUT, |_, _| {
                Err(discovery_error("foo", "metadata unavailable"))
            })
            .is_err()
        );
        assert!(resolve_archive_versions(Vec::new()).unwrap().is_empty());
    }

    #[test]
    fn archive_cache_requires_explicit_scan() {
        let temp = tempfile::tempdir().unwrap();
        let archive_cache = temp.path().join("pax-ala");
        std::fs::create_dir(&archive_cache).unwrap();
        package(
            &archive_cache.join("foo-1-1-any.pkg.tar"),
            "foo",
            "2:1-1",
            "any",
        );
        assert!(
            cached_versions("foo", &[temp.path().to_path_buf()], "x86_64")
                .unwrap()
                .candidates
                .is_empty()
        );
        let explicit = cached_versions("foo", &[archive_cache], "x86_64").unwrap();
        assert_eq!(explicit.candidates.len(), 1);
        assert_eq!(explicit.candidates[0].version.epoch, 2);
    }

    #[test]
    fn archive_filename_decodes_basename_without_changing_request_url() {
        assert_eq!(
            archive_filename("https://host/f/foo/foo-2%3A1%2B2-1-any.pkg.tar.zst").unwrap(),
            "foo-2:1+2-1-any.pkg.tar.zst"
        );
        for path in [
            "../foo-1-1-any.pkg.tar",
            "%2e%2e/foo-1-1-any.pkg.tar",
            "foo%2f-1-1-any.pkg.tar",
            "foo%255c-1-1-any.pkg.tar",
            "foo-1-1-any.pkg.tar.sig",
            "foo-1-1-any.pkg.tar?x",
            "foo-1-1-any.pkg.tar#x",
            "foo-1-1-any.pkg.tar/",
        ] {
            assert!(
                archive_filename(&format!("https://host/{path}")).is_err(),
                "{path}"
            );
        }
    }

    fn metadata_tar(name: &str, version: &str, arch: &str, prefix_size: usize) -> Vec<u8> {
        let mut archive = tar::Builder::new(Vec::new());
        for (path, bytes) in [
            (".MTREE", vec![b'x'; prefix_size]),
            (
                ".PKGINFO",
                format!("pkgname = {name}\npkgver = {version}\narch = {arch}\n").into_bytes(),
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive
                .append_data(&mut header, path, bytes.as_slice())
                .unwrap();
        }
        archive.into_inner().unwrap()
    }

    #[test]
    fn metadata_checks_identity_release_and_explicit_epoch() {
        let candidate = filename_candidate("foo", "any", "foo-1-2-any.pkg.tar").unwrap();
        let filename = "foo-1-2-any.pkg.tar";
        let bytes = metadata_tar("foo", "4:1-2", "any", 1024);
        assert_eq!(
            read_remote_pkginfo(&candidate, filename, bytes.as_slice())
                .unwrap()
                .epoch,
            4
        );
        for (name, version, arch) in [
            ("other", "1-2", "any"),
            ("foo", "1-2", "x86_64"),
            ("foo", "1-3", "any"),
            ("foo", "2-2", "any"),
        ] {
            assert!(
                read_remote_pkginfo(
                    &candidate,
                    filename,
                    metadata_tar(name, version, arch, 0).as_slice()
                )
                .is_err()
            );
        }
        assert!(
            read_remote_pkginfo(&candidate, "foo-3:1-2-any.pkg.tar", bytes.as_slice()).is_err()
        );
        let duplicate = b"pkgname = foo\npkgname = foo\npkgver = 1-2\narch = any\n";
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(duplicate.len() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, ".PKGINFO", duplicate.as_slice())
            .unwrap();
        assert!(
            read_remote_pkginfo(
                &candidate,
                filename,
                archive.into_inner().unwrap().as_slice()
            )
            .is_err()
        );
    }

    #[test]
    fn metadata_read_limits_and_deadline_are_enforced() {
        let mut reader = MetadataReader::new(
            std::io::repeat(b'x'),
            Instant::now() + INDEX_TIMEOUT,
            "compressed",
        );
        assert!(
            std::io::copy(&mut reader, &mut std::io::sink())
                .unwrap_err()
                .to_string()
                .contains("compressed limit")
        );
        let candidate = filename_candidate("foo", "any", "foo-1-1-any.pkg.tar").unwrap();
        let bytes = metadata_tar("foo", "1-1", "any", METADATA_LIMIT as usize);
        let reader =
            MetadataReader::new(bytes.as_slice(), Instant::now() + INDEX_TIMEOUT, "decoded");
        assert!(
            read_remote_pkginfo(&candidate, "foo-1-1-any.pkg.tar", reader)
                .unwrap_err()
                .to_string()
                .contains("decoded limit")
        );
        let mut expired = MetadataReader::new(bytes.as_slice(), Instant::now(), "decoded");
        assert_eq!(
            expired.read(&mut [0; 1]).unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
    }

    fn large_window_zstd_metadata(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).unwrap();
        encoder.window_log(27).unwrap();
        encoder.long_distance_matching(true).unwrap();
        encoder.include_contentsize(false).unwrap();
        encoder.write_all(bytes).unwrap();
        // Emit a streaming frame header before finishing; a small, single-shot
        // frame could otherwise advertise a smaller window than requested.
        encoder.flush().unwrap();
        let frame = encoder.finish().unwrap();
        assert_eq!(&frame[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
        assert_eq!(frame[4] & 0x20, 0, "fixture must have a window descriptor");
        assert_eq!(
            frame[5],
            (27 - 10) << 3,
            "fixture must require a 128 MiB window"
        );
        let mut restricted = zstd::Decoder::new(frame.as_slice()).unwrap();
        restricted.window_log_max(23).unwrap();
        let error = restricted.read_to_end(&mut Vec::new()).unwrap_err();
        assert!(
            error.to_string().contains("Frame requires too much memory"),
            "{error}"
        );
        frame
    }

    #[test]
    fn remote_metadata_streams_all_formats_and_returns_authoritative_epoch() {
        let bytes = metadata_tar("foo", "7:1-2", "any", 1024);
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&bytes).unwrap();
        let mut xz = xz2::write::XzEncoder::new(Vec::new(), 1);
        xz.write_all(&bytes).unwrap();
        for (suffix, body) in [
            (".pkg.tar", bytes.clone()),
            (".pkg.tar.gz", gzip.finish().unwrap()),
            (".pkg.tar.xz", xz.finish().unwrap()),
            (".pkg.tar.zst", large_window_zstd_metadata(&bytes)),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!(
                "http://{}/foo-1-2-any{suffix}",
                listener.local_addr().unwrap()
            );
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = [0; 4096];
                let count = stream.read(&mut request).unwrap();
                assert!(count > 0);
                // Large packages are allowed: metadata discovery must not read the rest.
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\nConnection: close\r\n\r\n").unwrap();
                let _ = stream.write_all(&body);
            });
            let mut candidate =
                filename_candidate("foo", "any", &format!("foo-1-2-any{suffix}")).unwrap();
            candidate.remote_url = Some(url);
            assert_eq!(
                archive_package_version(&candidate).unwrap().to_string(),
                "7:1-2"
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn http_reads_index_and_rejects_redirects_errors_and_oversized_bodies() {
        let body = "<a href='foo-1-1-any.pkg.tar.zst'>foo</a>";
        let (url, server) = serve(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        );
        let candidates = archive_versions("foo", "x86_64", &url).unwrap();
        server.join().unwrap();
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].remote_url.as_ref().unwrap().starts_with(&url));
        for response in [
            b"HTTP/1.1 302 Found\r\nLocation: http://example.invalid/\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                INDEX_LIMIT + 1
            )
            .into_bytes(),
            [
                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".as_slice(),
                &vec![b'x'; INDEX_LIMIT as usize + 1],
            ]
            .concat(),
        ] {
            let (url, server) = serve(response);
            assert!(archive_versions("foo", "x86_64", &url).is_err());
            server.join().unwrap();
        }
    }
}
