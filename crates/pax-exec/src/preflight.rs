//! Read-only archive checks to run before planning, logging, hooks, or removals.
//!
//! This is not signature verification, a filesystem snapshot, or a dry-run extractor.
//! In particular it cannot predict changes made by hooks or guarantee later I/O.
//! Conservative restrictions: two tar end blocks and aligned zero padding are required;
//! gzip/xz must contain one stream (matching the extractor); hardlinks must reference an
//! earlier regular payload in this archive, not another hardlink or an installed file.
//! Nonempty directories are never assumed to become empty during the transaction.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, Metadata};
use std::io::{self, BufReader, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use crate::error::{ExecError, Result};
use crate::extract::validate_identity;

const BLOCK: u64 = 512;
const PKGINFO_LIMIT: u64 = 4 * 1024 * 1024;

/// Validate the entire archive without creating the root or changing package files.
/// `None` skips architecture compatibility, but still requires one nonempty `arch`.
/// `Some("")` and `Some("auto")` select the architecture of the running executable.
/// Archive signatures and identity against the transaction remain caller responsibilities.
pub(crate) fn validate_archive(
    path: &Path,
    root: &Path,
    expected_architecture: Option<&str>,
) -> Result<()> {
    validate_inner(path, root, expected_architecture).map_err(|error| ExecError::Extraction {
        pkg: path.display().to_string(),
        message: format!("preflight: {error}"),
    })
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn context<T>(path: &Path, operation: &str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("{}: {operation}: {error}", path.display()),
        )
    })
}

struct Counted<R> {
    inner: R,
    bytes: u64,
}

impl<R> Counted<R> {
    fn new(inner: R) -> Self {
        Self { inner, bytes: 0 }
    }
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.bytes = self
            .bytes
            .checked_add(count as u64)
            .ok_or_else(|| invalid("archive length overflow"))?;
        Ok(count)
    }
}

// The bufread decoders leave bytes after their first stream in the underlying
// buffer. Rejecting those bytes avoids validating a different tar than extract.rs,
// whose gzip/xz decoders also stop after the first stream.
enum SingleDecoder {
    Gzip(flate2::bufread::GzDecoder<BufReader<File>>),
    Xz(xz2::bufread::XzDecoder<BufReader<File>>),
}

struct SingleStream {
    decoder: SingleDecoder,
    finished: bool,
}

impl Read for SingleStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.finished {
            return Ok(0);
        }
        let count = match &mut self.decoder {
            SingleDecoder::Gzip(decoder) => decoder.read(buffer)?,
            SingleDecoder::Xz(decoder) => decoder.read(buffer)?,
        };
        if count != 0 {
            return Ok(count);
        }
        match &mut self.decoder {
            SingleDecoder::Gzip(decoder) => {
                let mut byte = [0];
                if decoder.get_mut().read(&mut byte)? != 0 {
                    return Err(invalid("gzip has trailing bytes or additional members"));
                }
            }
            SingleDecoder::Xz(decoder) => {
                let mut byte = [0];
                if decoder.get_mut().read(&mut byte)? != 0 {
                    return Err(invalid("xz has trailing bytes or additional streams"));
                }
            }
        }
        self.finished = true;
        Ok(0)
    }
}

fn open_archive(path: &Path) -> io::Result<Box<dyn Read>> {
    if !std::fs::metadata(path)?.is_file() {
        return Err(invalid("archive is not a regular file"));
    }
    let file = File::open(path)?;
    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    if filename.ends_with(".zst") {
        Ok(Box::new(zstd::Decoder::new(file)?))
    } else if filename.ends_with(".gz") {
        Ok(Box::new(SingleStream {
            decoder: SingleDecoder::Gzip(flate2::bufread::GzDecoder::new(BufReader::new(file))),
            finished: false,
        }))
    } else if filename.ends_with(".xz") {
        Ok(Box::new(SingleStream {
            decoder: SingleDecoder::Xz(xz2::bufread::XzDecoder::new(BufReader::new(file))),
            finished: false,
        }))
    } else {
        Ok(Box::new(file))
    }
}

fn validate_inner(path: &Path, root: &Path, architecture: Option<&str>) -> io::Result<()> {
    let reader = context(path, "open decompressor", open_archive(path))?;
    let root = context(root, "resolve installation root", validation_root(root))?;
    let mut state = Inspection::new(root);
    let mut archive = tar::Archive::new(Counted::new(reader));
    let mut next_header = 0;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let member = entry.path()?.into_owned();
        // entry.size(), unlike header.size(), includes an effective PAX size.
        // GNU sparse records are rejected below; they need different accounting.
        let padded_size = entry
            .size()
            .checked_add(BLOCK - 1)
            .ok_or_else(|| invalid("member size overflow"))?
            / BLOCK
            * BLOCK;
        next_header = entry
            .raw_file_position()
            .checked_add(padded_size)
            .ok_or_else(|| invalid("member position overflow"))?;
        context(
            &member,
            "inspect member",
            state.inspect(&mut entry, &member, architecture),
        )?;
    }

    let mut reader = archive.into_inner();
    // tar 0.4 accepts both EOF on a header boundary and a single zero block.
    // Its position distinguishes those cases without retaining payload bytes.
    if reader.bytes.checked_sub(next_header) != Some(BLOCK) {
        return Err(invalid("tar terminator: missing first zero block"));
    }
    let mut second = [0; BLOCK as usize];
    context(
        path,
        "read second tar end block",
        reader.read_exact(&mut second),
    )?;
    if second.iter().any(|byte| *byte != 0) {
        return Err(invalid("tar terminator: second block is not zero-filled"));
    }
    let padding = context(
        path,
        "read decompressor to EOF after tar terminator",
        read_zero_padding(&mut reader),
    )?;
    if padding % BLOCK != 0 {
        return Err(invalid("tar terminator: unaligned trailing padding"));
    }
    state.finish()
}

fn read_zero_padding(reader: &mut impl Read) -> io::Result<u64> {
    let mut count = 0u64;
    let mut buffer = [0; 64 * 1024];
    loop {
        let length = reader.read(&mut buffer)?;
        if length == 0 {
            return Ok(count);
        }
        if buffer[..length].iter().any(|byte| *byte != 0) {
            return Err(invalid("nonzero trailing data or an additional stream"));
        }
        count = count
            .checked_add(length as u64)
            .ok_or_else(|| invalid("padding length overflow"))?;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Regular,
    Directory,
    Symlink(PathBuf),
    Hardlink,
}

struct Payload {
    destination: PathBuf,
    node: Node,
}

struct Inspection {
    root: PathBuf,
    // Keys are root-relative, after resolving parents, but NOT the final symlink.
    nodes: HashMap<PathBuf, Node>,
    payload: HashMap<PathBuf, Payload>,
    metadata: HashSet<PathBuf>,
    backups: Option<HashSet<PathBuf>>,
}

impl Inspection {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            nodes: HashMap::new(),
            payload: HashMap::new(),
            metadata: HashSet::new(),
            backups: None,
        }
    }

    fn inspect<R: Read>(
        &mut self,
        entry: &mut tar::Entry<'_, R>,
        raw_path: &Path,
        architecture: Option<&str>,
    ) -> io::Result<()> {
        validate_extensions(entry)?;
        let path = relative_path(raw_path)?;
        let kind = entry.header().entry_type();
        entry.header().mode()?;
        let node = if kind.is_file() {
            if raw_path.as_os_str().as_bytes().ends_with(b"/") {
                return Err(invalid("regular entry has a directory-style name"));
            }
            Node::Regular
        } else if kind.is_dir() {
            Node::Directory
        } else if kind.is_symlink() {
            let target = entry
                .link_name()?
                .ok_or_else(|| invalid("missing symlink target"))?;
            if target.as_os_str().is_empty() || target.as_os_str().as_bytes().contains(&0) {
                return Err(invalid("empty or NUL-containing symlink target"));
            }
            Node::Symlink(target.into_owned())
        } else if kind.is_hard_link() {
            Node::Hardlink
        } else {
            return Err(invalid(format!("unsupported tar entry type {:?}", kind)));
        };
        if node != Node::Regular && entry.size() != 0 {
            return Err(invalid("non-regular entry has a payload"));
        }
        if path.as_os_str().is_empty() {
            return if node == Node::Directory {
                Ok(())
            } else {
                Err(invalid("empty payload path"))
            };
        }
        let name = path
            .to_str()
            .ok_or_else(|| invalid("non-UTF-8 member path"))?;
        let size = entry.size();
        if name.starts_with('.') {
            if node != Node::Regular {
                return Err(invalid("non-regular metadata entry"));
            }
            if matches!(name, ".PKGINFO" | ".INSTALL" | ".MTREE") {
                // The existing metadata readers strip exactly one leading './'.
                let raw = raw_path.as_os_str().as_bytes();
                if raw.strip_prefix(b"./").unwrap_or(raw) != name.as_bytes() {
                    return Err(invalid("non-canonical metadata path"));
                }
                if !self.metadata.insert(path.clone()) {
                    return Err(invalid(format!("duplicate {name}")));
                }
            }
            let mut contents = Counted::new(&mut *entry);
            match name {
                ".PKGINFO" => {
                    if size > PKGINFO_LIMIT {
                        return Err(invalid(".PKGINFO exceeds the 4 MiB limit"));
                    }
                    let mut text = String::new();
                    contents.read_to_string(&mut text)?;
                    self.backups = Some(parse_pkginfo(&text, architecture)?);
                }
                ".INSTALL" => validate_utf8(&mut contents)?,
                ".MTREE" => validate_mtree(&mut contents)?,
                _ => {
                    io::copy(&mut contents, &mut io::sink())?;
                }
            }
            return require_size(contents.bytes, size);
        }

        let destination = self.destination(&path)?;
        if let Some(previous) = self.payload.get(&path) {
            if node != Node::Directory || previous.node != Node::Directory {
                return Err(invalid("duplicate payload path"));
            }
        }
        if let Some(previous) = self.nodes.get(&destination) {
            if node != Node::Directory || *previous != Node::Directory {
                return Err(invalid(format!(
                    "destination {} already supplied by another member or used as a directory",
                    destination.display()
                )));
            }
        }
        if node == Node::Hardlink {
            let target = entry
                .link_name()?
                .ok_or_else(|| invalid("missing hardlink target"))?;
            let target = relative_path(&target)?;
            if target.as_os_str().is_empty() {
                return Err(invalid("empty hardlink target"));
            }
            let source = self.destination(&target)?;
            if source == destination {
                return Err(invalid("self-referential hardlink"));
            }
            if self.nodes.get(&source) != Some(&Node::Regular) {
                return Err(invalid(format!(
                    "hardlink source {} is not an earlier regular payload in this archive",
                    target.display()
                )));
            }
        }
        self.check_destination(&destination, &node)?;
        let actual = io::copy(entry, &mut io::sink())?;
        require_size(actual, size)?;
        // Include implicit directories: a later member cannot turn an already
        // populated parent into a file or symlink even if the parent wasn't listed.
        let mut parent = destination.parent();
        while let Some(directory) = parent {
            if !directory.as_os_str().is_empty() {
                self.nodes
                    .entry(directory.to_path_buf())
                    .or_insert(Node::Directory);
            }
            parent = directory.parent();
        }
        self.nodes.insert(destination.clone(), node.clone());
        self.payload.insert(path, Payload { destination, node });
        Ok(())
    }

    fn destination(&self, path: &Path) -> io::Result<PathBuf> {
        let parent = path.parent().unwrap_or(Path::new(""));
        let mut pending: VecDeque<_> = parent
            .components()
            .map(|part| Some(part.as_os_str().to_os_string()))
            .collect();
        let mut resolved = PathBuf::new();
        let mut followed = 0;
        while let Some(part) = pending.pop_front() {
            let Some(part) = part else {
                // A symlink target must exist when extraction traverses it.
                // Missing ordinary parents may be created, dangling links may not.
                if !resolved.as_os_str().is_empty()
                    && self.nodes.get(&resolved) != Some(&Node::Directory)
                {
                    let absolute = self.root.join(&resolved);
                    if !context(
                        &absolute,
                        "inspect parent symlink target",
                        optional_metadata(&absolute),
                    )?
                    .is_some_and(|metadata| metadata.is_dir())
                    {
                        return Err(invalid(format!(
                            "dangling parent symlink target {}",
                            absolute.display()
                        )));
                    }
                }
                continue;
            };
            if part == "." {
                continue;
            }
            if part == ".." {
                if !resolved.pop() {
                    return Err(invalid("parent symlink escapes installation root"));
                }
                continue;
            }
            let candidate = resolved.join(&part);
            let link = match self.nodes.get(&candidate) {
                Some(Node::Symlink(target)) => Some(target.clone()),
                Some(Node::Directory) => None,
                Some(_) => {
                    return Err(invalid(format!(
                        "non-directory parent {}",
                        candidate.display()
                    )));
                }
                None => {
                    let absolute = self.root.join(&candidate);
                    match optional_metadata(&absolute)? {
                        Some(meta) if meta.file_type().is_symlink() => {
                            Some(std::fs::read_link(absolute)?)
                        }
                        Some(meta) if !meta.is_dir() => {
                            return Err(invalid(format!(
                                "non-directory parent {}",
                                candidate.display()
                            )));
                        }
                        _ => None,
                    }
                }
            };
            if let Some(target) = link {
                followed += 1;
                if followed > 40 {
                    return Err(invalid("parent symlink loop or more than 40 links"));
                }
                let target = if target.is_absolute() {
                    // Extraction happens outside chroot. A literal /usr link in
                    // an alternate root is valid data, but unsafe to traverse.
                    let target = target.strip_prefix(&self.root).map_err(|_| {
                        invalid(format!(
                            "parent symlink {} points outside installation root",
                            candidate.display()
                        ))
                    })?;
                    resolved.clear();
                    target
                } else {
                    target.as_path()
                };
                pending.push_front(None);
                for component in target.components().rev() {
                    pending.push_front(Some(component.as_os_str().to_os_string()));
                }
            } else {
                resolved.push(part);
            }
        }
        Ok(resolved.join(
            path.file_name()
                .ok_or_else(|| invalid("empty destination"))?,
        ))
    }

    fn check_destination(&self, destination: &Path, node: &Node) -> io::Result<()> {
        let absolute = self.root.join(destination);
        let Some(metadata) = context(
            &absolute,
            "inspect destination",
            optional_metadata(&absolute),
        )?
        else {
            return Ok(());
        };
        if *node == Node::Directory && !metadata.is_dir() {
            return Err(invalid(format!(
                "{}: cannot replace an existing non-directory with a directory",
                absolute.display()
            )));
        }
        if *node != Node::Directory && metadata.is_dir() {
            let mut children = context(
                &absolute,
                "inspect directory contents",
                std::fs::read_dir(&absolute),
            )?;
            if context(
                &absolute,
                "read directory entry",
                children.next().transpose(),
            )?
            .is_some()
            {
                return Err(invalid(format!(
                    "{}: cannot replace a nonempty directory with a non-directory",
                    absolute.display()
                )));
            }
        }
        Ok(())
    }

    fn finish(&self) -> io::Result<()> {
        let backups = self
            .backups
            .as_ref()
            .ok_or_else(|| invalid("missing .PKGINFO"))?;
        for path in backups {
            let Some(payload) = self.payload.get(path) else {
                // Obsolete backup declarations occur in real packages (e.g. mc).
                continue;
            };
            if payload.node != Node::Regular {
                return Err(invalid(format!(
                    "backup {} is not a regular payload",
                    path.display()
                )));
            }
            let destination = self.root.join(&payload.destination);
            if context(
                &destination,
                "inspect backup destination",
                optional_metadata(&destination),
            )?
            .is_some_and(|meta| !meta.is_file())
            {
                return Err(invalid(format!(
                    "{}: backup destination is not a regular file",
                    destination.display()
                )));
            }
            let mut filename = payload.destination.file_name().unwrap().to_os_string();
            filename.push(".pacnew");
            let pacnew = payload.destination.with_file_name(filename);
            let absolute = self.root.join(&pacnew);
            // Without old baseline metadata we cannot know whether .pacnew will
            // be needed. A directory there is conservatively always a blocker.
            if self.nodes.get(&pacnew) == Some(&Node::Directory)
                || context(
                    &absolute,
                    "inspect backup .pacnew",
                    optional_metadata(&absolute),
                )?
                .is_some_and(|meta| meta.is_dir())
            {
                return Err(invalid(format!(
                    "{}: backup .pacnew destination is a directory",
                    absolute.display()
                )));
            }
        }
        Ok(())
    }
}

fn require_size(actual: u64, expected: u64) -> io::Result<()> {
    if actual != expected {
        return Err(invalid(format!(
            "truncated payload: expected {expected} bytes, read {actual}"
        )));
    }
    Ok(())
}

fn optional_metadata(path: &Path) -> io::Result<Option<Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn validation_root(root: &Path) -> io::Result<PathBuf> {
    if let Some(metadata) = optional_metadata(root)? {
        let canonical = root.canonicalize()?;
        if !metadata.is_dir() && !std::fs::metadata(&canonical)?.is_dir() {
            return Err(invalid("installation root is not a directory"));
        }
        return Ok(canonical);
    }
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| invalid("invalid installation root"))?;
    let name = absolute
        .file_name()
        .ok_or_else(|| invalid("invalid installation root"))?;
    Ok(validation_root(parent)?.join(name))
}

fn relative_path(path: &Path) -> io::Result<PathBuf> {
    let text = path.to_str().ok_or_else(|| invalid("non-UTF-8 path"))?;
    if text.chars().any(char::is_control) {
        return Err(invalid("control character in package path"));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            _ => return Err(invalid(format!("unsafe relative path {}", path.display()))),
        }
    }
    Ok(normalized)
}

fn parse_pkginfo(text: &str, architecture: Option<&str>) -> io::Result<HashSet<PathBuf>> {
    let mut scalars = HashMap::new();
    let mut backups = HashSet::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        if matches!(key, "pkgname" | "pkgver" | "arch") {
            if raw_line != line
                || value.is_empty()
                || value.trim() != value
                || value.chars().any(char::is_control)
            {
                return Err(invalid(format!(".PKGINFO: non-canonical or empty {key}")));
            }
            if scalars.insert(key, value).is_some() {
                return Err(invalid(format!(".PKGINFO: duplicate scalar {key}")));
            }
        } else if key == "backup" {
            // The extractor accepts one './' prefix, but compares the rest as
            // text. Reject other spellings rather than losing backup semantics.
            let value = value.strip_prefix("./").unwrap_or(value);
            let path = relative_path(Path::new(value))?;
            if path.as_os_str().is_empty() || path.as_os_str().as_bytes() != value.as_bytes() {
                return Err(invalid(format!(
                    ".PKGINFO: non-canonical backup path {value:?}"
                )));
            }
            if !backups.insert(path) {
                return Err(invalid(format!(".PKGINFO: duplicate backup path {value}")));
            }
        }
    }
    let field = |key| {
        scalars
            .get(key)
            .copied()
            .ok_or_else(|| invalid(format!(".PKGINFO: missing {key}")))
    };
    let name = field("pkgname")?;
    let version = field("pkgver")?;
    let arch = field("arch")?;
    validate_identity(name, version).map_err(|error| invalid(error.to_string()))?;
    pax_core::version::Version::parse(version)
        .map_err(|error| invalid(format!(".PKGINFO: {error}")))?;
    if let Some(expected) = architecture {
        let expected = if expected.is_empty() || expected == "auto" {
            std::env::consts::ARCH
        } else {
            expected
        };
        if arch != "any" && arch != expected {
            return Err(invalid(format!(
                ".PKGINFO: architecture {arch} is incompatible with {expected}"
            )));
        }
    }
    Ok(backups)
}

fn validate_extensions<R: Read>(entry: &mut tar::Entry<'_, R>) -> io::Result<()> {
    if let Some(extensions) = entry.pax_extensions()? {
        for extension in extensions {
            let extension = extension?;
            let key = extension.key_bytes();
            if key.starts_with(b"GNU.sparse")
                || key == b"SCHILY.realsize"
                || (key == b"SCHILY.filetype" && extension.value_bytes() == b"sparse")
            {
                return Err(invalid("unsupported PAX sparse payload"));
            }
        }
    }
    Ok(())
}

fn validate_utf8(reader: &mut impl Read) -> io::Result<()> {
    let mut buffer = [0; 64 * 1024 + 4];
    let mut pending = 0;
    loop {
        let length = reader.read(&mut buffer[pending..])?;
        if length == 0 {
            return if pending == 0 {
                Ok(())
            } else {
                Err(invalid("incomplete UTF-8 sequence at end of metadata"))
            };
        }
        let length = pending + length;
        match std::str::from_utf8(&buffer[..length]) {
            Ok(_) => pending = 0,
            Err(error) if error.error_len().is_none() => {
                let valid = error.valid_up_to();
                pending = length - valid;
                buffer.copy_within(valid..length, 0);
            }
            Err(error) => return Err(invalid(format!("invalid UTF-8 metadata: {error}"))),
        }
    }
}

fn validate_mtree(reader: &mut impl Read) -> io::Result<()> {
    // Arch .MTREE is normally gzip-compressed, not raw UTF-8. Validate the
    // decompressed text and gzip trailer; do not retain either representation.
    let mut prefix = Vec::with_capacity(2);
    reader.by_ref().take(2).read_to_end(&mut prefix)?;
    let gzip = prefix == [0x1f, 0x8b];
    let mut stream = io::Cursor::new(prefix).chain(reader);
    if gzip {
        validate_utf8(&mut flate2::read::MultiGzDecoder::new(stream))
    } else {
        validate_utf8(&mut stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    const INFO: &str = "pkgname = test\npkgver = 1-1\narch = any\n";

    #[derive(Clone, Copy)]
    enum Member<'a> {
        File(&'a str, &'a [u8]),
        Directory(&'a str),
        Symlink(&'a str, &'a str),
        Hardlink(&'a str, &'a str),
        Special(&'a str, tar::EntryType),
        Pax(&'a str, &'a [u8]),
    }

    fn package(info: &str, members: &[Member<'_>]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for member in std::iter::once(Member::File(".PKGINFO", info.as_bytes()))
            .chain(members.iter().copied())
        {
            let (path, kind, data, target) = match member {
                Member::File(path, data) => (path, tar::EntryType::Regular, data, None),
                Member::Directory(path) => (path, tar::EntryType::Directory, &[][..], None),
                Member::Symlink(path, target) => {
                    (path, tar::EntryType::Symlink, &[][..], Some(target))
                }
                Member::Hardlink(path, target) => {
                    (path, tar::EntryType::Link, &[][..], Some(target))
                }
                Member::Special(path, kind) => (path, kind, &[][..], None),
                Member::Pax(key, value) => {
                    builder.append_pax_extensions([(key, value)]).unwrap();
                    continue;
                }
            };
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            if let Some(target) = target {
                builder.append_link(&mut header, path, target).unwrap();
            } else {
                header.set_cksum();
                builder.append_data(&mut header, path, data).unwrap();
            }
        }
        builder.into_inner().unwrap()
    }

    fn compress(codec: &str, bytes: &[u8]) -> Vec<u8> {
        match codec {
            "gz" => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                encoder.write_all(bytes).unwrap();
                encoder.finish().unwrap()
            }
            "xz" => {
                let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
                encoder.write_all(bytes).unwrap();
                encoder.finish().unwrap()
            }
            "zst" => {
                let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).unwrap();
                encoder.include_checksum(true).unwrap();
                encoder.write_all(bytes).unwrap();
                encoder.finish().unwrap()
            }
            _ => bytes.to_vec(),
        }
    }

    fn archive(directory: &Path, bytes: &[u8], codec: &str) -> PathBuf {
        let path = directory.join(format!("test.pkg.tar.{codec}"));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn check(bytes: &[u8], root: &Path) -> Result<()> {
        let temp = tempfile::tempdir().unwrap();
        let path = archive(temp.path(), bytes, "tar");
        validate_archive(&path, root, Some("x86_64"))
    }

    #[test]
    #[ignore = "requires PAX_TEST_PACKAGE_ARCHIVE pointing to a real cached package"]
    fn real_archive_preflight_and_reinstallation() {
        let archive = PathBuf::from(
            std::env::var_os("PAX_TEST_PACKAGE_ARCHIVE")
                .expect("set PAX_TEST_PACKAGE_ARCHIVE to a real cached package"),
        );
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        validate_archive(&archive, &root, Some("auto")).unwrap();
        let metadata = crate::extract::extract_package(&archive, &root, &HashMap::new()).unwrap();
        let link = metadata
            .files
            .iter()
            .filter_map(|file| {
                let path = root.join(file);
                std::fs::read_link(&path).ok().map(|target| (path, target))
            })
            .next();
        if let Some((path, _)) = &link {
            std::fs::remove_file(path).unwrap();
            std::fs::write(path, b"old package regular file").unwrap();
        }
        validate_archive(&archive, &root, Some("auto")).unwrap();
        let reinstalled =
            crate::extract::extract_package(&archive, &root, &HashMap::new()).unwrap();
        assert_eq!(metadata.files, reinstalled.files);
        if let Some((path, target)) = link {
            assert_eq!(std::fs::read_link(&path).unwrap(), target);
            eprintln!(
                "validated and reinstalled {}; exercised file-to-symlink at {}",
                archive.display(),
                path.display()
            );
        } else {
            eprintln!(
                "validated and reinstalled {}; archive has no symlinks",
                archive.display()
            );
        }
    }

    #[test]
    fn reads_supported_compression_without_creating_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("missing/root");
        let bytes = package(INFO, &[Member::File("usr/bin/tool", b"contents")]);
        for codec in ["tar", "gz", "xz", "zst"] {
            let path = archive(temp.path(), &compress(codec, &bytes), codec);
            validate_archive(&path, &root, Some("x86_64")).unwrap();
            assert!(!temp.path().join("missing").exists());
        }
    }

    #[test]
    fn requires_two_tar_end_blocks_and_zero_aligned_padding() {
        let temp = tempfile::tempdir().unwrap();
        // Zero payload bytes must not be mistaken for a tar terminator.
        let bytes = package(INFO, &[Member::File("zeros", &[0; 512])]);
        for removed in [512, 1024] {
            assert!(check(&bytes[..bytes.len() - removed], temp.path()).is_err());
        }
        let mut nonzero = bytes.clone();
        let last_block = nonzero.len() - 512;
        nonzero[last_block] = 1;
        assert!(check(&nonzero, temp.path()).is_err());
        let mut extra = bytes.clone();
        extra.extend([0; 512]);
        check(&extra, temp.path()).unwrap();
        extra.push(0);
        assert!(check(&extra, temp.path()).is_err());
        let mut concatenated = bytes.clone();
        concatenated.extend(bytes);
        assert!(check(&concatenated, temp.path()).is_err());
    }

    #[test]
    fn rejects_truncation_after_pkginfo_inside_payload_and_bad_header() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = package(INFO, &[Member::File("file", &[7; 512])]);
        assert!(check(&bytes[..1024], temp.path()).is_err());
        assert!(check(&bytes[..1539], temp.path()).is_err());
        let mut bad_header = bytes;
        bad_header[0] ^= 1;
        assert!(check(&bad_header, temp.path()).is_err());
    }

    #[test]
    fn checks_compressed_footers_after_tar_terminator() {
        let temp = tempfile::tempdir().unwrap();
        let mut bytes = package(INFO, &[]);
        bytes.extend(vec![0; 128 * 1024]);
        for codec in ["gz", "xz", "zst"] {
            let encoded = compress(codec, &bytes);
            let mut damaged = encoded.clone();
            let last = damaged.len() - 1;
            damaged[last] ^= 0x80;
            for broken in [&damaged[..], &encoded[..encoded.len() - 1]] {
                let path = archive(temp.path(), broken, codec);
                let error = validate_archive(&path, temp.path(), None)
                    .unwrap_err()
                    .to_string();
                assert!(error.contains(&path.display().to_string()), "{error}");
            }
        }
    }

    #[test]
    fn rejects_additional_gzip_xz_streams_but_reads_zstd_frames() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = package(INFO, &[]);
        for codec in ["gz", "xz"] {
            let mut encoded = compress(codec, &bytes);
            encoded.extend(compress(codec, b""));
            let path = archive(temp.path(), &encoded, codec);
            assert!(validate_archive(&path, temp.path(), None).is_err());
        }
        let mut encoded = compress("zst", &bytes[..1024]);
        encoded.extend(compress("zst", &bytes[1024..]));
        let path = archive(temp.path(), &encoded, "zst");
        validate_archive(&path, temp.path(), None).unwrap();
        encoded.extend(compress("zst", b"unexpected tail"));
        let path = archive(temp.path(), &encoded, "zst");
        assert!(validate_archive(&path, temp.path(), None).is_err());
    }

    #[test]
    fn rejects_duplicate_identity_scalars_and_checks_architecture() {
        let temp = tempfile::tempdir().unwrap();
        for duplicate in ["pkgname = other\n", "pkgver = 2-1\n", "arch = aarch64\n"] {
            let bytes = package(&format!("{INFO}{duplicate}"), &[]);
            let error = check(&bytes, temp.path()).unwrap_err().to_string();
            assert!(error.contains("duplicate scalar"), "{error}");
        }
        let info = "pkgname = test\npkgname = ../invalid\npkgver = 1-1\narch = any\n";
        assert!(check(&package(info, &[]), temp.path()).is_err());
        let bytes = package("pkgname = test\npkgver = 1-1\narch = aarch64\n", &[]);
        let path = archive(temp.path(), &bytes, "tar");
        assert!(validate_archive(&path, temp.path(), Some("x86_64")).is_err());
        validate_archive(&path, temp.path(), Some("aarch64")).unwrap();
        validate_archive(&path, temp.path(), None).unwrap();
        for info in [
            "pkgname = test\npkgver = 1-1\n",
            " pkgname = test\npkgver = 1-1\narch = any\n",
        ] {
            assert!(check(&package(info, &[]), temp.path()).is_err());
        }
    }

    #[test]
    fn metadata_entries_are_unique_and_text_is_utf8() {
        let temp = tempfile::tempdir().unwrap();
        for name in [".PKGINFO", ".INSTALL", ".MTREE"] {
            let bytes = package(
                INFO,
                &[Member::File(name, b"first"), Member::File(name, &[0xff])],
            );
            assert!(check(&bytes, temp.path()).is_err());
        }
        for name in [".INSTALL", ".MTREE"] {
            assert!(check(&package(INFO, &[Member::File(name, &[0xff])]), temp.path()).is_err());
        }
        for payload in [b"#mtree\n".as_slice(), &[0xff][..]] {
            let mtree = compress("gz", payload);
            let result = check(
                &package(INFO, &[Member::File(".MTREE", &mtree)]),
                temp.path(),
            );
            assert_eq!(result.is_ok(), payload == b"#mtree\n");
        }
        let mut mtree = compress("gz", b"#mtree\n");
        let last = mtree.len() - 1;
        mtree[last] ^= 1;
        assert!(
            check(
                &package(INFO, &[Member::File(".MTREE", &mtree)]),
                temp.path()
            )
            .is_err()
        );
    }

    #[test]
    fn validates_utf8_across_read_boundaries() {
        struct ShortReads<'a>(&'a [u8]);
        impl Read for ShortReads<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                let length = buffer.len().min(1);
                self.0.read(&mut buffer[..length])
            }
        }
        validate_utf8(&mut ShortReads("привет 😀".as_bytes())).unwrap();
        assert!(validate_utf8(&mut ShortReads(&[0xf0, 0x9f, 0x98])).is_err());
        assert!(validate_utf8(&mut ShortReads(&[0xc0, 0xaf])).is_err());
    }

    #[test]
    fn backup_paths_match_extractor_spelling_and_obsolete_entries_are_allowed() {
        let temp = tempfile::tempdir().unwrap();
        for path in [
            "etc//config",
            "etc/./config",
            "etc/config/",
            "../config",
            "/etc/config",
            "././etc/config",
        ] {
            let bytes = package(
                &format!("{INFO}backup = {path}\n"),
                &[Member::File("etc/config", b"new")],
            );
            assert!(check(&bytes, temp.path()).is_err(), "{path}");
        }
        for path in ["etc/config", "./etc/config"] {
            let bytes = package(
                &format!("{INFO}backup = {path}\nbackup = etc/obsolete\n"),
                &[Member::File("etc/config", b"new")],
            );
            check(&bytes, temp.path()).unwrap();
        }
    }

    #[test]
    fn hardlinks_require_an_earlier_regular_source_not_an_installed_file() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("source"), b"old").unwrap();
        std::fs::write(temp.path().join("self"), b"keep").unwrap();
        let cases = [
            vec![Member::Hardlink("link", "missing")],
            vec![Member::Hardlink("link", "source")],
            vec![
                Member::Hardlink("link", "source"),
                Member::File("source", b"new"),
            ],
            vec![Member::Hardlink("self", "self")],
            vec![
                Member::Directory("directory"),
                Member::Hardlink("link", "directory"),
            ],
            vec![
                Member::Symlink("symlink", "other"),
                Member::Hardlink("link", "symlink"),
            ],
            vec![
                Member::File("first", b"new"),
                Member::Hardlink("second", "first"),
                Member::Hardlink("third", "second"),
            ],
        ];
        for members in cases {
            assert!(check(&package(INFO, &members), temp.path()).is_err());
            assert_eq!(std::fs::read(temp.path().join("self")).unwrap(), b"keep");
            assert_eq!(std::fs::read(temp.path().join("source")).unwrap(), b"old");
            assert!(!temp.path().join("link").exists());
        }
        check(
            &package(
                INFO,
                &[
                    Member::File("source", b"new"),
                    Member::Hardlink("link", "source"),
                ],
            ),
            temp.path(),
        )
        .unwrap();
    }

    #[test]
    fn resolves_existing_root_aliases_for_payload_hardlinks_and_backups() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("usr/lib")).unwrap();
        symlink("usr/lib", temp.path().join("lib")).unwrap();
        let bytes = package(
            INFO,
            &[
                Member::File("usr/lib/source", b"new"),
                Member::Hardlink("lib/link", "lib/source"),
            ],
        );
        check(&bytes, temp.path()).unwrap();
        let bytes = package(
            INFO,
            &[
                Member::File("usr/lib/source", b"new"),
                Member::Hardlink("lib/source", "usr/lib/source"),
            ],
        );
        assert!(check(&bytes, temp.path()).is_err());
        std::fs::create_dir(temp.path().join("usr/lib/config.pacnew")).unwrap();
        let bytes = package(
            &format!("{INFO}backup = lib/config\n"),
            &[Member::File("lib/config", b"new")],
        );
        assert!(check(&bytes, temp.path()).is_err());
        assert_eq!(
            std::fs::read_link(temp.path().join("lib")).unwrap(),
            Path::new("usr/lib")
        );
        assert!(!temp.path().join("usr/lib/source").exists());
    }

    #[test]
    fn preserves_symlink_data_but_rejects_escaping_parent_traversal() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("sentinel"), b"keep").unwrap();
        for target in ["/usr/lib/library", "../../outside", "../lib/library"] {
            check(
                &package(INFO, &[Member::Symlink("usr/link", target)]),
                &root,
            )
            .unwrap();
        }
        for target in ["/usr", "../../outside"] {
            let bytes = package(
                INFO,
                &[
                    Member::Symlink("usr/link", target),
                    Member::File("usr/link/file", b"bad"),
                ],
            );
            assert!(check(&bytes, &root).is_err());
        }
        symlink(&outside, root.join("escape")).unwrap();
        assert!(
            check(
                &package(INFO, &[Member::File("escape/file", b"bad")]),
                &root
            )
            .is_err()
        );
        // Replacing the final symlink is safe: it must not be traversed.
        check(&package(INFO, &[Member::File("escape", b"new")]), &root).unwrap();
        let bytes = package(
            INFO,
            &[
                Member::Symlink("usr/link", "../lib"),
                Member::File("usr/link/file", b"new"),
            ],
        );
        assert!(
            check(&bytes, &root).is_err(),
            "cannot traverse a dangling incoming link"
        );
        std::fs::create_dir(root.join("lib")).unwrap();
        check(&bytes, &root).unwrap();
        assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(), b"keep");
        assert!(!root.join("usr").exists());
        assert!(!outside.join("file").exists());
    }

    #[test]
    fn supports_absolute_internal_aliases_and_detects_existing_link_loops() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(temp.path().join("usr/lib")).unwrap();
        symlink(temp.path().join("usr/lib"), temp.path().join("lib")).unwrap();
        check(
            &package(INFO, &[Member::File("lib/file", b"new")]),
            temp.path(),
        )
        .unwrap();
        symlink("loop-b", temp.path().join("loop-a")).unwrap();
        symlink("loop-a", temp.path().join("loop-b")).unwrap();
        assert!(
            check(
                &package(INFO, &[Member::File("loop-a/file", b"new")]),
                temp.path()
            )
            .is_err()
        );
        symlink("missing", temp.path().join("dangling")).unwrap();
        assert!(
            check(
                &package(INFO, &[Member::File("dangling/file", b"new")]),
                temp.path()
            )
            .is_err()
        );
        let bytes = package(
            INFO,
            &[
                Member::Directory("made"),
                Member::Symlink("alias", "made"),
                Member::File("alias/file", b"new"),
            ],
        );
        check(&bytes, temp.path()).unwrap();
        assert!(!temp.path().join("made").exists());
    }

    #[test]
    fn rejects_unsupported_types_and_pax_sparse() {
        let temp = tempfile::tempdir().unwrap();
        for kind in [
            tar::EntryType::Fifo,
            tar::EntryType::Char,
            tar::EntryType::Block,
            tar::EntryType::GNUSparse,
            tar::EntryType::new(b'Z'),
        ] {
            assert!(
                check(
                    &package(INFO, &[Member::Special("file", kind)]),
                    temp.path()
                )
                .is_err()
            );
        }
        for (key, value) in [
            ("GNU.sparse.map", b"0,1".as_slice()),
            ("SCHILY.filetype", b"sparse".as_slice()),
        ] {
            let bytes = package(INFO, &[Member::Pax(key, value), Member::File("file", b"x")]);
            assert!(check(&bytes, temp.path()).is_err());
        }
        let bytes = package(
            INFO,
            &[
                Member::Pax("comment", b"ordinary metadata"),
                Member::File("file", b"x"),
            ],
        );
        check(&bytes, temp.path()).unwrap();
    }

    #[test]
    fn incompatible_destinations_fail_without_changing_earlier_members() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("file"), b"old").unwrap();
        std::fs::create_dir(temp.path().join("data")).unwrap();
        std::fs::write(temp.path().join("data/user-file"), b"keep").unwrap();
        for member in [
            Member::Directory("file"),
            Member::File("data", b"new"),
            Member::Symlink("data", "target"),
        ] {
            let bytes = package(INFO, &[Member::File("earlier", b"new"), member]);
            assert!(check(&bytes, temp.path()).is_err());
            assert!(!temp.path().join("earlier").exists());
            assert_eq!(std::fs::read(temp.path().join("file")).unwrap(), b"old");
            assert_eq!(
                std::fs::read(temp.path().join("data/user-file")).unwrap(),
                b"keep"
            );
        }
        let bytes = package(
            INFO,
            &[
                Member::File("parent/child", b"new"),
                Member::Symlink("parent", "target"),
            ],
        );
        assert!(check(&bytes, temp.path()).is_err());
    }

    #[test]
    fn permits_file_symlink_and_empty_directory_replacements() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(temp.path().join("file"), b"old").unwrap();
        symlink("missing", temp.path().join("link")).unwrap();
        std::fs::create_dir(temp.path().join("empty")).unwrap();
        for member in [
            Member::Symlink("file", "/absolute/target"),
            Member::File("link", b"new"),
            Member::Symlink("link", "other"),
            Member::File("empty", b"new"),
            Member::Symlink("empty", "other"),
        ] {
            check(&package(INFO, &[member]), temp.path()).unwrap();
        }
        assert_eq!(std::fs::read(temp.path().join("file")).unwrap(), b"old");
        assert_eq!(
            std::fs::read_link(temp.path().join("link")).unwrap(),
            Path::new("missing")
        );
        assert!(temp.path().join("empty").is_dir());
    }

    #[test]
    fn detects_existing_and_incoming_pacnew_directories() {
        let temp = tempfile::tempdir().unwrap();
        let info = format!("{INFO}backup = etc/config\n");
        std::fs::create_dir_all(temp.path().join("etc/config.pacnew")).unwrap();
        std::fs::write(temp.path().join("etc/config"), b"edited").unwrap();
        let bytes = package(&info, &[Member::File("etc/config", b"new")]);
        let error = check(&bytes, temp.path()).unwrap_err().to_string();
        assert!(error.contains(".pacnew"), "{error}");
        assert_eq!(
            std::fs::read(temp.path().join("etc/config")).unwrap(),
            b"edited"
        );
        let missing = temp.path().join("missing");
        let bytes = package(
            &info,
            &[
                Member::File("etc/config", b"new"),
                Member::Directory("etc/config.pacnew"),
            ],
        );
        assert!(check(&bytes, &missing).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn streams_large_regular_payloads_and_bounds_pkginfo() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("large.pkg.tar");
        let mut builder = tar::Builder::new(File::create(&path).unwrap());
        for (name, size, reader) in [
            (
                ".PKGINFO",
                INFO.len() as u64,
                Box::new(INFO.as_bytes()) as Box<dyn Read>,
            ),
            (
                "large",
                16 * 1024 * 1024,
                Box::new(io::repeat(0x5a).take(16 * 1024 * 1024)) as Box<dyn Read>,
            ),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(size);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, reader).unwrap();
        }
        builder.finish().unwrap();
        drop(builder);
        let root = temp.path().join("missing");
        validate_archive(&path, &root, None).unwrap();
        assert!(!root.exists());
        let bytes = package(&"x".repeat(PKGINFO_LIMIT as usize + 1), &[]);
        assert!(check(&bytes, &root).is_err());
    }
}
