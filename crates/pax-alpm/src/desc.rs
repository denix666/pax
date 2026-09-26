use std::collections::HashMap;

use pax_core::error::Result;
use pax_core::package::*;
use pax_core::version::Version;

pub fn parse_desc(input: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::with_capacity(20);
    let mut current_key: Option<&str> = None;
    let mut current_values: Vec<String> = Vec::new();

    for line in input.lines() {
        if line.starts_with('%') && line.ends_with('%') && line.len() > 2 {
            if let Some(key) = current_key.take() {
                if !current_values.is_empty() {
                    map.insert(key.to_string(), std::mem::take(&mut current_values));
                }
            }
            current_key = Some(&line[1..line.len() - 1]);
            continue;
        }

        if line.is_empty() {
            if let Some(key) = current_key.take() {
                if !current_values.is_empty() {
                    map.insert(key.to_string(), std::mem::take(&mut current_values));
                }
            }
            continue;
        }

        if current_key.is_some() {
            current_values.push(line.to_string());
        }
    }

    if let Some(key) = current_key {
        if !current_values.is_empty() {
            map.insert(key.to_string(), current_values);
        }
    }

    map
}

fn get_single(map: &HashMap<String, Vec<String>>, key: &str) -> String {
    map.get(key)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default()
}

fn get_single_opt(map: &HashMap<String, Vec<String>>, key: &str) -> Option<String> {
    map.get(key).and_then(|v| v.first()).cloned()
}

fn get_multi(map: &HashMap<String, Vec<String>>, key: &str) -> Vec<String> {
    map.get(key).cloned().unwrap_or_default()
}

fn parse_deps(map: &HashMap<String, Vec<String>>, key: &str) -> Vec<Dependency> {
    get_multi(map, key)
        .iter()
        .filter_map(|s| Dependency::parse(s).ok())
        .collect()
}

fn parse_optdeps(map: &HashMap<String, Vec<String>>, key: &str) -> Vec<OptionalDependency> {
    get_multi(map, key)
        .iter()
        .filter_map(|s| OptionalDependency::parse(s).ok())
        .collect()
}

pub fn desc_to_package_info(map: &HashMap<String, Vec<String>>) -> Result<PackageInfo> {
    let version = Version::parse(&get_single(map, "VERSION"))?;

    Ok(PackageInfo {
        name: get_single(map, "NAME"),
        version,
        base: get_single_opt(map, "BASE"),
        description: get_single(map, "DESC"),
        url: get_single_opt(map, "URL"),
        arch: get_single(map, "ARCH"),
        build_date: get_single(map, "BUILDDATE").parse().unwrap_or(0),
        packager: get_single(map, "PACKAGER"),
        licenses: get_multi(map, "LICENSE"),
        groups: get_multi(map, "GROUPS"),
        depends: parse_deps(map, "DEPENDS"),
        optdepends: parse_optdeps(map, "OPTDEPENDS"),
        provides: parse_deps(map, "PROVIDES"),
        conflicts: parse_deps(map, "CONFLICTS"),
        replaces: parse_deps(map, "REPLACES"),
        xdata: get_multi(map, "XDATA"),
    })
}

pub fn desc_to_local_package(map: &HashMap<String, Vec<String>>) -> Result<LocalPackage> {
    let info = desc_to_package_info(map)?;

    let reason = match get_single(map, "REASON").as_str() {
        "1" => InstallReason::Dependency,
        _ => InstallReason::Explicit,
    };

    let validation = get_multi(map, "VALIDATION")
        .iter()
        .flat_map(|s| s.split_whitespace())
        .map(|s| match s {
            "pgp" => Validation::Pgp,
            "sha256" => Validation::Sha256,
            "md5" => Validation::Md5,
            "none" => Validation::None,
            other => Validation::Unknown(other.to_string()),
        })
        .collect();

    Ok(LocalPackage {
        info,
        install_date: get_single(map, "INSTALLDATE").parse().unwrap_or(0),
        size: get_single(map, "SIZE").parse().unwrap_or(0),
        reason,
        validation,
    })
}

pub fn desc_to_sync_package(
    map: &HashMap<String, Vec<String>>,
    repository: &str,
) -> Result<SyncPackage> {
    let info = desc_to_package_info(map)?;

    Ok(SyncPackage {
        info,
        filename: get_single(map, "FILENAME"),
        compressed_size: get_single(map, "CSIZE").parse().unwrap_or(0),
        installed_size: get_single(map, "ISIZE").parse().unwrap_or(0),
        md5sum: get_single_opt(map, "MD5SUM"),
        sha256sum: get_single_opt(map, "SHA256SUM"),
        pgpsig: get_single_opt(map, "PGPSIG"),
        makedepends: parse_deps(map, "MAKEDEPENDS"),
        checkdepends: parse_deps(map, "CHECKDEPENDS"),
        repository: repository.to_string(),
    })
}

pub fn generate_local_desc(
    pkg: &LocalPackage,
    installed_size: u64,
    install_date: i64,
    reason: InstallReason,
    validation: &[Validation],
) -> String {
    let mut out = String::new();
    let info = &pkg.info;

    write_field(&mut out, "NAME", &info.name);
    write_field(&mut out, "VERSION", &info.version.to_string());
    if let Some(ref base) = info.base {
        write_field(&mut out, "BASE", base);
    }
    write_field(&mut out, "DESC", &info.description);
    if let Some(ref url) = info.url {
        write_field(&mut out, "URL", url);
    }
    write_field(&mut out, "ARCH", &info.arch);
    write_field(&mut out, "BUILDDATE", &info.build_date.to_string());
    write_field(&mut out, "INSTALLDATE", &install_date.to_string());
    write_field(&mut out, "PACKAGER", &info.packager);
    write_field(&mut out, "SIZE", &installed_size.to_string());

    match reason {
        InstallReason::Dependency => write_field(&mut out, "REASON", "1"),
        InstallReason::Explicit => {}
    }

    for lic in &info.licenses {
        write_field(&mut out, "LICENSE", lic);
    }

    let val_str: Vec<&str> = validation
        .iter()
        .map(|v| match v {
            Validation::Pgp => "pgp",
            Validation::Sha256 => "sha256",
            Validation::Md5 => "md5",
            Validation::None => "none",
            Validation::Unknown(s) => s.as_str(),
        })
        .collect();
    if !val_str.is_empty() {
        write_field(&mut out, "VALIDATION", &val_str.join(" "));
    }

    write_multi_deps(&mut out, "REPLACES", &info.replaces);
    write_multi_deps(&mut out, "DEPENDS", &info.depends);
    write_multi_optdeps(&mut out, "OPTDEPENDS", &info.optdepends);
    write_multi_deps(&mut out, "CONFLICTS", &info.conflicts);
    write_multi_deps(&mut out, "PROVIDES", &info.provides);

    for group in &info.groups {
        write_field(&mut out, "GROUPS", group);
    }

    for xd in &info.xdata {
        write_field(&mut out, "XDATA", xd);
    }

    out
}

pub fn generate_local_desc_from_pkginfo(
    pkginfo: &str,
    installed_size: u64,
    install_date: i64,
    reason: InstallReason,
    validation: &[Validation],
) -> String {
    let fields = parse_pkginfo(pkginfo);
    let mut out = String::new();

    write_field(&mut out, "NAME", fields.get("pkgname").map(|v| v[0].as_str()).unwrap_or(""));
    write_field(&mut out, "VERSION", fields.get("pkgver").map(|v| v[0].as_str()).unwrap_or(""));
    if let Some(base) = fields.get("pkgbase").and_then(|v| v.first()) {
        write_field(&mut out, "BASE", base);
    }
    write_field(&mut out, "DESC", fields.get("pkgdesc").map(|v| v[0].as_str()).unwrap_or(""));
    if let Some(url) = fields.get("url").and_then(|v| v.first()) {
        write_field(&mut out, "URL", url);
    }
    write_field(&mut out, "ARCH", fields.get("arch").map(|v| v[0].as_str()).unwrap_or(""));
    write_field(&mut out, "BUILDDATE", fields.get("builddate").map(|v| v[0].as_str()).unwrap_or("0"));
    write_field(&mut out, "INSTALLDATE", &install_date.to_string());
    write_field(&mut out, "PACKAGER", fields.get("packager").map(|v| v[0].as_str()).unwrap_or(""));
    write_field(&mut out, "SIZE", &installed_size.to_string());

    match reason {
        InstallReason::Dependency => write_field(&mut out, "REASON", "1"),
        InstallReason::Explicit => {}
    }

    if let Some(licenses) = fields.get("license") {
        for lic in licenses {
            write_field(&mut out, "LICENSE", lic);
        }
    }

    let val_str: Vec<&str> = validation
        .iter()
        .map(|v| match v {
            Validation::Pgp => "pgp",
            Validation::Sha256 => "sha256",
            Validation::Md5 => "md5",
            Validation::None => "none",
            Validation::Unknown(s) => s.as_str(),
        })
        .collect();
    if !val_str.is_empty() {
        write_field(&mut out, "VALIDATION", &val_str.join(" "));
    }

    write_multi_raw(&mut out, "REPLACES", fields.get("replaces"));
    write_multi_raw(&mut out, "DEPENDS", fields.get("depend"));
    write_multi_raw(&mut out, "OPTDEPENDS", fields.get("optdepend"));
    write_multi_raw(&mut out, "CONFLICTS", fields.get("conflict"));
    write_multi_raw(&mut out, "PROVIDES", fields.get("provides"));
    write_multi_raw(&mut out, "GROUPS", fields.get("group"));
    write_multi_raw(&mut out, "XDATA", fields.get("xdata"));

    out
}

pub fn generate_files_content(files: &[String], backup: &[(String, String)]) -> String {
    let mut out = String::from("%FILES%\n");
    for f in files {
        out.push_str(f);
        out.push('\n');
    }
    out.push('\n');

    if !backup.is_empty() {
        out.push_str("%BACKUP%\n");
        for (path, md5) in backup {
            out.push_str(path);
            out.push('\t');
            out.push_str(md5);
            out.push('\n');
        }
        out.push('\n');
    }

    out
}

fn parse_pkginfo(pkginfo: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for line in pkginfo.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(" = ") {
            map.entry(key.to_string())
                .or_default()
                .push(value.to_string());
        }
    }
    map
}

fn write_field(out: &mut String, field: &str, value: &str) {
    out.push('%');
    out.push_str(field);
    out.push_str("%\n");
    out.push_str(value);
    out.push_str("\n\n");
}

fn write_multi_deps(out: &mut String, field: &str, deps: &[Dependency]) {
    if deps.is_empty() {
        return;
    }
    out.push('%');
    out.push_str(field);
    out.push_str("%\n");
    for dep in deps {
        out.push_str(&dep.to_string());
        out.push('\n');
    }
    out.push('\n');
}

fn write_multi_optdeps(out: &mut String, field: &str, deps: &[OptionalDependency]) {
    if deps.is_empty() {
        return;
    }
    out.push('%');
    out.push_str(field);
    out.push_str("%\n");
    for dep in deps {
        out.push_str(&dep.to_string());
        out.push('\n');
    }
    out.push('\n');
}

fn write_multi_raw(out: &mut String, field: &str, values: Option<&Vec<String>>) {
    let Some(vals) = values else { return };
    if vals.is_empty() {
        return;
    }
    out.push('%');
    out.push_str(field);
    out.push_str("%\n");
    for v in vals {
        out.push_str(v);
        out.push('\n');
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_desc() {
        let input = r#"%NAME%
gcc

%VERSION%
16.2.1+r23+gd564253eb6c8-1

%DESC%
The GNU Compiler Collection

%DEPENDS%
glibc>=2.27
libmpc
zlib

"#;
        let map = parse_desc(input);
        assert_eq!(map["NAME"], vec!["gcc"]);
        assert_eq!(map["VERSION"], vec!["16.2.1+r23+gd564253eb6c8-1"]);
        assert_eq!(map["DESC"], vec!["The GNU Compiler Collection"]);
        assert_eq!(map["DEPENDS"], vec!["glibc>=2.27", "libmpc", "zlib"]);
    }

    #[test]
    fn test_desc_to_local_package() {
        let input = r#"%NAME%
test-pkg

%VERSION%
1.0-1

%DESC%
A test package

%ARCH%
x86_64

%BUILDDATE%
1700000000

%INSTALLDATE%
1700000100

%PACKAGER%
Test <test@test.com>

%SIZE%
12345

%REASON%
1

%DEPENDS%
glibc
openssl>=3.0

"#;
        let map = parse_desc(input);
        let pkg = desc_to_local_package(&map).unwrap();
        assert_eq!(pkg.info.name, "test-pkg");
        assert_eq!(pkg.reason, InstallReason::Dependency);
        assert_eq!(pkg.size, 12345);
        assert_eq!(pkg.info.depends.len(), 2);
        assert_eq!(pkg.info.depends[1].name, "openssl");
    }

    #[test]
    fn test_generate_desc_from_pkginfo() {
        let pkginfo = r#"# Generated by makepkg 7.1.0
pkgname = test-pkg
pkgbase = test-pkg
pkgver = 1.0-1
pkgdesc = A test package
url = https://example.com
builddate = 1700000000
packager = Test <test@test.com>
size = 12345
arch = x86_64
license = MIT
depend = glibc
depend = openssl>=3.0
xdata = pkgtype=pkg
"#;
        let desc = generate_local_desc_from_pkginfo(
            pkginfo,
            12345,
            1700000100,
            InstallReason::Explicit,
            &[Validation::Sha256],
        );

        let map = parse_desc(&desc);
        assert_eq!(map["NAME"], vec!["test-pkg"]);
        assert_eq!(map["VERSION"], vec!["1.0-1"]);
        assert_eq!(map["BASE"], vec!["test-pkg"]);
        assert_eq!(map["INSTALLDATE"], vec!["1700000100"]);
        assert_eq!(map["SIZE"], vec!["12345"]);
        assert_eq!(map["VALIDATION"], vec!["sha256"]);
        assert_eq!(map["DEPENDS"], vec!["glibc", "openssl>=3.0"]);
        assert!(!map.contains_key("REASON"));
    }

    #[test]
    fn test_generate_files_content() {
        let files = vec!["usr/".to_string(), "usr/bin/".to_string(), "usr/bin/test".to_string()];
        let backup = vec![("etc/test.conf".to_string(), "abc123".to_string())];
        let content = generate_files_content(&files, &backup);

        let parsed = crate::files::parse_files(&content);
        assert_eq!(parsed.files, files);
        assert_eq!(parsed.backup.len(), 1);
        assert_eq!(parsed.backup[0].path, "etc/test.conf");
        assert_eq!(parsed.backup[0].md5, "abc123");
    }

    #[test]
    fn test_parse_pkginfo() {
        let pkginfo = r#"# Generated by makepkg
pkgname = nginx
pkgver = 1.30.4-1
backup = etc/nginx/nginx.conf
backup = etc/nginx/fastcgi.conf
depend = glibc
depend = pcre2
"#;
        let fields = parse_pkginfo(pkginfo);
        assert_eq!(fields["pkgname"], vec!["nginx"]);
        assert_eq!(fields["backup"], vec!["etc/nginx/nginx.conf", "etc/nginx/fastcgi.conf"]);
        assert_eq!(fields["depend"], vec!["glibc", "pcre2"]);
    }
}
