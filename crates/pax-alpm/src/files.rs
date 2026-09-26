use pax_core::package::BackupFile;

pub struct ParsedFiles {
    pub files: Vec<String>,
    pub backup: Vec<BackupFile>,
}

pub fn parse_files(input: &str) -> ParsedFiles {
    let mut files = Vec::new();
    let mut backup = Vec::new();
    let mut current_section: Option<&str> = None;

    for line in input.lines() {
        if line.starts_with('%') && line.ends_with('%') {
            current_section = Some(match line {
                "%FILES%" => "files",
                "%BACKUP%" => "backup",
                _ => "",
            });
            continue;
        }

        if line.is_empty() {
            current_section = None;
            continue;
        }

        match current_section {
            Some("files") => {
                files.push(line.to_string());
            }
            Some("backup") => {
                if let Some((path, md5)) = line.split_once('\t') {
                    backup.push(BackupFile {
                        path: path.to_string(),
                        md5: md5.to_string(),
                    });
                }
            }
            _ => {}
        }
    }

    ParsedFiles { files, backup }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_files() {
        let input = r#"%FILES%
usr/
usr/bin/
usr/bin/gcc
usr/include/

%BACKUP%
etc/gcc/config.conf	abc123def456

"#;
        let result = parse_files(input);
        assert_eq!(result.files.len(), 4);
        assert_eq!(result.files[2], "usr/bin/gcc");
        assert_eq!(result.backup.len(), 1);
        assert_eq!(result.backup[0].path, "etc/gcc/config.conf");
        assert_eq!(result.backup[0].md5, "abc123def456");
    }
}
