use crate::error::{PaxError, Result};
use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Version {
    pub epoch: u32,
    pub pkgver: String,
    pub pkgrel: String,
}

impl Version {
    pub fn parse(s: &str) -> Result<Self> {
        let (epoch, rest) = match s.find(':') {
            Some(pos) => {
                let epoch_str = &s[..pos];
                let epoch = epoch_str
                    .parse::<u32>()
                    .map_err(|_| PaxError::InvalidVersion(s.to_string()))?;
                (epoch, &s[pos + 1..])
            }
            None => (0, s),
        };

        let (pkgver, pkgrel) = match rest.rfind('-') {
            Some(pos) => (rest[..pos].to_string(), rest[pos + 1..].to_string()),
            None => (rest.to_string(), String::new()),
        };

        if pkgver.is_empty() {
            return Err(PaxError::InvalidVersion(s.to_string()));
        }

        Ok(Version {
            epoch,
            pkgver,
            pkgrel,
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.epoch > 0 {
            write!(f, "{}:", self.epoch)?;
        }
        write!(f, "{}", self.pkgver)?;
        if !self.pkgrel.is_empty() {
            write!(f, "-{}", self.pkgrel)?;
        }
        Ok(())
    }
}

impl Version {
    /// Compare ignoring pkgrel (used when dep constraint has no pkgrel, matching pacman behavior)
    pub fn cmp_no_pkgrel(&self, other: &Self) -> Ordering {
        let epoch_cmp = self.epoch.cmp(&other.epoch);
        if epoch_cmp != Ordering::Equal {
            return epoch_cmp;
        }
        vercmp_segment(&self.pkgver, &other.pkgver)
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let epoch_cmp = self.epoch.cmp(&other.epoch);
        if epoch_cmp != Ordering::Equal {
            return epoch_cmp;
        }

        let ver_cmp = vercmp_segment(&self.pkgver, &other.pkgver);
        if ver_cmp != Ordering::Equal {
            return ver_cmp;
        }

        vercmp_segment(&self.pkgrel, &other.pkgrel)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Exact reimplementation of pacman's rpmvercmp from lib/libalpm/version.c
fn vercmp_segment(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }

    let a = a.as_bytes();
    let b = b.as_bytes();

    let mut one = 0usize;
    let mut two = 0usize;
    let mut ptr1;
    let mut ptr2;

    while one < a.len() && two < b.len() {
        let prev_one = one;
        let prev_two = two;

        while one < a.len() && !a[one].is_ascii_alphanumeric() {
            one += 1;
        }
        while two < b.len() && !b[two].is_ascii_alphanumeric() {
            two += 1;
        }

        if one >= a.len() || two >= b.len() {
            break;
        }

        // If separator lengths differ, the one with fewer separators is newer
        let sep_len_a = one - prev_one;
        let sep_len_b = two - prev_two;
        if sep_len_a != sep_len_b {
            return if sep_len_a < sep_len_b {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }

        ptr1 = one;
        ptr2 = two;

        let isnum = if a[ptr1].is_ascii_digit() {
            while ptr1 < a.len() && a[ptr1].is_ascii_digit() {
                ptr1 += 1;
            }
            while ptr2 < b.len() && b[ptr2].is_ascii_digit() {
                ptr2 += 1;
            }
            true
        } else {
            while ptr1 < a.len() && a[ptr1].is_ascii_alphabetic() {
                ptr1 += 1;
            }
            while ptr2 < b.len() && b[ptr2].is_ascii_alphabetic() {
                ptr2 += 1;
            }
            false
        };

        // one segment is empty (e.g., one is digit, two is alpha → two had no digits)
        if one == ptr1 {
            return Ordering::Less;
        }
        if two == ptr2 {
            return if isnum {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        let seg_a = &a[one..ptr1];
        let seg_b = &b[two..ptr2];

        if isnum {
            let ta = trim_leading_zeros(seg_a);
            let tb = trim_leading_zeros(seg_b);

            let len_cmp = ta.len().cmp(&tb.len());
            if len_cmp != Ordering::Equal {
                return len_cmp;
            }
            let cmp = ta.cmp(tb);
            if cmp != Ordering::Equal {
                return cmp;
            }
        } else {
            let cmp = seg_a.cmp(seg_b);
            if cmp != Ordering::Equal {
                return cmp;
            }
        }

        one = ptr1;
        two = ptr2;
    }

    if one >= a.len() && two >= b.len() {
        return Ordering::Equal;
    }

    // The final showdown: we never want a remaining alpha string to
    // beat an empty string.
    let one_ch = a.get(one);
    let two_ch = b.get(two);

    if (one_ch.is_none() && two_ch.is_some_and(|c| !c.is_ascii_alphabetic()))
        || one_ch.is_some_and(|c| c.is_ascii_alphabetic())
    {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

fn trim_leading_zeros(s: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < s.len() - 1 && s[i] == b'0' {
        i += 1;
    }
    &s[i..]
}

/// Split a directory name like "gcc-16.2.1+r23+gfoo-1" into ("gcc", "16.2.1+r23+gfoo-1").
/// The version always contains exactly one hyphen (pkgver-pkgrel),
/// so we find the second-to-last hyphen.
pub fn split_namever(dirname: &str) -> Option<(&str, &str)> {
    let last = dirname.rfind('-')?;
    if last == 0 {
        return None;
    }
    let second_last = dirname[..last].rfind('-')?;
    let name = &dirname[..second_last];
    let version = &dirname[second_last + 1..];
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name, version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parse() {
        let v = Version::parse("1.2.3-1").unwrap();
        assert_eq!(v.epoch, 0);
        assert_eq!(v.pkgver, "1.2.3");
        assert_eq!(v.pkgrel, "1");

        let v = Version::parse("2:1.6.8-1").unwrap();
        assert_eq!(v.epoch, 2);
        assert_eq!(v.pkgver, "1.6.8");
        assert_eq!(v.pkgrel, "1");
    }

    #[test]
    fn test_version_display() {
        let v = Version::parse("1.2.3-1").unwrap();
        assert_eq!(v.to_string(), "1.2.3-1");

        let v = Version::parse("2:1.6.8-1").unwrap();
        assert_eq!(v.to_string(), "2:1.6.8-1");
    }

    #[test]
    fn test_vercmp() {
        assert!(Version::parse("1.0-1").unwrap() < Version::parse("1.1-1").unwrap());
        assert!(Version::parse("1.1-1").unwrap() > Version::parse("1.0-1").unwrap());
        assert!(Version::parse("1.0-1").unwrap() == Version::parse("1.0-1").unwrap());
        assert!(Version::parse("1:1.0-1").unwrap() > Version::parse("2.0-1").unwrap());
        assert!(Version::parse("1.0-2").unwrap() > Version::parse("1.0-1").unwrap());
        assert!(Version::parse("1.0a-1").unwrap() < Version::parse("1.0b-1").unwrap());
        assert!(Version::parse("1.0-1").unwrap() > Version::parse("1.0rc1-1").unwrap());
        assert!(Version::parse("1.0.1-1").unwrap() > Version::parse("1.0-1").unwrap());
    }

    #[test]
    fn test_vercmp_complex() {
        assert!(
            Version::parse("16.2.1+r23+gd564253eb6c8-1").unwrap()
                > Version::parse("16.2.0-1").unwrap()
        );
        assert!(
            Version::parse("2.44+r24+g16be1518495f-1").unwrap()
                > Version::parse("2.44-1").unwrap()
        );
    }

    #[test]
    fn test_vercmp_alpha_suffix() {
        // Alpha directly after digit = pre-release (older)
        assert!(Version::parse("1.0a-1").unwrap() < Version::parse("1.0-1").unwrap());
        assert!(Version::parse("1.0beta1-1").unwrap() < Version::parse("1.0-1").unwrap());
        // Alpha after separator = new segment (newer)
        assert!(Version::parse("1.0.a-1").unwrap() > Version::parse("1.0-1").unwrap());
        assert!(Version::parse("1.0.rc1-1").unwrap() > Version::parse("1.0-1").unwrap());
        // Extra numeric segment after separator = newer
        assert!(Version::parse("1.0.1-1").unwrap() > Version::parse("1.0-1").unwrap());
        assert!(Version::parse("1.0.0-1").unwrap() > Version::parse("1.0-1").unwrap());
    }

    #[test]
    fn test_cmp_no_pkgrel() {
        let v = Version::parse("17.2-1").unwrap();
        let dep_ver = Version::parse("17.2").unwrap();
        assert_eq!(v.cmp_no_pkgrel(&dep_ver), Ordering::Equal);

        let v2 = Version::parse("17.3-1").unwrap();
        assert_eq!(v2.cmp_no_pkgrel(&dep_ver), Ordering::Greater);

        let v3 = Version::parse("17.1-2").unwrap();
        assert_eq!(v3.cmp_no_pkgrel(&dep_ver), Ordering::Less);
    }

    #[test]
    fn test_split_namever() {
        assert_eq!(
            split_namever("gcc-16.2.1+r23+gd564253eb6c8-1"),
            Some(("gcc", "16.2.1+r23+gd564253eb6c8-1"))
        );
        assert_eq!(
            split_namever("python-pyxdg-0.28-7"),
            Some(("python-pyxdg", "0.28-7"))
        );
        assert_eq!(split_namever("7zip-26.03-1"), Some(("7zip", "26.03-1")));
        assert_eq!(
            split_namever("lib32-gcc-libs-16.2.1-1"),
            Some(("lib32-gcc-libs", "16.2.1-1"))
        );
    }
}
