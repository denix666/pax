use serde::Deserialize;

use crate::error::{AurError, Result};

const AUR_RPC_URL: &str = "https://aur.archlinux.org/rpc/v5";

fn aur_agent() -> ureq::Agent {
    use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
    ureq::Agent::config_builder()
        .tls_config(
            TlsConfig::builder()
                .provider(TlsProvider::NativeTls)
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .new_agent()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AurPackage {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub maintainer: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    #[serde(rename = "URLPath")]
    pub url_path: Option<String>,
    pub package_base: String,
    #[serde(rename = "PackageBaseID")]
    pub package_base_id: u64,
    pub num_votes: u32,
    pub popularity: f64,
    pub out_of_date: Option<u64>,
    pub first_submitted: u64,
    pub last_modified: u64,
    #[serde(default)]
    pub depends: Vec<String>,
    #[serde(default)]
    pub make_depends: Vec<String>,
    #[serde(default)]
    pub check_depends: Vec<String>,
    #[serde(default)]
    pub opt_depends: Vec<String>,
    #[serde(default)]
    pub conflicts: Vec<String>,
    #[serde(default)]
    pub provides: Vec<String>,
    #[serde(default)]
    pub replaces: Vec<String>,
    #[serde(default)]
    pub license: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RpcResponse {
    resultcount: u32,
    results: Vec<AurPackage>,
    #[serde(rename = "type")]
    response_type: String,
    #[serde(default)]
    error: Option<String>,
}

pub fn suggest(prefix: &str) -> Result<Vec<String>> {
    let url = format!("https://aur.archlinux.org/rpc/v5/suggest/{}", urlenc(prefix));
    let body = aur_agent()
        .get(&url)
        .call()
        .map_err(|e| AurError::Http(e.to_string()))?
        .into_body()
        .read_to_string()
        .map_err(|e| AurError::Http(e.to_string()))?;
    let names: Vec<String> = serde_json::from_str(&body)?;
    Ok(names)
}

pub fn search(query: &str) -> Result<Vec<AurPackage>> {
    let url = format!("{AUR_RPC_URL}/search?arg={}&by=name-desc", urlenc(query));
    let resp = do_request(&url)?;
    Ok(resp.results)
}

pub fn info(names: &[&str]) -> Result<Vec<AurPackage>> {
    if names.is_empty() {
        return Ok(Vec::new());
    }

    let args: String = names.iter().map(|n| format!("&arg[]={}", urlenc(n))).collect();
    let url = format!("{AUR_RPC_URL}/info?{}", &args[1..]);
    let resp = do_request(&url)?;
    Ok(resp.results)
}

fn do_request(url: &str) -> Result<RpcResponse> {
    let body = aur_agent()
        .get(url)
        .call()
        .map_err(|e| AurError::Http(e.to_string()))?
        .into_body()
        .read_to_string()
        .map_err(|e| AurError::Http(e.to_string()))?;

    let resp: RpcResponse = serde_json::from_str(&body)?;

    if let Some(err) = resp.error {
        return Err(AurError::Api(err));
    }

    Ok(resp)
}

fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_urlenc() {
        assert_eq!(urlenc("yay"), "yay");
        assert_eq!(urlenc("foo bar"), "foo%20bar");
        assert_eq!(urlenc("a+b"), "a%2Bb");
    }
}
