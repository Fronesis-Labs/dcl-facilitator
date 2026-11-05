//! Runtime configuration from environment variables.

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8080;
const DEFAULT_RECEIPT_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone)]
pub struct Config {
    pub host: IpAddr,
    pub port: u16,
    /// Base mainnet JSON-RPC URL. Absent means `/verify` cannot accept a
    /// payload and `/settle` cannot broadcast. No public host is assumed.
    pub base_rpc_url: Option<String>,
    pub database_path: Option<String>,
    /// Absolute path to a hex-encoded relayer key outside this repository.
    pub settler_key_file: Option<String>,
    /// Address whose signature must be on `decisionEvidence`. Absent means
    /// `/settle` cannot sign or broadcast.
    pub oracle_address: Option<[u8; 20]>,
    pub settler_max_fee_per_gas: Option<u128>,
    pub receipt_timeout: Duration,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("invalid HOST value: {0}")]
    Host(String),
    #[error("invalid PORT value: {0}")]
    Port(String),
    #[error("invalid BASE_RPC_URL value")]
    RpcUrl,
    #[error("invalid DATABASE_PATH value")]
    Database,
    #[error("invalid settler key file")]
    SettlerKey,
    #[error("settler key file must be outside the repository")]
    KeyLocation,
    #[error("invalid SETTLER_MAX_FEE_PER_GAS value")]
    MaxFee,
    #[error("invalid ORACLE_ADDRESS value")]
    Oracle,
    #[error("invalid SETTLE_RECEIPT_TIMEOUT_SECS value")]
    ReceiptTimeout,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Separate from `from_env` so tests do not have to touch process state.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let host_raw = get("HOST").unwrap_or_else(|| DEFAULT_HOST.to_string());
        let host = host_raw
            .parse::<IpAddr>()
            .map_err(|_| ConfigError::Host(host_raw))?;

        let port = match get("PORT") {
            None => DEFAULT_PORT,
            Some(raw) => raw.parse::<u16>().map_err(|_| ConfigError::Port(raw))?,
        };

        let base_rpc_url = match get("BASE_RPC_URL") {
            None => None,
            Some(raw) => Some(parse_rpc_url(raw)?),
        };
        let database_path = match get("DATABASE_PATH") {
            None => None,
            Some(raw) => Some(parse_database_path(raw)?),
        };
        let settler_key_file = match get("SETTLER_KEY_FILE") {
            None => None,
            Some(raw) => Some(parse_key_path(raw)?),
        };
        let oracle_address = match get("ORACLE_ADDRESS") {
            None => None,
            Some(raw) => Some(parse_oracle(&raw)?),
        };
        let settler_max_fee_per_gas = match get("SETTLER_MAX_FEE_PER_GAS") {
            None => None,
            Some(raw) => Some(parse_fee(raw)?),
        };
        if settler_key_file.is_some() != settler_max_fee_per_gas.is_some() {
            return Err(ConfigError::SettlerKey);
        }
        if let Some(path) = &settler_key_file {
            ensure_key_outside_repository(path)?;
        }
        let receipt_timeout = match get("SETTLE_RECEIPT_TIMEOUT_SECS") {
            None => DEFAULT_RECEIPT_TIMEOUT,
            Some(raw) => {
                let seconds = raw
                    .parse::<u64>()
                    .map_err(|_| ConfigError::ReceiptTimeout)?;
                if !(1..=120).contains(&seconds) {
                    return Err(ConfigError::ReceiptTimeout);
                }
                Duration::from_secs(seconds)
            }
        };

        Ok(Self {
            host,
            port,
            base_rpc_url,
            database_path,
            settler_key_file,
            oracle_address,
            settler_max_fee_per_gas,
            receipt_timeout,
        })
    }
}

fn parse_database_path(raw: String) -> Result<String, ConfigError> {
    if raw.trim() != raw || raw.is_empty() {
        return Err(ConfigError::Database);
    }
    Ok(raw)
}

fn parse_key_path(raw: String) -> Result<String, ConfigError> {
    if raw.trim() != raw || raw.is_empty() || !Path::new(&raw).is_absolute() {
        return Err(ConfigError::SettlerKey);
    }
    Ok(raw)
}

/// Reject a key whose path, or whose symlink target, is inside this repository.
/// The error does not include the path or any key bytes.
fn ensure_key_outside_repository(path: &str) -> Result<(), ConfigError> {
    let root = std::fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")))
        .map_err(|_| ConfigError::SettlerKey)?;
    let configured = Path::new(path);
    if is_inside(&root, &lexical_absolute(configured)) {
        return Err(ConfigError::KeyLocation);
    }
    let resolved = std::fs::canonicalize(configured).map_err(|_| ConfigError::SettlerKey)?;
    if is_inside(&root, &resolved) {
        return Err(ConfigError::KeyLocation);
    }
    Ok(())
}

fn lexical_absolute(path: &Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            _ => out.push(component),
        }
    }
    out
}

fn is_inside(root: &Path, path: &Path) -> bool {
    let root = compare_key(root);
    let path = compare_key(path);
    let root = root.trim_end_matches(['\\', '/']);
    path == root || path.starts_with(&format!("{root}\\")) || path.starts_with(&format!("{root}/"))
}

fn compare_key(path: &Path) -> String {
    let owned = path.to_string_lossy().into_owned();
    let text = if let Some(rest) = owned.strip_prefix(r"\\?\") {
        rest
    } else if let Some(rest) = owned.strip_prefix("//?/") {
        rest
    } else {
        owned.as_str()
    };
    #[cfg(windows)]
    {
        text.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        text.to_string()
    }
}

fn parse_oracle(raw: &str) -> Result<[u8; 20], ConfigError> {
    if raw.trim() != raw {
        return Err(ConfigError::Oracle);
    }
    let hex = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .ok_or(ConfigError::Oracle)?;
    if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ConfigError::Oracle);
    }
    let bytes = hex.as_bytes();
    let mut address = [0u8; 20];
    for (index, byte) in address.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2]).ok_or(ConfigError::Oracle)?;
        let low = hex_nibble(bytes[index * 2 + 1]).ok_or(ConfigError::Oracle)?;
        *byte = (high << 4) | low;
    }
    Ok(address)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_fee(raw: String) -> Result<u128, ConfigError> {
    let fee = raw.parse::<u128>().map_err(|_| ConfigError::MaxFee)?;
    if fee == 0 {
        return Err(ConfigError::MaxFee);
    }
    Ok(fee)
}

/// Operator-supplied Base HTTP endpoint. No default host is assumed.
fn parse_rpc_url(raw: String) -> Result<String, ConfigError> {
    let trimmed = raw.trim();
    if trimmed != raw || trimmed.is_empty() {
        return Err(ConfigError::RpcUrl);
    }
    let rest = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"));
    match rest {
        Some(rest) if !rest.is_empty() && !rest.contains(' ') => Ok(trimmed.to_string()),
        _ => Err(ConfigError::RpcUrl),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn defaults_bind_to_loopback() {
        let cfg = Config::from_lookup(|_| None).unwrap();
        assert!(cfg.host.is_loopback());
        assert_eq!(cfg.port, 8080);
        assert!(cfg.base_rpc_url.is_none());
        assert!(cfg.settler_key_file.is_none());
        assert_eq!(cfg.receipt_timeout, Duration::from_secs(20));
    }

    #[test]
    fn settler_key_must_be_absolute_and_paired_with_a_fee_ceiling() {
        let relative = Config::from_lookup(|key| {
            (key == "SETTLER_KEY_FILE").then(|| "keys/relayer.hex".to_string())
        });
        assert_eq!(relative.unwrap_err(), ConfigError::SettlerKey);

        let unpaired =
            Config::from_lookup(|key| (key == "SETTLER_MAX_FEE_PER_GAS").then(|| "1".to_string()));
        assert_eq!(unpaired.unwrap_err(), ConfigError::SettlerKey);

        let zero = Config::from_lookup(|key| match key {
            "SETTLER_KEY_FILE" => Some(absolute_key_outside_repo()),
            "SETTLER_MAX_FEE_PER_GAS" => Some("0".to_string()),
            _ => None,
        });
        assert_eq!(zero.unwrap_err(), ConfigError::MaxFee);
    }

    /// Absolute path that never exists in this repository. Zero-fee rejection
    /// happens before the file is opened, so the path only has to be absolute.
    fn absolute_key_outside_repo() -> String {
        #[cfg(windows)]
        {
            r"C:\keys\relayer.hex".to_string()
        }
        #[cfg(unix)]
        {
            "/keys/relayer.hex".to_string()
        }
    }

    #[test]
    fn rpc_url_must_be_http() {
        let ok = Config::from_lookup(|k| {
            (k == "BASE_RPC_URL").then(|| "http://127.0.0.1:8545".to_string())
        })
        .unwrap();
        assert_eq!(ok.base_rpc_url.as_deref(), Some("http://127.0.0.1:8545"));

        let bad =
            Config::from_lookup(|k| (k == "BASE_RPC_URL").then(|| "file:///tmp/x".to_string()));
        assert_eq!(bad.unwrap_err(), ConfigError::RpcUrl);
    }

    #[test]
    fn rejects_garbage() {
        let bad_host = Config::from_lookup(|k| (k == "HOST").then(|| "nope".to_string()));
        assert_eq!(bad_host.unwrap_err(), ConfigError::Host("nope".to_string()));

        let bad_port = Config::from_lookup(|k| (k == "PORT").then(|| "99999".to_string()));
        assert_eq!(
            bad_port.unwrap_err(),
            ConfigError::Port("99999".to_string())
        );
    }

    #[test]
    fn settler_key_outside_the_repository_is_accepted() {
        let path = std::env::temp_dir().join(format!("dcl-key-outside-{}", std::process::id()));
        std::fs::write(&path, [0u8; 8]).unwrap();
        let loaded = with_key(&path);
        let _ = std::fs::remove_file(&path);
        let loaded = loaded.unwrap();
        assert_eq!(loaded.settler_key_file.as_deref(), path.to_str());
        assert!(loaded.settler_max_fee_per_gas.is_some());
    }

    #[test]
    fn settler_key_inside_the_repository_is_rejected() {
        let path = repository_dir("key-inside");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, [0u8; 8]).unwrap();
        let loaded = with_key(&path);
        let _ = std::fs::remove_file(&path);
        assert_eq!(loaded.unwrap_err(), ConfigError::KeyLocation);
    }

    #[test]
    fn settler_key_symlink_into_the_repository_is_rejected() {
        let inside = repository_dir("key-link-target");
        std::fs::create_dir_all(inside.parent().unwrap()).unwrap();
        std::fs::write(&inside, [0u8; 8]).unwrap();
        let link = std::env::temp_dir().join(format!("dcl-key-link-{}", std::process::id()));
        let _ = std::fs::remove_file(&link);
        link_file(&inside, &link).expect("symlink");
        let loaded = with_key(&link);
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&inside);
        assert_eq!(loaded.unwrap_err(), ConfigError::KeyLocation);
    }

    fn with_key(path: &std::path::Path) -> Result<Config, ConfigError> {
        let owned = path.to_string_lossy().to_string();
        Config::from_lookup(move |key| match key {
            "SETTLER_KEY_FILE" => Some(owned.clone()),
            "SETTLER_MAX_FEE_PER_GAS" => Some("10".to_string()),
            _ => None,
        })
    }

    fn repository_dir(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("settler-{name}-{}", std::process::id()))
    }

    fn link_file(target: &std::path::Path, link: &std::path::Path) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link)
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
    }
}
