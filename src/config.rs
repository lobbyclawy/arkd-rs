use serde::{Deserialize, Serialize};
use std::path::Path;

/// Deployment mode: Full (Redis + PostgreSQL) or Light (SQLite + in-memory).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    #[default]
    Full,
    Light,
}

/// Top-level config file structure (config.toml)
#[derive(Debug, Deserialize, Default)]
pub struct FileConfig {
    #[serde(default)]
    pub server: ServerSection,
    #[allow(dead_code)] // Will be used when Bitcoin RPC is wired
    #[serde(default)]
    pub bitcoin: BitcoinSection,
    #[serde(default)]
    pub ark: ArkSection,
    #[serde(default)]
    pub deployment: DeploymentSection,
}

/// Deployment configuration section.
#[derive(Debug, Deserialize, Default)]
pub struct DeploymentSection {
    /// Deployment mode: "full" (default) or "light".
    #[serde(default)]
    pub mode: DeploymentMode,
}

impl DeploymentSection {
    /// Returns `true` when the deployment is configured for light mode.
    pub fn is_light(&self) -> bool {
        matches!(self.mode, DeploymentMode::Light)
    }

    /// Human-readable label for the store backends implied by the current mode.
    pub fn store_info(&self) -> &'static str {
        if self.is_light() {
            "sqlite+in-memory"
        } else {
            "postgresql+redis"
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct ServerSection {
    pub grpc_addr: Option<String>,
    pub rest_addr: Option<String>,
    pub require_auth: Option<bool>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub asp_key_hex: Option<String>,
    pub esplora_url: Option<String>,
    pub admin_token: Option<String>,
    /// Disable macaroon-based authentication.
    pub no_macaroons: Option<bool>,
    /// Disable TLS (plaintext mode).
    pub no_tls: Option<bool>,
    /// Unlocker type: env or file.
    pub unlocker_type: Option<String>,
    /// Path to the password file when unlocker_type = file.
    pub unlocker_file_path: Option<String>,
}

#[allow(dead_code)] // Fields will be used when Bitcoin RPC integration is wired
#[derive(Debug, Deserialize, Default)]
pub struct BitcoinSection {
    pub network: Option<String>,
    pub rpc_host: Option<String>,
    pub rpc_port: Option<u16>,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ArkSection {
    pub round_duration_secs: Option<u64>,
    pub round_interval_blocks: Option<u32>,
    pub allow_csv_block_type: Option<bool>,
}

impl FileConfig {
    /// Shortcut: is the deployment mode set to light?
    pub fn is_light_mode(&self) -> bool {
        self.deployment.is_light()
    }

    /// Shortcut: human-readable store backend label.
    pub fn store_info(&self) -> &'static str {
        self.deployment.store_info()
    }
}

/// Load config from file path. Returns default config if file doesn't exist.
pub fn load_config(path: &Path) -> anyhow::Result<FileConfig> {
    if !path.exists() {
        tracing::warn!(path = %path.display(), "Config file not found, using defaults");
        return Ok(FileConfig::default());
    }
    let content = std::fs::read_to_string(path)?;
    let config: FileConfig = toml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Config parse error in {}: {e}", path.display()))?;
    tracing::info!(path = %path.display(), "Config loaded");
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_config_missing_file_returns_default() {
        let result = load_config(Path::new("/tmp/nonexistent_arkd_config.toml"));
        assert!(result.is_ok());
        let cfg = result.unwrap();
        assert!(cfg.server.grpc_addr.is_none());
        assert!(cfg.ark.round_duration_secs.is_none());
    }

    #[test]
    fn test_load_config_parses_grpc_addr() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "[server]\ngrpc_addr = \"0.0.0.0:9999\"").unwrap();

        let cfg = load_config(&path).unwrap();
        assert_eq!(cfg.server.grpc_addr.as_deref(), Some("0.0.0.0:9999"));
    }

    #[test]
    fn test_load_config_invalid_toml_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "{{{{not valid toml").unwrap();

        let result = load_config(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_empty_file_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.toml");
        std::fs::write(&path, "").unwrap();

        let cfg = load_config(&path).unwrap();
        assert!(cfg.server.grpc_addr.is_none());
        assert!(cfg.bitcoin.network.is_none());
        assert!(cfg.ark.round_duration_secs.is_none());
    }

    #[test]
    fn test_deployment_mode_default_is_full() {
        let mode = DeploymentMode::default();
        assert_eq!(mode, DeploymentMode::Full);
    }

    #[test]
    fn test_deployment_mode_serde_light() {
        let json = serde_json::to_string(&DeploymentMode::Light).unwrap();
        assert_eq!(json, "\"light\"");
        let parsed: DeploymentMode = serde_json::from_str("\"light\"").unwrap();
        assert_eq!(parsed, DeploymentMode::Light);
    }

    #[test]
    fn test_deployment_mode_serde_full() {
        let json = serde_json::to_string(&DeploymentMode::Full).unwrap();
        assert_eq!(json, "\"full\"");
        let parsed: DeploymentMode = serde_json::from_str("\"full\"").unwrap();
        assert_eq!(parsed, DeploymentMode::Full);
    }

    #[test]
    fn test_cli_default_config_path() {
        use crate::cli::Cli;
        use clap::Parser;

        // Parse with no args (use default)
        let cli = Cli::try_parse_from(["arkd"]).unwrap();
        assert_eq!(cli.config, "config.toml");
    }

    // ── Issue #119: deployment-mode wiring tests ──

    #[test]
    fn test_light_mode_is_light_returns_true() {
        let section = DeploymentSection {
            mode: DeploymentMode::Light,
        };
        assert!(section.is_light());
    }

    #[test]
    fn test_full_mode_is_light_returns_false() {
        let section = DeploymentSection {
            mode: DeploymentMode::Full,
        };
        assert!(!section.is_light());
    }

    #[test]
    fn test_store_info_light_vs_full() {
        let light = DeploymentSection {
            mode: DeploymentMode::Light,
        };
        assert_eq!(light.store_info(), "sqlite+in-memory");

        let full = DeploymentSection {
            mode: DeploymentMode::Full,
        };
        assert_eq!(full.store_info(), "postgresql+redis");
    }
}
