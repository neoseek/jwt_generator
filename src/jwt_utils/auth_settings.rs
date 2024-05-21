use std::fmt::Formatter;
use std::fs::File;
use std::io;
use std::io::BufReader;
use serde::Deserialize;
use serde_json::Result;

///
/// # Auth Config
/// - Contains Config values needed to obtain JWT Token
///
#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    tenant_id : String,
    client_id : String,
    cert_path : String,
    cert_subject : String
}

impl AuthConfig {
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn cert_path(&self) -> &str {
        &self.cert_path
    }
    pub fn cert_subject(&self) -> &str {
        &self.cert_subject
    }
}

/// Reads the Config content from an existing json file an loads as a AuthConfig struct
pub fn read_auth_config_from_file(file_path: &str) -> Result<AuthConfig> {
    let file = File::open(&file_path).expect("Failed to open file");
    let file_reader = BufReader::new(file);
    let config: AuthConfig = serde_json::from_reader(file_reader)?;
    Ok(config)
}