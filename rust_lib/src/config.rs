use once_cell::sync::Lazy;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub database_passphrase: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            database_url: "speem.db".to_string(),
            database_passphrase: "default_passphrase".to_string(),
        }
    }
}

static CONFIG: Lazy<Mutex<Config>> = Lazy::new(|| Mutex::new(Config::default()));

pub fn get_config() -> Config {
    CONFIG.lock().unwrap().clone()
}

pub fn set_config(new_config: Config) {
    let mut config = CONFIG.lock().unwrap();
    *config = new_config;
}

pub fn load_config_from_file(file_path: &str) -> std::io::Result<()> {
    let config_content = fs::read_to_string(file_path)?;
    let new_config: Config = serde_json::from_str(&config_content)?;
    set_config(new_config);
    Ok(())
}