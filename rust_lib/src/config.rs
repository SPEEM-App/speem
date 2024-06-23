use once_cell::sync::Lazy;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    // Add other configuration fields as needed
}

impl Default for Config {
    fn default() -> Self {
        Config {
            database_url: "sqlite::memory:".to_string(),
            // Initialize other fields with default values
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
