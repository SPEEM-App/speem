use crate::config::get_config;
use crate::errors::Result;
use sqlx::{sqlite::SqlitePool, Pool, Sqlite};

pub struct Storage {
	pool: Pool<Sqlite>,
}

impl Storage {
	pub async fn new() -> Result<Self> {
		let config = get_config();
		let pool = SqlitePool::connect(&config.database_url).await?;
		Ok(Storage { pool })
	}

	pub async fn init(&self) -> Result<()> {
		sqlx::query(
			r#"
                        CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                display_name TEXT,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            );
            "#,
		)
		.execute(&self.pool)
		.await?;
		Ok(())
	}
}
