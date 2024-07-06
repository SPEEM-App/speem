use crate::config::get_config;
use crate::errors::{Result};
use rusqlite::{params, Connection};
use uuid::Uuid;
use std::path::Path;

pub struct Storage {
	conn: Connection,
}

impl Storage {
	pub fn new() -> Result<Self> {
		let config = get_config();
		let conn = Connection::open(Path::new(&config.database_url))?;

		// Enable SQLCipher and set the passphrase
		conn.execute("PRAGMA key = ?", params![config.database_passphrase])?;

		Ok(Storage { conn })
	}

	pub fn init(&self) -> Result<()> {
		self.conn.execute_batch(
			"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                display_name TEXT,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                title TEXT,
                is_group BOOLEAN NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversation_participants (
                conversation_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                FOREIGN KEY(conversation_id) REFERENCES conversations(id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                PRIMARY KEY (conversation_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(conversation_id) REFERENCES conversations(id),
                FOREIGN KEY(sender_id) REFERENCES users(id)
            );
            CREATE INDEX IF NOT EXISTS idx_messages_conversation_id ON messages (conversation_id);
            CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages (sender_id);
            ",
		)?;
		Ok(())
	}

	// CRUD operations for users
	pub fn create_user(&self, email: &str, display_name: &str, public_key: &str, private_key: &str) -> Result<()> {
		let id = Uuid::new_v4().to_string();
		self.conn.execute(
			"INSERT INTO users (id, email, display_name, public_key, private_key) VALUES (?1, ?2, ?3, ?4, ?5)",
			params![id, email, display_name, public_key, private_key],
		)?;
		Ok(())
	}

	pub fn get_user(&self, email: &str) -> Result<Option<(String, String, String, String)>> {
		let mut stmt = self.conn.prepare("SELECT id, email, display_name, public_key FROM users WHERE email = ?1")?;
		let user_iter = stmt.query_map(params![email], |row| {
			Ok((
				row.get(0)?,
				row.get(1)?,
				row.get(2)?,
				row.get(3)?,
			))
		})?;

		for user in user_iter {
			return Ok(Some(user?));
		}
		Ok(None)
	}

	pub fn update_user(&self, email: &str, display_name: &str) -> Result<()> {
		self.conn.execute(
			"UPDATE users SET display_name = ?1 WHERE email = ?2",
			params![display_name, email],
		)?;
		Ok(())
	}

	pub fn delete_user(&self, email: &str) -> Result<()> {
		self.conn.execute(
			"DELETE FROM users WHERE email = ?1",
			params![email],
		)?;
		Ok(())
	}

	// CRUD operations for conversations
	pub fn create_conversation(&self, title: &str, is_group: bool) -> Result<()> {
		let id = Uuid::new_v4().to_string();
		self.conn.execute(
			"INSERT INTO conversations (id, title, is_group) VALUES (?1, ?2, ?3)",
			params![id, title, is_group],
		)?;
		Ok(())
	}

	pub fn get_conversation(&self, id: &str) -> Result<Option<(String, String, bool)>> {
		let mut stmt = self.conn.prepare("SELECT id, title, is_group FROM conversations WHERE id = ?1")?;
		let conversation_iter = stmt.query_map(params![id], |row| {
			Ok((
				row.get(0)?,
				row.get(1)?,
				row.get(2)?,
			))
		})?;

		for conversation in conversation_iter {
			return Ok(Some(conversation?));
		}
		Ok(None)
	}

	pub fn update_conversation(&self, id: &str, title: &str) -> Result<()> {
		self.conn.execute(
			"UPDATE conversations SET title = ?1 WHERE id = ?2",
			params![title, id],
		)?;
		Ok(())
	}

	pub fn delete_conversation(&self, id: &str) -> Result<()> {
		self.conn.execute(
			"DELETE FROM conversations WHERE id = ?1",
			params![id],
		)?;
		Ok(())
	}

	// CRUD operations for messages
	pub fn create_message(&self, conversation_id: &str, sender_id: &str, message: &str) -> Result<()> {
		let id = Uuid::new_v4().to_string();
		self.conn.execute(
			"INSERT INTO messages (id, conversation_id, sender_id, message) VALUES (?1, ?2, ?3, ?4)",
			params![id, conversation_id, sender_id, message],
		)?;
		Ok(())
	}

	pub fn get_messages(&self, conversation_id: &str) -> Result<Vec<(String, String, String, String)>> {
		let mut stmt = self.conn.prepare("SELECT id, sender_id, message, timestamp FROM messages WHERE conversation_id = ?1")?;
		let message_iter = stmt.query_map(params![conversation_id], |row| {
			Ok((
				row.get(0)?,
				row.get(1)?,
				row.get(2)?,
				row.get(3)?,
			))
		})?;

		let mut messages = Vec::new();
		for message in message_iter {
			messages.push(message?);
		}
		Ok(messages)
	}
}