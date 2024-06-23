pub mod config;
pub mod crypto;
pub mod errors;
pub mod storage;

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn test_storage_init() {
        let storage = storage::Storage::new().await.unwrap();
        storage.init().await.unwrap();
    }
}
