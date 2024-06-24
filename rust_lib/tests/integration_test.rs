#[cfg(test)]
mod integration_test {
    use tokio;
    use speem::storage::Storage;

    #[tokio::test]
    async fn test_database_init() {
        let storage = Storage::new().await.unwrap();
        storage.init().await.unwrap();
    }
}
