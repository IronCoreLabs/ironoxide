mod common;

#[cfg(feature = "beta")]
mod search_tests {
    use crate::common::initialize_sdk;
    use ironoxide::{group::GroupOps, prelude::*, search::*};

    #[tokio::test]
    async fn create_blind_index() -> Result<(), IronOxideErr> {
        let ironoxide = initialize_sdk().await?;
        let group_create_result = ironoxide.group_create(&Default::default()).await?;
        ironoxide
            .create_blind_index(group_create_result.id())
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn create_blind_index_search_tokenize_data() -> Result<(), IronOxideErr> {
        let ironoxide = initialize_sdk().await?;
        let group_create_result = ironoxide.group_create(&Default::default()).await?;
        let encrypted_blind_index = ironoxide
            .create_blind_index(group_create_result.id())
            .await?;
        let search_sdk = encrypted_blind_index.initialize_search(&ironoxide).await?;
        let index_tokens = search_sdk.tokenize_data("hello world", Option::None);
        assert_eq!(index_tokens.len(), 6); //hel, ell, elo, wor, orl, rld --The numbers are random and aren't worth asserting about.
        Ok(())
    }

    #[tokio::test]
    async fn create_index_and_tokenize_query() -> Result<(), IronOxideErr> {
        let ironoxide = initialize_sdk().await?;
        let group_create_result = ironoxide.group_create(&Default::default()).await?;
        let encrypted_blind_index = ironoxide
            .create_blind_index(group_create_result.id())
            .await?;
        let search_sdk = encrypted_blind_index.initialize_search(&ironoxide).await?;
        let search_tokens = search_sdk.tokenize_data("hello world", Option::None);
        let search_tokens_two = search_sdk.tokenize_query("hello world", Option::None);
        assert_eq!(search_tokens_two, search_tokens);
        Ok(())
    }

    #[tokio::test]
    async fn create_index_changes_partition() -> Result<(), IronOxideErr> {
        let ironoxide = initialize_sdk().await?;
        let group_create_result = ironoxide.group_create(&Default::default()).await?;
        let encrypted_blind_index = ironoxide
            .create_blind_index(group_create_result.id())
            .await?;
        let search_sdk = encrypted_blind_index.initialize_search(&ironoxide).await?;
        let search_tokens = search_sdk.tokenize_data("hello world", Option::None);
        let search_tokens_two = search_sdk.tokenize_data("hello world", Option::Some("foo"));
        //Since one has a partition_id, these should be different.
        assert_ne!(search_tokens_two, search_tokens);
        Ok(())
    }
}
