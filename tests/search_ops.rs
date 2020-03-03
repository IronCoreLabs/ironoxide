mod common;

#[cfg(feature = "beta")]
mod search_tests {
    use crate::common::initialize_sdk;
    use ironoxide::{group::GroupOps, prelude::*, search::*};

    #[tokio::test]
    async fn create_index() -> Result<(), IronOxideErr> {
        let sdk = initialize_sdk().await?;
        let group_create_result = sdk.group_create(&Default::default()).await?;
        sdk.create_index(group_create_result.id()).await?;
        Ok(())
    }

    #[tokio::test]
    async fn create_and_initialize_blind_index_search() -> Result<(), IronOxideErr> {
        let sdk = initialize_sdk().await?;
        let group_create_result = sdk.group_create(&Default::default()).await?;
        let result = sdk
            .create_and_initialize_blind_index_search(group_create_result.id())
            .await?;
        let index_tokens = result.sdk.tokenize_data("hello world", Option::None);
        assert_eq!(index_tokens.len(), 6); //hel, ell, elo, wor, orl, rld --The numbers are random and aren't worth asserting about.
        Ok(())
    }

    #[tokio::test]
    async fn create_and_initialize_blind_index_search_consistency() -> Result<(), IronOxideErr> {
        let sdk = initialize_sdk().await?;
        let group_create_result = sdk.group_create(&Default::default()).await?;
        let initialize_result = sdk
            .create_and_initialize_blind_index_search(group_create_result.id())
            .await?;
        let search_sdk = initialize_result.sdk;
        let search_tokens = search_sdk.tokenize_data("hello world", Option::None);
        let search_tokens_two = search_sdk.tokenize_query("hello world", Option::None);
        assert_eq!(search_tokens_two, search_tokens);
        Ok(())
    }

    #[tokio::test]
    async fn create_index_changes_partition() -> Result<(), IronOxideErr> {
        let sdk = initialize_sdk().await?;
        let group_create_result = sdk.group_create(&Default::default()).await?;
        let initialize_result = sdk
            .create_and_initialize_blind_index_search(group_create_result.id())
            .await?;
        let search_sdk = initialize_result.sdk;
        let search_tokens = search_sdk.tokenize_data("hello world", Option::None);
        let search_tokens_two = search_sdk.tokenize_data("hello world", Option::Some("foo"));
        //Since one has a partition_id, these should be different.
        assert_ne!(search_tokens_two, search_tokens);
        Ok(())
    }

    #[tokio::test]
    async fn create_index_consistency_with_decrypt() -> Result<(), IronOxideErr> {
        let sdk = initialize_sdk().await?;
        let group_create_result = sdk.group_create(&Default::default()).await?;
        let initialize_result = sdk
            .create_and_initialize_blind_index_search(group_create_result.id())
            .await?;
        let search_sdk = initialize_result.sdk;
        let second_search_sdk = sdk
            .initialize_blind_index_search(&initialize_result.encrypted_salt)
            .await?;
        //The sdk created from the salt and the new sdk from a decrypted salt should be equal.
        assert_eq!(search_sdk, second_search_sdk);
        Ok(())
    }
}
