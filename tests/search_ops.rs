mod common;

#[cfg(feature = "beta")]
mod search_tests {
    use crate::common::initialize_sdk;
    use ironoxide::{group::GroupOps, prelude::*, search::*};

    #[tokio::test]
    async fn create_index() -> Result<(), IronOxideErr> {
        let sdk = initialize_sdk().await?;
        let group_create_result = sdk.group_create(&Default::default()).await?;
        let result = sdk.create_index(group_create_result.id()).await?;
        assert_eq!(result.access_errs().is_empty(), true);
        assert_eq!(result.grants().is_empty(), false);
        Ok(())
    }

    #[tokio::test]
    async fn create_index_and_initialize() -> Result<(), IronOxideErr> {
        let sdk = initialize_sdk().await?;
        let group_create_result = sdk.group_create(&Default::default()).await?;
        let result = sdk
            .create_index_and_initialize("hello world", Option::None, group_create_result.id())
            .await?;
        assert_eq!(result.index.len(), 6); //hel, ell, elo, wor, orl, rld --The numbers are random and aren't worth asserting about.
        Ok(())
    }

    #[tokio::test]
    async fn create_index_and_initialize_consistency() -> Result<(), IronOxideErr> {
        let sdk = initialize_sdk().await?;
        let group_create_result = sdk.group_create(&Default::default()).await?;
        let initialize_result = sdk
            .create_index_and_initialize("hello world", Option::None, group_create_result.id())
            .await?;
        let search_sdk = initialize_result.sdk;
        let search_tokens = search_sdk.generate_index_tokens("hello world", Option::None);
        assert_eq!(initialize_result.index, search_tokens);
        Ok(())
    }

    #[tokio::test]
    async fn create_index_consistency_with_decrypt() -> Result<(), IronOxideErr> {
        let sdk = initialize_sdk().await?;
        let group_create_result = sdk.group_create(&Default::default()).await?;
        let initialize_result = sdk
            .create_index_and_initialize("", Option::None, group_create_result.id())
            .await?;
        let search_sdk = initialize_result.sdk;
        let second_search_sdk = sdk
            .initialize_search_index(
                initialize_result.encrypted_salt.encrypted_data(),
                initialize_result.encrypted_salt.encrypted_deks(),
            )
            .await?;
        //The sdk created from the salt and the new sdk from a decrypted salt should be equal.
        assert_eq!(search_sdk, second_search_sdk);
        Ok(())
    }
}
