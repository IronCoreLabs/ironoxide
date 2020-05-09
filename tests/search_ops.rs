mod common;

#[cfg(feature = "beta")]
mod search_tests {
    use crate::common::initialize_sdk;
    use galvanic_assert::{
        assert_that,
        matchers::{collection::contains_subset, geq},
    };
    use ironoxide::prelude::*;

    async fn setup_test() -> Result<BlindIndexSearch, IronOxideErr> {
        let ironoxide = initialize_sdk().await?;
        let group_create_result = ironoxide.group_create(&Default::default()).await?;
        let encrypted_blind_index = ironoxide
            .create_blind_index(group_create_result.id())
            .await?;
        encrypted_blind_index.initialize_search(&ironoxide).await
    }

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
    async fn serde_blind_index_salt_roundtrips() -> Result<(), IronOxideErr> {
        let ebis = EncryptedBlindIndexSalt {
            encrypted_deks: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            encrypted_salt_bytes: vec![0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30],
        };
        let ebis_str = serde_json::to_string(&ebis).unwrap();
        let expect_json = r#"{"encryptedDeks":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],"encryptedSaltBytes":[0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30]}"#;
        assert_eq!(ebis_str, expect_json);
        let ebis2: EncryptedBlindIndexSalt = serde_json::from_str(&ebis_str).unwrap();
        assert_eq!(ebis2, ebis);
        Ok(())
    }

    #[tokio::test]
    async fn transliterate_string() -> Result<(), IronOxideErr> {
        let search_sdk = setup_test().await?;
        let tl_str = search_sdk.transliterate_string("Æneid - 北亰.");
        assert_eq!(tl_str, "aeneid  bei jing ");
        Ok(())
    }

    #[tokio::test]
    async fn create_blind_index_search_tokenize_data() -> Result<(), IronOxideErr> {
        let search_sdk = setup_test().await?;
        let index_tokens = search_sdk.tokenize_data("hello world", Option::None)?;
        assert_that!(&index_tokens.len(), geq(7)); //hel, ell, elo, wor, orl, rld  plus some extras -- The numbers are random and aren't worth asserting about.
        Ok(())
    }

    #[tokio::test]
    async fn create_index_and_tokenize_query() -> Result<(), IronOxideErr> {
        let search_sdk = setup_test().await?;
        let search_index_data = search_sdk.tokenize_data("hello world", Option::None)?;
        let search_tokens = search_sdk.tokenize_query("hello world", Option::None)?;
        assert_that!(&search_index_data, contains_subset(search_tokens));
        Ok(())
    }

    #[tokio::test]
    async fn tokenize_query_changes_partition() -> Result<(), IronOxideErr> {
        let search_sdk = setup_test().await?;
        let search_tokens = search_sdk.tokenize_query("hello world", Option::None)?;
        let search_tokens_two = search_sdk.tokenize_query("hello world", Option::Some("foo"))?;
        //Since one has a partition_id, these should be different.
        assert_ne!(search_tokens_two, search_tokens);
        Ok(())
    }
}
