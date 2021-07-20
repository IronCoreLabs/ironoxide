// =============================================================================
// This is a sample program in Rust that uses the ironoxide SDK to illustrate
// various patterns for using the encrypted search features.
//
// These patterns are discussed in detail in the Data Control Platform guide:
// https://ironcorelabs.com/docs/data-control-platform/guide/#encrypted-search-patterns
//
// This program is a very simple example that illustrates how you can use the
// IronCore SDKs in your application to do short substring searches of data
// that is end-to-end encrypted. The app will store and retrieve customer
// records that include some sensitive data - initially, the customer's name
// and email address. The app will use the ironoxide functions to generate
// secure search index tokens for each customer's name then encrypt the
// customer's name and email before saving a customer record. It will use the
// search index tokens to search for customers matching a name query.
//
// The example then shows how you can add an index on the email addresses so
// you can securely search them.
//
// The program stores some information in a global mutable state store - this
// is meant to simulate a service that the application would call to fetch and
// retrieve data.
//
// To execute this program, you need to provide a file that contains a device
// context. This file can be generated using the ironoxide-cli utility. You can
// download this from https://github.com/IronCoreLabs/ironoxide-cli/releases;
// if a compiled version for your platform or architecture is not available, you
// can use cargo to build and install it. The program assumes the device
// context file is named "example.devcon" in the current directory.
//
// Also note that this program creates two different groups - in order to avoid
// errors when executing the program multiple times, it appends the current
// time (as a time_t) when the program is started to a fixed string to form a
// unique group ID for each group.
//
// Copyright (c) 2020  IronCore Labs, Inc.
// =============================================================================

use anyhow::{anyhow, Result};
use ironoxide::prelude::*;
use lazy_static::lazy_static;
use mut_static::MutStatic;
use std::{
    collections::HashSet,
    convert::TryFrom,
    fs::File,
    iter::FromIterator,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

// This is a sample struct that contains some data about a customer that an
// application might track.
#[derive(Clone)]
struct Customer {
    id: u32,
    name: String,
    email: String,
}

// This is a corresponding struct that is generated after the customer has been
// processed to secure the sensitive fields and to generate search tokens for each
// of those fields.
#[derive(Clone)]
struct EncryptedCustomer {
    id: u32,
    enc_name: Vec<u8>,
    name_keys: Vec<u8>,
    enc_email: Vec<u8>,
    email_keys: Vec<u8>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let sdk = initialize_sdk_from_file(&PathBuf::from("example.devcon")).await?;

    // Capture the time when the program starts as a string, for use as a suffix
    // to create (hopefully) unique group IDs.
    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    // Create a group to use to protect the blind search index that will
    // be used on the customer names, then create an index using that group
    let salt_group_id = create_group_id("indexedSearchGroup", &start_time)?;
    // start-snippet{createIndex}
    create_group(&sdk, &salt_group_id, "PII Search").await?;
    let encrypted_salt = sdk.create_blind_index(&salt_group_id).await?;
    save_name_salt_to_app_server(encrypted_salt);
    // end-snippet{createIndex}

    // Initialize the new index so it can be used for indexing and search
    // start-snippet{initIndex}
    let encrypted_salt = get_name_salt_from_app_server();
    let blind_index = encrypted_salt.initialize_search(&sdk).await?;
    // end-snippet{initIndex}

    // Create a group to use for the encryption of customer records.
    // Note this is not the same as the group that was used to secure
    // the blind index, but anyone that needs to be able to search for
    // customers by name will need to belong to both groups.
    let group_id = create_group_id("customerService", &start_time)?;
    create_group(&sdk, &group_id, "Customer Service").await?;

    // Add some test customers to the "server store"
    let cust1 = Customer {
        id: 1,
        name: "Gumby".to_string(),
        email: "gumby@gumby.io".to_string(),
    };
    save_customer(&cust1, &group_id, &sdk, &blind_index).await?;
    let cust2 = Customer {
        id: 2,
        name: "Æ neid 北亰".to_string(),
        email: "".to_string(),
    };
    save_customer(&cust2, &group_id, &sdk, &blind_index).await?;
    let cust3 = Customer {
        id: 3,
        name: "aeneid bei jing".to_string(),
        email: "".to_string(),
    };
    save_customer(&cust3, &group_id, &sdk, &blind_index).await?;
    let cust4 = Customer {
        id: 4,
        name: "J. Fred Muggs".to_string(),
        email: "j.fred.muggs@nowhere.com".to_string(),
    };
    save_customer(&cust4, &group_id, &sdk, &blind_index).await?;

    // Allow the user to enter additional customers
    add_customers(&4, &group_id, &sdk, &blind_index).await?;

    // Now ask the user for a query string, ask the server for matching records,
    // and display all matches to the user
    // start-snippet{executeSearch}
    let query_str = get_search_query();
    display_customer_matches_by_name(&sdk, &blind_index, &query_str).await?;
    // end-snippet{executeSearch}

    // Now suppose that we decided the application should allow searches by the email address
    // as well as the name. To support the expanded capability, first create a second blind
    // index to use for the email address fields.
    // start-snippet{createSecondIndex}
    let encrypted_salt2 = sdk.create_blind_index(&salt_group_id).await?;
    save_email_salt_to_app_server(encrypted_salt2);

    let encrypted_salt2 = get_email_salt_from_app_server();
    let blind_index2 = encrypted_salt2.initialize_search(&sdk).await?;
    // end-snippet{createSecondIndex}

    // Now save customers using both blind indices
    let cust24 = Customer {
        id: 24,
        name: "Pokey".to_string(),
        email: "pokey@gumby.io".to_string(),
    };
    save_customer_with_2_indices(&cust24, &group_id, &sdk, &blind_index, &blind_index2).await?;

    Ok(())
}

// Allow the user to enter additional customers and store each of them in the mock server
async fn add_customers(
    last_id: &u32,
    group_id: &ironoxide::group::GroupId,
    sdk: &ironoxide::IronOxide,
    blind_index: &ironoxide::search::BlindIndexSearch,
) -> Result<()> {
    let mut next_id = last_id + 1;
    loop {
        let mut name = String::new();
        println!("Enter next customer name, or blank line to quit");
        std::io::stdin()
            .read_line(&mut name)
            .expect("error: couldn't read input");
        name = name.trim().to_string();
        if name.is_empty() {
            break;
        } else {
            let mut email = String::new();
            println!("Enter customer's email");
            std::io::stdin()
                .read_line(&mut email)
                .expect("error: couldn't read input");
            email = email.trim().to_string();

            let cust = Customer {
                id: next_id,
                name,
                email,
            };
            save_customer(&cust, &group_id, &sdk, &blind_index).await?;
        }
        next_id += 1;
    }

    Ok(())
}

// Given a customer record and the context for encrypting and indexing the customer's name
// field, generate the index tokens for the name, encrypt the name and email, and save the
// customer record with the index tokens to the server.
async fn save_customer(
    cust: &Customer,
    group_id: &ironoxide::group::GroupId,
    sdk: &ironoxide::IronOxide,
    blind_index: &ironoxide::search::BlindIndexSearch,
) -> Result<()> {
    // start-snippet{indexData}
    // Generate tokens need to search for matching customer names
    let name_tokens = blind_index
        .tokenize_data(&cust.name, None)?
        .into_iter()
        .collect::<Vec<u32>>();

    // Encrypt the name and email addresses to protect privacy. Also need to store EDEKs
    // to decrypt them.
    let encrypt_opts = DocumentEncryptOpts::with_explicit_grants(
        None,                  // document ID - create unique
        None,                  // document name
        false,                 // don't encrypt to self
        vec![group_id.into()], // users and groups to which to grant access
    );
    let enc_name = sdk
        .document_encrypt_unmanaged(cust.name.as_bytes(), &encrypt_opts)
        .await?;
    let enc_email = sdk
        .document_encrypt_unmanaged(cust.email.as_bytes(), &encrypt_opts)
        .await?;

    let enc_cust = EncryptedCustomer {
        id: cust.id,
        enc_name: enc_name.encrypted_data().to_vec(),
        name_keys: enc_name.encrypted_deks().to_vec(),
        enc_email: enc_email.encrypted_data().to_vec(),
        email_keys: enc_email.encrypted_deks().to_vec(),
    };
    save_customer_to_app_server(enc_cust, name_tokens, vec![]);
    // end-snippet{indexData}

    Ok(())
}

// Given a customer record and the context for encrypting and indexing the customer's name
// and email fields, generate the index tokens for the name and for the email, encrypt the
// name and email, and save the customer record with both sets of index tokens to the server.
async fn save_customer_with_2_indices(
    cust: &Customer,
    group_id: &ironoxide::group::GroupId,
    sdk: &ironoxide::IronOxide,
    name_blind_index: &ironoxide::search::BlindIndexSearch,
    email_blind_index: &ironoxide::search::BlindIndexSearch,
) -> Result<()> {
    // start-snippet{useSecondIndex}
    // Generate the index tokens for the customer name and email address
    let name_tokens = name_blind_index
        .tokenize_data(&cust.name, None)?
        .into_iter()
        .collect::<Vec<u32>>();
    let email_tokens = email_blind_index
        .tokenize_data(&cust.email, None)?
        .into_iter()
        .collect::<Vec<u32>>();

    // Encrypt the name and email addresses to protect privacy. Also need to store EDEKs
    // to decrypt them.
    let encrypt_opts = DocumentEncryptOpts::with_explicit_grants(
        None,                  // document ID - create unique
        None,                  // document name
        false,                 // don't encrypt to self
        vec![group_id.into()], // users and groups to which to grant access
    );
    let enc_name = sdk
        .document_encrypt_unmanaged(cust.name.as_bytes(), &encrypt_opts)
        .await?;
    let enc_email = sdk
        .document_encrypt_unmanaged(cust.email.as_bytes(), &encrypt_opts)
        .await?;

    let enc_cust = EncryptedCustomer {
        id: cust.id,
        enc_name: enc_name.encrypted_data().to_vec(),
        name_keys: enc_name.encrypted_deks().to_vec(),
        enc_email: enc_email.encrypted_data().to_vec(),
        email_keys: enc_email.encrypted_deks().to_vec(),
    };
    save_customer_to_app_server(enc_cust, name_tokens, email_tokens);
    // end-snippet{useSecondIndex}

    Ok(())
}

// Load the device context and use it to initialize ironoxide
async fn initialize_sdk_from_file(device_path: &Path) -> Result<IronOxide> {
    if device_path.is_file() {
        let device_context_file = File::open(&device_path)?;
        let device_context: DeviceContext = serde_json::from_reader(device_context_file)?;
        println!("Found DeviceContext in \"{}\"", device_path.display());
        Ok(ironoxide::initialize(&device_context, &Default::default()).await?)
    } else {
        Err(anyhow!(
            "Couldn't open file {} containing DeviceContext",
            device_path.display()
        ))
    }
}

// Add the program start time to the end of the specified string to
// form a unique id string, then create a GroupId from it
// start-snippet{createGroupId}
fn create_group_id(id_str: &str, start_time: &str) -> Result<ironoxide::group::GroupId> {
    let gid = id_str.to_owned() + start_time;
    Ok(ironoxide::group::GroupId::try_from(gid)?)
}
// end-snippet{createGroupId}

// Create a group with the specified ID and name, assuming the current user
// should be a member and an admin
// start-snippet{createGroup}
async fn create_group(
    sdk: &IronOxide,
    group_id: &ironoxide::group::GroupId,
    name: &str,
) -> Result<GroupCreateResult> {
    let opts = GroupCreateOpts::new(
        Some(group_id.to_owned()),                   // ID
        Some(GroupName::try_from(name.to_owned())?), // name
        true,                                        // add as admin
        true,                                        // add as user
        None,                                        // owner - defaults to caller
        vec![],                                      // additional admins
        vec![],                                      // additional users
        false,                                       // needs rotation
    );
    let group = sdk.group_create(&opts).await?;
    Ok(group)
}
// end-snippet{createGroup}

// Given a customer record and the transliterated query string, broken into
// words, decrypt the name in the customer record, then check whether the
// decrypted name contains all of the word fragments from the query string.
// If so, return the decrypted name. Otherwise, the record was a false positive,
// so return None.
// start-snippet{filterCust}
async fn filter_customer(
    sdk: &IronOxide,
    cust: &EncryptedCustomer,
    name_parts: &[&str],
) -> Result<Option<String>> {
    let dec_result = sdk
        .document_decrypt_unmanaged(&cust.enc_name, &cust.name_keys)
        .await?;
    let dec_name = std::str::from_utf8(&dec_result.decrypted_data()).unwrap();
    let dec_name_trans = ironoxide::search::transliterate_string(&dec_name);
    if name_parts
        .iter()
        .all(|name_part| dec_name_trans.contains(name_part))
    {
        Ok(Some(dec_name.to_string()))
    } else {
        Ok(None)
    }
}
// end-snippet{filterCust}

// Given a query string, generate the set of index tokens and use this to
// retrieve possible matches from the server. Transliterate the string,
// break it into pieces on white space, and for each returned customer,
// check to see if the customer name actually contains the words from the
// query. If so, output the customer ID and name.
// start-snippet{displayCust}
async fn display_customer_matches_by_name(
    sdk: &IronOxide,
    name_index: &BlindIndexSearch,
    query_str: &str,
) -> Result<()> {
    let query_tokens = name_index
        .tokenize_query(query_str, None)?
        .into_iter()
        .collect();
    let customer_recs = search_customers_by_name(query_tokens);
    let trans_query = ironoxide::search::transliterate_string(&query_str);
    let name_parts: Vec<&str> = trans_query.split_whitespace().collect();
    for cust in customer_recs.iter() {
        let result = filter_customer(&sdk, &cust, &name_parts).await?;
        match result {
            Some(decrypted_name) => println!("{} {} matched query", cust.id, decrypted_name),
            None => println!("{} did not match query", cust.id),
        }
    }
    Ok(())
}
// end-snippet{displayCust}

// Mock out some functions that would call the back-end service and return data in the real app
// We use some mutable global state to persist things that the service usually would.
struct AppServerMock {
    pub name_salt: Option<EncryptedBlindIndexSalt>,
    pub email_salt: Option<EncryptedBlindIndexSalt>,
    pub customers: Vec<(HashSet<u32>, HashSet<u32>, EncryptedCustomer)>,
}

impl Default for AppServerMock {
    fn default() -> Self {
        AppServerMock {
            name_salt: None,
            email_salt: None,
            customers: vec![],
        }
    }
}

lazy_static! {
    static ref MOCK_APP_SERVER: MutStatic<AppServerMock> =
        MutStatic::from(AppServerMock::default());
}

fn save_name_salt_to_app_server(encrypted_salt: EncryptedBlindIndexSalt) {
    MOCK_APP_SERVER.write().unwrap().name_salt = Some(encrypted_salt);
}

fn get_name_salt_from_app_server() -> EncryptedBlindIndexSalt {
    MOCK_APP_SERVER.read().unwrap().name_salt.clone().unwrap()
}

fn save_email_salt_to_app_server(encrypted_salt: EncryptedBlindIndexSalt) {
    MOCK_APP_SERVER.write().unwrap().email_salt = Some(encrypted_salt);
}

fn get_email_salt_from_app_server() -> EncryptedBlindIndexSalt {
    MOCK_APP_SERVER.read().unwrap().email_salt.clone().unwrap()
}

fn save_customer_to_app_server(
    customer: EncryptedCustomer,
    name_tokens: Vec<u32>,
    email_tokens: Vec<u32>,
) {
    let name_set = HashSet::from_iter(name_tokens);
    let email_set = HashSet::from_iter(email_tokens);
    MOCK_APP_SERVER
        .write()
        .unwrap()
        .customers
        .push((name_set, email_set, customer));
}

// Find any customers whose set of name tokens contains the set of query tokens as a subset.
fn search_customers_by_name(tokens: Vec<u32>) -> Vec<EncryptedCustomer> {
    let name_query = HashSet::from_iter(tokens);
    let cust_list = &MOCK_APP_SERVER.read().unwrap().customers;
    let matching_cust: Vec<(HashSet<u32>, HashSet<u32>, EncryptedCustomer)> = cust_list
        .iter()
        .filter(|(name_set, _email_set, _cust)| name_query.is_subset(&name_set))
        .cloned()
        .collect();
    matching_cust
        .iter()
        .map(|(_name_tokens, _email_tokens, cust)| cust.clone())
        .collect()
}

fn get_search_query() -> String {
    let mut query = String::new();
    println!("Enter query string");
    std::io::stdin()
        .read_line(&mut query)
        .expect("error: couldn't read input");
    query.trim().to_string()
}
