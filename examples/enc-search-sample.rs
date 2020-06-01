// =============================================================================
// This is a sample program in Rust that uses the ironoxide SDK to illustrate
// various patterns for using the encrypted search features.
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
// time (as a time_t) when the program is started to the group IDs.
//
// Copyright (c) 2020  IronCore Labs, Inc.
// =============================================================================

use ironoxide::prelude::*;
use lazy_static::lazy_static;
use mut_static::MutStatic;
use std::{
    convert::TryFrom,
    fmt,
    fs::File,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, AppErr>;

// This is a sample struct that contains some data about a customer that an
// application might track.
#[derive(Clone)]
struct Customer {
    id: u32,
    name: String,
    name_keys: String,
    email: String,
    email_keys: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let sdk = initialize_sdk_from_file(&PathBuf::from("example.devcon")).await?;
    GLOBAL_STATE.set(GlobalState::new())?;

    // Create a group to use to protect the blind search index that will
    // be used on the customer names, then create an index using that group
    // start-snippet{createIndex}
    let salt_group_id = create_group_id("indexedSearchGroup")?;
    create_group(&sdk, &salt_group_id, "PII Search").await?;
    let encrypted_salt = sdk.create_blind_index(&salt_group_id).await?;
    let encrypted_salt_str = serde_json::to_string(&encrypted_salt)?;
    save_encrypted_salt_to_app_server(encrypted_salt_str);
    // end-snippet{createIndex}

    // Initialize the new index so it can be used for indexing and search
    // start-snippet{initIndex}
    let encrypted_salt_str = get_encrypted_salt_from_app_server();
    let encrypted_salt: EncryptedBlindIndexSalt = serde_json::from_str(&encrypted_salt_str)?;
    let blind_index = encrypted_salt.initialize_search(&sdk).await?;
    // end-snippet{initIndex}

    // Create a group to use for the encryption of customer records.
    // Note this is not the same as the group that was used to secure
    // the blind index, but anyone that needs to be able to search for
    // customers by name will need to belong to both groups.
    let group_id = create_group_id("customerService")?;
    create_group(&sdk, &group_id, "Customer Service").await?;

    // Add some test customers to the "server store"
    let cust1 = encrypt_customer(&sdk, 1, "Gumby", "", &group_id).await?;
    save_customer(cust1, &[], &[]);
    let cust2 = encrypt_customer(&sdk, 2, "Æ neid 北亰", "", &group_id).await?;
    save_customer(cust2, &[], &[]);
    let cust3 = encrypt_customer(&sdk, 3, "aeneid bei jing", "", &group_id).await?;
    save_customer(cust3, &[], &[]);

    // Allow the user to enter additional customers
    let mut next_id = 4;
    loop {
        let mut name = String::new();
        println!("Enter next customer name, or blank line to quit");
        std::io::stdin()
            .read_line(&mut name)
            .expect("error: couldn't read input");
        name = name.trim().to_string();
        if &name == "" {
            break;
        } else {
            let mut email = String::new();
            println!("Enter customer's email");
            std::io::stdin()
                .read_line(&mut email)
                .expect("error: couldn't read input");
            email = email.trim().to_string();

            let cust = encrypt_customer(&sdk, next_id, &name, &email, &group_id).await?;
            save_customer(cust, &[], &[]);
        }
        next_id += 1;
    }

    // now create a new customer record to index
    let mut customer = Customer {
        id: 23,
        name: "J. Fred Muggs".to_string(),
        name_keys: "".to_string(),
        email: "j.fred.muggs@nowhere.com".to_string(),
        email_keys: "".to_string(),
    };

    // Generate the index tokens for the customer name, then encrypt it
    // start-snippet{indexData}
    let name_tokens = blind_index
        .tokenize_data(&customer.name, None)?
        .into_iter()
        .collect::<Vec<u32>>();
    let group_id = create_group_id("customerService")?;
    let encrypt_opts = DocumentEncryptOpts::with_explicit_grants(
        None,                  // document ID - create unique
        None,                  // document name
        false,                 // don't encrypt to self
        vec![group_id.into()], // users and groups to which to grant access
    );
    let enc_name = sdk
        .document_encrypt_unmanaged(customer.name.as_bytes(), &encrypt_opts)
        .await?;
    // Replace name with encoded encrypted version. Also need to store EDEKs to decrypt name.
    customer.name = base64::encode(enc_name.encrypted_data());
    customer.name_keys = base64::encode(enc_name.encrypted_deks());
    save_customer(customer.clone(), &name_tokens, &[]);
    // end-snippet{indexData}

    // Now ask the user for a query string, ask the server for matching records,
    // and display all matches to the user
    // start-snippet{executeSearch}
    let query_str = get_search_query();
    display_matching_customers(&sdk, &blind_index, &query_str).await?;
    // end-snippet{executeSearch}

    // Now create a second blind index to use for the email address fields.
    // start-snippet{createSecondIndex}
    let encrypted_salt2 = sdk.create_blind_index(&salt_group_id).await?;
    let blind_index2 = encrypted_salt2.initialize_search(&sdk).await?;
    // end-snippet{createSecondIndex}

    let mut customer2 = Customer {
        id: 24,
        name: "Pokey".to_string(),
        name_keys: "".to_string(),
        email: "pokey@gumby.io".to_string(),
        email_keys: "".to_string(),
    };

    // start-snippet{useSecondIndex}
    // Generate the index tokens for the customer name and email address, then encrypt them
    let name_tokens = blind_index
        .tokenize_data(&customer2.name, None)?
        .into_iter()
        .collect::<Vec<u32>>();
    let email_tokens = blind_index2
        .tokenize_data(&customer2.email, None)?
        .into_iter()
        .collect::<Vec<u32>>();
    let enc_name = sdk
        .document_encrypt_unmanaged(&customer2.name.as_bytes(), &encrypt_opts)
        .await?;
    let enc_email = sdk
        .document_encrypt_unmanaged(&customer2.email.as_bytes(), &encrypt_opts)
        .await?;
    // Replace name and email with encoded encrypted versions. Also need to store EDEKs to decrypt both.
    customer2.name = base64::encode(enc_name.encrypted_data());
    customer2.name_keys = base64::encode(enc_name.encrypted_deks());
    customer2.email = base64::encode(enc_email.encrypted_data());
    customer2.email_keys = base64::encode(enc_email.encrypted_deks());
    save_customer(customer, &name_tokens, &email_tokens);
    // end-snippet{useSecondIndex}

    Ok(())
}

// Load the device context and use it to initialize ironoxide
async fn initialize_sdk_from_file(device_path: &PathBuf) -> Result<IronOxide> {
    if device_path.is_file() {
        let device_context_file = File::open(&device_path)?;
        let device_context: DeviceContext = serde_json::from_reader(device_context_file)?;
        println!("Found DeviceContext in \"{}\"", device_path.display());
        Ok(ironoxide::initialize(&device_context, &Default::default()).await?)
    } else {
        Err(AppErr(
            format!(
                "Couldn't open file {} containing DeviceContext",
                device_path.display()
            )
            .to_string(),
        ))
    }
}

// Add the program start time to the end of the specified string to
// form a unique id string, then create a GroupId from it
// start-snippet{createGroupId}
fn create_group_id(id_str: &str) -> Result<GroupId> {
    let stime = &GLOBAL_STATE.read().unwrap().start_time;
    let gid = id_str.to_owned() + stime;
    Ok(GroupId::try_from(gid)?)
}
// end-snippet{createGroupId}

// Create a group with the specified ID and name, assuming the current user
// should be a member and an admin
// start-snippet{createGroup}
async fn create_group(
    sdk: &IronOxide,
    group_id: &GroupId,
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

// Given a customer's data, encrypt the PII and create a Customer struct
// containing the encrypted data and DEKs
async fn encrypt_customer(
    sdk: &IronOxide,
    id: u32,
    name: &str,
    email: &str,
    group_id: &GroupId,
) -> Result<Customer> {
    let encrypt_opts = DocumentEncryptOpts::with_explicit_grants(
        None,                  // document ID
        None,                  // document name
        true,                  // encrypt to self
        vec![group_id.into()], // users and groups to which to grant access
    );
    let enc_result = sdk
        .document_encrypt_unmanaged(name.as_bytes(), &encrypt_opts)
        .await?;
    let enc_name = base64::encode(enc_result.encrypted_data());
    let enc_name_keys = base64::encode(enc_result.encrypted_deks());

    Ok(Customer {
        id,
        name: enc_name,
        name_keys: enc_name_keys,
        email: email.to_string(),
        email_keys: "".to_string(),
    })
}

// Given a customer record and the transliterated query string, broken into
// words, decrypt the name in the customer record, then check whether the
// decrypted name contains all of the word fragments from the query string.
// If so, return the decrypted name. Otherwise, the record was a false positive,
// so return None.
// start-snippet{filterCust}
async fn filter_customer(
    sdk: &IronOxide,
    cust: &Customer,
    name_parts: &Vec<&str>,
) -> Result<Option<String>> {
    let cust_enc_name = base64::decode(&cust.name)?;
    let cust_name_keys = base64::decode(&cust.name_keys)?;
    let dec_result = sdk
        .document_decrypt_unmanaged(&cust_enc_name, &cust_name_keys)
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
async fn display_matching_customers(
    sdk: &IronOxide,
    name_index: &BlindIndexSearch,
    query_str: &str,
) -> Result<()> {
    let query_tokens = name_index
        .tokenize_query(query_str, None)?
        .into_iter()
        .collect();
    let customer_recs = search_customers(&query_tokens);
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
struct GlobalState {
    pub encrypted_salt: String,
    pub customers: Vec<Customer>,
    pub start_time: String,
}

impl GlobalState {
    pub fn new() -> Self {
        GlobalState {
            encrypted_salt: "".to_string(),
            customers: vec![],
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string(),
        }
    }
}

lazy_static! {
    static ref GLOBAL_STATE: MutStatic<GlobalState> = MutStatic::new();
}

fn save_encrypted_salt_to_app_server(encrypted_salt: String) {
    GLOBAL_STATE.write().unwrap().encrypted_salt = encrypted_salt;
}

fn get_encrypted_salt_from_app_server() -> String {
    GLOBAL_STATE.read().unwrap().encrypted_salt.clone()
}

// For now, we ignore the tokens associated with each customer rec
fn save_customer(customer: Customer, _name_tokens: &[u32], _email_tokens: &[u32]) {
    GLOBAL_STATE.write().unwrap().customers.push(customer);
}

// Just return all the records that we have in the store for now
fn search_customers(_tokens: &Vec<u32>) -> Vec<Customer> {
    GLOBAL_STATE.read().unwrap().customers.clone()
}

fn get_search_query() -> String {
    let mut query = String::new();
    println!("Enter query string");
    std::io::stdin()
        .read_line(&mut query)
        .expect("error: couldn't read input");
    query.trim().to_string()
}

// Set up an error type that is used to report different errors
struct AppErr(String);

impl fmt::Display for AppErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl From<IronOxideErr> for AppErr {
    fn from(e: IronOxideErr) -> Self {
        match e {
            IronOxideErr::AesError(_) => {
                Self("There was an error with the provided password.".to_string())
            }
            _ => Self(e.to_string()),
        }
    }
}
impl From<serde_json::Error> for AppErr {
    fn from(e: serde_json::Error) -> Self {
        Self(e.to_string())
    }
}
impl From<std::io::Error> for AppErr {
    fn from(e: std::io::Error) -> Self {
        Self(e.to_string())
    }
}
impl From<base64::DecodeError> for AppErr {
    fn from(e: base64::DecodeError) -> Self {
        Self(e.to_string())
    }
}
impl From<mut_static::Error> for AppErr {
    fn from(e: mut_static::Error) -> Self {
        Self(e.to_string())
    }
}

// Whenever an AppError happens, the default derived debug output is ugly and convoluted,
// so using the Display for the internal String is cleaner and easier to understand
impl fmt::Debug for AppErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
