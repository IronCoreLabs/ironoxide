use anyhow::Result;
use ironoxide::prelude::*;
use std::{fs::File, io::Write, path::PathBuf};

#[tokio::main]
async fn main() -> Result<()> {
    let sdk = initialize_sdk_from_file("examples/example-ironoxide-device.json".into()).await?;
    let documents: Vec<DocumentEncryptResult> = encrypt_documents(&sdk, 5).await?;
    println!("1. Decrypt as needed");
    println!("2. Decrypt in window");
    println!("3. Decrypt in bulk");
    print!("Choose a method of decryption: ");
    std::io::stdout().flush()?;
    let method = read_usize()?;
    match method {
        1 => decrypt_as_needed(&sdk, documents).await?,
        2 => decrypt_in_chunks(&sdk, documents).await?,
        3 => decrypt_in_bulk(&sdk, documents).await?,
        _ => panic!("Invalid selection"),
    };
    Ok(())
}

/// Loads the device context and uses it to initialize an IronOxide.
///
/// If the file cannot be found, this function will panic.
async fn initialize_sdk_from_file(device_path: PathBuf) -> Result<IronOxide> {
    if device_path.is_file() {
        let device_context_file = File::open(&device_path)?;
        let device_context: DeviceContext = serde_json::from_reader(device_context_file)?;
        let ironoxide = ironoxide::initialize(&device_context, &Default::default()).await?;
        Ok(ironoxide)
    } else {
        panic!(
            "Couldn't open file {} containing DeviceContext",
            device_path.display()
        )
    }
}

/// Encrypts a given number of documents with a generated ID and no name.
async fn encrypt_documents(
    sdk: &IronOxide,
    number_of_documents: u8,
) -> ironoxide::Result<Vec<DocumentEncryptResult>> {
    println!("Encrypting {} documents...", number_of_documents);
    let opts = DocumentEncryptOpts::default();
    let encrypted_documents = futures::future::try_join_all(
        (0..number_of_documents).map(|_| sdk.document_encrypt(b"foobar", &opts)),
    )
    .await;
    println!("Done\n");
    encrypted_documents
}

/// From a list of encrypted documents, decrypts a selected document and prints its decrypted data.
async fn decrypt_as_needed(sdk: &IronOxide, documents: Vec<DocumentEncryptResult>) -> Result<()> {
    println!("\nEncrypted Documents:");
    for i in 0..documents.len() {
        println!("#{}: {}", i + 1, documents[i].id().id());
    }
    print!("\nDocument # to decrypt: ");
    std::io::stdout().flush()?;
    let doc_index = read_usize()? - 1;
    let encrypted_document = documents.get(doc_index).expect("Index out of range.");
    let decrypted_document = decrypt_document(sdk, &encrypted_document).await?;
    println!(
        "Successfully decrypted!\nDecrypted data: {}",
        std::str::from_utf8(decrypted_document.decrypted_data())?
    );
    Ok(())
}

async fn decrypt_in_chunks(sdk: &IronOxide, documents: Vec<DocumentEncryptResult>) -> Result<()> {
    let page_size = get_window_size(documents.len())?;
    // let chunks: Vec<_> = documents[..].chunks(page_size).collect();
    let mut start = 0;
    let mut previous_start: usize = 1;
    let mut decrypted_documents = vec![];
    loop {
        if start != previous_start {
            previous_start = start;
            let window_docs = &documents[start..std::cmp::min(start + page_size, documents.len())];
            decrypted_documents = futures::future::try_join_all(
                window_docs.iter().map(|doc| decrypt_document(sdk, doc)),
            )
            .await?;
        }
        println!("Decrypted documents:");
        for i in 0..decrypted_documents.len() {
            println!("#{}: {}", start + i + 1, decrypted_documents[i].id().id());
        }
        print!("Document # to decrypt, 'n' for next page, 'p' for previous page, or 'q' to quit: ");
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        match input.trim().parse::<usize>() {
            // User entered a number
            Ok(num) => match num {
                n if (n > 0 && n <= page_size) => {
                    println!(
                        "ID: {}\nDecrypted data: {}",
                        decrypted_documents[start + num - 1].id().id(),
                        std::str::from_utf8(decrypted_documents[num - 1].decrypted_data())?
                    );
                    break;
                }
                _ => {
                    println!("Invalid selection");
                    continue;
                }
            },
            // User entered a string
            Err(_) => match input.trim() {
                "n" => {
                    start = match start + page_size {
                        n if n < documents.len() => n,
                        _ => start,
                    }
                }
                "p" => {
                    start = match start.checked_sub(page_size) {
                        Some(n) => n,
                        None => 0,
                    }
                }
                "q" => break,
                _ => {
                    println!("Invalid selection");
                    continue;
                }
            },
        };
    }
    Ok(())
}

fn get_window_size(max_size: usize) -> Result<usize> {
    print!("Enter page size: ");
    std::io::stdout().flush()?;
    let page_size_input = read_usize()?;
    let page_size = match page_size_input {
        0 => panic!("Page size cannot be zero"),
        n if n > max_size => max_size,
        _ => page_size_input,
    };
    println!("");
    Ok(page_size)
}

/// From a list of encrypted documents, decrypts all documents and prints the decrypted data of a selected document.
/// We don't currently offer a batch decrypt function, so this uses a `try_join_all` of the futures returned by `document_decrypt`.
async fn decrypt_in_bulk(sdk: &IronOxide, documents: Vec<DocumentEncryptResult>) -> Result<()> {
    println!("\nDecrypting all documents in bulk...");
    let decrypted_documents =
        futures::future::try_join_all(documents.iter().map(|doc| decrypt_document(sdk, doc)))
            .await?;
    println!("\nDecrypted Documents:");
    for i in 0..documents.len() {
        println!("#{}: {}", i + 1, documents[i].id().id());
    }
    print!("\nDocument # to view: ");
    std::io::stdout().flush()?;
    let doc_index = read_usize()?;
    println!(
        "Decrypted data: {}",
        std::str::from_utf8(decrypted_documents[doc_index - 1].decrypted_data())?
    );
    Ok(())
}

/// Decrypts a single document, explicitly printing when the decryption takes place.
async fn decrypt_document(
    sdk: &IronOxide,
    document: &DocumentEncryptResult,
) -> Result<DocumentDecryptResult> {
    println!("Decrypting document with ID {}", document.id().id());
    let decrypted_document = sdk.document_decrypt(document.encrypted_data()).await?;
    Ok(decrypted_document)
}

/// Reads a usize from stdin.
fn read_usize() -> Result<usize> {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().parse()?)
}
