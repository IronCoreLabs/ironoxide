use anyhow::{Error, Result};
use ironoxide::prelude::*;
use std::{fs::File, io::Write, path::PathBuf, str::from_utf8};

#[tokio::main]
async fn main() -> Result<()> {
    let sdk = initialize_sdk_from_file("examples/example-ironoxide-device.json".into()).await?;
    let documents = generate_encrypted_documents(&sdk, 5).await?;
    let document_data: Vec<&[u8]> = documents.iter().map(|doc| doc.encrypted_data()).collect();
    println!("1. Decrypt as needed");
    println!("2. Decrypt in pages");
    println!("3. Decrypt in bulk");
    let method = read_usize("Choose a method of decryption: ")?;
    match method {
        1 => decrypt_as_needed(&sdk, &document_data).await?,
        2 => decrypt_in_pages(&sdk, &document_data).await?,
        3 => decrypt_in_bulk(&sdk, &document_data).await?,
        _ => println!("Invalid selection"),
    };
    Ok(())
}

/// From a list of encrypted documents, decrypts a selected document and prints its decrypted data.
async fn decrypt_as_needed(sdk: &IronOxide, documents: &[&[u8]]) -> Result<()> {
    print_encrypted_documents(sdk, documents);
    let doc_index = read_usize("\nDocument # to decrypt: ")? - 1;
    // start-snippet{decryptAsNeeded}
    let encrypted_doc = documents.get(doc_index).expect("Index out of range.");
    let id = sdk.document_get_id_from_bytes(encrypted_doc)?;
    println!("Decrypting document with ID {}\n", id.id());
    let decrypted_doc = sdk.document_decrypt(encrypted_doc).await?;
    // end-snippet{decryptAsNeeded}
    print_decrypted_data(&decrypted_doc)?;
    Ok(())
}

/// From a list of encrypted documents, decrypts a selected number at a time and allows the user
/// to view the decrypted data of one.
async fn decrypt_in_pages(sdk: &IronOxide, documents: &[&[u8]]) -> Result<()> {
    let page_size = read_page_size(documents.len())?;
    // start-snippet{decryptInPages}
    let pages: Vec<_> = documents.chunks(page_size).collect();
    let mut maybe_current_page = Some(0);
    let mut previous_page = 1;
    let mut decrypted_documents = vec![];
    while let Some(current_page) = maybe_current_page {
        if current_page == previous_page {
            println!("Page did not change, so the documents are already decrypted.")
        } else {
            previous_page = current_page;
            decrypted_documents = futures::future::try_join_all(
                pages
                    .get(current_page)
                    .ok_or_else(|| Error::msg("Invalid document page."))?
                    .iter()
                    .map(|doc| decrypt_document(sdk, doc)),
            )
            .await?;
        }
        print_decrypted_documents(&decrypted_documents, current_page * page_size);
        maybe_current_page =
            get_new_current_page(current_page, page_size, pages.len(), &decrypted_documents)?;
    }
    // end-snippet{decryptInPages}
    Ok(())
}

/// From a list of encrypted documents, decrypts all documents and prints the decrypted data of a selected document.
/// We don't currently offer a batch decrypt function, so this uses a `try_join_all` of the futures returned by `document_decrypt`.
async fn decrypt_in_bulk(sdk: &IronOxide, documents: &[&[u8]]) -> Result<()> {
    // start-snippet{decryptInBulk}
    println!("\nDecrypting all documents in bulk...");
    let decrypted_documents =
        futures::future::try_join_all(documents.iter().map(|doc| decrypt_document(sdk, doc)))
            .await?;
    print_decrypted_documents(&decrypted_documents, 0);
    let doc_index = read_usize("\nDocument # to view: ")?;
    let decrypted_doc = &decrypted_documents[doc_index - 1];
    // end-snippet{decryptInPages}
    print_decrypted_data(decrypted_doc)?;
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
async fn generate_encrypted_documents(
    sdk: &IronOxide,
    number_of_documents: u8,
) -> ironoxide::Result<Vec<DocumentEncryptResult>> {
    println!("Encrypting {} documents...", number_of_documents);
    let opts = DocumentEncryptOpts::default();
    let encrypted_documents = futures::future::try_join_all(
        (0..number_of_documents).map(|_| sdk.document_encrypt(b"foobar".to_vec(), &opts)),
    )
    .await;
    println!("Done\n");
    encrypted_documents
}

/// Decrypts a single document, explicitly printing when the decryption takes place.
async fn decrypt_document(sdk: &IronOxide, document: &[u8]) -> Result<DocumentDecryptResult> {
    let id = sdk.document_get_id_from_bytes(document)?;
    println!("Decrypting document with ID {}", id.id());
    let decrypted_document = sdk.document_decrypt(document).await?;
    Ok(decrypted_document)
}

/// Reads input from the user and determines what the new current page should be or if the loop should exit.
///
/// Can go the the next page or previous page, view a document on the current page, or quit.
///
/// Returns a `Some` with the number of the page the user wishes to view,
/// or `None` if the user views a document or chooses to quit.
fn get_new_current_page(
    current_page: usize,
    page_size: usize,
    pages_len: usize,
    decrypted_documents: &[DocumentDecryptResult],
) -> Result<Option<usize>> {
    let input = read_stdin(
        "\nDocument # to decrypt, 'n' for next page, 'p' for previous page, or 'q' to quit: ",
    )?;
    println!();
    Ok(match input.trim().parse::<usize>() {
        // User entered a number
        Ok(num) => {
            let current_min = current_page * page_size + 1;
            let current_max = current_min + decrypted_documents.len() - 1;

            // Number corresponds to a document on the current page
            if num >= current_min && num <= current_max {
                let doc = &decrypted_documents[num - current_min];
                print_decrypted_data(doc)?;
                None
            }
            // Number is not on the current page
            else {
                println!("Invalid selection");
                Some(current_page)
            }
        }
        // User entered a string
        Err(_) => match input.trim() {
            // Next page (without going over the max)
            "n" => Some(std::cmp::min(current_page + 1, pages_len - 1)),
            // Previous page (without going below zero)
            "p" => current_page.checked_sub(1).or(Some(0)),
            // Quit
            "q" => None,
            // Invalid
            _ => {
                println!("Invalid selection");
                Some(current_page)
            }
        },
    })
}

/// Prints a single decrypted document.
fn print_decrypted_data(document: &DocumentDecryptResult) -> Result<()> {
    println!(
        "ID: {}\nDecrypted data: {}",
        document.id().id(),
        from_utf8(document.decrypted_data())?
    );
    Ok(())
}

/// From a list of documents, prints out every document's number and ID.
/// If a document's number should be increased due to what page it's on, set `page_offset` to the
/// current page number * the page size, otherwise set it to 0.
fn print_decrypted_documents(decrypted_documents: &[DocumentDecryptResult], page_offset: usize) {
    println!("\nDecrypted documents:");
    decrypted_documents
        .iter()
        .enumerate()
        .for_each(|(offset, doc)| {
            let doc_number = page_offset + offset + 1;
            println!("#{}: {}", doc_number, doc.id().id())
        });
}

/// From a list of documents, prints out every document's number and ID.
/// If a document's number should be increased due to what page it's on, set `page_offset` to the
/// current page number * the page size, otherwise set it to 0.
fn print_encrypted_documents(sdk: &IronOxide, encrypted_documents: &[&[u8]]) {
    println!("\nEncrypted documents:");
    encrypted_documents
        .iter()
        .enumerate()
        .for_each(|(offset, doc)| {
            let id = sdk
                .document_get_id_from_bytes(doc)
                .expect("Invalid document bytes");
            println!("#{}: {}", offset + 1, id.id())
        });
}

/// Reads the desired page size from stdin
fn read_page_size(max_size: usize) -> Result<usize> {
    let page_size_input = read_usize("Enter page size: ")?;
    let page_size = match page_size_input {
        0 => panic!("Page size cannot be zero"),
        n if n > max_size => max_size,
        _ => page_size_input,
    };
    println!();
    Ok(page_size)
}

/// Reads a usize from stdin with the given prompt.
fn read_usize(text: &str) -> Result<usize> {
    Ok(read_stdin(text)?.trim().parse()?)
}

/// Read from stdin with the given prompt.
fn read_stdin(text: &str) -> Result<String> {
    print!("{}", text);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input)
}
