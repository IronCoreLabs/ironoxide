//! Streaming AES-GCM encryption/decryption using AES-CTR + incremental GHASH
//!
//! This module implements streaming AES-GCM by decomposing the algorithm into its two
//! incremental components:
//! - AES-CTR: Stream cipher for encryption/decryption (via aws-lc-rs)
//! - GHASH: Authentication tag computation (via RustCrypto/ghash crate)
//!
//! This allows processing large files with constant memory usage while producing
//! output compatible with standard AES-GCM (same format as `crypto::aes` module).
//!
//! https://en.wikipedia.org/wiki/Galois/Counter_Mode gives a pretty good explanation of the algorithm we're patching
//! together from its constituent parts. The NIST documents lay it out in mathematical notation, if you need further
//! reference.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                        STREAMING AES-GCM ARCHITECTURE                       │
//! │                                                                             │
//! │  Standard AES-GCM is not streamable because authentication requires all     │
//! │  ciphertext before producing/verifying the tag. We decompose GCM into:      │
//! │                                                                             │
//! │    AES-GCM = AES-CTR (encryption) + GHASH (authentication)                  │
//! │                                                                             │
//! │  Both components can process data incrementally, enabling constant-memory   │
//! │  streaming while producing output identical to standard AES-GCM.            │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                              KEY DERIVATION                                 │
//! │                                                                             │
//! │   Given: K (256-bit key), IV (96-bit random nonce)                          │
//! │                                                                             │
//! │   ┌─────────────┐                                                           │
//! │   │  0^128      │──────► AES_K ──────► H (GHASH subkey)                     │
//! │   │ (128 zeros) │                                                           │
//! │   └─────────────┘                                                           │
//! │                                                                             │
//! │   ┌─────────────────────┐                                                   │
//! │   │  IV  │ 0^31 │ 1     │──► AES_K ──► Encrypted_J0 (for final tag XOR)     │
//! │   │ 96b  │ 31b  │ 1b    │    (J0 = initial counter block)                   │
//! │   └─────────────────────┘                                                   │
//! │                                                                             │
//! │   CTR counter starts at J0 + 1 = IV || 0^31 || 2                            │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                              ENCRYPTION FLOW                                │
//! │                                                                             │
//! │   Plaintext chunks          AES-CTR                     Output              │
//! │   ┌──────────┐         ┌─────────────┐                                      │
//! │   │ P_1      │────────►│ CTR(IV||2)  │──────► C_1 ────────┬──► Ciphertext   │
//! │   └──────────┘         └─────────────┘                    │                 │
//! │   ┌──────────┐         ┌─────────────┐                    │                 │
//! │   │ P_2      │────────►│ CTR(IV||3)  │──────► C_2 ─────┬──┼──► Ciphertext   │
//! │   └──────────┘         └─────────────┘                 │  │                 │
//! │       ...                   ...                        │  │                 │
//! │   ┌──────────┐         ┌─────────────┐                 │  │                 │
//! │   │ P_n      │────────►│ CTR(IV||n+1)│──────► C_n ──┬──┼──┼──► Ciphertext   │
//! │   └──────────┘         └─────────────┘              │  │  │                 │
//! │                                                     │  │  │                 │
//! │                     GHASH Accumulation              │  │  │                 │
//! │                     ┌──────────────────────────┐    │  │  │                 │
//! │                     │  GhashAccumulator        │◄───┴──┴──┘                 │
//! │                     │  (buffers partial blocks)│                            │
//! │                     └────────────┬─────────────┘                            │
//! │                                  │                                          │
//! │                                  ▼                                          │
//! │   ┌─────────────────────────────────────────────────┐                       │
//! │   │ len_block = [AAD_len_bits || CT_len_bits]       │                       │
//! │   │             [    0^64     || ciphertext_len*8 ] │                       │
//! │   └────────────────────────┬────────────────────────┘                       │
//! │                            │                                                │
//! │                            ▼                                                │
//! │   ┌───────────────────────────────────────────────────────────────────┐     │
//! │   │  Tag = GHASH(C_1 || C_2 || ... || C_n || len_block) ⊕ Encrypted_J0│     │
//! │   └───────────────────────────────────────────────────────────────────┘     │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                              DECRYPTION FLOW                                │
//! │                                                                             │
//! │   Input stream:  [IV (12 bytes)][ciphertext...][tag (16 bytes)]             │
//! │                                                                             │
//! │   Strategy: Hold back last 16 bytes of each chunk until verify() is called  │
//! │                                                                             │
//! │   ┌──────────┐                                                              │
//! │   │ Read IV  │──────────────► Initialize CTR & GHASH (same as encrypt)      │
//! │   └──────────┘                                                              │
//! │                                                                             │
//! │   ┌──────────────────┐    ┌──────────────────┐                              │
//! │   │ Ciphertext chunk │───►│ held_back buffer │ (always keep last 16 bytes)  │
//! │   └──────────────────┘    └────────┬─────────┘                              │
//! │                                    │                                        │
//! │                    ┌───────────────┴───────────────┐                        │
//! │                    │ Process bytes before held_back│                        │
//! │                    └───────────────┬───────────────┘                        │
//! │                                    │                                        │
//! │                    ┌───────────────┴───────────────┐                        │
//! │                    ▼                               ▼                        │
//! │               ┌─────────┐                    ┌───────────┐                  │
//! │               │ GHASH   │                    │ AES-CTR   │                  │
//! │               │ update  │                    │ decrypt   │                  │
//! │               └────┬────┘                    └─────┬─────┘                  │
//! │                    │                               │                        │
//! │                    ▼                               ▼                        │
//! │           hash = (hash ⊕ block) * H          ┌───────────┐                  │
//! │           (fold into 128-bit hash)           │ Write     │                  │
//! │                                              │ plaintext │                  │
//! │                                              └───────────┘                  │
//! │                                                                             │
//! │   On verify():                                                              │
//! │   ┌─────────────────────────────────────────────────────────────────────┐   │
//! │   │  1. held_back (16 bytes) = expected_tag                             │   │
//! │   │  2. computed_tag = GHASH(all_ciphertext || len_block) ⊕ Encrypted_J0│   │
//! │   │  3. constant_time_compare(computed_tag, expected_tag)               │   │
//! │   │  4. Return remaining plaintext or authentication error              │   │
//! │   └─────────────────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                              WIRE FORMAT                                    │
//! │                                                                             │
//! │   ┌────────────┬─────────────────────────────────┬────────────────┐         │
//! │   │   IV       │         Ciphertext              │     Tag        │         │
//! │   │ (12 bytes) │       (plaintext_len bytes)     │  (16 bytes)    │         │
//! │   └────────────┴─────────────────────────────────┴────────────────┘         │
//! │                                                                             │
//! │   Total output size = 12 + plaintext_len + 16 = plaintext_len + 28 bytes    │
//! │                                                                             │
//! │   Compatible with: crypto::aes module (bidirectional interop verified)      │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
// In Java/Scala/nodejs we were able to find common crypto libraries that implemented this model but did not find any
// in Rust. If one is found (RustCrypto, ring, aws-lc-rs, etc), use that instead of doing it ourselves.

use aws_lc_rs::{
    cipher::{
        AES_256, DecryptionContext, EncryptingKey, EncryptionContext, StreamingDecryptingKey,
        StreamingEncryptingKey, UnboundCipherKey,
    },
    constant_time,
};
use ghash::{GHash, universal_hash::UniversalHash};
use rand::CryptoRng;
use std::{
    io::{BufReader, BufWriter, Read, Write},
    ops::DerefMut,
    sync::Mutex,
};

use crate::{
    IronOxideErr, Result,
    crypto::aes::{AES_BLOCK_SIZE, AES_GCM_TAG_LEN, AES_IV_LEN, AES_KEY_LEN},
    internal::take_lock,
};

/// Default block/chunk size for the file input/output (64 KB)
pub(crate) const DEFAULT_IO_BLOCK_SIZE: usize = 64 * 1024;

/// Build a counter block from IV and counter value.
/// For 96-bit IVs: result = IV || counter (big-endian u32)
fn build_counter_block(iv: &[u8; AES_IV_LEN], counter: u32) -> ghash::Block {
    let mut block = ghash::Block::default();
    block[..AES_IV_LEN].copy_from_slice(iv);
    block[AES_IV_LEN..].copy_from_slice(&counter.to_be_bytes());
    block
}

/// Appends the standard GCM length block [len(AAD) || len(ciphertext)] in bits,
/// then XORs the GHASH output with encrypted J0 to produce the final tag.
fn finalize_gcm_tag(
    ghash_acc: GhashAccumulator,
    encrypted_j0: &ghash::Block,
    ciphertext_len: u64,
) -> [u8; AES_GCM_TAG_LEN] {
    // Finalize the accumulator (handles any pending partial block)
    let mut ghash = ghash_acc.finalize();

    // Update GHASH with length block: [len(AAD) || len(ciphertext)] in bits, big-endian
    let mut len_block = ghash::Block::default();
    // First 8 bytes: AAD length in bits (always 0 for us)
    // Last 8 bytes: ciphertext length in bits
    len_block[8..].copy_from_slice(&(ciphertext_len * 8).to_be_bytes());
    ghash.update(&[len_block]);

    // Compute final tag: GHASH_output XOR AES_K(J0)
    let ghash_output = ghash.finalize();
    let mut tag = [0u8; AES_GCM_TAG_LEN];
    for i in 0..AES_GCM_TAG_LEN {
        tag[i] = ghash_output[i] ^ encrypted_j0[i];
    }
    tag
}

/// Accumulator for GHASH that properly handles block boundaries.
/// Only processes complete 16-byte blocks during updates; padding is applied only at finalization.
/// This is needed because while streaming we get a variable number of bytes from the BufReader, depending on its
/// own internal buffering logic. Using this accumulator makes sure we're always feeding appropriately sized blocks
/// into the GHASH update, so it doesn't pad anything prematurely.
struct GhashAccumulator {
    ghash: GHash,
    /// Partial block pending processing (0-15 bytes)
    pending: Vec<u8>,
}

impl GhashAccumulator {
    fn new(ghash: GHash) -> Self {
        Self {
            ghash,
            pending: Vec::with_capacity(AES_BLOCK_SIZE),
        }
    }

    /// Update GHASH with data. Only processes complete 16-byte blocks;
    /// partial data is buffered until more data arrives or finalize is called.
    fn update(&mut self, data: &[u8]) {
        self.pending.extend_from_slice(data);

        // Process all complete 16-byte blocks
        let complete_blocks = self.pending.len() / AES_BLOCK_SIZE;
        let complete_len = complete_blocks * AES_BLOCK_SIZE;

        for chunk in self.pending[..complete_len].chunks_exact(AES_BLOCK_SIZE) {
            let mut block = ghash::Block::default();
            block.copy_from_slice(chunk);
            self.ghash.update(&[block]);
        }

        // Keep only the remaining partial block
        self.pending.drain(..complete_len);
    }

    /// Finalize GHASH, padding any remaining partial block.
    fn finalize(mut self) -> GHash {
        // Process any remaining partial block with zero padding
        if !self.pending.is_empty() {
            let mut block = ghash::Block::default();
            block[..self.pending.len()].copy_from_slice(&self.pending);
            self.ghash.update(&[block]);
        }
        self.ghash
    }
}

/// Initialize GHASH and pre-compute encrypted initial counter block for AES-GCM.
/// - H = GHASH key
/// - J0 = IV || 0^31 || 1 is the initial counter block
fn init_gcm_state(key: &[u8; AES_KEY_LEN], iv: &[u8; AES_IV_LEN]) -> Result<(GHash, ghash::Block)> {
    // Create ECB key for single-block operations (H derivation and J0 encryption)
    let ecb_cipher_key = UnboundCipherKey::new(&AES_256, key)
        .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;
    let ecb_key = EncryptingKey::ecb(ecb_cipher_key)
        .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;

    // Derive GHASH key: H = AES_K(0^128)
    let mut ghash_key = ghash::Key::default();
    ecb_key
        .encrypt(&mut ghash_key)
        .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;
    let ghash = GHash::new(&ghash_key);

    // Pre-compute encrypted J0 for final tag: AES_K(IV || 0^31 || 1)
    let mut encrypted_j0 = build_counter_block(iv, 1);
    ecb_key
        .encrypt(&mut encrypted_j0)
        .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;

    Ok((ghash, encrypted_j0))
}

/// Streaming encryptor using AES-CTR + incremental GHASH. Produces output identical to standard AES-GCM encryption.
pub(crate) struct StreamingEncryptor {
    /// The cipher/encryptor doing the actual CTR encryption.
    ctr_cipher: StreamingEncryptingKey,
    /// The GHASH accumulator that handles block boundaries correctly.
    ghash_acc: GhashAccumulator,
    /// Pre-computed AES_K(J0) for final tag computation
    encrypted_j0: ghash::Block,
    /// Count of the byte-length written by this encryptor.
    ciphertext_len: u64,
}

impl StreamingEncryptor {
    /// Create a new streaming encryptor with the given key and IV.
    pub(crate) fn new(key: &[u8; AES_KEY_LEN], iv: [u8; AES_IV_LEN]) -> Result<Self> {
        let (ghash, encrypted_initial_counter_block) = init_gcm_state(key, &iv)?;

        // Create AES-CTR key starting at counter 2 (J0+1)
        let ctr_iv: [u8; AES_BLOCK_SIZE] = build_counter_block(&iv, 2).into();
        let ctr_cipher_key = UnboundCipherKey::new(&AES_256, key)
            .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;
        let context = EncryptionContext::Iv128(ctr_iv.into());
        // `less_safe_ctr` so we can use the same encryption context as our GCM
        let ctr_key = StreamingEncryptingKey::less_safe_ctr(ctr_cipher_key, context)
            .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;

        Ok(Self {
            ctr_cipher: ctr_key,
            ghash_acc: GhashAccumulator::new(ghash),
            encrypted_j0: encrypted_initial_counter_block,
            ciphertext_len: 0,
        })
    }

    /// Encrypt a (input-sized, not AES block) chunk of plaintext and write ciphertext to output buffer.
    ///
    /// The output buffer must be at least as large as the input.
    /// After this call, the GHASH accumulator is updated with the ciphertext.
    pub(crate) fn process_chunk(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        if output.len() < input.len() {
            return Err(IronOxideErr::FileIoError {
                path: None,
                operation: "encrypt".to_string(),
                message: "Output buffer too small".to_string(),
            });
        }

        // For CTR mode, output buffer needs extra space for potential block alignment
        let min_out_size = input.len() + AES_BLOCK_SIZE - 1;
        let mut temp_output = vec![0u8; min_out_size];

        // Encrypt with AES-CTR
        let buffer_update = self
            .ctr_cipher
            .update(input, &mut temp_output)
            .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;

        let written = buffer_update.written();
        let written_len = written.len();

        // Copy to output
        output[..written_len].copy_from_slice(written);

        // Update GHASH accumulator with ciphertext
        self.ghash_acc.update(&output[..written_len]);
        self.ciphertext_len += written_len as u64;

        Ok(written_len)
    }

    /// Finalize encryption and return the authentication tag.
    /// This must be called after all plaintext has been processed. The tag should be appended to the ciphertext.
    /// Returns the tag and any remaining ciphertext bytes.
    pub(crate) fn finalize(mut self) -> Result<(Vec<u8>, [u8; AES_GCM_TAG_LEN])> {
        // CTR mode is streaming so it doesn't buffer bytes, and final_output should be empty. `aws-lc-rs` has an
        // output argument anyway (part of their generic traits), so we'll defensively flush as though there could
        // be remaining output.
        let mut final_output = vec![0u8; AES_BLOCK_SIZE];
        let (_, buffer_update_info) = self
            .ctr_cipher
            .finish(&mut final_output)
            .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;

        // If we _did_ write something to the final output buffer, make sure that we push those same bytes into GHASH
        let remaining = buffer_update_info.written().to_vec();
        if !remaining.is_empty() {
            self.ghash_acc.update(&remaining);
            self.ciphertext_len += remaining.len() as u64;
        }

        let tag = finalize_gcm_tag(self.ghash_acc, &self.encrypted_j0, self.ciphertext_len);
        Ok((remaining, tag))
    }
}

/// Streaming decryptor using AES-CTR + incremental GHASH verification.
pub(crate) struct StreamingDecryptor {
    /// The cipher/decryptor doing the actual CTR decryption.
    ctr_cipher: StreamingDecryptingKey,
    /// The GHASH accumulator that handles block boundaries correctly.
    ghash_acc: GhashAccumulator,
    /// Count of the byte-length of ciphertext processed.
    ciphertext_len: u64,
    /// Pre-computed AES_K(J0) for final tag computation
    encrypted_j0: ghash::Block,
    /// Buffer holding the trailing bytes that might be the GCM tag.
    /// We always hold back the last 16 bytes until verify() is called.
    held_back: Vec<u8>,
}

impl StreamingDecryptor {
    /// Create a new streaming decryptor with the given key and IV.
    pub(crate) fn new(key: &[u8; AES_KEY_LEN], iv: [u8; AES_IV_LEN]) -> Result<Self> {
        let (ghash, encrypted_j0) = init_gcm_state(key, &iv)?;

        // Create AES-CTR key starting at counter 2
        let ctr_iv: [u8; AES_BLOCK_SIZE] = build_counter_block(&iv, 2).into();
        let ctr_cipher_key = UnboundCipherKey::new(&AES_256, key)
            .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;
        let context = DecryptionContext::Iv128(ctr_iv.into());
        let ctr_key = StreamingDecryptingKey::ctr(ctr_cipher_key, context)
            .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;

        Ok(Self {
            ctr_cipher: ctr_key,
            ghash_acc: GhashAccumulator::new(ghash),
            encrypted_j0,
            held_back: Vec::with_capacity(AES_GCM_TAG_LEN),
            ciphertext_len: 0,
        })
    }

    /// Process a (input sized, not AES block) chunk of ciphertext (which includes the trailing GCM tag),
    /// writing plaintext to output buffer.
    ///
    /// This method holds back the last 16 bytes (the GCM tag) while processing.
    /// Call `verify()` after all data has been processed to verify the tag
    /// and get any remaining plaintext.
    pub(crate) fn process_chunk(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        // Combine held_back bytes with new input
        let mut combined = std::mem::take(&mut self.held_back);
        combined.extend_from_slice(input);

        // If we don't have more than tag length, hold it all back
        if combined.len() <= AES_GCM_TAG_LEN {
            self.held_back = combined;
            return Ok(0);
        }

        // Process all but the last tag-length bytes
        let to_process_len = combined.len() - AES_GCM_TAG_LEN;
        let ciphertext = &combined[..to_process_len];
        self.held_back = combined[to_process_len..].to_vec();

        if output.len() < ciphertext.len() {
            return Err(IronOxideErr::FileIoError {
                path: None,
                operation: "decrypt".to_string(),
                message: "Output buffer too small".to_string(),
            });
        }

        // Update GHASH accumulator with ciphertext BEFORE decryption
        self.ghash_acc.update(ciphertext);
        self.ciphertext_len += ciphertext.len() as u64;

        // For CTR mode, output buffer needs extra space for potential block alignment
        let min_out_size = ciphertext.len() + AES_BLOCK_SIZE - 1;
        let mut temp_output = vec![0u8; min_out_size];

        // Decrypt with AES-CTR
        let buffer_update = self
            .ctr_cipher
            .update(ciphertext, &mut temp_output)
            .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;

        let written = buffer_update.written();
        let written_len = written.len();

        // Copy to output
        output[..written_len].copy_from_slice(written);

        Ok(written_len)
    }

    /// Verify the authentication tag and return any remaining plaintext.
    ///
    /// The tag is extracted from the bytes held back during `process_block` calls.
    /// Returns `Ok(remaining_plaintext)` if authentication succeeds, or an error if:
    /// - Not enough bytes were provided (less than 16 bytes total)
    /// - The authentication tag doesn't match
    pub(crate) fn verify(self) -> Result<Vec<u8>> {
        // The held_back buffer should contain exactly the GCM tag
        if self.held_back.len() != AES_GCM_TAG_LEN {
            return Err(IronOxideErr::AesGcmDecryptError);
        }

        let expected_tag: [u8; AES_GCM_TAG_LEN] = self
            .held_back
            .try_into()
            .map_err(|_| IronOxideErr::AesGcmDecryptError)?;

        // Finalize CTR mode - get any remaining bytes
        let mut final_output = vec![0u8; AES_BLOCK_SIZE];
        let buffer_update = self
            .ctr_cipher
            .finish(&mut final_output)
            .map_err(|_| IronOxideErr::AesError(aws_lc_rs::error::Unspecified))?;

        let remaining = buffer_update.written().to_vec();

        let computed_tag =
            finalize_gcm_tag(self.ghash_acc, &self.encrypted_j0, self.ciphertext_len);

        constant_time::verify_slices_are_equal(&computed_tag, &expected_tag)
            .map_err(|_| IronOxideErr::AesGcmDecryptError)?;

        Ok(remaining)
    }
}

/// Streaming encrypt data from a reader to a writer.
/// Generates the IV internally and writes it to the output before the ciphertext,
/// similar to how `aes::encrypt` bundles IV with ciphertext.
/// Output format: [IV (12 bytes)][ciphertext][tag (16 bytes)]
pub(crate) fn encrypt_stream<R: Read, W: Write, RNG: CryptoRng>(
    key: &[u8; AES_KEY_LEN],
    rng: &Mutex<RNG>,
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
) -> Result<()> {
    // Generate IV
    let mut iv = [0u8; AES_IV_LEN];
    take_lock(rng).deref_mut().fill_bytes(&mut iv);

    // Write IV to output
    writer
        .write_all(&iv)
        .map_err(|e| IronOxideErr::FileIoError {
            path: None,
            operation: "write_iv".to_string(),
            message: e.to_string(),
        })?;

    let mut encryptor = StreamingEncryptor::new(key, iv)?;
    let mut input_buffer = vec![0u8; DEFAULT_IO_BLOCK_SIZE];
    let mut output_buffer = vec![0u8; DEFAULT_IO_BLOCK_SIZE + AES_BLOCK_SIZE];

    while let n @ 1.. = reader
        .read(&mut input_buffer)
        .map_err(|e| IronOxideErr::FileIoError {
            path: None,
            operation: "read".to_string(),
            message: e.to_string(),
        })?
    {
        let written = encryptor.process_chunk(&input_buffer[..n], &mut output_buffer)?;
        writer
            .write_all(&output_buffer[..written])
            .map_err(|e| IronOxideErr::FileIoError {
                path: None,
                operation: "write".to_string(),
                message: e.to_string(),
            })?;
    }

    let (remaining, tag) = encryptor.finalize()?;
    if !remaining.is_empty() {
        writer
            .write_all(&remaining)
            .map_err(|e| IronOxideErr::FileIoError {
                path: None,
                operation: "write".to_string(),
                message: e.to_string(),
            })?;
    }

    writer
        .write_all(&tag)
        .map_err(|e| IronOxideErr::FileIoError {
            path: None,
            operation: "write".to_string(),
            message: e.to_string(),
        })?;

    writer.flush().map_err(|e| IronOxideErr::FileIoError {
        path: None,
        operation: "flush".to_string(),
        message: e.to_string(),
    })?;

    Ok(())
}

/// Stream-decrypt data from a reader to a writer.
/// Reads the IV from the input before the ciphertext.
/// Expected input format: [IV (12 bytes)][ciphertext][tag (16 bytes)]
pub(crate) fn decrypt_stream<R: Read, W: Write>(
    key: &[u8; AES_KEY_LEN],
    reader: &mut BufReader<R>,
    writer: &mut BufWriter<W>,
) -> Result<()> {
    // Read IV from input
    let mut iv = [0u8; AES_IV_LEN];
    reader
        .read_exact(&mut iv)
        .map_err(|e| IronOxideErr::FileIoError {
            path: None,
            operation: "read_iv".to_string(),
            message: e.to_string(),
        })?;

    let mut decryptor = StreamingDecryptor::new(key, iv)?;
    let mut input_buffer = vec![0u8; DEFAULT_IO_BLOCK_SIZE];
    // Output buffer needs extra space since we may process more than we read
    // (due to combining held_back bytes with new input)
    let mut output_buffer = vec![0u8; DEFAULT_IO_BLOCK_SIZE + AES_BLOCK_SIZE + AES_GCM_TAG_LEN];

    while let n @ 1.. = reader
        .read(&mut input_buffer)
        .map_err(|e| IronOxideErr::FileIoError {
            path: None,
            operation: "read".to_string(),
            message: e.to_string(),
        })?
    {
        let written = decryptor.process_chunk(&input_buffer[..n], &mut output_buffer)?;
        if written > 0 {
            writer
                .write_all(&output_buffer[..written])
                .map_err(|e| IronOxideErr::FileIoError {
                    path: None,
                    operation: "write".to_string(),
                    message: e.to_string(),
                })?;
        }
    }

    let remaining_plaintext = decryptor.verify()?;
    if !remaining_plaintext.is_empty() {
        writer
            .write_all(&remaining_plaintext)
            .map_err(|e| IronOxideErr::FileIoError {
                path: None,
                operation: "write".to_string(),
                message: e.to_string(),
            })?;
    }

    writer.flush().map_err(|e| IronOxideErr::FileIoError {
        path: None,
        operation: "flush".to_string(),
        message: e.to_string(),
    })?;

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::aes;
    use proptest::prelude::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use std::io::Cursor;

    pub fn generate_test_key() -> [u8; AES_KEY_LEN] {
        let mut key = [0u8; AES_KEY_LEN];
        rand::rng().fill_bytes(&mut key);
        key
    }

    pub fn test_rng() -> Mutex<StdRng> {
        Mutex::new(StdRng::from_rng(&mut rand::rng()))
    }

    #[test]
    fn test_streaming_encrypt_decrypt_roundtrip() {
        let key = generate_test_key();
        let rng = test_rng();
        let plaintext = b"deadbeef";
        let mut ciphertext_buf = Vec::new();
        let mut decrypted_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));

            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }

        {
            let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
            let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

            decrypt_stream(&key, &mut reader, &mut writer).unwrap();
        }

        assert_eq!(decrypted_buf, plaintext);
    }

    #[test]
    fn test_streaming_encrypt_decrypt_large_data() {
        let key = generate_test_key();
        let rng = test_rng();

        // 1MB of random data
        let mut plaintext = vec![0u8; 1024 * 1024];
        rand::rng().fill_bytes(&mut plaintext);
        let mut ciphertext_buf = Vec::new();
        let mut decrypted_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(&plaintext));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));

            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }
        let expected_len = AES_IV_LEN + plaintext.len() + AES_GCM_TAG_LEN;
        assert_eq!(ciphertext_buf.len(), expected_len);

        {
            let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
            let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

            decrypt_stream(&key, &mut reader, &mut writer).unwrap();
        }
        assert_eq!(decrypted_buf, plaintext);
    }

    #[test]
    fn test_streaming_decrypt_detects_tampered_ciphertext() {
        let key = generate_test_key();
        let rng = test_rng();
        let plaintext = b"deadbeef";
        let mut ciphertext_buf = Vec::new();
        let mut decrypted_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));

            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }

        // Tamper with ciphertext (first byte after IV)
        ciphertext_buf[AES_IV_LEN] ^= 0xFF;

        // Decrypt should fail
        let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
        let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

        let result = decrypt_stream(&key, &mut reader, &mut writer);
        assert!(result.is_err());
    }

    #[test]
    fn test_streaming_decrypt_detects_tampered_tag() {
        let key = generate_test_key();
        let rng = test_rng();
        let plaintext = b"Hello, World!";
        let mut ciphertext_buf = Vec::new();
        let mut decrypted_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));

            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }

        // Tamper with tag (last byte)
        let last_idx = ciphertext_buf.len() - 1;
        ciphertext_buf[last_idx] ^= 0xFF;

        // Decrypt should fail
        let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
        let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

        let result = decrypt_stream(&key, &mut reader, &mut writer);
        assert!(result.is_err());
    }

    // Encrypt with streaming, decrypt with standard aes module
    // This verifies bidirectional interoperability
    #[test]
    fn test_interop_with_aes_module_decrypt_streaming_encrypted() {
        let key = generate_test_key();
        let rng = test_rng();
        let plaintext = b"Test data for interop";
        let mut ciphertext_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));

            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }

        let mut aes_value: aes::AesEncryptedValue = ciphertext_buf.as_slice().try_into().unwrap();
        let decrypted = aes::decrypt(&mut aes_value, key).unwrap();
        assert_eq!(decrypted, plaintext.as_slice());
    }

    // Encrypt with standard aes module, decrypt with streaming
    // This test verifies we can decrypt standard AES-GCM output
    #[test]
    fn test_interop_with_aes_module_streaming_decrypt_aes_encrypted() {
        let key = generate_test_key();
        let rng = test_rng();
        let plaintext = b"Test data for interop";
        let mut decrypted_buf = Vec::new();

        let encrypted = aes::encrypt(&rng, plaintext.to_vec(), key).unwrap();
        let encrypted_bytes = encrypted.bytes();
        {
            let mut reader = BufReader::new(Cursor::new(encrypted_bytes));
            let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

            decrypt_stream(&key, &mut reader, &mut writer).unwrap();
        }

        assert_eq!(decrypted_buf, plaintext);
    }

    // Encrypt large data with streaming, decrypt with standard aes module
    #[test]
    fn test_interop_large_data_streaming_encrypt_standard_decrypt() {
        let key = generate_test_key();
        let rng = test_rng();
        let mut ciphertext_buf = Vec::new();

        // 1MB random data
        let mut plaintext = vec![0u8; 1024 * 1024];
        rand::rng().fill_bytes(&mut plaintext);

        {
            let mut reader = BufReader::new(Cursor::new(&plaintext));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));

            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }

        let mut aes_value: aes::AesEncryptedValue = ciphertext_buf.as_slice().try_into().unwrap();
        let decrypted = aes::decrypt(&mut aes_value, key).unwrap();
        assert_eq!(decrypted, plaintext.as_slice());
    }

    // Encrypt large data with standard aes, decrypt with streaming
    #[test]
    fn test_interop_large_data_standard_encrypt_streaming_decrypt() {
        let key = generate_test_key();
        let rng = test_rng();
        let mut decrypted_buf = Vec::new();

        // 1MB random data
        let mut plaintext = vec![0u8; 1024 * 1024];
        rand::rng().fill_bytes(&mut plaintext);

        let encrypted = aes::encrypt(&rng, plaintext.clone(), key).unwrap();
        let encrypted_bytes = encrypted.bytes();

        {
            let mut reader = BufReader::new(Cursor::new(encrypted_bytes));
            let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

            decrypt_stream(&key, &mut reader, &mut writer).unwrap();
        }

        assert_eq!(decrypted_buf, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = generate_test_key();
        let rng = test_rng();
        let plaintext: &[u8] = &[];
        let mut ciphertext_buf = Vec::new();
        let mut decrypted_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));

            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }

        // Empty plaintext produces IV (12 bytes) + tag (16 bytes) = 28 bytes
        assert_eq!(ciphertext_buf.len(), AES_IV_LEN + AES_GCM_TAG_LEN);

        {
            let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
            let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

            decrypt_stream(&key, &mut reader, &mut writer).unwrap();
        }

        assert_eq!(decrypted_buf.len(), 0);
    }

    #[test]
    fn test_single_byte_plaintext() {
        let key = generate_test_key();
        let rng = test_rng();
        let plaintext = &[42u8];
        let mut ciphertext_buf = Vec::new();
        let mut decrypted_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));

            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }
        {
            let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
            let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

            decrypt_stream(&key, &mut reader, &mut writer).unwrap();
        }

        assert_eq!(decrypted_buf, plaintext);
    }

    // Edge case tests for block boundaries and error conditions
    #[test]
    fn test_exact_block_boundary_16_bytes() {
        let key = generate_test_key();
        let rng = test_rng();
        // Exactly one AES block (16 bytes)
        let plaintext = [0xABu8; 16];
        let mut ciphertext_buf = Vec::new();
        let mut decrypted_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));

            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }
        {
            let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
            let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

            decrypt_stream(&key, &mut reader, &mut writer).unwrap();
        }
        assert_eq!(decrypted_buf, plaintext);
    }

    #[test]
    fn test_exact_block_boundary_32_bytes() {
        let key = generate_test_key();
        let rng = test_rng();
        // Exactly two AES blocks (32 bytes)
        let plaintext = [0xCDu8; 32];
        let mut ciphertext_buf = Vec::new();
        let mut decrypted_buf = Vec::new();
        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));

            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }
        {
            let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
            let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

            decrypt_stream(&key, &mut reader, &mut writer).unwrap();
        }
        assert_eq!(decrypted_buf, plaintext);
    }

    #[test]
    fn test_exact_block_boundary_48_bytes() {
        let key = generate_test_key();
        let rng = test_rng();
        // Exactly three AES blocks (48 bytes)
        let plaintext = [0xEFu8; 48];
        let mut ciphertext_buf = Vec::new();
        let mut decrypted_buf = Vec::new();
        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));
            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }
        {
            let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
            let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));
            decrypt_stream(&key, &mut reader, &mut writer).unwrap();
        }
        assert_eq!(decrypted_buf, plaintext);
    }

    #[test]
    fn test_one_over_block_boundary_17_bytes() {
        let key = generate_test_key();
        let rng = test_rng();
        // One byte over block boundary
        let plaintext = [0x12u8; 17];
        let mut ciphertext_buf = Vec::new();
        let mut decrypted_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));
            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }
        {
            let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
            let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));
            decrypt_stream(&key, &mut reader, &mut writer).unwrap();
        }
        assert_eq!(decrypted_buf, plaintext);
    }

    #[test]
    fn test_one_under_block_boundary_15_bytes() {
        let key = generate_test_key();
        let rng = test_rng();
        // One byte under block boundary
        let plaintext = [0x34u8; 15];
        let mut ciphertext_buf = Vec::new();
        let mut decrypted_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));
            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }
        {
            let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
            let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));
            decrypt_stream(&key, &mut reader, &mut writer).unwrap();
        }

        assert_eq!(decrypted_buf, plaintext);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let encrypt_key = generate_test_key();
        let decrypt_key = generate_test_key(); // Different key
        let rng = test_rng();
        let plaintext = b"Data encrypted with one key, decrypted with another";
        let mut ciphertext_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));
            encrypt_stream(&encrypt_key, &rng, &mut reader, &mut writer).unwrap();
        }

        // Try to decrypt with wrong key
        let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
        let mut decrypted_buf = Vec::new();
        let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

        let result = decrypt_stream(&decrypt_key, &mut reader, &mut writer);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let key = generate_test_key();
        let rng = test_rng();
        let plaintext = b"Some data to encrypt";
        let mut ciphertext_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));
            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }

        // Truncate the ciphertext (remove some bytes from the end)
        ciphertext_buf.truncate(ciphertext_buf.len() - 5);

        let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
        let mut decrypted_buf = Vec::new();
        let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

        let result = decrypt_stream(&key, &mut reader, &mut writer);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_to_just_iv_fails() {
        let key = generate_test_key();
        let rng = test_rng();
        let plaintext = b"Some data";
        let mut ciphertext_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));
            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }

        // Truncate to just the IV (12 bytes) - no ciphertext or tag
        ciphertext_buf.truncate(AES_IV_LEN);

        let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
        let mut decrypted_buf = Vec::new();
        let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

        let result = decrypt_stream(&key, &mut reader, &mut writer);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_missing_partial_tag_fails() {
        let key = generate_test_key();
        let rng = test_rng();
        let plaintext = b"Test data for partial tag truncation";
        let mut ciphertext_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));
            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }

        // Remove half the tag (8 bytes)
        ciphertext_buf.truncate(ciphertext_buf.len() - 8);

        let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
        let mut decrypted_buf = Vec::new();
        let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

        let result = decrypt_stream(&key, &mut reader, &mut writer);
        assert!(result.is_err());
    }

    #[test]
    fn test_iv_modification_fails() {
        let key = generate_test_key();
        let rng = test_rng();
        let plaintext = b"Test IV modification detection";
        let mut ciphertext_buf = Vec::new();

        {
            let mut reader = BufReader::new(Cursor::new(plaintext.as_slice()));
            let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));
            encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
        }

        // Modify the IV (first 12 bytes)
        ciphertext_buf[0] ^= 0xFF;

        let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
        let mut decrypted_buf = Vec::new();
        let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));

        let result = decrypt_stream(&key, &mut reader, &mut writer);
        assert!(result.is_err());
    }

    #[test]
    fn test_various_sizes_near_io_block_boundary() {
        let key = generate_test_key();
        let rng = test_rng();

        // Test sizes around the default IO block size (64KB)
        let test_sizes = [
            DEFAULT_IO_BLOCK_SIZE - 1,
            DEFAULT_IO_BLOCK_SIZE,
            DEFAULT_IO_BLOCK_SIZE + 1,
            DEFAULT_IO_BLOCK_SIZE * 2 - 1,
            DEFAULT_IO_BLOCK_SIZE * 2,
            DEFAULT_IO_BLOCK_SIZE * 2 + 1,
        ];

        for size in test_sizes {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let mut ciphertext_buf = Vec::new();
            let mut decrypted_buf = Vec::new();

            {
                let mut reader = BufReader::new(Cursor::new(&plaintext));
                let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));
                encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
            }
            {
                let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
                let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));
                decrypt_stream(&key, &mut reader, &mut writer).unwrap();
            }

            assert_eq!(decrypted_buf, plaintext, "Failed for size {}", size);
        }
    }

    /// Concrete test showing that naive GHash chunking produces wrong results.
    /// This demonstrates why GhashAccumulator is needed.
    #[test]
    fn test_ghash_naive_chunking_concrete() {
        // 6 bytes of data, split at byte 3
        let data = [1u8, 2, 3, 4, 5, 6];
        // Non-zero key so GHASH actually computes something
        let key = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let ghash_key = ghash::Key::from(key);

        // Correct: all data in one block, padded at end
        let output_correct = {
            let mut ghash = GHash::new(&ghash_key);
            let mut block = ghash::Block::default();
            block[..6].copy_from_slice(&data);
            // block = [1,2,3,4,5,6,0,0,0,0,0,0,0,0,0,0]
            ghash.update(&[block]);
            ghash.finalize()
        };

        // Wrong: split data into two padded blocks
        let output_wrong = {
            let mut ghash = GHash::new(&ghash_key);
            let mut block1 = ghash::Block::default();
            block1[..3].copy_from_slice(&data[..3]);
            // block1 = [1,2,3,0,0,0,0,0,0,0,0,0,0,0,0,0]
            ghash.update(&[block1]);

            let mut block2 = ghash::Block::default();
            block2[..3].copy_from_slice(&data[3..]);
            // block2 = [4,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0]
            ghash.update(&[block2]);
            ghash.finalize()
        };

        // These MUST be different - 1 block vs 2 blocks
        assert_ne!(
            output_correct.as_slice(),
            output_wrong.as_slice(),
            "Naive chunking should produce different result!"
        );
    }

    proptest! {
        #[test]
        fn prop_streaming_roundtrip(plaintext in prop::collection::vec(any::<u8>(), 0..100_000)) {
            let key = generate_test_key();
            let rng = test_rng();
            let mut ciphertext_buf = Vec::new();
            let mut decrypted_buf = Vec::new();

            {
                let mut reader = BufReader::new(Cursor::new(&plaintext));
                let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));
                encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
            }
            {
                let mut reader = BufReader::new(Cursor::new(&ciphertext_buf));
                let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));
                decrypt_stream(&key, &mut reader, &mut writer).unwrap();
            }

            prop_assert_eq!(plaintext, decrypted_buf);
        }

        #[test]
        fn prop_streaming_interop_standard_decrypt(plaintext in prop::collection::vec(any::<u8>(), 0..50_000)) {
            let key = generate_test_key();
            let rng = test_rng();
            let mut ciphertext_buf = Vec::new();
            {
                let mut reader = BufReader::new(Cursor::new(&plaintext));
                let mut writer = BufWriter::new(Cursor::new(&mut ciphertext_buf));
                encrypt_stream(&key, &rng, &mut reader, &mut writer).unwrap();
            }
            let mut aes_value: aes::AesEncryptedValue = ciphertext_buf.as_slice().try_into().unwrap();
            let decrypted = aes::decrypt(&mut aes_value, key).unwrap();

            prop_assert_eq!(&plaintext[..], decrypted);
        }

        #[test]
        fn prop_standard_encrypt_streaming_decrypt(plaintext in prop::collection::vec(any::<u8>(), 0..50_000)) {
            let key = generate_test_key();
            let rng = test_rng();
            let mut decrypted_buf = Vec::new();

            let encrypted = aes::encrypt(&rng, plaintext.clone(), key).unwrap();
            let encrypted_bytes = encrypted.bytes();
            {
                let mut reader = BufReader::new(Cursor::new(encrypted_bytes));
                let mut writer = BufWriter::new(Cursor::new(&mut decrypted_buf));
                decrypt_stream(&key, &mut reader, &mut writer).unwrap();
            }
            prop_assert_eq!(plaintext, decrypted_buf);
        }

        /// GhashAccumulator produces same result regardless of chunk sizes
        #[test]
        fn prop_ghash_accumulator_chunking_invariant(data in prop::collection::vec(any::<u8>(), 1..5000), chunk_sizes in prop::collection::vec(1..100usize, 1..50)) {
            // Non-zero key so GHASH actually computes something
            let key = [
                0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
            ];
            let ghash_key = ghash::Key::from(key);

            // Compute with all-at-once
            let mut acc_single = GhashAccumulator::new(GHash::new(&ghash_key));
            acc_single.update(&data);
            let ghash_single = acc_single.finalize();

            // Now compute with arbitrary chunking. This simulates BufReader giving us any length (not only 16 byte
            // multiples) up to 8KiB for a chunk. If you naively break the chunk up into blocks, you'll potentially end
            // up with a padded value in the middle of the GHash accumulation, resulting in an incorrect tag.
            let mut acc_chunked = GhashAccumulator::new(GHash::new(&ghash_key));
            let mut offset = 0;
            for &size in &chunk_sizes {
                if offset >= data.len() { break; }
                let end = (offset + size).min(data.len());
                acc_chunked.update(&data[offset..end]);
                offset = end;
            }
            // Process any remaining data
            if offset < data.len() {
                acc_chunked.update(&data[offset..]);
            }
            let ghash_chunked = acc_chunked.finalize();

            // Both should produce the same final tag state
            let block = ghash::Block::default();
            let output_single = {
                let mut g = ghash_single;
                g.update(&[block]);
                g.finalize()
            };
            let output_chunked = {
                let mut g = ghash_chunked;
                g.update(&[block]);
                g.finalize()
            };

            prop_assert_eq!(output_single.as_slice(), output_chunked.as_slice());
        }
    }
}
