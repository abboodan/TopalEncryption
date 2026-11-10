//! Topal file encryption.
//!
//! Every `.topal` file is self-contained and can be decrypted with the password alone.
//!
//! Layout (all integers little-endian):
//!
//! | offset | size | field                                              |
//! |--------|------|----------------------------------------------------|
//! | 0      | 5    | magic `TOPAL`                                      |
//! | 5      | 1    | format version                                     |
//! | 6      | 12   | Argon2id memory (KiB), passes, lanes               |
//! | 18     | 16   | Argon2id salt                                      |
//! | 34     | 4    | plaintext chunk size                               |
//! | 38     | 19   | stream nonce prefix                                |
//! | 57     | 24   | key-wrap nonce                                     |
//! | 81     | 48   | file key, wrapped with the password-derived key    |
//! | 129    | ...  | chunks, each `chunk size + 16` bytes (last shorter)|
//!
//! The first 57 bytes are bound to the wrapped key as associated data, so any change to
//! the header makes the file undecryptable rather than silently reinterpreted.
//!
//! Password -> Argon2id -> key-encryption key (KEK). The KEK unwraps a random per-file
//! key, which encrypts the content in chunks with XChaCha20-Poly1305 in the STREAM
//! construction (chunks cannot be reordered, dropped, duplicated or truncated).
//!
//! An [`Encryptor`] runs Argon2id once and reuses its salt for every file it writes, and
//! a [`Decryptor`] caches derived keys per salt. A batch of thousands of files therefore
//! costs one key derivation, not one per file.

pub mod batch;

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::Mutex;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

/// File extension of encrypted files, without the dot.
pub const EXTENSION: &str = "topal";

const MAGIC: &[u8; 5] = b"TOPAL";
const VERSION: u8 = 1;

const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const SALT_LEN: usize = 16;
const STREAM_PREFIX_LEN: usize = 19;
const WRAP_NONCE_LEN: usize = 24;
const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;

/// Header bytes authenticated as associated data of the wrapped key.
const AAD_LEN: usize = 57;
/// Total header size in bytes.
pub const HEADER_LEN: usize = AAD_LEN + WRAP_NONCE_LEN + WRAPPED_KEY_LEN;

/// Plaintext bytes per chunk in files written by this version.
pub const CHUNK_SIZE: u32 = 1 << 20;

// Bounds accepted when reading, so a crafted header cannot demand absurd resources.
const MAX_CHUNK_SIZE: u32 = 16 << 20;
const MAX_MEMORY_KIB: u32 = 4 << 20;
const MAX_PASSES: u32 = 64;
const MAX_LANES: u32 = 64;

type Secret = Zeroizing<[u8; KEY_LEN]>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("not a Topal file")]
    NotTopal,
    #[error("unsupported Topal format version {0}")]
    UnsupportedVersion(u8),
    #[error("invalid key derivation parameters")]
    InvalidKdfParams,
    #[error("wrong password, or the file header is damaged")]
    WrongPassword,
    #[error("file content is damaged or incomplete")]
    Corrupted,
    #[error("verification failed: the file changed while it was being encrypted")]
    VerificationFailed,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Argon2id cost settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl Default for KdfParams {
    /// 256 MiB, 3 passes, 4 lanes: roughly a second on a desktop CPU.
    fn default() -> Self {
        Self { memory_kib: 256 * 1024, passes: 3, lanes: 4 }
    }
}

fn derive_kek(password: &[u8], salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Secret> {
    let argon_params = Params::new(params.memory_kib, params.passes, params.lanes, Some(KEY_LEN))
        .map_err(|_| Error::InvalidKdfParams)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut kek = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut *kek)
        .map_err(|_| Error::InvalidKdfParams)?;
    Ok(kek)
}

fn cipher(key: &[u8; KEY_LEN]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(Key::from_slice(key))
}

struct Header {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    chunk_size: u32,
    stream_prefix: [u8; STREAM_PREFIX_LEN],
    wrap_nonce: [u8; WRAP_NONCE_LEN],
    wrapped_key: [u8; WRAPPED_KEY_LEN],
}

impl Header {
    fn aad(&self) -> [u8; AAD_LEN] {
        let mut aad = [0u8; AAD_LEN];
        aad[0..5].copy_from_slice(MAGIC);
        aad[5] = VERSION;
        aad[6..10].copy_from_slice(&self.params.memory_kib.to_le_bytes());
        aad[10..14].copy_from_slice(&self.params.passes.to_le_bytes());
        aad[14..18].copy_from_slice(&self.params.lanes.to_le_bytes());
        aad[18..34].copy_from_slice(&self.salt);
        aad[34..38].copy_from_slice(&self.chunk_size.to_le_bytes());
        aad[38..57].copy_from_slice(&self.stream_prefix);
        aad
    }

    fn write_to(&self, mut writer: impl Write) -> io::Result<()> {
        writer.write_all(&self.aad())?;
        writer.write_all(&self.wrap_nonce)?;
        writer.write_all(&self.wrapped_key)
    }

    fn read_from(mut reader: impl Read) -> Result<Self> {
        let mut raw = [0u8; HEADER_LEN];
        if read_full(&mut reader, &mut raw)? != HEADER_LEN || &raw[0..5] != MAGIC {
            return Err(Error::NotTopal);
        }
        if raw[5] != VERSION {
            return Err(Error::UnsupportedVersion(raw[5]));
        }
        let u32_at = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let params = KdfParams { memory_kib: u32_at(6), passes: u32_at(10), lanes: u32_at(14) };
        if params.memory_kib > MAX_MEMORY_KIB || params.passes > MAX_PASSES || params.lanes > MAX_LANES {
            return Err(Error::InvalidKdfParams);
        }
        let chunk_size = u32_at(34);
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err(Error::Corrupted);
        }
        Ok(Self {
            params,
            salt: raw[18..34].try_into().unwrap(),
            chunk_size,
            stream_prefix: raw[38..57].try_into().unwrap(),
            wrap_nonce: raw[57..81].try_into().unwrap(),
            wrapped_key: raw[81..129].try_into().unwrap(),
        })
    }
}

/// Reads until `buf` is full or the input ends; returns the number of bytes read.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Encrypts any number of files under one password with a single key derivation.
pub struct Encryptor {
    params: KdfParams,
    salt: [u8; SALT_LEN],
    kek: Secret,
}

impl Encryptor {
    /// Derives the key from `password`. This is the slow step; do it once per batch.
    pub fn new(password: &str, params: KdfParams) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let kek = derive_kek(password.as_bytes(), &salt, params)?;
        Ok(Self { params, salt, kek })
    }

    /// Encrypts everything from `reader` into `writer`. Returns the plaintext byte count.
    /// Memory use is two chunks regardless of input size.
    pub fn encrypt(&self, mut reader: impl Read, mut writer: impl Write) -> Result<u64> {
        let mut file_key = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut *file_key);

        let mut header = Header {
            params: self.params,
            salt: self.salt,
            chunk_size: CHUNK_SIZE,
            stream_prefix: [0u8; STREAM_PREFIX_LEN],
            wrap_nonce: [0u8; WRAP_NONCE_LEN],
            wrapped_key: [0u8; WRAPPED_KEY_LEN],
        };
        OsRng.fill_bytes(&mut header.stream_prefix);
        OsRng.fill_bytes(&mut header.wrap_nonce);
        let wrapped = cipher(&self.kek)
            .encrypt(
                XNonce::from_slice(&header.wrap_nonce),
                Payload { msg: &file_key[..], aad: &header.aad() },
            )
            .expect("wrapping a 32-byte key cannot fail");
        header.wrapped_key.copy_from_slice(&wrapped);
        header.write_to(&mut writer)?;

        let mut stream = EncryptorBE32::from_aead(
            cipher(&file_key),
            GenericArray::from_slice(&header.stream_prefix),
        );
        let chunk = CHUNK_SIZE as usize;
        let mut current = Zeroizing::new(vec![0u8; chunk]);
        let mut next = Zeroizing::new(vec![0u8; chunk]);
        let mut current_len = read_full(&mut reader, &mut current)?;
        let mut total = 0u64;
        loop {
            // A chunk is the last one only if nothing follows it, so read one ahead.
            let next_len =
                if current_len == chunk { read_full(&mut reader, &mut next)? } else { 0 };
            total += current_len as u64;
            if next_len == 0 {
                let sealed = stream
                    .encrypt_last(&current[..current_len])
                    .map_err(|_| Error::Corrupted)?;
                writer.write_all(&sealed)?;
                break;
            }
            let sealed =
                stream.encrypt_next(&current[..current_len]).map_err(|_| Error::Corrupted)?;
            writer.write_all(&sealed)?;
            std::mem::swap(&mut current, &mut next);
            current_len = next_len;
        }
        writer.flush()?;
        Ok(total)
    }
}

/// Decrypts files, deriving the key once per distinct salt and caching it.
pub struct Decryptor {
    password: Zeroizing<Vec<u8>>,
    keys: Mutex<HashMap<([u8; SALT_LEN], KdfParams), Secret>>,
}

impl Decryptor {
    pub fn new(password: &str) -> Self {
        Self {
            password: Zeroizing::new(password.as_bytes().to_vec()),
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Holding the lock while deriving keeps parallel callers from each allocating
    /// Argon2's memory for the same salt at once.
    fn kek(&self, salt: [u8; SALT_LEN], params: KdfParams) -> Result<Secret> {
        let mut keys = self.keys.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(kek) = keys.get(&(salt, params)) {
            return Ok(kek.clone());
        }
        let kek = derive_kek(&self.password, &salt, params)?;
        keys.insert((salt, params), kek.clone());
        Ok(kek)
    }

    /// Decrypts everything from `reader` into `writer`. Returns the plaintext byte count.
    ///
    /// Each chunk is authenticated before it is written, but truncation is only detected
    /// at the end: on error, discard whatever was written.
    pub fn decrypt(&self, mut reader: impl Read, mut writer: impl Write) -> Result<u64> {
        let header = Header::read_from(&mut reader)?;
        let kek = self.kek(header.salt, header.params)?;
        let unwrapped = Zeroizing::new(
            cipher(&kek)
                .decrypt(
                    XNonce::from_slice(&header.wrap_nonce),
                    Payload { msg: &header.wrapped_key[..], aad: &header.aad() },
                )
                .map_err(|_| Error::WrongPassword)?,
        );
        let mut file_key = Zeroizing::new([0u8; KEY_LEN]);
        file_key.copy_from_slice(&unwrapped);

        let mut stream = DecryptorBE32::from_aead(
            cipher(&file_key),
            GenericArray::from_slice(&header.stream_prefix),
        );
        let chunk = header.chunk_size as usize + TAG_LEN;
        let mut current = vec![0u8; chunk];
        let mut next = vec![0u8; chunk];
        let mut current_len = read_full(&mut reader, &mut current)?;
        let mut total = 0u64;
        loop {
            let next_len =
                if current_len == chunk { read_full(&mut reader, &mut next)? } else { 0 };
            if next_len == 0 {
                let plain = Zeroizing::new(
                    stream.decrypt_last(&current[..current_len]).map_err(|_| Error::Corrupted)?,
                );
                writer.write_all(&plain)?;
                total += plain.len() as u64;
                break;
            }
            let plain = Zeroizing::new(
                stream.decrypt_next(&current[..current_len]).map_err(|_| Error::Corrupted)?,
            );
            writer.write_all(&plain)?;
            total += plain.len() as u64;
            std::mem::swap(&mut current, &mut next);
            current_len = next_len;
        }
        writer.flush()?;
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { memory_kib: 1024, passes: 1, lanes: 1 };
    const CHUNK: usize = CHUNK_SIZE as usize;

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8).collect()
    }

    fn encrypt(enc: &Encryptor, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        assert_eq!(enc.encrypt(data, &mut out).unwrap(), data.len() as u64);
        out
    }

    fn decrypt(password: &str, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        Decryptor::new(password).decrypt(data, &mut out)?;
        Ok(out)
    }

    #[test]
    fn roundtrip_around_chunk_boundaries() {
        let enc = Encryptor::new("pw", FAST).unwrap();
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK, 3 * CHUNK + 5] {
            let data = sample(len);
            let sealed = encrypt(&enc, &data);
            let chunks = len.div_ceil(CHUNK).max(1);
            assert_eq!(sealed.len(), HEADER_LEN + len + chunks * TAG_LEN, "len {len}");
            assert_eq!(decrypt("pw", &sealed).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn wrong_password_is_rejected() {
        let sealed = encrypt(&Encryptor::new("pw", FAST).unwrap(), b"secret");
        assert!(matches!(decrypt("pW", &sealed), Err(Error::WrongPassword)));
    }

    #[test]
    fn ciphertext_does_not_contain_plaintext() {
        let data = b"a very recognisable plaintext marker".repeat(10);
        let sealed = encrypt(&Encryptor::new("pw", FAST).unwrap(), &data);
        assert!(!sealed.windows(16).any(|w| w == &data[..16]));
    }

    #[test]
    fn every_header_byte_is_authenticated() {
        let sealed = encrypt(&Encryptor::new("pw", FAST).unwrap(), b"secret");
        // Skip magic, version and KDF costs: those fail earlier with their own errors
        // (or make Argon2 derive a different key, which is the same rejection).
        for at in 18..HEADER_LEN {
            let mut bad = sealed.clone();
            bad[at] ^= 1;
            assert!(decrypt("pw", &bad).is_err(), "header byte {at} not authenticated");
        }
    }

    #[test]
    fn flipped_content_bit_is_detected() {
        let mut sealed = encrypt(&Encryptor::new("pw", FAST).unwrap(), &sample(CHUNK + 100));
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(matches!(decrypt("pw", &sealed), Err(Error::Corrupted)));
    }

    #[test]
    fn truncation_is_detected() {
        let sealed = encrypt(&Encryptor::new("pw", FAST).unwrap(), &sample(2 * CHUNK + 100));
        let whole_chunk = HEADER_LEN + CHUNK + TAG_LEN;
        for cut in [HEADER_LEN, whole_chunk, 2 * whole_chunk - HEADER_LEN, sealed.len() - 1] {
            assert!(
                matches!(decrypt("pw", &sealed[..cut]), Err(Error::Corrupted)),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn swapped_chunks_are_detected() {
        let mut sealed = encrypt(&Encryptor::new("pw", FAST).unwrap(), &sample(2 * CHUNK + 100));
        let size = CHUNK + TAG_LEN;
        let (first, second) = sealed[HEADER_LEN..HEADER_LEN + 2 * size].split_at_mut(size);
        first.swap_with_slice(second);
        assert!(matches!(decrypt("pw", &sealed), Err(Error::Corrupted)));
    }

    #[test]
    fn garbage_is_not_a_topal_file() {
        assert!(matches!(decrypt("pw", b"hello"), Err(Error::NotTopal)));
        assert!(matches!(decrypt("pw", &[0u8; 500]), Err(Error::NotTopal)));
    }

    #[test]
    fn batch_shares_one_derivation_but_not_keys() {
        let enc = Encryptor::new("pw", FAST).unwrap();
        let a = encrypt(&enc, b"same content");
        let b = encrypt(&enc, b"same content");
        assert_eq!(a[18..34], b[18..34], "one batch uses one salt");
        assert_ne!(a[HEADER_LEN..], b[HEADER_LEN..], "each file has its own key");

        let dec = Decryptor::new("pw");
        for sealed in [&a, &b] {
            let mut out = Vec::new();
            dec.decrypt(&sealed[..], &mut out).unwrap();
            assert_eq!(out, b"same content");
        }
        assert_eq!(dec.keys.lock().unwrap().len(), 1, "key derived once for the batch");
    }
}
