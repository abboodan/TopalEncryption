//! Topal file encryption.
//!
//! Every `.topal` file is self-contained and can be decrypted with the password alone.
//!
//! Layout of format version 2 (all integers little-endian):
//!
//! | offset | size | field                                               |
//! |--------|------|-----------------------------------------------------|
//! | 0      | 5    | magic `TOPAL`                                       |
//! | 5      | 1    | format version (`2`)                                |
//! | 6      | 1    | flags: 1 = folder container, 2 = has recovery slot  |
//! | 7      | 12   | Argon2id memory (KiB), passes, lanes                |
//! | 19     | 16   | Argon2id salt                                       |
//! | 35     | 4    | plaintext chunk size                                |
//! | 39     | 19   | stream nonce prefix                                 |
//! | 58     | 24   | key-wrap nonce                                      |
//! | 82     | 48   | file key, wrapped with the password-derived key     |
//! | 130    | 32   | recovery slot: ephemeral X25519 public key          |
//! | 162    | 48   | recovery slot: file key, wrapped for the recovery key |
//! | ...    | ...  | chunks, each `chunk size + 16` bytes (last shorter) |
//!
//! The recovery slot (80 bytes) is present only when its flag is set. Version 1 is the
//! same without the flags byte and without a recovery slot, and is still read.
//!
//! The first 58 bytes are bound to the password-wrapped key as associated data, so any
//! change to the header makes the file undecryptable rather than silently reinterpreted.
//! The recovery slot is bound to everything except the password's salt and costs, which
//! is what lets the password be changed without the recovery key.
//!
//! Password -> Argon2id -> key-encryption key (KEK). The KEK unwraps a random per-file
//! key, which encrypts the content in chunks with XChaCha20-Poly1305 in the STREAM
//! construction (chunks cannot be reordered, dropped, duplicated or truncated).
//!
//! In version 2 the encrypted stream starts with the original name (`u16` length, then
//! UTF-8), followed by the file content or, for a folder container, an [`archive`].
//!
//! An [`Encryptor`] runs Argon2id once and reuses its salt for every file it writes, and
//! a [`Decryptor`] caches derived keys per salt. A batch of thousands of files therefore
//! costs one key derivation, not one per file.

pub mod archive;
pub mod batch;
pub mod passphrase;
pub mod recovery;

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

use recovery::{RecoveryKey, RecoveryPublic, EPHEMERAL_LEN};

/// File extension of encrypted files, without the dot.
pub const EXTENSION: &str = "topal";

const MAGIC: &[u8; 5] = b"TOPAL";
const VERSION_1: u8 = 1;
const VERSION_2: u8 = 2;

const FLAG_FOLDER: u8 = 1;
const FLAG_RECOVERY: u8 = 2;
const KNOWN_FLAGS: u8 = FLAG_FOLDER | FLAG_RECOVERY;

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const TAG_LEN: usize = 16;
const SALT_LEN: usize = 16;
const STREAM_PREFIX_LEN: usize = 19;
const WRAP_NONCE_LEN: usize = 24;
const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;

/// Bytes after magic and version that every header has, by version.
const V1_REST_LEN: usize = 12 + SALT_LEN + 4 + STREAM_PREFIX_LEN + WRAP_NONCE_LEN + WRAPPED_KEY_LEN;
const V2_REST_LEN: usize = 1 + V1_REST_LEN;
const RECOVERY_SLOT_LEN: usize = EPHEMERAL_LEN + WRAPPED_KEY_LEN;

/// The largest header any version can have. It fits in one 512-byte disk sector.
pub const MAX_HEADER_LEN: usize = 6 + V2_REST_LEN + RECOVERY_SLOT_LEN;

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
    #[error("{0}")]
    Io(#[source] io::Error),
    #[error("not a Topal file")]
    NotTopal,
    #[error("unsupported Topal format version {0}")]
    UnsupportedVersion(u8),
    #[error("invalid key derivation parameters")]
    InvalidKdfParams,
    #[error("wrong password, or the file header is damaged")]
    WrongPassword,
    #[error("wrong recovery key, or the file header is damaged")]
    WrongRecoveryKey,
    #[error("this file was not encrypted with a recovery key")]
    NoRecoverySlot,
    #[error("this is not a valid recovery key")]
    InvalidRecoveryKey,
    #[error("file content is damaged or incomplete")]
    Corrupted,
    #[error("verification failed: the file changed while it was being encrypted")]
    VerificationFailed,
    #[error("the encrypted folder contains an unsafe path")]
    UnsafePath,
    #[error("an output with this name already exists")]
    OutputExists,
}

pub type Result<T> = std::result::Result<T, Error>;

// Our errors travel through `Read` implementations wrapped in an `io::Error`; these two
// conversions unwrap them again so that callers see `Corrupted`, not a generic I/O error.
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        if err.get_ref().is_some_and(|inner| inner.is::<Error>()) {
            let inner = err.into_inner().expect("checked above");
            *inner.downcast::<Error>().expect("checked above")
        } else {
            Error::Io(err)
        }
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        match err {
            Error::Io(err) => err,
            other => io::Error::new(io::ErrorKind::InvalidData, other),
        }
    }
}

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

/// What an encrypted file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The content of one file.
    File,
    /// A whole folder, packed as an [`archive`].
    Folder,
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

struct RecoverySlot {
    ephemeral: [u8; EPHEMERAL_LEN],
    wrapped_key: [u8; WRAPPED_KEY_LEN],
}

struct Header {
    version: u8,
    /// Always zero in version 1, which has no flags byte.
    flags: u8,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    chunk_size: u32,
    stream_prefix: [u8; STREAM_PREFIX_LEN],
    wrap_nonce: [u8; WRAP_NONCE_LEN],
    wrapped_key: [u8; WRAPPED_KEY_LEN],
    recovery: Option<RecoverySlot>,
}

impl Header {
    /// Everything before the key-wrap nonce: the associated data of the password slot.
    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(58);
        aad.extend_from_slice(MAGIC);
        aad.push(self.version);
        if self.version >= VERSION_2 {
            aad.push(self.flags);
        }
        aad.extend_from_slice(&self.params.memory_kib.to_le_bytes());
        aad.extend_from_slice(&self.params.passes.to_le_bytes());
        aad.extend_from_slice(&self.params.lanes.to_le_bytes());
        aad.extend_from_slice(&self.salt);
        aad.extend_from_slice(&self.chunk_size.to_le_bytes());
        aad.extend_from_slice(&self.stream_prefix);
        aad
    }

    /// Associated data of the recovery slot: the header without the password's salt and
    /// costs, so that changing the password leaves the slot valid.
    fn recovery_aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(48);
        aad.extend_from_slice(b"TOPAL recovery slot");
        aad.push(self.version);
        aad.push(self.flags);
        aad.extend_from_slice(&self.chunk_size.to_le_bytes());
        aad.extend_from_slice(&self.stream_prefix);
        aad
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.aad();
        bytes.extend_from_slice(&self.wrap_nonce);
        bytes.extend_from_slice(&self.wrapped_key);
        if let Some(slot) = &self.recovery {
            bytes.extend_from_slice(&slot.ephemeral);
            bytes.extend_from_slice(&slot.wrapped_key);
        }
        bytes
    }

    fn kind(&self) -> Kind {
        if self.flags & FLAG_FOLDER != 0 {
            Kind::Folder
        } else {
            Kind::File
        }
    }

    fn read_from(mut reader: impl Read) -> Result<Self> {
        let mut start = [0u8; 6];
        if read_full(&mut reader, &mut start)? != start.len() || &start[0..5] != MAGIC {
            return Err(Error::NotTopal);
        }
        let version = start[5];
        let mut raw = [0u8; V2_REST_LEN];
        let rest = match version {
            VERSION_1 => &mut raw[1..],
            VERSION_2 => &mut raw[..],
            other => return Err(Error::UnsupportedVersion(other)),
        };
        if read_full(&mut reader, rest)? != rest.len() {
            return Err(Error::Corrupted);
        }
        // `raw` now has the version 2 layout from the flags byte on, flags zero for v1.
        let flags = raw[0];
        if flags & !KNOWN_FLAGS != 0 {
            return Err(Error::UnsupportedVersion(version));
        }
        let u32_at = |at: usize| u32::from_le_bytes(raw[at..at + 4].try_into().unwrap());
        let params = KdfParams { memory_kib: u32_at(1), passes: u32_at(5), lanes: u32_at(9) };
        if params.memory_kib > MAX_MEMORY_KIB || params.passes > MAX_PASSES || params.lanes > MAX_LANES {
            return Err(Error::InvalidKdfParams);
        }
        let chunk_size = u32_at(29);
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err(Error::Corrupted);
        }
        let recovery = if flags & FLAG_RECOVERY != 0 {
            let mut slot = [0u8; RECOVERY_SLOT_LEN];
            if read_full(&mut reader, &mut slot)? != slot.len() {
                return Err(Error::Corrupted);
            }
            Some(RecoverySlot {
                ephemeral: slot[..EPHEMERAL_LEN].try_into().unwrap(),
                wrapped_key: slot[EPHEMERAL_LEN..].try_into().unwrap(),
            })
        } else {
            None
        };
        Ok(Self {
            version,
            flags,
            params,
            salt: raw[13..29].try_into().unwrap(),
            chunk_size,
            stream_prefix: raw[33..52].try_into().unwrap(),
            wrap_nonce: raw[52..76].try_into().unwrap(),
            wrapped_key: raw[76..124].try_into().unwrap(),
            recovery,
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
    recovery: Option<RecoveryPublic>,
}

impl Encryptor {
    /// Derives the key from `password`. This is the slow step; do it once per batch.
    pub fn new(password: &str, params: KdfParams) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let kek = derive_kek(password.as_bytes(), &salt, params)?;
        Ok(Self { params, salt, kek, recovery: None })
    }

    /// Also lets the holder of this recovery key open every file encrypted from now on.
    pub fn with_recovery(mut self, public: Option<RecoveryPublic>) -> Self {
        self.recovery = public;
        self
    }

    /// Fills in the password slot of `header` for `file_key`.
    fn wrap(&self, header: &mut Header, file_key: &Secret) {
        header.params = self.params;
        header.salt = self.salt;
        OsRng.fill_bytes(&mut header.wrap_nonce);
        let wrapped = cipher(&self.kek)
            .encrypt(
                XNonce::from_slice(&header.wrap_nonce),
                Payload { msg: &file_key[..], aad: &header.aad() },
            )
            .expect("wrapping a 32-byte key cannot fail");
        header.wrapped_key.copy_from_slice(&wrapped);
    }

    /// Encrypts everything from `reader` into `writer`, recording `name` (the original
    /// file or folder name, may be empty) inside the encrypted stream. Returns the number
    /// of bytes taken from `reader`. Memory use is two chunks regardless of input size.
    pub fn encrypt(
        &self,
        kind: Kind,
        name: &str,
        reader: impl Read,
        mut writer: impl Write,
    ) -> Result<u64> {
        let name_len = u16::try_from(name.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the file name is too long"))?;
        let mut prefix = Vec::with_capacity(2 + name.len());
        prefix.extend_from_slice(&name_len.to_le_bytes());
        prefix.extend_from_slice(name.as_bytes());
        let prefix_len = prefix.len() as u64;
        let mut reader = io::Cursor::new(prefix).chain(reader);

        let mut file_key = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut *file_key);

        let mut header = Header {
            version: VERSION_2,
            flags: if kind == Kind::Folder { FLAG_FOLDER } else { 0 }
                | if self.recovery.is_some() { FLAG_RECOVERY } else { 0 },
            params: self.params,
            salt: self.salt,
            chunk_size: CHUNK_SIZE,
            stream_prefix: [0u8; STREAM_PREFIX_LEN],
            wrap_nonce: [0u8; WRAP_NONCE_LEN],
            wrapped_key: [0u8; WRAPPED_KEY_LEN],
            recovery: None,
        };
        OsRng.fill_bytes(&mut header.stream_prefix);
        self.wrap(&mut header, &file_key);
        if let Some(public) = &self.recovery {
            let (ephemeral, wrapped_key) = recovery::seal(public, &file_key, &header.recovery_aad());
            header.recovery = Some(RecoverySlot { ephemeral, wrapped_key });
        }
        writer.write_all(&header.to_bytes())?;

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
        Ok(total - prefix_len)
    }

    /// Changes the password of an encrypted file without touching its content: reads the
    /// header from `reader`, opens it with `old`, and returns a replacement header of the
    /// same length whose password slot belongs to this encryptor. Writing those bytes over
    /// the start of the file is the whole operation. A recovery slot is kept as it is.
    pub fn rewrap(&self, old: &Decryptor, reader: impl Read) -> Result<Vec<u8>> {
        let mut header = Header::read_from(reader)?;
        let file_key = old.file_key(&header)?;
        self.wrap(&mut header, &file_key);
        Ok(header.to_bytes())
    }
}

enum Credential {
    Password(Zeroizing<Vec<u8>>),
    Recovery(RecoveryKey),
}

/// Decrypts files, deriving the key once per distinct salt and caching it.
pub struct Decryptor {
    credential: Credential,
    keys: Mutex<HashMap<([u8; SALT_LEN], KdfParams), Secret>>,
}

/// An encrypted file whose header has been accepted.
pub struct Opened<R> {
    pub kind: Kind,
    /// The original file or folder name recorded when encrypting. `None` for version 1
    /// files and when no name was recorded. It comes from the file, so treat it as
    /// untrusted input: see [`archive::is_safe_name`].
    pub name: Option<String>,
    /// The decrypted content: file bytes, or an [`archive`] for a folder.
    pub content: DecryptReader<R>,
}

impl Decryptor {
    pub fn new(password: &str) -> Self {
        Self {
            credential: Credential::Password(Zeroizing::new(password.as_bytes().to_vec())),
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Opens files with a recovery key instead of the password.
    pub fn with_recovery_key(key: RecoveryKey) -> Self {
        Self { credential: Credential::Recovery(key), keys: Mutex::new(HashMap::new()) }
    }

    /// Holding the lock while deriving keeps parallel callers from each allocating
    /// Argon2's memory for the same salt at once.
    fn kek(&self, password: &[u8], salt: [u8; SALT_LEN], params: KdfParams) -> Result<Secret> {
        let mut keys = self.keys.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(kek) = keys.get(&(salt, params)) {
            return Ok(kek.clone());
        }
        let kek = derive_kek(password, &salt, params)?;
        keys.insert((salt, params), kek.clone());
        Ok(kek)
    }

    fn file_key(&self, header: &Header) -> Result<Secret> {
        match &self.credential {
            Credential::Password(password) => {
                let kek = self.kek(password, header.salt, header.params)?;
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
                Ok(file_key)
            }
            Credential::Recovery(key) => {
                let slot = header.recovery.as_ref().ok_or(Error::NoRecoverySlot)?;
                recovery::open(key, &slot.ephemeral, &slot.wrapped_key, &header.recovery_aad())
            }
        }
    }

    /// Reads and checks the header, and returns the content as a reader.
    pub fn open<R: Read>(&self, mut reader: R) -> Result<Opened<R>> {
        let header = Header::read_from(&mut reader)?;
        let file_key = self.file_key(&header)?;
        let stream = DecryptorBE32::from_aead(
            cipher(&file_key),
            GenericArray::from_slice(&header.stream_prefix),
        );
        let chunk = header.chunk_size as usize + TAG_LEN;
        let mut content = DecryptReader {
            reader,
            stream: Some(stream),
            current: vec![0u8; chunk],
            current_len: 0,
            next: vec![0u8; chunk],
            plain: Zeroizing::new(Vec::new()),
            pos: 0,
        };
        content.current_len = read_full(&mut content.reader, &mut content.current)?;

        let name = if header.version >= VERSION_2 {
            let mut len = [0u8; 2];
            content.read_exact(&mut len).map_err(truncated)?;
            let mut name = vec![0u8; usize::from(u16::from_le_bytes(len))];
            content.read_exact(&mut name).map_err(truncated)?;
            let name = String::from_utf8(name).map_err(|_| Error::Corrupted)?;
            (!name.is_empty()).then_some(name)
        } else {
            None
        };
        Ok(Opened { kind: header.kind(), name, content })
    }

    /// Decrypts everything from `reader` into `writer`. Returns the plaintext byte count.
    ///
    /// Each chunk is authenticated before it is written, but truncation is only detected
    /// at the end: on error, discard whatever was written.
    pub fn decrypt(&self, reader: impl Read, mut writer: impl Write) -> Result<u64> {
        let mut content = self.open(reader)?.content;
        let mut total = 0u64;
        while let Some(plain) = content.next_chunk()? {
            writer.write_all(plain)?;
            total += plain.len() as u64;
        }
        writer.flush()?;
        Ok(total)
    }
}

/// Content that ends before its own structure says it should is damaged, not an I/O fault.
fn truncated(err: io::Error) -> Error {
    if err.kind() == io::ErrorKind::UnexpectedEof {
        Error::Corrupted
    } else {
        err.into()
    }
}

/// Decrypted content of one file. Every byte it returns has been authenticated, and it
/// reports the end only after authenticating that the stream really ends there.
pub struct DecryptReader<R> {
    reader: R,
    /// `None` once the last chunk has been decrypted.
    stream: Option<DecryptorBE32<XChaCha20Poly1305>>,
    current: Vec<u8>,
    current_len: usize,
    next: Vec<u8>,
    plain: Zeroizing<Vec<u8>>,
    pos: usize,
}

impl<R: Read> DecryptReader<R> {
    /// Decrypts the next chunk into `plain`. Returns `false` at the end of the stream.
    fn fill(&mut self) -> Result<bool> {
        let Some(mut stream) = self.stream.take() else { return Ok(false) };
        let chunk = self.current.len();
        // A chunk is the last one only if nothing follows it, so read one ahead.
        let next_len =
            if self.current_len == chunk { read_full(&mut self.reader, &mut self.next)? } else { 0 };
        let sealed = &self.current[..self.current_len];
        self.pos = 0;
        if next_len == 0 {
            let plain = stream.decrypt_last(sealed).map_err(|_| Error::Corrupted)?;
            self.plain = Zeroizing::new(plain);
        } else {
            let plain = stream.decrypt_next(sealed).map_err(|_| Error::Corrupted)?;
            self.plain = Zeroizing::new(plain);
            std::mem::swap(&mut self.current, &mut self.next);
            self.current_len = next_len;
            self.stream = Some(stream);
        }
        Ok(true)
    }

    /// The rest of the current chunk, or the whole next one; `None` at the end. Faster
    /// than [`Read::read`] for bulk copying because nothing is copied in between.
    pub fn next_chunk(&mut self) -> Result<Option<&[u8]>> {
        while self.pos >= self.plain.len() {
            if !self.fill()? {
                return Ok(None);
            }
        }
        let start = std::mem::replace(&mut self.pos, self.plain.len());
        Ok(Some(&self.plain[start..]))
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.plain.len() {
            if !self.fill()? {
                return Ok(0);
            }
        }
        let n = buf.len().min(self.plain.len() - self.pos);
        buf[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { memory_kib: 1024, passes: 1, lanes: 1 };
    const CHUNK: usize = CHUNK_SIZE as usize;
    /// Header of a version 2 file without a recovery slot.
    const HEADER: usize = 6 + V2_REST_LEN;
    /// An empty name still takes its two length bytes at the start of the stream.
    const PREFIX: usize = 2;

    fn sample(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i.wrapping_mul(31) ^ (i >> 8)) as u8).collect()
    }

    fn encrypt(enc: &Encryptor, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        assert_eq!(enc.encrypt(Kind::File, "", data, &mut out).unwrap(), data.len() as u64);
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
        for len in [0, 1, CHUNK - PREFIX - 1, CHUNK - PREFIX, CHUNK - PREFIX + 1, CHUNK, 2 * CHUNK, 3 * CHUNK + 5] {
            let data = sample(len);
            let sealed = encrypt(&enc, &data);
            let chunks = (len + PREFIX).div_ceil(CHUNK).max(1);
            assert_eq!(sealed.len(), HEADER + PREFIX + len + chunks * TAG_LEN, "len {len}");
            assert_eq!(decrypt("pw", &sealed).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn name_and_kind_are_recorded_inside_the_file() {
        let enc = Encryptor::new("pw", FAST).unwrap();
        let mut sealed = Vec::new();
        enc.encrypt(Kind::Folder, "صور العطلة", &b"content"[..], &mut sealed).unwrap();
        assert!(!sealed.windows(4).any(|w| w == "صو".as_bytes()), "the name is encrypted");

        let mut opened = Decryptor::new("pw").open(&sealed[..]).unwrap();
        assert_eq!(opened.kind, Kind::Folder);
        assert_eq!(opened.name.as_deref(), Some("صور العطلة"));
        let mut content = Vec::new();
        opened.content.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"content");

        let plain = encrypt(&enc, b"x");
        let opened = Decryptor::new("pw").open(&plain[..]).unwrap();
        assert_eq!((opened.kind, opened.name), (Kind::File, None));
    }

    #[test]
    fn reading_in_small_pieces_matches_bulk_decryption() {
        let data = sample(2 * CHUNK + 77);
        let sealed = encrypt(&Encryptor::new("pw", FAST).unwrap(), &data);
        let mut content = Decryptor::new("pw").open(&sealed[..]).unwrap().content;
        let mut out = Vec::new();
        let mut buf = [0u8; 4093];
        loop {
            let n = content.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(out, data);
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
        let key = RecoveryKey::generate();
        let plain = encrypt(&Encryptor::new("pw", FAST).unwrap(), b"secret");
        let with_slot = encrypt(
            &Encryptor::new("pw", FAST).unwrap().with_recovery(Some(key.public())),
            b"secret",
        );
        assert_eq!(with_slot.len(), plain.len() + RECOVERY_SLOT_LEN);
        // Skip magic, version and KDF costs: those fail earlier with their own errors
        // (or make Argon2 derive a different key, which is the same rejection).
        for at in (6..7).chain(19..HEADER) {
            let mut bad = plain.clone();
            bad[at] ^= 1;
            assert!(decrypt("pw", &bad).is_err(), "header byte {at} not authenticated");
        }
        // With the recovery key, everything but the password's own fields is checked.
        let by_key = |data: &[u8]| {
            Decryptor::with_recovery_key(key.clone()).decrypt(data, io::sink()).map(|_| ())
        };
        by_key(&with_slot).unwrap();
        for at in (6..7).chain(35..58).chain(HEADER..HEADER + RECOVERY_SLOT_LEN) {
            let mut bad = with_slot.clone();
            bad[at] ^= 1;
            assert!(by_key(&bad).is_err(), "header byte {at} not authenticated for recovery");
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
        let whole_chunk = CHUNK + TAG_LEN;
        for cut in [HEADER - 1, HEADER, HEADER + whole_chunk, HEADER + 2 * whole_chunk, sealed.len() - 1] {
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
        let (first, second) = sealed[HEADER..HEADER + 2 * size].split_at_mut(size);
        first.swap_with_slice(second);
        assert!(matches!(decrypt("pw", &sealed), Err(Error::Corrupted)));
    }

    #[test]
    fn garbage_is_not_a_topal_file() {
        assert!(matches!(decrypt("pw", b"hello"), Err(Error::NotTopal)));
        assert!(matches!(decrypt("pw", &[0u8; 500]), Err(Error::NotTopal)));
        assert!(matches!(decrypt("pw", b"TOPAL\x09 and more"), Err(Error::UnsupportedVersion(9))));
    }

    #[test]
    fn batch_shares_one_derivation_but_not_keys() {
        let enc = Encryptor::new("pw", FAST).unwrap();
        let a = encrypt(&enc, b"same content");
        let b = encrypt(&enc, b"same content");
        assert_eq!(a[19..35], b[19..35], "one batch uses one salt");
        assert_ne!(a[HEADER..], b[HEADER..], "each file has its own key");

        let dec = Decryptor::new("pw");
        for sealed in [&a, &b] {
            let mut out = Vec::new();
            dec.decrypt(&sealed[..], &mut out).unwrap();
            assert_eq!(out, b"same content");
        }
        assert_eq!(dec.keys.lock().unwrap().len(), 1, "key derived once for the batch");
    }

    #[test]
    fn recovery_key_opens_files_without_the_password() {
        let key = RecoveryKey::generate();
        let data = sample(CHUNK + 9);
        let sealed =
            encrypt(&Encryptor::new("pw", FAST).unwrap().with_recovery(Some(key.public())), &data);

        let mut out = Vec::new();
        Decryptor::with_recovery_key(key).decrypt(&sealed[..], &mut out).unwrap();
        assert_eq!(out, data);
        assert_eq!(decrypt("pw", &sealed).unwrap(), data, "the password still works");

        let other = Decryptor::with_recovery_key(RecoveryKey::generate());
        assert!(matches!(other.decrypt(&sealed[..], io::sink()), Err(Error::WrongRecoveryKey)));

        let no_slot = encrypt(&Encryptor::new("pw", FAST).unwrap(), &data);
        assert!(matches!(other.decrypt(&no_slot[..], io::sink()), Err(Error::NoRecoverySlot)));
    }

    #[test]
    fn password_change_rewrites_only_the_header() {
        let key = RecoveryKey::generate();
        let data = sample(CHUNK + 9);
        let sealed = encrypt(
            &Encryptor::new("old", FAST).unwrap().with_recovery(Some(key.public())),
            &data,
        );

        let new = Encryptor::new("new", FAST).unwrap();
        let header = new.rewrap(&Decryptor::new("old"), &sealed[..]).unwrap();
        assert_eq!(header.len(), HEADER + RECOVERY_SLOT_LEN);
        let mut changed = sealed.clone();
        changed[..header.len()].copy_from_slice(&header);

        assert_eq!(decrypt("new", &changed).unwrap(), data);
        assert!(matches!(decrypt("old", &changed), Err(Error::WrongPassword)));
        let mut out = Vec::new();
        Decryptor::with_recovery_key(key.clone()).decrypt(&changed[..], &mut out).unwrap();
        assert_eq!(out, data, "the recovery slot survives a password change");

        assert!(matches!(new.rewrap(&Decryptor::new("bad"), &sealed[..]), Err(Error::WrongPassword)));
        // A forgotten password can be replaced using the recovery key.
        let header = new.rewrap(&Decryptor::with_recovery_key(key), &sealed[..]).unwrap();
        let mut reset = sealed;
        reset[..header.len()].copy_from_slice(&header);
        assert_eq!(decrypt("new", &reset).unwrap(), data);
    }
}
