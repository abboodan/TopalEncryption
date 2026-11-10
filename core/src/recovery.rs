//! Recovery keys: a second way to open files when the password is forgotten.
//!
//! A recovery key is an X25519 key pair. The public half is kept on the PC and is all that
//! encryption needs; the secret half is shown to the user once, to be printed or stored
//! somewhere safe, and is never written to disk by this library. Whoever holds it can open
//! every file encrypted while its public half was active, without the password.
//!
//! For each file, the per-file key is sealed to the public key: a fresh ephemeral X25519
//! key is combined with the recipient key, the shared secret goes through HKDF-SHA256, and
//! the result wraps the file key with XChaCha20-Poly1305.

use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{Error, Result, KEY_LEN, TAG_LEN};

const SECRET_PREFIX: &str = "TOPAL-KEY";
const PUBLIC_PREFIX: &str = "TOPAL-PUB";
const HKDF_INFO: &[u8] = b"topal recovery key wrap v2";
const CHECKSUM_LEN: usize = 2;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub(crate) const EPHEMERAL_LEN: usize = 32;

/// The secret half: opens files. Shown to the user once and never stored by the app.
#[derive(Clone)]
pub struct RecoveryKey(StaticSecret);

/// The public half: lets encryption add a recovery slot. Cannot open anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecoveryPublic([u8; 32]);

fn checksum(prefix: &str, bytes: &[u8; 32]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::new().chain_update(prefix.as_bytes()).chain_update(bytes).finalize();
    [digest[0], digest[1]]
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for ch in text.bytes() {
        let value = ALPHABET.iter().position(|&c| c == ch)? as u32;
        acc = (acc << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// `PREFIX-ABCDE-FGHIJ-...`: the key bytes and a two-byte checksum in base32.
fn encode(prefix: &str, bytes: &[u8; 32]) -> Zeroizing<String> {
    let mut payload = Zeroizing::new(Vec::with_capacity(32 + CHECKSUM_LEN));
    payload.extend_from_slice(bytes);
    payload.extend_from_slice(&checksum(prefix, bytes));
    let body = Zeroizing::new(base32_encode(&payload));
    let mut out = Zeroizing::new(String::from(prefix));
    for group in body.as_bytes().chunks(5) {
        out.push('-');
        out.push_str(std::str::from_utf8(group).expect("base32 is ASCII"));
    }
    out
}

/// Accepts any case, and ignores dashes and whitespace, so a hand-typed key works.
fn decode(prefix: &str, text: &str) -> Result<Zeroizing<[u8; 32]>> {
    let compact: Zeroizing<String> = Zeroizing::new(
        text.chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );
    let prefix_compact: String = prefix.chars().filter(|c| *c != '-').collect();
    let body = compact.strip_prefix(&prefix_compact).ok_or(Error::InvalidRecoveryKey)?;
    let payload = Zeroizing::new(base32_decode(body).ok_or(Error::InvalidRecoveryKey)?);
    if payload.len() != 32 + CHECKSUM_LEN {
        return Err(Error::InvalidRecoveryKey);
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(&payload[..32]);
    if payload[32..] != checksum(prefix, &bytes) {
        return Err(Error::InvalidRecoveryKey);
    }
    Ok(bytes)
}

impl RecoveryKey {
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(OsRng))
    }

    pub fn public(&self) -> RecoveryPublic {
        RecoveryPublic(PublicKey::from(&self.0).to_bytes())
    }

    /// Parses the text form produced by [`RecoveryKey::to_text`].
    pub fn parse(text: &str) -> Result<Self> {
        Ok(Self(StaticSecret::from(*decode(SECRET_PREFIX, text)?)))
    }

    /// The text the user keeps: `TOPAL-KEY-XXXXX-XXXXX-...`.
    pub fn to_text(&self) -> Zeroizing<String> {
        encode(SECRET_PREFIX, self.0.as_bytes())
    }
}

impl RecoveryPublic {
    pub fn parse(text: &str) -> Result<Self> {
        Ok(Self(*decode(PUBLIC_PREFIX, text)?))
    }
}

impl fmt::Display for RecoveryPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode(PUBLIC_PREFIX, &self.0))
    }
}

/// The wrapping key is unique to this ephemeral key, so it is used for one message only
/// and a fixed nonce is safe.
fn wrap_cipher(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32]) -> XChaCha20Poly1305 {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral);
    salt[32..].copy_from_slice(recipient);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(Some(&salt), shared)
        .expand(HKDF_INFO, &mut *key)
        .expect("32 bytes is a valid HKDF output length");
    XChaCha20Poly1305::new(Key::from_slice(&*key))
}

/// Seals `file_key` to `public`. Returns the ephemeral public key and the wrapped key.
pub(crate) fn seal(
    public: &RecoveryPublic,
    file_key: &[u8; KEY_LEN],
    aad: &[u8],
) -> ([u8; EPHEMERAL_LEN], [u8; KEY_LEN + TAG_LEN]) {
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral = PublicKey::from(&ephemeral_secret).to_bytes();
    let shared = ephemeral_secret.diffie_hellman(&PublicKey::from(public.0));
    let sealed = wrap_cipher(shared.as_bytes(), &ephemeral, &public.0)
        .encrypt(&XNonce::default(), Payload { msg: file_key, aad })
        .expect("wrapping a 32-byte key cannot fail");
    let mut wrapped = [0u8; KEY_LEN + TAG_LEN];
    wrapped.copy_from_slice(&sealed);
    (ephemeral, wrapped)
}

pub(crate) fn open(
    key: &RecoveryKey,
    ephemeral: &[u8; EPHEMERAL_LEN],
    wrapped: &[u8; KEY_LEN + TAG_LEN],
    aad: &[u8],
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let shared = key.0.diffie_hellman(&PublicKey::from(*ephemeral));
    if !shared.was_contributory() {
        return Err(Error::WrongRecoveryKey);
    }
    let recipient = key.public().0;
    let plain = Zeroizing::new(
        wrap_cipher(shared.as_bytes(), ephemeral, &recipient)
            .decrypt(&XNonce::default(), Payload { msg: &wrapped[..], aad })
            .map_err(|_| Error::WrongRecoveryKey)?,
    );
    let mut file_key = Zeroizing::new([0u8; KEY_LEN]);
    file_key.copy_from_slice(&plain);
    Ok(file_key)
}

/// Where the active public key is remembered between runs, shared by the app and the CLI:
/// `%APPDATA%\TopalEncryption\recovery-public.txt` on Windows.
pub fn store_path() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("TopalEncryption").join("recovery-public.txt"))
}

fn no_store() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no settings folder is available on this system")
}

/// The public key new files are sealed to, if a recovery key is active.
pub fn load_public() -> Result<Option<RecoveryPublic>> {
    let Some(path) = store_path() else { return Ok(None) };
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(RecoveryPublic::parse(&text)?)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub fn save_public(public: &RecoveryPublic) -> Result<()> {
    let path = store_path().ok_or_else(no_store)?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(path, format!("{public}\n"))?;
    Ok(())
}

/// Stops adding a recovery slot to new files. Files already encrypted keep theirs.
pub fn clear_public() -> Result<()> {
    let Some(path) = store_path() else { return Ok(()) };
    match fs::remove_file(path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_form_roundtrips_and_tolerates_typing() {
        let key = RecoveryKey::generate();
        let text = key.to_text();
        assert!(text.starts_with("TOPAL-KEY-"));
        let sloppy = text.to_lowercase().replace('-', " ");
        assert_eq!(RecoveryKey::parse(&sloppy).unwrap().public(), key.public());

        let public = key.public();
        assert_eq!(RecoveryPublic::parse(&public.to_string()).unwrap(), public);
    }

    #[test]
    fn typos_and_wrong_kinds_are_rejected() {
        let key = RecoveryKey::generate();
        let text = key.to_text().to_string();
        let last = text.chars().last().unwrap();
        let swapped = if last == 'A' { 'B' } else { 'A' };
        let typo = format!("{}{swapped}", &text[..text.len() - 1]);
        // The final character carries only two payload bits, so change an earlier one too.
        let mut chars: Vec<char> = typo.chars().collect();
        chars[12] = if chars[12] == 'Q' { 'R' } else { 'Q' };
        let typo: String = chars.into_iter().collect();
        assert!(matches!(RecoveryKey::parse(&typo), Err(Error::InvalidRecoveryKey)));
        assert!(RecoveryKey::parse(&key.public().to_string()).is_err());
        assert!(RecoveryPublic::parse(&text).is_err());
        assert!(RecoveryKey::parse("hello").is_err());
    }

    #[test]
    fn only_the_matching_key_opens_a_sealed_key() {
        let key = RecoveryKey::generate();
        let file_key = [7u8; KEY_LEN];
        let (ephemeral, wrapped) = seal(&key.public(), &file_key, b"aad");
        assert_eq!(*open(&key, &ephemeral, &wrapped, b"aad").unwrap(), file_key);
        assert!(open(&RecoveryKey::generate(), &ephemeral, &wrapped, b"aad").is_err());
        assert!(open(&key, &ephemeral, &wrapped, b"other").is_err());
    }
}
