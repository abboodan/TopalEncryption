//! Randomised robustness tests: damaged and hostile input must be refused cleanly.
//!
//! Each test mutates valid data at random and checks properties that must hold for every
//! mutation, not just the hand-picked ones in the unit tests. They run a few thousand
//! rounds by default; set `TOPAL_FUZZ_ITERATIONS` for a longer session and
//! `TOPAL_FUZZ_SEED` to replay a failure (the seed is printed on every run).

use std::fs;
use std::io::Read;
use std::path::Path;

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use topal_core::archive::{self, Packer};
use topal_core::recovery::RecoveryKey;
use topal_core::{Decryptor, Encryptor, KdfParams, Kind, CHUNK_SIZE};

const FAST: KdfParams = KdfParams { memory_kib: 1024, passes: 1, lanes: 1 };

// Layout of a version 2 header with a recovery slot.
const PASSWORD_ONLY: [std::ops::Range<usize>; 2] = [7..35, 58..130];
const RECOVERY_SLOT: std::ops::Range<usize> = 130..210;
const HEADER_LEN: usize = 210;

fn iterations() -> usize {
    std::env::var("TOPAL_FUZZ_ITERATIONS").ok().and_then(|n| n.parse().ok()).unwrap_or(3000)
}

fn rng(test: &str) -> StdRng {
    let seed = std::env::var("TOPAL_FUZZ_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or_else(|| rand::thread_rng().next_u64());
    println!("{test}: TOPAL_FUZZ_SEED={seed}");
    StdRng::seed_from_u64(seed)
}

/// One random edit: the kinds of damage a disk, a transfer or an attacker can cause.
fn mutate(rng: &mut StdRng, original: &[u8]) -> Vec<u8> {
    let mut data = original.to_vec();
    let len = data.len();
    // Favour the header: that is where the structure is.
    let position = |rng: &mut StdRng| {
        if rng.gen_bool(0.6) {
            rng.gen_range(0..len.min(HEADER_LEN + 64))
        } else {
            rng.gen_range(0..len)
        }
    };
    match rng.gen_range(0..8) {
        0 => {
            let at = position(rng);
            data[at] ^= 1 << rng.gen_range(0..8);
        }
        1 => {
            let at = position(rng);
            data[at] = rng.gen();
        }
        2 => data.truncate(position(rng)),
        3 => {
            let extra = rng.gen_range(1..64);
            data.extend((0..extra).map(|_| rng.gen::<u8>()));
        }
        4 => {
            let at = position(rng);
            let count = rng.gen_range(1..32).min(len - at);
            data.drain(at..at + count);
        }
        5 => {
            let at = position(rng);
            let count = rng.gen_range(1..32).min(len - at);
            let copy = data[at..at + count].to_vec();
            data.splice(at..at, copy);
        }
        6 => {
            let at = position(rng);
            let count = rng.gen_range(1..64).min(len - at);
            rng.fill_bytes(&mut data[at..at + count]);
        }
        _ => {
            let (a, b) = (position(rng), position(rng));
            let count = rng.gen_range(1..32).min(len - a.max(b));
            for i in 0..count {
                data.swap(a + i, b + i);
            }
        }
    }
    data
}

/// Whether Argon2 with the costs in this header is cheap enough to run in a test. Costs
/// are covered by the associated data like every other header byte; this only keeps a
/// mutated cost field from asking for gigabytes.
fn costs_are_small(data: &[u8]) -> bool {
    if data.len() < 19 {
        return true;
    }
    let field = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
    field(7) <= 32 * 1024 && field(11) <= 4 && field(15) <= 8
}

fn changed_only_within(original: &[u8], mutated: &[u8], ranges: &[std::ops::Range<usize>]) -> bool {
    original.len() == mutated.len()
        && original
            .iter()
            .zip(mutated)
            .enumerate()
            .all(|(at, (a, b))| a == b || ranges.iter().any(|range| range.contains(&at)))
}

fn open(decryptor: &Decryptor, data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    decryptor.decrypt(data, &mut out).ok().map(|_| out)
}

#[test]
fn damaged_files_are_never_accepted_as_something_else() {
    let mut rng = rng("damaged_files");
    let key = RecoveryKey::generate();
    let encryptor = Encryptor::new("pw", FAST).unwrap().with_recovery(Some(key.public()));
    let by_password = Decryptor::new("pw");
    let by_key = Decryptor::with_recovery_key(key);

    let samples: Vec<(Vec<u8>, Vec<u8>)> = [0, 1, 700, CHUNK_SIZE as usize + 300]
        .into_iter()
        .map(|len| {
            let mut plain = vec![0u8; len];
            rng.fill_bytes(&mut plain);
            let mut sealed = Vec::new();
            encryptor.encrypt(Kind::File, "name.bin", &plain[..], &mut sealed).unwrap();
            (plain, sealed)
        })
        .collect();

    let (mut refused, mut tolerated) = (0u64, 0u64);
    for round in 0..iterations() {
        // The multi-megabyte sample is slow to copy and decrypt: use it less often.
        let pick = if round % 16 == 0 { 3 } else { rng.gen_range(0..3) };
        let (plain, sealed) = &samples[pick];
        let mutated = mutate(&mut rng, sealed);
        if mutated == *sealed {
            continue;
        }

        // The password authenticates everything except the recovery slot, and the
        // recovery key everything except the password's own fields. Damage outside those
        // exceptions must be refused; damage inside them must not change the content.
        let password_result =
            if costs_are_small(&mutated) { open(&by_password, &mutated) } else { None };
        if changed_only_within(sealed, &mutated, &[RECOVERY_SLOT]) {
            assert_eq!(password_result.as_ref(), Some(plain), "round {round}: slot damage broke the password");
            tolerated += 1;
        } else {
            assert_eq!(password_result, None, "round {round}: damaged file accepted by password");
            refused += 1;
        }

        let key_result = open(&by_key, &mutated);
        if changed_only_within(sealed, &mutated, &PASSWORD_ONLY) {
            assert_eq!(key_result.as_ref(), Some(plain), "round {round}: password-field damage broke the key");
        } else {
            assert_eq!(key_result, None, "round {round}: damaged file accepted by recovery key");
        }
    }
    println!("refused {refused}, tolerated by design {tolerated}");
    assert!(refused > 0 && tolerated > 0, "the mutations did not exercise both cases");
}

#[test]
fn random_bytes_are_never_a_valid_file() {
    let mut rng = rng("random_bytes");
    let decryptor = Decryptor::new("pw");
    for _ in 0..iterations() {
        let mut data = vec![0u8; rng.gen_range(0..400)];
        rng.fill_bytes(&mut data);
        // Half of them at least look like a Topal file at first sight.
        if rng.gen_bool(0.5) && data.len() >= 7 {
            data[..5].copy_from_slice(b"TOPAL");
            data[5] = rng.gen_range(1..=2);
            data[6] = rng.gen_range(0..4);
        }
        if costs_are_small(&data) || data.get(5) == Some(&1) && data.len() < 18 {
            assert!(open(&decryptor, &data).is_none());
        }
    }
}

fn pack(folder: &Path) -> Vec<u8> {
    let entries = archive::list(folder).unwrap();
    let mut packed = Vec::new();
    Packer::new(&entries, |path: &Path| fs::File::open(path)).read_to_end(&mut packed).unwrap();
    packed
}

#[test]
fn damaged_archives_never_write_outside_their_folder() {
    let mut rng = rng("damaged_archives");
    let source = tempfile::tempdir().unwrap();
    fs::create_dir_all(source.path().join("a/b")).unwrap();
    fs::write(source.path().join("a/b/one.txt"), b"one").unwrap();
    fs::write(source.path().join("a/two.bin"), vec![3u8; 500]).unwrap();
    fs::write(source.path().join("three"), b"").unwrap();
    let packed = pack(source.path());

    let hostile: [&[u8]; 6] = [b"..", b"../", b"/", b"\\", b"C:", b"..\\"];
    let arena = tempfile::tempdir().unwrap();
    for round in 0..iterations() / 4 {
        let mut mutated = mutate(&mut rng, &packed);
        // Also plant path fragments an attacker would try.
        if rng.gen_bool(0.5) {
            let fragment = hostile[rng.gen_range(0..hostile.len())];
            let at = rng.gen_range(0..mutated.len().max(1));
            let end = (at + fragment.len()).min(mutated.len());
            mutated[at..end].copy_from_slice(&fragment[..end - at]);
        }

        let parent = arena.path().join(format!("round{round}"));
        let root = parent.join("root");
        fs::create_dir_all(&root).unwrap();
        // Accepted or refused, nothing may appear next to (or above) the target folder.
        let _ = archive::unpack(&mutated[..], &root);
        let siblings: Vec<_> = fs::read_dir(&parent).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(siblings, ["root"], "round {round}: something was written outside the folder");
        assert_eq!(
            fs::read_dir(arena.path()).unwrap().count(),
            1,
            "round {round}: something escaped two levels up"
        );
        fs::remove_dir_all(&parent).unwrap();
    }
}

#[test]
fn recovery_key_text_never_panics_and_rarely_parses() {
    let mut rng = rng("recovery_key_text");
    let real = RecoveryKey::generate().to_text().to_string();
    let mut accepted = 0;
    for _ in 0..iterations() {
        let mut text: Vec<char> = real.chars().collect();
        for _ in 0..rng.gen_range(1..4) {
            let at = rng.gen_range(0..text.len());
            match rng.gen_range(0..3) {
                0 => text[at] = char::from(rng.gen_range(b'!'..=b'~')),
                1 => {
                    text.remove(at);
                }
                _ => text.insert(at, char::from_u32(rng.gen_range(0x20..0x3000)).unwrap_or('x')),
            }
            if text.is_empty() {
                break;
            }
        }
        let text: String = text.into_iter().collect();
        if RecoveryKey::parse(&text).is_ok() {
            accepted += 1;
        }
    }
    // Case changes, dashes and spaces are accepted on purpose; a real typo has to get
    // past a 16-bit checksum.
    println!("accepted {accepted} of {}", iterations());
    assert!(accepted * 20 < iterations(), "too many damaged keys were accepted");
}
