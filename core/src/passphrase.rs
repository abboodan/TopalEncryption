//! Random passphrases made of common English words.

use rand::rngs::OsRng;
use rand::Rng;
use zeroize::Zeroizing;

/// Words in a passphrase by default: 6 words from a 2048-word list is 66 bits.
pub const DEFAULT_WORDS: usize = 6;

/// Picks `words` words uniformly at random (at least 4) and joins them with dashes.
///
/// The list is the 2048-word BIP-39 English list: short, common words whose first four
/// letters are unique. Each word adds 11 bits.
pub fn generate(words: usize) -> Zeroizing<String> {
    let list = bip39::Language::English.word_list();
    let mut out = Zeroizing::new(String::new());
    for index in 0..words.max(4) {
        if index > 0 {
            out.push('-');
        }
        out.push_str(list[OsRng.gen_range(0..list.len())]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_the_requested_number_of_words_and_varies() {
        let first = generate(6);
        assert_eq!(first.split('-').count(), 6);
        assert!(first.split('-').all(|word| !word.is_empty() && word.is_ascii()));
        assert_ne!(*first, *generate(6));
        assert_eq!(generate(1).split('-').count(), 4, "never fewer than four words");
    }
}
