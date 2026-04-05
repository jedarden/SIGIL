//! SLIP39 mnemonic encoding for Shamir shares
//!
//! This module implements encoding and decoding of Shamir shares as
//! mnemonic phrases using a wordlist similar to BIP39.

use crate::{Result, ShamirError, Share, SLIP39_WORDLIST};
use once_cell::sync::Lazy;
use std::sync::Mutex;

/// Wordlist cache (parsed from the wordlist string)
static WORDLIST: Lazy<Mutex<Vec<String>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Bits per word in the wordlist (1024 words = 10 bits)
const BITS_PER_WORD: usize = 10;

/// Initialize the wordlist from the included wordlist text
fn init_wordlist() {
    let mut list = WORDLIST.lock().unwrap();
    if list.is_empty() {
        list.extend(SLIP39_WORDLIST.lines().map(|s| s.to_string()));
    }
}

/// Encode a share as a SLIP39 mnemonic phrase
///
/// The mnemonic phrase encodes:
/// - Share metadata (index, threshold, total_shares)
/// - Share data
/// - Checksum for integrity verification
pub fn encode_share(share: &Share) -> Result<String> {
    init_wordlist();

    let wordlist = WORDLIST.lock().unwrap();

    // Calculate total bits needed
    let metadata_bits = 24; // 4 bits each for index, threshold, total_shares, 8 bits for data length (up to 255 bytes)
    let data_bits = share.data.len() * 8;
    let checksum_bits = 32; // 4 bytes checksum

    let total_bits = metadata_bits + data_bits + checksum_bits;
    let word_count = total_bits.div_ceil(BITS_PER_WORD);

    if word_count > wordlist.len() {
        return Err(ShamirError::MnemonicError(format!(
            "Share data too large: {} words needed, max {}",
            word_count,
            wordlist.len()
        )));
    }

    // Encode share into bitstream
    let mut bitstream = Vec::new();

    // Encode metadata (4 bits each for index, threshold, total_shares, 8 bits for data length)
    push_bits(&mut bitstream, share.index as u64, 4);
    push_bits(&mut bitstream, share.threshold as u64, 4);
    push_bits(&mut bitstream, share.total_shares as u64, 4);
    push_bits(&mut bitstream, share.data.len() as u64, 8); // Length prefix (up to 255 bytes)

    // Encode data
    for &byte in &share.data {
        push_bits(&mut bitstream, byte as u64, 8);
    }

    // Encode checksum
    for &byte in &share.checksum {
        push_bits(&mut bitstream, byte as u64, 8);
    }

    // Convert bitstream to words
    let words = bitstream_to_words(&bitstream, &wordlist);

    Ok(words.join(" "))
}

/// Decode a SLIP39 mnemonic phrase into a share
pub fn decode_share(mnemonic: &str) -> Result<Share> {
    init_wordlist();

    let wordlist = WORDLIST.lock().unwrap();

    // Split mnemonic into words
    let words: Vec<&str> = mnemonic.split_whitespace().collect();

    if words.is_empty() {
        return Err(ShamirError::MnemonicError(
            "Empty mnemonic phrase".to_string(),
        ));
    }

    // Convert words to bitstream
    let bitstream = words_to_bitstream(&words, &wordlist)?;

    if bitstream.len() < 32 {
        return Err(ShamirError::MnemonicError(
            "Mnemonic too short to contain valid share".to_string(),
        ));
    }

    let mut bit_pos = 0;

    // Decode metadata
    let index = pop_bits(&bitstream, &mut bit_pos, 4) as u8;
    let threshold = pop_bits(&bitstream, &mut bit_pos, 4) as u8;
    let total_shares = pop_bits(&bitstream, &mut bit_pos, 4) as u8;
    let data_len = pop_bits(&bitstream, &mut bit_pos, 8) as usize; // 8 bits for data length

    // Validate metadata
    if index == 0 || index > total_shares {
        return Err(ShamirError::MnemonicError(format!(
            "Invalid share index: {} (total shares: {})",
            index, total_shares
        )));
    }

    if threshold < 2 || threshold > total_shares {
        return Err(ShamirError::MnemonicError(format!(
            "Invalid threshold: {} (must be between 2 and {})",
            threshold, total_shares
        )));
    }

    if data_len == 0 || data_len > 64 {
        return Err(ShamirError::MnemonicError(format!(
            "Invalid data length: {} (must be between 1 and 64)",
            data_len
        )));
    }

    // Decode data
    let remaining_bits = bitstream.len() - bit_pos;
    let expected_data_bits = data_len * 8;
    let checksum_bits = 32;

    if remaining_bits < expected_data_bits + checksum_bits {
        return Err(ShamirError::MnemonicError(
            "Mnemonic too short for declared data length".to_string(),
        ));
    }

    let mut data = vec![0u8; data_len];
    for byte in data.iter_mut().take(data_len) {
        *byte = pop_bits(&bitstream, &mut bit_pos, 8) as u8;
    }

    // Decode checksum
    let mut checksum = [0u8; 4];
    for byte in checksum.iter_mut() {
        *byte = pop_bits(&bitstream, &mut bit_pos, 8) as u8;
    }

    let share = Share {
        index,
        threshold,
        total_shares,
        data,
        checksum,
    };

    // Verify checksum
    if !share.verify() {
        return Err(ShamirError::ChecksumFailed(
            "Share checksum verification failed".to_string(),
        ));
    }

    Ok(share)
}

/// Push bits into a bitstream
fn push_bits(bitstream: &mut Vec<bool>, value: u64, bits: usize) {
    for i in 0..bits {
        let bit = (value >> (bits - 1 - i)) & 1 == 1;
        bitstream.push(bit);
    }
}

/// Pop bits from a bitstream
fn pop_bits(bitstream: &[bool], bit_pos: &mut usize, bits: usize) -> u64 {
    let mut value = 0u64;
    for i in 0..bits {
        if *bit_pos + i < bitstream.len() && bitstream[*bit_pos + i] {
            value |= 1 << (bits - 1 - i);
        }
    }
    *bit_pos += bits;
    value
}

/// Convert a bitstream to word indices
fn bitstream_to_words(bitstream: &[bool], wordlist: &[String]) -> Vec<String> {
    let word_count = bitstream.len().div_ceil(BITS_PER_WORD);
    let mut words = Vec::with_capacity(word_count);

    for i in 0..word_count {
        let mut word_index = 0usize;
        for j in 0..BITS_PER_WORD {
            let bit_pos = i * BITS_PER_WORD + j;
            if bit_pos < bitstream.len() && bitstream[bit_pos] {
                word_index |= 1 << (BITS_PER_WORD - 1 - j);
            }
        }
        if word_index < wordlist.len() {
            words.push(wordlist[word_index].clone());
        }
    }

    words
}

/// Convert word indices back to a bitstream
fn words_to_bitstream(words: &[&str], wordlist: &[String]) -> Result<Vec<bool>> {
    let mut bitstream = Vec::new();

    for &word in words {
        // Find word index in wordlist
        let word_index = wordlist.iter().position(|w| w == word).ok_or_else(|| {
            ShamirError::MnemonicError(format!("Invalid word in mnemonic: {}", word))
        })?;

        // Convert index to bits
        for j in 0..BITS_PER_WORD {
            let bit = (word_index >> (BITS_PER_WORD - 1 - j)) & 1 == 1;
            bitstream.push(bit);
        }
    }

    Ok(bitstream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let share = Share::new(1, 3, 5, vec![1, 2, 3, 4, 5, 6, 7, 8]);

        let mnemonic = encode_share(&share).unwrap();
        let decoded = decode_share(&mnemonic).unwrap();

        assert_eq!(decoded.index, share.index);
        assert_eq!(decoded.threshold, share.threshold);
        assert_eq!(decoded.total_shares, share.total_shares);
        assert_eq!(decoded.data, share.data);
        assert_eq!(decoded.checksum, share.checksum);
    }

    #[test]
    fn test_encode_decode_32_bytes() {
        let data: Vec<u8> = (0..32).collect();
        let share = Share::new(5, 7, 10, data);

        let mnemonic = encode_share(&share).unwrap();
        let decoded = decode_share(&mnemonic).unwrap();

        assert_eq!(decoded.index, share.index);
        assert_eq!(decoded.data, share.data);
    }

    #[test]
    fn test_decode_invalid_word() {
        let invalid_mnemonic = "invalid word phrase here";
        assert!(decode_share(invalid_mnemonic).is_err());
    }

    #[test]
    fn test_decode_empty_mnemonic() {
        assert!(decode_share("").is_err());
        assert!(decode_share("   ").is_err());
    }

    #[test]
    fn test_checksum_verification() {
        let share = Share::new(2, 3, 5, vec![10, 20, 30]);

        let mut mnemonic = encode_share(&share).unwrap();

        // Corrupt a word
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        if !words.is_empty() {
            let corrupted = words[0].chars().rev().collect::<String>();
            mnemonic = mnemonic.replace(words[0], &corrupted);
        }

        assert!(decode_share(&mnemonic).is_err());
    }

    #[test]
    fn test_mnemonic_format() {
        let share = Share::new(1, 3, 5, vec![1, 2, 3, 4]);
        let mnemonic = encode_share(&share).unwrap();

        // Mnemonic should be space-separated words
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert!(!words.is_empty());
        assert!(words.len() <= 24); // Reasonable upper bound
    }
}
