#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{fmt::Display, hash::Hash};

pub mod md2;
pub mod md4;
pub mod md5;
pub mod sha1;

/// A variable-size digest, which can easily be converted into a hexadecimal string for user-facing output.
///
/// This struct is returned by all hashing functions.
///
/// # Examples
///
/// [`Digest`] implements [`Display`], which means it can automatically be converted to a human-readable format by formatting it:
///
/// ```rust
/// let digest = lore::md5("example");
/// println!("Digest: {}", digest); // -> Digest: 1a79a4d60de6718e8e5b326e338ae533
/// ```
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest<const S: usize>([u8; S]);

/// Convert the digest into a hexadecimal string representation.
impl<const S: usize> Display for Digest<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            &self
                .0
                .iter()
                .map(|u| format!("{:02x}", u))
                .collect::<String>(),
        )
    }
}

impl<const S: usize> From<Digest<S>> for [u8; S] {
    fn from(digest: Digest<S>) -> Self {
        digest.0
    }
}

impl<'a, const S: usize> From<&'a Digest<S>> for &'a [u8] {
    fn from(digest: &'a Digest<S>) -> Self {
        digest.0.as_slice()
    }
}

impl<const S: usize> From<Digest<S>> for Vec<u8> {
    fn from(digest: Digest<S>) -> Self {
        digest.0.to_vec()
    }
}

impl<const S: usize> AsRef<[u8]> for Digest<S> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

pub fn bytes_to_words_le(bytes: impl AsRef<[u8]>) -> Vec<u32> {
    bytes
        .as_ref()
        .array_chunks::<4>()
        .map(|chunk| u32::from_le_bytes(*chunk))
        .collect()
}

pub fn words_to_bytes_le(words: impl AsRef<[u32]>) -> Vec<u8> {
    words
        .as_ref()
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect()
}

pub fn bytes_to_words_be(bytes: impl AsRef<[u8]>) -> Vec<u32> {
    bytes
        .as_ref()
        .array_chunks::<4>()
        .map(|chunk| u32::from_be_bytes(*chunk))
        .collect()
}

pub fn words_to_bytes_be(words: impl AsRef<[u32]>) -> Vec<u8> {
    words
        .as_ref()
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_words_le_works() {
        assert_eq!(
            vec![0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            bytes_to_words_le([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10
            ])
        );
    }

    #[test]
    fn words_to_bytes_le_works() {
        assert_eq!(
            vec![
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10
            ],
            words_to_bytes_le([0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476])
        );
    }
}
