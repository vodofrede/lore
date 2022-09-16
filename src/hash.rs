use std::fmt::Display;

pub mod md2;
pub mod md4;
pub mod md5;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Digest<const S: usize>([u8; S]);

impl<const S: usize> Display for Digest<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            &self
                .0
                .iter()
                .map(|u| format!("{:02x}", u))
                .collect::<Vec<_>>()
                .join(""),
        )
    }
}

pub(crate) fn bytes_to_words_le(bytes: impl AsRef<[u8]>) -> Vec<u32> {
    bytes
        .as_ref()
        .array_chunks::<4>()
        .map(|chunk| u32::from_le_bytes(*chunk))
        .collect()
}

pub(crate) fn words_to_bytes_le(words: impl AsRef<[u32]>) -> Vec<u8> {
    words
        .as_ref()
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_words_le_works() {
        assert_eq!(
            vec![0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            bytes_to_words_le([
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10
            ])
        )
    }

    #[test]
    fn words_to_bytes_le_works() {
        assert_eq!(
            vec![
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                0x32, 0x10
            ],
            words_to_bytes_le([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476])
        )
    }
}
