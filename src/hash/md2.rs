use crate::hash::Digest;

/// see RFC1319
const S: [u8; 256] = [
    0x29, 0x2E, 0x43, 0xC9, 0xA2, 0xD8, 0x7C, 0x01, 0x3D, 0x36, 0x54, 0xA1, 0xEC, 0xF0, 0x06, 0x13,
    0x62, 0xA7, 0x05, 0xF3, 0xC0, 0xC7, 0x73, 0x8C, 0x98, 0x93, 0x2B, 0xD9, 0xBC, 0x4C, 0x82, 0xCA,
    0x1E, 0x9B, 0x57, 0x3C, 0xFD, 0xD4, 0xE0, 0x16, 0x67, 0x42, 0x6F, 0x18, 0x8A, 0x17, 0xE5, 0x12,
    0xBE, 0x4E, 0xC4, 0xD6, 0xDA, 0x9E, 0xDE, 0x49, 0xA0, 0xFB, 0xF5, 0x8E, 0xBB, 0x2F, 0xEE, 0x7A,
    0xA9, 0x68, 0x79, 0x91, 0x15, 0xB2, 0x07, 0x3F, 0x94, 0xC2, 0x10, 0x89, 0x0B, 0x22, 0x5F, 0x21,
    0x80, 0x7F, 0x5D, 0x9A, 0x5A, 0x90, 0x32, 0x27, 0x35, 0x3E, 0xCC, 0xE7, 0xBF, 0xF7, 0x97, 0x03,
    0xFF, 0x19, 0x30, 0xB3, 0x48, 0xA5, 0xB5, 0xD1, 0xD7, 0x5E, 0x92, 0x2A, 0xAC, 0x56, 0xAA, 0xC6,
    0x4F, 0xB8, 0x38, 0xD2, 0x96, 0xA4, 0x7D, 0xB6, 0x76, 0xFC, 0x6B, 0xE2, 0x9C, 0x74, 0x04, 0xF1,
    0x45, 0x9D, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5B, 0xCF, 0x65, 0xE6, 0x2D, 0xA8, 0x02,
    0x1B, 0x60, 0x25, 0xAD, 0xAE, 0xB0, 0xB9, 0xF6, 0x1C, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7E, 0x0F,
    0x55, 0x47, 0xA3, 0x23, 0xDD, 0x51, 0xAF, 0x3A, 0xC3, 0x5C, 0xF9, 0xCE, 0xBA, 0xC5, 0xEA, 0x26,
    0x2C, 0x53, 0x0D, 0x6E, 0x85, 0x28, 0x84, 0x09, 0xD3, 0xDF, 0xCD, 0xF4, 0x41, 0x81, 0x4D, 0x52,
    0x6A, 0xDC, 0x37, 0xC8, 0x6C, 0xC1, 0xAB, 0xFA, 0x24, 0xE1, 0x7B, 0x08, 0x0C, 0xBD, 0xB1, 0x4A,
    0x78, 0x88, 0x95, 0x8B, 0xE3, 0x63, 0xE8, 0x6D, 0xE9, 0xCB, 0xD5, 0xFE, 0x3B, 0x00, 0x1D, 0x39,
    0xF2, 0xEF, 0xB7, 0x0E, 0x66, 0x58, 0xD0, 0xE4, 0xA6, 0x77, 0x72, 0xF8, 0xEB, 0x75, 0x4B, 0x0A,
    0x31, 0x44, 0x50, 0xB4, 0x8F, 0xED, 0x1F, 0x1A, 0xDB, 0x99, 0x8D, 0x33, 0x9F, 0x11, 0x83, 0x14,
];

fn pad(message: impl AsRef<[u8]>) -> Vec<u8> {
    let mut message = message.as_ref().to_vec();
    let padding_length = 16 - (message.len() % 16);
    message.append(&mut vec![padding_length as u8; padding_length]);
    message
}

fn checksum(message: impl AsRef<[u8]>) -> Vec<u8> {
    let mut message = message.as_ref().to_vec();
    let mut checksum = vec![0u8; 16];

    let mut last = 0;
    for block in message.array_chunks::<16>() {
        for i in 0..16 {
            checksum[i] ^= S[(block[i] ^ last) as usize];
            last = checksum[i];
        }
    }

    message.append(&mut checksum);
    message
}

/// Computes the MD2 hash value (digest) of the input bytes.
///
/// Returns a 16-byte `Digest` which implements `Display` in order to get at hexadecimal-string representation.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let input = "abc";
/// let digest = lore::md2(input);
///
/// assert_eq!(digest.to_string(), "da853b0d3f88d99b30283a69e6ded6bb");
/// ```
pub fn hash(msg: impl AsRef<[u8]>) -> Digest<16> {
    let padded = checksum(pad(msg));
    let buffer = padded
        .array_chunks::<16>()
        .fold([0u8; 48], |mut buffer, chunk| {
            // copy chunk into buffer
            for i in 0..16 {
                buffer[16 + i] = chunk[i];
                buffer[32 + i] = buffer[16 + i] ^ buffer[i];
            }

            // do 18 rounds
            let mut t = 0;
            for i in 0..18 {
                for b in buffer.iter_mut() {
                    *b ^= S[t as usize];
                    t = *b;
                }
                t = t.wrapping_add(i);
            }

            buffer
        });
    let digest = *buffer.array_chunks::<16>().next().unwrap();

    Digest(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md2_pad() {
        // assert that padding length is always correct
        assert!(pad([]).len() % 16 == 0);
        assert!(pad([0u8]).len() % 16 == 0);
        assert!(pad([0u8; 15]).len() % 16 == 0);
        assert!(pad([0u8; 16]).len() % 16 == 0);
        assert!(pad([0u8; 476]).len() % 16 == 0);

        // check some simple cases
        assert_eq!(vec![16u8; 16], pad([]));
        assert_eq!(
            vec![0, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15],
            pad([0u8])
        );
    }

    #[test]
    fn md2_checksum() {
        assert_eq!(
            vec![
                16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 98, 56, 103, 182,
                175, 82, 121, 94, 95, 33, 78, 151, 32, 190, 234, 141
            ],
            checksum(vec![16u8; 16])
        );

        assert_eq!(
            vec![
                0u8, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 41, 224, 10, 216,
                109, 48, 122, 164, 206, 220, 139, 100, 42, 212, 254, 68
            ],
            checksum(vec![
                0u8, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15
            ])
        );
    }

    #[test]
    fn md2_hash() {
        assert_eq!(
            "a9046c73e00331af68917d3804f70655",
            hash(b"hello").to_string()
        );

        assert_eq!("8350e5a3e24c153df2275c9f80692773", hash(b"").to_string());
        assert_eq!("32ec01ec4a6dac72c0ab96fb34c0b5d1", hash(b"a").to_string());
        assert_eq!("da853b0d3f88d99b30283a69e6ded6bb", hash(b"abc").to_string());

        assert_eq!(
            "03d85a0d629d2c442e987525319fc471",
            hash(b"The quick brown fox jumps over the lazy dog").to_string()
        );
    }
}
