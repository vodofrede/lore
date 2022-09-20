use crate::hash::{bytes_to_words_le, words_to_bytes_le, Digest};

// based on RFC1320
const A: u32 = 0x67452301;
const B: u32 = 0xefcdab89;
const C: u32 = 0x98badcfe;
const D: u32 = 0x10325476;

// additional constants for round 1, 2 & 3
const C1: u32 = 0;
const C2: u32 = 0x5a827999;
const C3: u32 = 0x6ed9eba1;

// shifts & indices for each step
const S: [u32; 48] = [
    3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13,
    3, 5, 9, 13, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15,
];
const W: [usize; 48] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14,
    3, 7, 11, 15, 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15,
];

// round functions
const F: fn(u32, u32, u32) -> u32 = |x, y, z| (x & y) | (!x & z);
const G: fn(u32, u32, u32) -> u32 = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
const H: fn(u32, u32, u32) -> u32 = |x: u32, y: u32, z: u32| x ^ y ^ z;

// pad the message to next 512-bit interval
pub fn pad(message: impl AsRef<[u8]>) -> Vec<u8> {
    let mut message = message.as_ref().to_vec();
    let message_length = message.len().wrapping_mul(8) as u64;

    // add 1 bit (le)
    message.push(0x80);

    // add 0 bits until length in bits is congruent to 448 mod 512
    while (message.len()) % 64 != 56 {
        message.push(0u8);
    }

    // append message length (64 bits)
    message.extend(message_length.to_le_bytes());

    message
}

// compute an invidiual step in the md4 algorithm
fn step([mut a, b, c, d]: [u32; 4], words: &[u32], i: usize) -> [u32; 4] {
    // choose function and constant based on which round is currently active
    let (f, k) = match i {
        0..=15 => (F, C1),
        16..=31 => (G, C2),
        32..=47 => (H, C3),
        _ => panic!("This function shouldn't be called using an index outside 0..48"),
    };

    // main operation
    a = f(b, c, d)
        .wrapping_add(a)
        .wrapping_add(words[W[i]])
        .wrapping_add(k)
        .rotate_left(S[i]);

    [a, b, c, d]
}

/// Computes the MD4 hash value (digest) of the input bytes.
///
/// Returns a 16-byte `Digest` which implements `Display` in order to get at hexadecimal-string representation.
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// let input = "abc";
/// let digest = lore::md4(input);
///
/// assert_eq!(digest.to_string(), "a448017aaf21d8525fc10ae87aa6729d");
/// ```
pub fn hash(message: impl AsRef<[u8]>) -> Digest<16> {
    let padded = pad(message);
    let buffer = padded.array_chunks::<64>().map(bytes_to_words_le).fold(
        [A, B, C, D],
        |[a, b, c, d], words| {
            // perform rounds on this chunk of data
            let mut state = [a, b, c, d];
            for i in 0..48 {
                state = step(state, &words, i);
                state.rotate_right(1);
            }

            [
                a.wrapping_add(state[0]),
                b.wrapping_add(state[1]),
                c.wrapping_add(state[2]),
                d.wrapping_add(state[3]),
            ]
        },
    );
    let digest = *words_to_bytes_le(buffer)
        .array_chunks::<16>()
        .next()
        .unwrap();

    Digest(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md4_pad() {
        assert_eq!(pad([1u8]).len() % 64, 0);
        assert_eq!(pad([1u8; 63]).len() % 64, 0);
        assert_eq!(pad([1u8; 65]).len() % 64, 0);
        assert_eq!(pad([1u8; 511]).len() % 64, 0);
        assert_eq!(pad([1u8; 512]).len() % 64, 0);
        assert_eq!(pad([1u8; 513]).len() % 64, 0);
        assert_eq!(pad([1u8; 4472]).len() % 64, 0);

        assert_eq!(
            vec![
                0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ],
            pad([1u8])
        );
    }

    #[test]
    fn md4_hash() {
        assert_eq!(
            "1bee69a46ba811185c194762abaeae90",
            hash("The quick brown fox jumps over the lazy dog").to_string()
        );
        assert_eq!(
            "b86e130ce7028da59e672d56ad0113df",
            hash("The quick brown fox jumps over the lazy cog").to_string()
        );
        assert_eq!("31d6cfe0d16ae931b73c59d7e0c089c0", hash("").to_string());

        // RFC 1320 test suite
        assert_eq!(hash("").to_string(), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hash("a").to_string(), "bde52cb31de33e46245e05fbdbd6fb24");
        assert_eq!(hash("abc").to_string(), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(
            hash("message digest").to_string(),
            "d9130a8164549fe818874806e1c7014b"
        );
        assert_eq!(
            hash("abcdefghijklmnopqrstuvwxyz").to_string(),
            "d79e1c308aa5bbcdeea8ed63df412da9"
        );
        assert_eq!(
            hash("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").to_string(),
            "043f8582f241db351ce627e153e7f0e4"
        );
        assert_eq!(
            hash(
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )
            .to_string(),
            "e33b4ddc9c38f2199c3e7b164fcc0536"
        );
        assert_eq!(
            hash("Rosetta Code").to_string(),
            "a52bcfc6a0d0d300cdc5ddbfbefe478b"
        );
    }

    #[test]
    fn md4_steps() {
        let expected: [[u32; 4]; 48] = [
            [0x2b9b7a8b, 0xefcdab89, 0x98badcfe, 0x10325476],
            [0x1ebbf3f6, 0x2b9b7a8b, 0xefcdab89, 0x98badcfe],
            [0xf636674f, 0x1ebbf3f6, 0x2b9b7a8b, 0xefcdab89],
            [0x3e787c49, 0xf636674f, 0x1ebbf3f6, 0x2b9b7a8b],
            [0x127b1453, 0x3e787c49, 0xf636674f, 0x1ebbf3f6],
            [0x9c35a18a, 0x127b1453, 0x3e787c49, 0xf636674f],
            [0x7e1c9145, 0x9c35a18a, 0x127b1453, 0x3e787c49],
            [0x0adad780, 0x7e1c9145, 0x9c35a18a, 0x127b1453],
            [0x85c62aed, 0x0adad780, 0x7e1c9145, 0x9c35a18a],
            [0x881a850b, 0x85c62aed, 0x0adad780, 0x7e1c9145],
            [0xf71e7006, 0x881a850b, 0x85c62aed, 0x0adad780],
            [0x135c5da7, 0xf71e7006, 0x881a850b, 0x85c62aed],
            [0x0727d7d9, 0x135c5da7, 0xf71e7006, 0x881a850b],
            [0x9b7d493d, 0x0727d7d9, 0x135c5da7, 0xf71e7006],
            [0x1e300fd2, 0x9b7d493d, 0x0727d7d9, 0x135c5da7],
            [0xb60174a1, 0x1e300fd2, 0x9b7d493d, 0x0727d7d9],
            [0x2a7873ab, 0xb60174a1, 0x1e300fd2, 0x9b7d493d],
            [0x86074f26, 0x2a7873ab, 0xb60174a1, 0x1e300fd2],
            [0x68021c3d, 0x86074f26, 0x2a7873ab, 0xb60174a1],
            [0xc9ad2750, 0x68021c3d, 0x86074f26, 0x2a7873ab],
            [0x6b1b8763, 0xc9ad2750, 0x68021c3d, 0x86074f26],
            [0x329a0609, 0x6b1b8763, 0xc9ad2750, 0x68021c3d],
            [0x3f3a2e5c, 0x329a0609, 0x6b1b8763, 0xc9ad2750],
            [0x34e64be9, 0x3f3a2e5c, 0x329a0609, 0x6b1b8763],
            [0x0de3f443, 0x34e64be9, 0x3f3a2e5c, 0x329a0609],
            [0x5fddbd79, 0x0de3f443, 0x34e64be9, 0x3f3a2e5c],
            [0x494abd6f, 0x5fddbd79, 0x0de3f443, 0x34e64be9],
            [0x9069bba6, 0x494abd6f, 0x5fddbd79, 0x0de3f443],
            [0x0d815e5e, 0x9069bba6, 0x494abd6f, 0x5fddbd79],
            [0x753ed018, 0x0d815e5e, 0x9069bba6, 0x494abd6f],
            [0xee224d71, 0x753ed018, 0x0d815e5e, 0x9069bba6],
            [0xd232eb01, 0xee224d71, 0x753ed018, 0x0d815e5e],
            [0x57e97dc9, 0xd232eb01, 0xee224d71, 0x753ed018],
            [0x252ee4a0, 0x57e97dc9, 0xd232eb01, 0xee224d71],
            [0x8d5bd7ef, 0x252ee4a0, 0x57e97dc9, 0xd232eb01],
            [0x92942054, 0x8d5bd7ef, 0x252ee4a0, 0x57e97dc9],
            [0x38475e43, 0x92942054, 0x8d5bd7ef, 0x252ee4a0],
            [0x22f47377, 0x38475e43, 0x92942054, 0x8d5bd7ef],
            [0xe6878422, 0x22f47377, 0x38475e43, 0x92942054],
            [0x5ab5fed1, 0xe6878422, 0x22f47377, 0x38475e43],
            [0x32463ee3, 0x5ab5fed1, 0xe6878422, 0x22f47377],
            [0x85465040, 0x32463ee3, 0x5ab5fed1, 0xe6878422],
            [0xb801aa18, 0x85465040, 0x32463ee3, 0x5ab5fed1],
            [0xd796ec48, 0xb801aa18, 0x85465040, 0x32463ee3],
            [0x5f8a08a4, 0xd796ec48, 0xb801aa18, 0x85465040],
            [0x7b15aa48, 0x5f8a08a4, 0xd796ec48, 0xb801aa18],
            [0x2722e8cf, 0x7b15aa48, 0x5f8a08a4, 0xd796ec48],
            [0x11062517, 0x2722e8cf, 0x7b15aa48, 0x5f8a08a4],
        ];

        // perform first step of md4 round 1
        let words: [u32; 16] = [
            0x65736f52, 0x20617474, 0x65646f43, 0x00000080, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000060, 0x00000000,
        ];
        let mut state: [u32; 4] = [A, B, C, D];

        #[allow(clippy::needless_range_loop)]
        for i in 0..48 {
            state = step(state, &words, i);
            assert_eq!(expected[i], state);
            state.rotate_right(1);
        }
    }
}
