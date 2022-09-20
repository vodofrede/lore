use crate::hash::{bytes_to_words_be, words_to_bytes_be, Digest};

// based on RFC3174, US Secure Hash Algorithm 1

// round functions
const F1: fn(u32, u32, u32) -> u32 = |x, y, z| (x & y) | ((!x) & z);
const F2: fn(u32, u32, u32) -> u32 = |x, y, z| x ^ y ^ z;
const F3: fn(u32, u32, u32) -> u32 = |x, y, z| (x & y) | (x & z) | (y & z);
const F4: fn(u32, u32, u32) -> u32 = |x, y, z| x ^ y ^ z;

// round constants
const K1: u32 = 0x5a827999;
const K2: u32 = 0x6ed9eba1;
const K3: u32 = 0x8f1bbcdc;
const K4: u32 = 0xca62c1d6;

// buffer 2 initial constants
const H0: u32 = 0x67452301;
const H1: u32 = 0xefcdab89;
const H2: u32 = 0x98badcfe;
const H3: u32 = 0x10325476;
const H4: u32 = 0xc3d2e1f0;

fn pad(message: impl AsRef<[u8]>) -> Vec<u8> {
    let mut message = message.as_ref().to_vec();
    let message_length = message.len().wrapping_mul(8) as u64;

    // push 1 bit (little endian)
    message.push(0x80);

    // pad with 0 bits until length is congruent with 64 mod 56 bytes
    while (message.len() % 64) < 56 {
        message.push(0);
    }

    // append the length of the original message (big endian)
    message.extend(message_length.to_be_bytes());

    message
}

fn step([a, b, c, d, e]: [u32; 5], words: &[u32], i: usize) -> [u32; 5] {
    let (k, f) = match i {
        0..=19 => (K1, F1),
        20..=39 => (K2, F2),
        40..=59 => (K3, F3),
        60..=79 => (K4, F4),
        _ => panic!("step function should not be called with index outside of range 0..80"),
    };

    [
        a.rotate_left(5)
            .wrapping_add(f(b, c, d))
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(words[i]),
        a,
        b.rotate_left(30),
        c,
        d,
    ]
}

/// Computes the SHA1 digest of the input bytes.
///
/// Returns a 20-byte long `Digest` which implements `Display` in order to get at hexadecimal-string representation.
///
/// # Examples
///
/// Basic usage:
///
/// ```rust
/// let input = "abc";
/// let digest = lore::sha1(input);
///
/// assert_eq!(digest.to_string(), "a9993e364706816aba3e25717850c26c9cd0d89d")
/// ```
pub fn hash(message: impl AsRef<[u8]>) -> Digest<20> {
    let padded = pad(message);

    let buffer = padded
        .array_chunks::<64>()
        .map(|chunk| bytes_to_words_be(*chunk))
        .fold([H0, H1, H2, H3, H4], |[a, b, c, d, e], mut words| {
            // extend 16 words to 80 words
            for i in 16..80 {
                words.push(
                    (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1),
                );
            }

            // initialize state
            let mut state = [a, b, c, d, e];

            // perform 80 steps
            for i in 0..80 {
                state = step(state, &words, i);
            }

            // add computed round state to buffer
            [
                a.wrapping_add(state[0]),
                b.wrapping_add(state[1]),
                c.wrapping_add(state[2]),
                d.wrapping_add(state[3]),
                e.wrapping_add(state[4]),
            ]
        });

    let digest = *words_to_bytes_be(buffer)
        .array_chunks::<20>()
        .next()
        .unwrap();

    Digest(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_pad() {
        let expected: [u8; 64] = [
            0x61, 0x62, 0x63, 0x64, 0x65, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x28,
        ];

        assert_eq!(
            expected.to_vec(),
            pad([0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101])
        );
    }

    #[test]
    fn sha1_hash() {
        assert_eq!(
            hash("").to_string(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );

        assert_eq!(
            hash("abc").to_string(),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }
}
