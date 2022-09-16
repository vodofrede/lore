use crate::hash::{bytes_to_words_le, md4::pad, words_to_bytes_le, Digest};

// based on RFC1321
const A: u32 = 0x67452301;
const B: u32 = 0xefcdab89;
const C: u32 = 0x98badcfe;
const D: u32 = 0x10325476;

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

// shifts & indices for each step
const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
const W: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8,
    13, 2, 7, 12, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 7, 14, 5, 12, 3, 10, 1,
    8, 15, 6, 13, 4, 11, 2, 9,
];

// round functions
const F: fn(u32, u32, u32) -> u32 = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
const G: fn(u32, u32, u32) -> u32 = |x: u32, y: u32, z: u32| (x & z) | (y & !z);
const H: fn(u32, u32, u32) -> u32 = |x: u32, y: u32, z: u32| x ^ y ^ z;
const I: fn(u32, u32, u32) -> u32 = |x: u32, y: u32, z: u32| y ^ (x | !z);

fn step([mut a, b, c, d]: [u32; 4], words: &[u32], index: usize) -> [u32; 4] {
    let f = match index {
        0..=15 => F,
        16..=31 => G,
        32..=47 => H,
        48..=63 => I,
        _ => panic!("This function shouldn't be called using an index outside 0..48"),
    };

    a = f(b, c, d)
        .wrapping_add(a)
        .wrapping_add(words[W[index]])
        .wrapping_add(K[index])
        .rotate_left(S[index])
        .wrapping_add(b);

    [a, b, c, d]
}

/// Compute the MD5 hash of the input bytes
/// # Examples
/// ```
/// let input = "lol";
/// let digest = lore::md5(input);
///
/// assert_eq!(digest.to_string(), "9cdfb439c7876e703e307864c9167a15");
/// ```
pub fn hash(message: impl AsRef<[u8]>) -> Digest<16> {
    let padded = pad(message);
    let buffer = padded.array_chunks::<64>().map(bytes_to_words_le).fold(
        [A, B, C, D],
        |[a, b, c, d], words| {
            println!("{words:08x?}");

            let mut state = [a, b, c, d];

            for i in 0..64 {
                state = step(state, &words, i);
                println!("{state:08x?}");
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
    fn md5_hash() {
        assert_eq!("d41d8cd98f00b204e9800998ecf8427e", hash("").to_string());
        assert_eq!(
            "73e51861b65c1e83d6136fb6a002585e",
            hash("tihi xd").to_string()
        );
        assert_eq!("9cdfb439c7876e703e307864c9167a15", hash("lol").to_string());
        assert_eq!(
            "fd6f92edff2b7db7cd92b494c4926ef0",
            hash("Lorem ipsum dolor sit amet. Nam placeat iste aut dolorem necessitatibus sit unde magni. Nam cumque quia nam fugit quibusdam ut incidunt minima nam dignissimos iusto et voluptatum magnam. Et pariatur eius vel excepturi odit libero sit molestiae consequatur vel nostrum ullam. Sit sint beatae eos doloribus sapiente aut aperiam ullam ut laboriosam debitis! Qui reiciendis rerum est omnis galisum aut similique iure est dolores fuga sit rerum dicta. Aut excepturi fuga et enim ipsum a quia ut velit atque id iste nobis. Non molestiae vero et veritatis aliquam sed enim ducimus. At sunt tempora quo quisquam unde aut ipsum nulla et fugit eius in nulla fugit qui magnam excepturi aut rerum officia. Et officia magnam eos reiciendis voluptatum ea voluptas recusandae in similique enim. Ut provident laudantium ut temporibus eius ut laudantium voluptate aut ducimus impedit. Et asperiores aperiam sit deleniti voluptas ex porro omnis ut voluptas assumenda aut necessitatibus aliquid.").to_string()
        );
    }

    #[test]
    fn md5_steps() {
        let expected: [[u32; 4]; 64] = [
            [0x5954a129, 0xefcdab89, 0x98badcfe, 0x10325476],
            [0x3171555d, 0x5954a129, 0xefcdab89, 0x98badcfe],
            [0x24368ecc, 0x3171555d, 0x5954a129, 0xefcdab89],
            [0x1d414db3, 0x24368ecc, 0x3171555d, 0x5954a129],
            [0x9da81fec, 0x1d414db3, 0x24368ecc, 0x3171555d],
            [0x983a9b4c, 0x9da81fec, 0x1d414db3, 0x24368ecc],
            [0x01f76eec, 0x983a9b4c, 0x9da81fec, 0x1d414db3],
            [0x82251f6b, 0x01f76eec, 0x983a9b4c, 0x9da81fec],
            [0x3648b77a, 0x82251f6b, 0x01f76eec, 0x983a9b4c],
            [0xa57749ed, 0x3648b77a, 0x82251f6b, 0x01f76eec],
            [0x69859a5a, 0xa57749ed, 0x3648b77a, 0x82251f6b],
            [0x8dd64e23, 0x69859a5a, 0xa57749ed, 0x3648b77a],
            [0x4cc08388, 0x8dd64e23, 0x69859a5a, 0xa57749ed],
            [0x9a1db095, 0x4cc08388, 0x8dd64e23, 0x69859a5a],
            [0xf3a1ec18, 0x9a1db095, 0x4cc08388, 0x8dd64e23],
            [0x68bf5f16, 0xf3a1ec18, 0x9a1db095, 0x4cc08388],
            [0x08cf03db, 0x68bf5f16, 0xf3a1ec18, 0x9a1db095],
            [0x03bceaa0, 0x08cf03db, 0x68bf5f16, 0xf3a1ec18],
            [0x2809715f, 0x03bceaa0, 0x08cf03db, 0x68bf5f16],
            [0xc305e2e6, 0x2809715f, 0x03bceaa0, 0x08cf03db],
            [0x0386e9c7, 0xc305e2e6, 0x2809715f, 0x03bceaa0],
            [0x0f4c9f59, 0x0386e9c7, 0xc305e2e6, 0x2809715f],
            [0x8814e065, 0x0f4c9f59, 0x0386e9c7, 0xc305e2e6],
            [0xd8d052d2, 0x8814e065, 0x0f4c9f59, 0x0386e9c7],
            [0x8ff59707, 0xd8d052d2, 0x8814e065, 0x0f4c9f59],
            [0x4069945d, 0x8ff59707, 0xd8d052d2, 0x8814e065],
            [0x213a0570, 0x4069945d, 0x8ff59707, 0xd8d052d2],
            [0xf2affb96, 0x213a0570, 0x4069945d, 0x8ff59707],
            [0x555223a9, 0xf2affb96, 0x213a0570, 0x4069945d],
            [0x37ba19ca, 0x555223a9, 0xf2affb96, 0x213a0570],
            [0x003749f2, 0x37ba19ca, 0x555223a9, 0xf2affb96],
            [0x20617338, 0x003749f2, 0x37ba19ca, 0x555223a9],
            [0xf3e971ee, 0x20617338, 0x003749f2, 0x37ba19ca],
            [0x4ec4ee85, 0xf3e971ee, 0x20617338, 0x003749f2],
            [0xe62bf9a6, 0x4ec4ee85, 0xf3e971ee, 0x20617338],
            [0x0ae8a02f, 0xe62bf9a6, 0x4ec4ee85, 0xf3e971ee],
            [0xbc31561a, 0x0ae8a02f, 0xe62bf9a6, 0x4ec4ee85],
            [0x6a9f6576, 0xbc31561a, 0x0ae8a02f, 0xe62bf9a6],
            [0x42e91ea3, 0x6a9f6576, 0xbc31561a, 0x0ae8a02f],
            [0x7a181668, 0x42e91ea3, 0x6a9f6576, 0xbc31561a],
            [0xedcc403b, 0x7a181668, 0x42e91ea3, 0x6a9f6576],
            [0x1fcae4da, 0xedcc403b, 0x7a181668, 0x42e91ea3],
            [0x217c84d1, 0x1fcae4da, 0xedcc403b, 0x7a181668],
            [0xf02591fa, 0x217c84d1, 0x1fcae4da, 0xedcc403b],
            [0x5375b853, 0xf02591fa, 0x217c84d1, 0x1fcae4da],
            [0xecd77499, 0x5375b853, 0xf02591fa, 0x217c84d1],
            [0x4bd1053f, 0xecd77499, 0x5375b853, 0xf02591fa],
            [0x7625a818, 0x4bd1053f, 0xecd77499, 0x5375b853],
            [0xf7223b53, 0x7625a818, 0x4bd1053f, 0xecd77499],
            [0x2e422a17, 0xf7223b53, 0x7625a818, 0x4bd1053f],
            [0xe5235245, 0x2e422a17, 0xf7223b53, 0x7625a818],
            [0x8e8a212d, 0xe5235245, 0x2e422a17, 0xf7223b53],
            [0x551950d2, 0x8e8a212d, 0xe5235245, 0x2e422a17],
            [0xf067530c, 0x551950d2, 0x8e8a212d, 0xe5235245],
            [0xdb4e97cc, 0xf067530c, 0x551950d2, 0x8e8a212d],
            [0x5b429768, 0xdb4e97cc, 0xf067530c, 0x551950d2],
            [0xb0c06d7a, 0x5b429768, 0xdb4e97cc, 0xf067530c],
            [0xd1906cf3, 0xb0c06d7a, 0x5b429768, 0xdb4e97cc],
            [0x3fc74ed9, 0xd1906cf3, 0xb0c06d7a, 0x5b429768],
            [0xa6b24624, 0x3fc74ed9, 0xd1906cf3, 0xb0c06d7a],
            [0xf9d3c272, 0xa6b24624, 0x3fc74ed9, 0xd1906cf3],
            [0x4e25ae2a, 0xf9d3c272, 0xa6b24624, 0x3fc74ed9],
            [0x1db436d8, 0x4e25ae2a, 0xf9d3c272, 0xa6b24624],
            [0x9350b12d, 0x1db436d8, 0x4e25ae2a, 0xf9d3c272],
        ];

        let words: [u32; 16] = [
            0x69686974, 0x80647820, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
            0x00000038, 0x00000000,
        ];
        let mut state = [A, B, C, D];

        #[allow(clippy::needless_range_loop)]
        for i in 0..64 {
            state = step(state, &words, i);
            assert_eq!(expected[i], state);
            state.rotate_right(1);
        }
    }
}
