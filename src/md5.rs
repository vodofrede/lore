use std::convert::TryInto;

// round functions as defined in RFC1321
const F: fn(u32, u32, u32) -> u32 = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
const G: fn(u32, u32, u32) -> u32 = |x: u32, y: u32, z: u32| (x & z) | (y & !z);
const H: fn(u32, u32, u32) -> u32 = |x: u32, y: u32, z: u32| x ^ y ^ z;
const I: fn(u32, u32, u32) -> u32 = |x: u32, y: u32, z: u32| y ^ (x | !z);

// constants used in RFC132
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

// shifts per round
const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

fn op(
    function: impl Fn(u32, u32, u32) -> u32,
    state: (u32, u32, u32, u32),
    word: u32,
    index: usize,
) -> u32 {
    function(state.1, state.2, state.3)
        .wrapping_add(state.0)
        .wrapping_add(word)
        .wrapping_add(K[index])
        .rotate_left(S[index])
        .wrapping_add(state.1)
}

fn preprocess(msg: impl AsRef<[u8]>) -> Vec<u8> {
    let mut message = msg.as_ref().to_vec();
    let len_in_bits = message.len().wrapping_mul(8) as u64;

    // padding
    // add one bit first (le), then pad with zeroes
    message.push(0b10000000);
    while (message.len() * 8) % 512 != 448 {
        message.push(0u8);
    }

    // append length
    message.extend(len_in_bits.to_le_bytes());

    message
}

pub fn hash(input: impl AsRef<[u8]>) -> String {
    let (a, b, c, d) = preprocess(input).chunks_exact(64).fold(
        (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32),
        |(mut a0, mut b0, mut c0, mut d0), chunk| {
            let mut words = [0u32; 16];
            for (word, c) in words.iter_mut().zip(chunk.chunks_exact(4)) {
                *word = u32::from_le_bytes(c.try_into().unwrap());
            }

            let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

            for i in (0..4).map(|i| i * 4) {
                a = op(F, (a, b, c, d), words[i], i);
                d = op(F, (d, a, b, c), words[i + 1], i + 1);
                c = op(F, (c, d, a, b), words[i + 2], i + 2);
                b = op(F, (b, c, d, a), words[i + 3], i + 3);
            }

            for i in (4..8).map(|i| i * 4) {
                a = op(G, (a, b, c, d), words[(5 * i + 1) % 16], i);
                d = op(G, (d, a, b, c), words[(5 * (i + 1) + 1) % 16], i + 1);
                c = op(G, (c, d, a, b), words[(5 * (i + 2) + 1) % 16], i + 2);
                b = op(G, (b, c, d, a), words[(5 * (i + 3) + 1) % 16], i + 3);
            }

            for i in (8..12).map(|i| i * 4) {
                a = op(H, (a, b, c, d), words[(3 * i + 5) % 16], i);
                d = op(H, (d, a, b, c), words[(3 * (i + 1) + 5) % 16], i + 1);
                c = op(H, (c, d, a, b), words[(3 * (i + 2) + 5) % 16], i + 2);
                b = op(H, (b, c, d, a), words[(3 * (i + 3) + 5) % 16], i + 3);
            }

            for i in (12..16).map(|i| i * 4) {
                a = op(I, (a, b, c, d), words[(7 * i) % 16], i);
                d = op(I, (d, a, b, c), words[(7 * (i + 1)) % 16], i + 1);
                c = op(I, (c, d, a, b), words[(7 * (i + 2)) % 16], i + 2);
                b = op(I, (b, c, d, a), words[(7 * (i + 3)) % 16], i + 3);
            }

            a0 = a0.wrapping_add(a);
            b0 = b0.wrapping_add(b);
            c0 = c0.wrapping_add(c);
            d0 = d0.wrapping_add(d);

            (a0, b0, c0, d0)
        },
    );

    format!(
        "{:08x}{:08x}{:08x}{:08x}",
        a.swap_bytes(),
        b.swap_bytes(),
        c.swap_bytes(),
        d.swap_bytes()
    )
}
