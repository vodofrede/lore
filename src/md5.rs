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

#[inline(always)]
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

            // round 1
            a = op(F, (a, b, c, d), words[0], 0);
            d = op(F, (d, a, b, c), words[1], 1);
            c = op(F, (c, d, a, b), words[2], 2);
            b = op(F, (b, c, d, a), words[3], 3);

            a = op(F, (a, b, c, d), words[4], 4);
            d = op(F, (d, a, b, c), words[5], 5);
            c = op(F, (c, d, a, b), words[6], 6);
            b = op(F, (b, c, d, a), words[7], 7);

            a = op(F, (a, b, c, d), words[8], 8);
            d = op(F, (d, a, b, c), words[9], 9);
            c = op(F, (c, d, a, b), words[10], 10);
            b = op(F, (b, c, d, a), words[11], 11);

            a = op(F, (a, b, c, d), words[12], 12);
            d = op(F, (d, a, b, c), words[13], 13);
            c = op(F, (c, d, a, b), words[14], 14);
            b = op(F, (b, c, d, a), words[15], 15);

            // round 2
            a = op(G, (a, b, c, d), words[1], 16);
            d = op(G, (d, a, b, c), words[6], 17);
            c = op(G, (c, d, a, b), words[11], 18);
            b = op(G, (b, c, d, a), words[0], 19);

            a = op(G, (a, b, c, d), words[5], 20);
            d = op(G, (d, a, b, c), words[10], 21);
            c = op(G, (c, d, a, b), words[15], 22);
            b = op(G, (b, c, d, a), words[4], 23);

            a = op(G, (a, b, c, d), words[9], 24);
            d = op(G, (d, a, b, c), words[14], 25);
            c = op(G, (c, d, a, b), words[3], 26);
            b = op(G, (b, c, d, a), words[8], 27);

            a = op(G, (a, b, c, d), words[13], 28);
            d = op(G, (d, a, b, c), words[2], 29);
            c = op(G, (c, d, a, b), words[7], 30);
            b = op(G, (b, c, d, a), words[12], 31);

            // round 3
            a = op(H, (a, b, c, d), words[5], 32);
            d = op(H, (d, a, b, c), words[8], 33);
            c = op(H, (c, d, a, b), words[11], 34);
            b = op(H, (b, c, d, a), words[14], 35);

            a = op(H, (a, b, c, d), words[1], 36);
            d = op(H, (d, a, b, c), words[4], 37);
            c = op(H, (c, d, a, b), words[7], 38);
            b = op(H, (b, c, d, a), words[10], 39);

            a = op(H, (a, b, c, d), words[13], 40);
            d = op(H, (d, a, b, c), words[0], 41);
            c = op(H, (c, d, a, b), words[3], 42);
            b = op(H, (b, c, d, a), words[6], 43);

            a = op(H, (a, b, c, d), words[9], 44);
            d = op(H, (d, a, b, c), words[12], 45);
            c = op(H, (c, d, a, b), words[15], 46);
            b = op(H, (b, c, d, a), words[2], 47);

            // round 4
            a = op(I, (a, b, c, d), words[0], 48);
            d = op(I, (d, a, b, c), words[7], 49);
            c = op(I, (c, d, a, b), words[14], 50);
            b = op(I, (b, c, d, a), words[5], 51);

            a = op(I, (a, b, c, d), words[12], 52);
            d = op(I, (d, a, b, c), words[3], 53);
            c = op(I, (c, d, a, b), words[10], 54);
            b = op(I, (b, c, d, a), words[1], 55);

            a = op(I, (a, b, c, d), words[8], 56);
            d = op(I, (d, a, b, c), words[15], 57);
            c = op(I, (c, d, a, b), words[6], 58);
            b = op(I, (b, c, d, a), words[13], 59);

            a = op(I, (a, b, c, d), words[4], 60);
            d = op(I, (d, a, b, c), words[11], 61);
            c = op(I, (c, d, a, b), words[2], 62);
            b = op(I, (b, c, d, a), words[9], 63);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5() {
        assert_eq!("73e51861b65c1e83d6136fb6a002585e", hash("tihi xd"));
        assert_eq!("9cdfb439c7876e703e307864c9167a15", hash("lol"));
        assert_eq!("5eb63bbbe01eeed093cb22bb8f5acdc3", hash("hello world"));
        assert_eq!("d41d8cd98f00b204e9800998ecf8427e", hash(""));
        assert_eq!(
            "fd6f92edff2b7db7cd92b494c4926ef0",
            hash("Lorem ipsum dolor sit amet. Nam placeat iste aut dolorem necessitatibus sit unde magni. Nam cumque quia nam fugit quibusdam ut incidunt minima nam dignissimos iusto et voluptatum magnam. Et pariatur eius vel excepturi odit libero sit molestiae consequatur vel nostrum ullam. Sit sint beatae eos doloribus sapiente aut aperiam ullam ut laboriosam debitis! Qui reiciendis rerum est omnis galisum aut similique iure est dolores fuga sit rerum dicta. Aut excepturi fuga et enim ipsum a quia ut velit atque id iste nobis. Non molestiae vero et veritatis aliquam sed enim ducimus. At sunt tempora quo quisquam unde aut ipsum nulla et fugit eius in nulla fugit qui magnam excepturi aut rerum officia. Et officia magnam eos reiciendis voluptatum ea voluptas recusandae in similique enim. Ut provident laudantium ut temporibus eius ut laudantium voluptate aut ducimus impedit. Et asperiores aperiam sit deleniti voluptas ex porro omnis ut voluptas assumenda aut necessitatibus aliquid.")
        );
    }
}
