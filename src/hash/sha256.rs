use crate::{hash::sha1::pad, Digest};

// based on RFC4634

// 2nd buffer constants
const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Computes the SHA224 hash value (digest) of the input bytes.
///
/// Returns a 28-byte `Digest` which implements `Display` in order to get at hexadecimal-string representation.
///
/// # Examples
///
/// Basic usage:
///
/// ```rust
/// let input = "abc";
/// let digest = lore::sha224(input);
///
/// assert_eq!(digest.to_string(), "")
/// ```
pub fn sha224(message: impl AsRef<[u8]>) -> Digest<28> {
    // the padding step is identical between sha1 and sha224 / sha256, so we re-use it.
    let padded = pad(message);
    todo!()
}

/// Computes the SHA256 hash value (digest) of the input bytes.
///
/// Returns a 32-byte `Digest` which implements `Display` in order to get at hexadecimal-string representation.
///
/// # Examples
///
/// Basic usage:
///
/// ```rust
/// let input = "abc";
/// let digest = lore::sha256(input);
///
/// assert_eq!(digest.to_string(), "")
/// ```
pub fn sha256(message: impl AsRef<[u8]>) -> Digest<32> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha224_hash() {
        assert_eq!(
            sha224("").to_string(),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn sha256_hash() {
        assert_eq!(
            sha256("").to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
