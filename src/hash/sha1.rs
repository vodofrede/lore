use crate::hash::Digest;

/// Computes the SHA1 digest of the input bytes.
///
/// Returns a `Digest<20>` which implements `Display` in order to get at hexadecimal-string representation.
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
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_hash() {}
}
