// rust nightly features
#![feature(array_chunks, array_zip)]
// lints
#![deny(missing_docs)]
#![warn(clippy::all, clippy::pedantic, clippy::cargo)]
#![allow(
    clippy::unreadable_literal,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names
)]
// docs
#![doc = include_str!("../README.md")]

mod hash;

pub use hash::md2::md2;
pub use hash::md4::md4;
pub use hash::md5::md5;
pub use hash::sha1::sha1;
pub use hash::sha256::sha224;
pub use hash::sha256::sha256;
pub use hash::sha512::sha384;
pub use hash::sha512::sha512;
pub use hash::Digest;
