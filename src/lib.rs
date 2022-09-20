// rust nightly features
#![feature(array_chunks)]
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

pub use hash::md2::hash as md2;
pub use hash::md4::hash as md4;
pub use hash::md5::hash as md5;
pub use hash::sha1::hash as sha1;
pub use hash::Digest;
