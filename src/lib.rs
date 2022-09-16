#![feature(array_chunks)]

mod hash;

pub use hash::md2::hash as md2;
pub use hash::md4::hash as md4;
pub use hash::md5::hash as md5;
