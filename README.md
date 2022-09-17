# Lore

Nightly-only hashing algorithms with a straight-forward API and no required dependencies.

This crate currently implements:

-   MD2, MD4, and MD5
-   SHA-1

Performance is not a priority of this crate, rather, the primary purpose of this crate is learning, as well as providing tests for the intermediate steps of algorithms.
This includes padding, checksums and round step functions.

The functions of this crate should probably not be used for production purposes.

Once [`slice::array_chunks`] is stabilized, this crate can be made to work on stable Rust.
The crate could be rewritten to use stable already, but this would increase the verbosity of many expressions.

[`slice::array_chunks`]: https://doc.rust-lang.org/std/primitive.slice.html#method.array_chunks

# Features

[Serde](https://crates.io/crates/serde) support is included, and is gated behind the `serde` feature.

# Examples

Basic usage:

```rust
let input = "lol xd";
let digest = lore::md5(input);
assert_eq!(digest.to_string(), "982d7f24f8985a6baa5cf129acc73561");
```
