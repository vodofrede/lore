# Lore

Hashing algorithms with a straight-forward API and no dependencies.

Nightly toolchain required.

Currently implements:

-   MD2, MD4, and MD5

## Example

```rust
fn main() {
    let input = "lol xd";
    let digest = lore::md5(input);
    assert_eq!(digest, "982d7f24f8985a6baa5cf129acc73561");
}
```
