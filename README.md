# Lore

Hashing algorithms. Currently only implements md5.

Doesn't use any dependencies.

Performance/stability not guaranteed.

## Example

```rust
use lore::md5;

fn main() {
    let input = "lol xd";
    let digest = md5::hash(input);
    assert_eq!(digest, "982d7f24f8985a6baa5cf129acc73561");
}
```
