use lore::md5;

fn main() {
    let input = "lol xd";

    assert_eq!(
        md5::hash(input).to_hex_string(),
        "982d7f24f8985a6baa5cf129acc73561"
    );
}
