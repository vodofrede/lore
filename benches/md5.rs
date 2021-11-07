use criterion::*;
use lore::md5;

fn md5(c: &mut Criterion) {
    c.bench_function("md5", |b| {
        b.iter(|| {
            let hash = md5::hash(black_box("tihi xd"));
            hash.to_hex_string();
        })
    });
}

criterion_group!(benches, md5);
criterion_main!(benches);
