use criterion::*;
use lore::md5;

fn md5(c: &mut Criterion) {
    let test = "tihi xd";

    c.bench_function("md5", |b| b.iter(|| md5::hash(black_box(test))));
}

criterion_group!(benches, md5);
criterion_main!(benches);
