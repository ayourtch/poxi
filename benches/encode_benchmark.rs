use criterion::{criterion_group, criterion_main, Criterion};
use scarust::*;

fn test_encode() {
    let p = Ether!().set_src(Value::Random) / IP!().set_dst(Value::Random) / UDP!();
}

fn encode_benchmark(c: &mut Criterion) {
    c.bench_function("encode ether+ip+udp", |b| b.iter(|| test_encode()));
}

criterion_group!(benches, encode_benchmark);
criterion_main!(benches);

