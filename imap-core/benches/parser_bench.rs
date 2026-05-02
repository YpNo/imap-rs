use criterion::{Criterion, criterion_group, criterion_main};
use imap_core::parser::parse_response;
use std::hint::black_box;

fn bench_parse_ok(c: &mut Criterion) {
    let input = b"* OK IMAP4rev1 Service Ready\r\n";
    c.bench_function("parse_untagged_ok", |b| {
        b.iter(|| parse_response(black_box(input)))
    });
}

fn bench_parse_fetch(c: &mut Criterion) {
    // A more complex example (even if current parser is a stub, we should bench it)
    let input = b"A1 OK FETCH completed\r\n";
    c.bench_function("parse_tagged_ok", |b| {
        b.iter(|| parse_response(black_box(input)))
    });
}

criterion_group!(benches, bench_parse_ok, bench_parse_fetch);
criterion_main!(benches);
