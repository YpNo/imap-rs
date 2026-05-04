//! Criterion benchmarks for the IMAP response parser.
//!
//! These cover the realistic shapes of frames produced by IMAP4rev2
//! servers: short status responses, capability lists, FETCH with literals
//! and BODYSTRUCTURE, plus the partial-input path so we measure the cost
//! of returning `Incomplete`.

use criterion::{Criterion, criterion_group, criterion_main};
use imap_core::parser::parse_response;
use std::hint::black_box;

fn bench_untagged_ok(c: &mut Criterion) {
    let input = b"* OK IMAP4rev2 Service Ready\r\n";
    c.bench_function("parse_untagged_ok", |b| {
        b.iter(|| parse_response(black_box(input)))
    });
}

fn bench_tagged_ok_with_capability_code(c: &mut Criterion) {
    // The shape returned after a successful LOGIN/AUTHENTICATE on a
    // server that announces caps inline.
    let input = b"A0042 OK [CAPABILITY IMAP4rev2 IDLE MOVE UIDPLUS LITERAL+ ENABLE AUTH=PLAIN] LOGIN completed\r\n";
    c.bench_function("parse_tagged_ok_with_capability_code", |b| {
        b.iter(|| parse_response(black_box(input)))
    });
}

fn bench_capability_data(c: &mut Criterion) {
    let input = b"* CAPABILITY IMAP4rev2 STARTTLS LOGINDISABLED IDLE MOVE UIDPLUS LITERAL+ AUTH=PLAIN AUTH=XOAUTH2\r\n";
    c.bench_function("parse_capability_data", |b| {
        b.iter(|| parse_response(black_box(input)))
    });
}

fn bench_fetch_with_literal(c: &mut Criterion) {
    // Realistic FETCH: BODY[] with a 1 KiB literal, plus UID and FLAGS.
    let mut input = Vec::with_capacity(1100);
    input.extend_from_slice(b"* 42 FETCH (UID 9001 FLAGS (\\Seen) BODY[] {1024}\r\n");
    input.extend_from_slice(&vec![b'a'; 1024]);
    input.extend_from_slice(b")\r\n");
    c.bench_function("parse_fetch_body_literal_1k", |b| {
        b.iter(|| parse_response(black_box(&input)))
    });
}

fn bench_fetch_bodystructure(c: &mut Criterion) {
    let input = b"* 1 FETCH (BODYSTRUCTURE ((\"text\" \"plain\" (\"charset\" \"utf-8\") NIL NIL \"7bit\" 12 1)(\"text\" \"html\" (\"charset\" \"utf-8\") NIL NIL \"quoted-printable\" 256 6) \"alternative\"))\r\n";
    c.bench_function("parse_fetch_bodystructure_multipart", |b| {
        b.iter(|| parse_response(black_box(input)))
    });
}

fn bench_incomplete_fast_path(c: &mut Criterion) {
    // Parser is asked for a frame on a buffer that is one byte short of
    // a complete CRLF — measures the cost of the Incomplete return path.
    let input = b"A1 OK done\r";
    c.bench_function("parse_incomplete_one_byte_short", |b| {
        b.iter(|| parse_response(black_box(input)))
    });
}

criterion_group!(
    benches,
    bench_untagged_ok,
    bench_tagged_ok_with_capability_code,
    bench_capability_data,
    bench_fetch_with_literal,
    bench_fetch_bodystructure,
    bench_incomplete_fast_path
);
criterion_main!(benches);
