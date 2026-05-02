#![no_main]

use libfuzzer_sys::fuzz_target;
use imap_core::parser::parse_response;

fuzz_target!(|data: &[u8]| {
    // The parser should either return Ok, Err(ParseError::*), but MUST NOT panic.
    let _ = parse_response(data);
});
