#![no_main]

use imap_core::error::ParseError;
use imap_core::parser::parse_response;
use libfuzzer_sys::fuzz_target;

/// Above this many consumed bytes, check a sample of cut points instead of
/// every one, so a single large input cannot make the run quadratic.
const EXHAUSTIVE_PREFIX_LIMIT: usize = 512;

fuzz_target!(|data: &[u8]| {
    // The parser must never panic, whatever it returns.
    let Ok((rest, _)) = parse_response(data) else {
        return;
    };

    // A successful parse must make progress and return a suffix of the input.
    assert!(rest.len() < data.len(), "Ok without consuming input");
    assert!(data.ends_with(rest), "remainder is not a suffix of the input");

    // Framing contract relied on by the client's read loop: every strict
    // prefix of a complete frame is `Incomplete`, never another error.
    let frame = &data[..data.len() - rest.len()];
    let check = |cut: usize| {
        assert_eq!(
            parse_response(&frame[..cut]).err(),
            Some(ParseError::Incomplete),
            "prefix of length {cut} is not Incomplete"
        );
    };
    if frame.len() <= EXHAUSTIVE_PREFIX_LIMIT {
        (0..frame.len()).for_each(check);
    } else {
        [1, frame.len() / 2, frame.len() - 1].into_iter().for_each(check);
    }
});
