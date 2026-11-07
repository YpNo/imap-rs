//! Minimal RFC 4648 §4 base64 encoder (standard alphabet, padded).
//!
//! The client needs base64 in exactly one place: the `AUTHENTICATE PLAIN`
//! SASL exchange encodes a payload of a few hundred bytes once per login.
//! An in-tree, `unsafe`-free encoder is simpler to audit than tracking a
//! 0.x crate that ships breaking releases and defaults to SIMD code paths
//! this crate does not want.

/// Standard base64 alphabet (RFC 4648 §4, Table 1).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Padding character appended so the output length is a multiple of four.
const PAD: u8 = b'=';

/// Number of input bytes consumed per output quantum.
const INPUT_GROUP: usize = 3;

/// Number of output characters produced per quantum.
const OUTPUT_GROUP: usize = 4;

/// Mask selecting one 6-bit sextet.
const SEXTET_MASK: u32 = 0x3F;

/// Length of the padded base64 encoding of `input_len` bytes:
/// `4 * ceil(input_len / 3)`.
pub(crate) fn encoded_len(input_len: usize) -> usize {
    input_len.div_ceil(INPUT_GROUP) * OUTPUT_GROUP
}

/// Append the standard, padded base64 encoding (RFC 4648 §4) of `input` to
/// `out`. The appended bytes are pure ASCII.
///
/// Writes into a caller-owned buffer so a secret's encoding can live in a
/// buffer that is wiped on drop; reserve [`encoded_len`] bytes first and
/// the buffer never reallocates, so no un-wiped copy is left behind.
pub(crate) fn encode_into(input: &[u8], out: &mut Vec<u8>) {
    let (groups, remainder) = input.as_chunks::<INPUT_GROUP>();
    for &[a, b, c] in groups {
        out.extend_from_slice(&encode_group(a, b, c));
    }
    match *remainder {
        [a] => {
            let [c0, c1, _, _] = encode_group(a, 0, 0);
            out.extend_from_slice(&[c0, c1, PAD, PAD]);
        }
        [a, b] => {
            let [c0, c1, c2, _] = encode_group(a, b, 0);
            out.extend_from_slice(&[c0, c1, c2, PAD]);
        }
        _ => {}
    }
}

/// Encode one 24-bit quantum as four alphabet characters.
fn encode_group(a: u8, b: u8, c: u8) -> [u8; OUTPUT_GROUP] {
    let n = (u32::from(a) << 16) | (u32::from(b) << 8) | u32::from(c);
    [
        ALPHABET[((n >> 18) & SEXTET_MASK) as usize],
        ALPHABET[((n >> 12) & SEXTET_MASK) as usize],
        ALPHABET[((n >> 6) & SEXTET_MASK) as usize],
        ALPHABET[(n & SEXTET_MASK) as usize],
    ]
}

#[cfg(test)]
mod tests {
    use super::{encode_into, encoded_len};

    fn encode(input: &[u8]) -> String {
        let mut out = Vec::with_capacity(encoded_len(input.len()));
        encode_into(input, &mut out);
        String::from_utf8(out).unwrap()
    }

    /// A buffer sized with `encoded_len` is filled exactly, so the encoder
    /// never reallocates and leaves no un-wiped copy of a secret behind.
    #[test]
    fn encode_into_fills_a_presized_buffer_without_growing_it() {
        for input in [
            &b""[..],
            b"f",
            b"fo",
            b"\0user\0correct horse battery staple",
        ] {
            let mut out = Vec::with_capacity(encoded_len(input.len()));
            let capacity = out.capacity();
            encode_into(input, &mut out);
            assert_eq!(out.len(), encoded_len(input.len()));
            assert_eq!(out.capacity(), capacity, "input {input:?}");
        }
    }

    /// RFC 4648 §10 test vectors.
    #[test]
    fn encode_rfc_vectors_match_expected() {
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (input, expected) in cases {
            assert_eq!(encode(input), *expected, "input {:?}", input);
        }
    }

    /// The SASL PLAIN payload shape the session code actually sends.
    #[test]
    fn encode_sasl_plain_payload_matches_known_encoding() {
        assert_eq!(encode(b"\0user\0pass"), "AHVzZXIAcGFzcw==");
    }

    /// Bytes >= 0x80 must be handled as raw octets, not as text.
    #[test]
    fn encode_high_bytes_uses_all_six_bit_groups() {
        assert_eq!(encode(&[0xFF, 0xFF, 0xFF]), "////");
        assert_eq!(encode(&[0x00, 0x00, 0x00]), "AAAA");
        assert_eq!(encode(&[0xFB, 0xFF]), "+/8=");
    }

    /// Output length is always 4 * ceil(n / 3) and uses only alphabet
    /// characters plus trailing padding.
    #[test]
    fn encode_arbitrary_lengths_produces_well_formed_output() {
        for n in 0..64usize {
            let input: Vec<u8> = (0..n).map(|i| (i * 37 % 256) as u8).collect();
            let out = encode(&input);
            assert_eq!(out.len(), n.div_ceil(3) * 4, "length for n={n}");
            let body = out.trim_end_matches('=');
            assert!(
                body.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/'),
                "alphabet for n={n}: {out}"
            );
            assert_eq!(out.len() - body.len(), (3 - n % 3) % 3, "padding for n={n}");
        }
    }
}
