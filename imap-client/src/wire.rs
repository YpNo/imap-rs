//! Validation of caller-supplied values before they are written into an
//! IMAP command line.
//!
//! IMAP is line-oriented: a CR or LF inside a command ends it, and whatever
//! follows becomes another command on the authenticated connection. Values an
//! application may take from its own users (message selectors, fetch items,
//! keywords, search text) are therefore checked against the grammar they are
//! meant to satisfy before they are formatted into a command.

use crate::error::ClientError;
use crate::flags::Flag;

/// Reject a command line containing CR, LF or NUL.
///
/// Applied to every tagged command before it is written, so no caller value
/// can end the current command and start another, whatever path it took.
pub(crate) fn reject_line_breaks(cmd: &str) -> Result<(), ClientError> {
    if cmd.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
        return Err(ClientError::InvalidArgument(
            "command contains CR, LF or NUL",
        ));
    }
    Ok(())
}

/// Validate an RFC 9051 `sequence-set` such as `1:5,7,9:*`.
///
/// Each comma-separated element is a `seq-number` (`*` or a non-zero
/// 32-bit number without leading zeros) or two of them joined by `:`.
///
/// # Errors
/// [`ClientError::InvalidArgument`] when `set` does not match the grammar.
pub(crate) fn sequence_set(set: &str) -> Result<&str, ClientError> {
    if !set.is_empty() && set.split(',').all(is_seq_range) {
        Ok(set)
    } else {
        Err(ClientError::InvalidArgument("sequence set"))
    }
}

fn is_seq_range(range: &str) -> bool {
    let mut ends = range.split(':');
    match (ends.next(), ends.next(), ends.next()) {
        (Some(only), None, None) => is_seq_number(only),
        (Some(from), Some(to), None) => is_seq_number(from) && is_seq_number(to),
        _ => false,
    }
}

fn is_seq_number(number: &str) -> bool {
    number == "*"
        || (!number.starts_with('0')
            && number.bytes().all(|b| b.is_ascii_digit())
            && number.parse::<u32>().is_ok())
}

/// Validate the item list of a `FETCH` command, such as `(FLAGS UID)` or
/// `BODY.PEEK[HEADER.FIELDS (FROM)]`.
///
/// Accepts printable ASCII with balanced `()` and `[]`, and rejects `{`, so
/// no literal can be announced from inside the item list.
///
/// # Errors
/// [`ClientError::InvalidArgument`] when `items` is empty, contains a
/// control or 8-bit byte or `{`, or has unbalanced brackets.
pub(crate) fn fetch_items(items: &str) -> Result<&str, ClientError> {
    let printable = items.bytes().all(|b| is_printable_ascii(b) && b != b'{');
    if !items.is_empty() && printable && has_balanced_brackets(items) {
        Ok(items)
    } else {
        Err(ClientError::InvalidArgument("fetch items"))
    }
}

fn has_balanced_brackets(text: &str) -> bool {
    let mut open = Vec::new();
    for c in text.chars() {
        match c {
            '(' | '[' => open.push(c),
            ')' if open.pop() != Some('(') => return false,
            ']' if open.pop() != Some('[') => return false,
            _ => {}
        }
    }
    open.is_empty()
}

/// Validate a flag for use in a `STORE` flag list.
///
/// System flags are constants and always valid. [`Flag::Custom`] must be a
/// `flag-keyword` or `flag-extension` (RFC 9051 §9): an atom, optionally
/// preceded by a single `\`. Anything else could close the list or add
/// flags the caller did not ask for.
///
/// # Errors
/// [`ClientError::InvalidArgument`] for a custom flag outside that grammar.
pub(crate) fn flag(flag: &Flag) -> Result<(), ClientError> {
    match flag {
        Flag::Custom(keyword) if !is_flag_keyword(keyword) => {
            Err(ClientError::InvalidArgument("flag keyword"))
        }
        _ => Ok(()),
    }
}

fn is_flag_keyword(keyword: &str) -> bool {
    let atom = keyword.strip_prefix('\\').unwrap_or(keyword);
    !atom.is_empty() && atom.bytes().all(is_atom_char)
}

/// `ATOM-CHAR` (RFC 9051 §9): printable ASCII other than SP and the
/// atom-specials `(`, `)`, `{`, `%`, `*`, `"`, `\`, `]`.
fn is_atom_char(b: u8) -> bool {
    is_printable_ascii(b)
        && !matches!(
            b,
            b' ' | b'(' | b')' | b'{' | b'%' | b'*' | b'"' | b'\\' | b']'
        )
}

fn is_printable_ascii(b: u8) -> bool {
    (b' '..=b'~').contains(&b)
}

/// Render `text` as an IMAP quoted string, escaping `"` and `\`.
///
/// Escaping keeps the text inside the string; line breaks are left to
/// [`reject_line_breaks`], which every command passes through.
pub(crate) fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        if matches!(c, '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected<T: std::fmt::Debug>(result: Result<T, ClientError>) -> bool {
        matches!(result, Err(ClientError::InvalidArgument(_)))
    }

    #[test]
    fn reject_line_breaks_with_cr_lf_or_nul_is_rejected() {
        assert!(reject_line_breaks("NOOP").is_ok());
        assert!(reject_line_breaks("SELECT \"INBOX\"").is_ok());
        for bad in ["NOOP\r\nZ1 LOGOUT", "NOOP\nX", "NOOP\rX", "NO\0OP"] {
            assert!(rejected(reject_line_breaks(bad)), "accepted {bad:?}");
        }
    }

    #[test]
    fn sequence_set_valid_forms_are_accepted() {
        for ok in [
            "1",
            "*",
            "1:5",
            "5:1",
            "2:*",
            "*:4",
            "1,3,5",
            "1:3,7,9:*",
            "4294967295",
        ] {
            assert_eq!(sequence_set(ok).ok(), Some(ok), "rejected {ok:?}");
        }
    }

    #[test]
    fn sequence_set_invalid_forms_are_rejected() {
        for bad in [
            "",
            "0",
            "01",
            "1:",
            ":5",
            "1::2",
            "1:2:3",
            "1,,2",
            ",1",
            "1,",
            "1 2",
            "a",
            "-1",
            "4294967296",
            "1\r\nX1 EXPUNGE",
        ] {
            assert!(rejected(sequence_set(bad)), "accepted {bad:?}");
        }
    }

    #[test]
    fn fetch_items_valid_forms_are_accepted() {
        for ok in [
            "ALL",
            "FAST",
            "BODY[]",
            "(FLAGS UID)",
            "BODY[]<0.1024>",
            "BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)]",
            "(UID RFC822.SIZE FLAGS BODY.PEEK[HEADER])",
        ] {
            assert_eq!(fetch_items(ok).ok(), Some(ok), "rejected {ok:?}");
        }
    }

    #[test]
    fn fetch_items_invalid_forms_are_rejected() {
        for bad in [
            "",
            "BODY[] {5}",
            "(FLAGS",
            "FLAGS)",
            "BODY[",
            "BODY]",
            "(BODY[)]",
            "UID\u{1}",
            "UID\tFLAGS",
            "BODY[é]",
            "ALL\r\nX1 EXPUNGE",
        ] {
            assert!(rejected(fetch_items(bad)), "accepted {bad:?}");
        }
    }

    #[test]
    fn flag_system_and_keyword_flags_are_accepted() {
        for f in [
            Flag::Seen,
            Flag::Answered,
            Flag::Flagged,
            Flag::Deleted,
            Flag::Draft,
            Flag::Recent,
        ] {
            assert!(flag(&f).is_ok(), "rejected {f:?}");
        }
        for ok in ["$Forwarded", "Work", "\\Important", "NonJunk"] {
            assert!(flag(&Flag::Custom(ok.into())).is_ok(), "rejected {ok:?}");
        }
    }

    #[test]
    fn flag_keyword_breaking_the_list_is_rejected() {
        for bad in [
            "",
            "a b",
            "x \\Deleted",
            "a)",
            "(a",
            "a\"b",
            "a%",
            "a*",
            "a]",
            "a{3}",
            "\\",
            "\\\\x",
            "é",
            "a\r\nZ1 EXPUNGE",
        ] {
            assert!(
                rejected(flag(&Flag::Custom(bad.into()))),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn quote_escapes_quoted_specials() {
        assert_eq!(quote("alice"), "\"alice\"");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote("x\" OR ALL DELETED"), "\"x\\\" OR ALL DELETED\"");
    }
}
