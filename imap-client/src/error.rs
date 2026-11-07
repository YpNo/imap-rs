//! Error type for the IMAP client.

use imap_core::error::ParseError;
use thiserror::Error;

/// Errors returned by [`RawClient`](crate::client::RawClient) and
/// [`Session`](crate::session::Session) operations.
#[derive(Error, Debug)]
pub enum ClientError {
    /// An underlying socket I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A server response could not be parsed.
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),
    /// The connection was closed before the operation completed.
    #[error("Connection closed")]
    ConnectionClosed,
    /// A single response frame exceeded the client's in-flight size cap — a
    /// denial-of-service guard against a server that never terminates a frame.
    #[error("response frame exceeded the maximum size of {max} bytes")]
    FrameTooLarge {
        /// The maximum frame size, in bytes, that the client will buffer.
        max: usize,
    },
    /// The server returned a tagged `NO` / `BAD`; the string is its resp-text,
    /// made safe to display by [`ClientError::command_failed`].
    #[error("Command failed: {0}")]
    CommandFailed(String),
    /// A command required a capability the server did not advertise.
    #[error("Capability not supported: {0}")]
    UnsupportedCapability(&'static str),
    /// The command did not receive its tagged response within the timeout.
    #[error("Command timed out")]
    Timeout,
    /// A caller-supplied argument cannot be sent safely: it contains a line
    /// break, or does not match the IMAP grammar it is used in. The string
    /// names the argument; the offending value is never included.
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
}

/// Longest server-supplied text kept in a [`ClientError::CommandFailed`],
/// in characters. Longer text is cut and ends with `…`.
pub const MAX_SERVER_TEXT_CHARS: usize = 512;

/// Stand-in for a character that is unsafe to display.
const REPLACEMENT: char = '\u{FFFD}';

impl ClientError {
    /// [`ClientError::CommandFailed`] built from server-supplied resp-text,
    /// made safe to print: control characters (C0, DEL, C1), line and
    /// paragraph separators, and bidirectional-formatting characters become
    /// U+FFFD, so a hostile server cannot drive the terminal or log viewer
    /// that displays the error, and the text is cut to
    /// [`MAX_SERVER_TEXT_CHARS`].
    pub fn command_failed(text: &str) -> Self {
        let mut safe: String = text
            .chars()
            .take(MAX_SERVER_TEXT_CHARS)
            .map(|c| {
                if is_unsafe_to_display(c) {
                    REPLACEMENT
                } else {
                    c
                }
            })
            .collect();
        if text.chars().nth(MAX_SERVER_TEXT_CHARS).is_some() {
            safe.push('…');
        }
        Self::CommandFailed(safe)
    }
}

/// Whether `c` can change how surrounding text is rendered: controls,
/// line and paragraph separators (shown as line breaks by some log
/// viewers), and bidirectional marks, embeddings, overrides and isolates.
fn is_unsafe_to_display(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{200E}'
                | '\u{200F}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_failed_replaces_terminal_control_characters() {
        let err =
            ClientError::command_failed("\u{1b}[2J\u{1b}[31mFAKE ALERT\u{7}\u{9b}31m\u{202e}txt");
        let shown = err.to_string();
        assert!(
            !shown.chars().any(|c| c.is_control() || c == '\u{202e}'),
            "{shown:?}"
        );
        assert!(shown.contains("FAKE ALERT"), "{shown:?}");
    }

    #[test]
    fn command_failed_replaces_line_separators_and_bidi_marks() {
        // U+2028/U+2029 render as line breaks in some log viewers, letting a
        // server fake a separate log line; the marks reorder nearby text.
        for c in ['\u{2028}', '\u{2029}', '\u{200E}', '\u{200F}', '\u{061C}'] {
            let ClientError::CommandFailed(text) = ClientError::command_failed(&format!("a{c}b"))
            else {
                panic!("expected CommandFailed");
            };
            assert_eq!(text, "a\u{FFFD}b", "U+{:04X}", c as u32);
        }
    }

    #[test]
    fn command_failed_truncates_long_server_text() {
        let err = ClientError::command_failed(&"é".repeat(MAX_SERVER_TEXT_CHARS * 4));
        let ClientError::CommandFailed(text) = err else {
            panic!("expected CommandFailed");
        };
        assert_eq!(text.chars().count(), MAX_SERVER_TEXT_CHARS + 1);
        assert!(text.ends_with('…'));
    }

    #[test]
    fn command_failed_keeps_ordinary_text_unchanged() {
        let ClientError::CommandFailed(text) =
            ClientError::command_failed("[AUTHENTICATIONFAILED] Invalid credentials (Failure)")
        else {
            panic!("expected CommandFailed");
        };
        assert_eq!(text, "[AUTHENTICATIONFAILED] Invalid credentials (Failure)");
    }
}
