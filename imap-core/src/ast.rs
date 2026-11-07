//! Borrowed AST for IMAP4rev1 / IMAP4rev2 server responses.
//!
//! All `&'a` references point into the original input buffer to preserve
//! the parser's zero-copy contract. Quoted-string escape sequences (`\\`,
//! `\"`) are NOT processed — the raw bytes are returned. Callers that need
//! unescaped values should post-process.
//!
//! `Debug` on [`FetchAttribute`] prints the length of message content
//! (bodies, headers, envelopes, body structures), never the content itself,
//! so logging a response cannot leak an e-mail or the codes it carries.

use core::fmt;

/// A single parsed server response line.
#[derive(Debug, PartialEq, Eq)]
pub enum Response<'a> {
    /// A status response (`OK`, `NO`, `BAD`, `PREAUTH`, `BYE`), tagged or untagged.
    Status(StatusResponse<'a>),
    /// An untagged data response (`CAPABILITY`, `LIST`, `FETCH`, …).
    Data(DataResponse<'a>),
    /// A command-continuation request (`+ …`).
    Continue(ContinueReq<'a>),
}

/// A status response: `<tag|*> <status> [code] text`.
#[derive(Debug, PartialEq, Eq)]
pub struct StatusResponse<'a> {
    /// The command tag this response answers, or `None` for an untagged (`*`) response.
    pub tag: Option<&'a str>,
    /// The status condition (`OK`, `NO`, `BAD`, `PREAUTH`, `BYE`).
    pub status: Status,
    /// Optional machine-readable response code in `[...]`, if present.
    pub code: Option<ResponseCode<'a>>,
    /// Human-readable response text following the status (and code).
    pub text: &'a str,
}

/// The status condition of a [`StatusResponse`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Status {
    /// `OK` — success or informational.
    Ok,
    /// `NO` — operational error; the command failed.
    No,
    /// `BAD` — protocol error; the command was malformed or unexpected.
    Bad,
    /// `PREAUTH` — the connection is already authenticated (greeting only).
    PreAuth,
    /// `BYE` — the server is closing the connection.
    Bye,
}

/// A machine-readable response code carried in `[...]` (RFC 9051 §7.1).
#[derive(Debug, PartialEq, Eq)]
pub enum ResponseCode<'a> {
    /// `ALERT` — text that must be shown to the user.
    Alert,
    /// `BADCHARSET` — the requested charset(s) are unsupported; the list of
    /// charsets the server does support.
    BadCharset(Vec<&'a str>),
    /// `CAPABILITY` — the server's capability list.
    Capability(Vec<&'a str>),
    /// `PARSE` — the server failed to parse a message's header/MIME structure.
    Parse,
    /// `PERMANENTFLAGS` — flags the client can change permanently in the mailbox.
    PermanentFlags(Vec<&'a str>),
    /// `READ-ONLY` — the mailbox was selected read-only.
    ReadOnly,
    /// `READ-WRITE` — the mailbox was selected read-write.
    ReadWrite,
    /// `TRYCREATE` — the target mailbox does not exist; create it and retry.
    TryCreate,
    /// `UIDNEXT` — the predicted next UID value for the mailbox.
    UidNext(u32),
    /// `UIDVALIDITY` — the mailbox's UID validity value.
    UidValidity(u32),
    /// `UNSEEN` — the sequence number of the first unseen message.
    Unseen(u32),
    /// Unrecognized response code: `[ATOM]` or `[ATOM SP rest]`.
    Other(&'a str, Option<&'a str>),
}

/// An untagged data response (`* …`).
#[derive(Debug, PartialEq, Eq)]
pub enum DataResponse<'a> {
    /// `CAPABILITY` — the server's advertised capabilities.
    Capability(Vec<&'a str>),
    /// `LIST` — a mailbox returned by the `LIST` command.
    List {
        /// Mailbox attribute flags (e.g. `\Noselect`, `\HasChildren`).
        flags: Vec<&'a str>,
        /// Hierarchy delimiter, or `None` for a flat namespace (`NIL`).
        delimiter: Option<&'a str>,
        /// The mailbox name.
        name: &'a str,
    },
    /// `LSUB` — a subscribed mailbox returned by the `LSUB` command.
    Lsub {
        /// Mailbox attribute flags.
        flags: Vec<&'a str>,
        /// Hierarchy delimiter, or `None` (`NIL`).
        delimiter: Option<&'a str>,
        /// The mailbox name.
        name: &'a str,
    },
    /// `STATUS` — requested status attributes for a mailbox.
    Status {
        /// The mailbox the status items describe.
        mailbox: &'a str,
        /// The returned status items.
        items: Vec<StatusItem>,
    },
    /// `SEARCH` — message numbers (or UIDs) matching a search.
    Search(Vec<u32>),
    /// `FLAGS` — the flags defined in the selected mailbox.
    Flags(Vec<&'a str>),
    /// `EXISTS` — the number of messages in the mailbox.
    Exists(u32),
    /// `RECENT` — the number of messages with the `\Recent` flag.
    Recent(u32),
    /// `EXPUNGE` — the sequence number of a message that was expunged.
    Expunge(u32),
    /// `FETCH` — message data for a single message.
    Fetch {
        /// The message sequence number.
        seq: u32,
        /// The fetched attributes for this message.
        attributes: Vec<FetchAttribute<'a>>,
    },
    /// Unrecognized untagged data response — the raw line bytes (without CRLF).
    Other(&'a [u8]),
}

/// A single item in a `STATUS` data response.
#[derive(Debug, PartialEq, Eq)]
pub enum StatusItem {
    /// `MESSAGES` — total message count.
    Messages(u32),
    /// `RECENT` — count of `\Recent` messages.
    Recent(u32),
    /// `UIDNEXT` — predicted next UID.
    UidNext(u32),
    /// `UIDVALIDITY` — UID validity value.
    UidValidity(u32),
    /// `UNSEEN` — count of unseen messages.
    Unseen(u32),
    /// RFC 7889 / RFC 9051 — newer attributes we surface but don't decode further.
    Other(u32),
}

/// A single attribute returned in a `FETCH` data response.
///
/// Its `Debug` output replaces message content with its length; see the
/// [module docs](crate::ast).
#[derive(PartialEq, Eq)]
pub enum FetchAttribute<'a> {
    /// `FLAGS` — the flags set on the message.
    Flags(Vec<&'a str>),
    /// `INTERNALDATE` — the server-side receipt timestamp (raw quoted string).
    InternalDate(&'a str),
    /// `RFC822.SIZE` — the message size in octets.
    Rfc822Size(u32),
    /// Full RFC822 message (legacy alias for `BODY[]`).
    Rfc822(&'a [u8]),
    /// `RFC822.HEADER` — the message header (legacy alias for `BODY[HEADER]`).
    Rfc822Header(&'a [u8]),
    /// `RFC822.TEXT` — the message body text (legacy alias for `BODY[TEXT]`).
    Rfc822Text(&'a [u8]),
    /// Parsed-form ENVELOPE bytes (raw, including outer parens).
    Envelope(&'a [u8]),
    /// `BODY` (no section) — non-extensible body structure as raw bytes.
    Body(&'a [u8]),
    /// `BODYSTRUCTURE` — extensible body structure as raw bytes.
    BodyStructure(&'a [u8]),
    /// `BODY[<section>]<<origin>>` with the data as raw bytes.
    BodySection {
        /// The section specifier (e.g. `HEADER`, `1.2.TEXT`), or `None` for `BODY[]`.
        section: Option<&'a str>,
        /// The starting octet offset for a partial (`<origin>`) fetch, if any.
        origin: Option<u32>,
        /// The section data, or `None` if the server returned `NIL`.
        data: Option<&'a [u8]>,
    },
    /// `UID` — the unique identifier of the message.
    Uid(u32),
}

/// `Debug` stand-in for message content: its length, never its bytes.
struct ByteCount(usize);

impl fmt::Debug for ByteCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.0)
    }
}

/// Debug-print a content-carrying tuple variant as `Name(<N bytes>)`.
fn content(f: &mut fmt::Formatter<'_>, name: &str, bytes: &[u8]) -> fmt::Result {
    f.debug_tuple(name).field(&ByteCount(bytes.len())).finish()
}

impl fmt::Debug for FetchAttribute<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flags(flags) => f.debug_tuple("Flags").field(flags).finish(),
            Self::InternalDate(date) => f.debug_tuple("InternalDate").field(date).finish(),
            Self::Rfc822Size(size) => f.debug_tuple("Rfc822Size").field(size).finish(),
            Self::Rfc822(b) => content(f, "Rfc822", b),
            Self::Rfc822Header(b) => content(f, "Rfc822Header", b),
            Self::Rfc822Text(b) => content(f, "Rfc822Text", b),
            Self::Envelope(b) => content(f, "Envelope", b),
            Self::Body(b) => content(f, "Body", b),
            Self::BodyStructure(b) => content(f, "BodyStructure", b),
            Self::BodySection {
                section,
                origin,
                data,
            } => f
                .debug_struct("BodySection")
                .field("section", section)
                .field("origin", origin)
                .field("data", &data.map(|d| ByteCount(d.len())))
                .finish(),
            Self::Uid(uid) => f.debug_tuple("Uid").field(uid).finish(),
        }
    }
}

/// A command-continuation request (`+ [code] text`).
#[derive(Debug, PartialEq, Eq)]
pub struct ContinueReq<'a> {
    /// Optional machine-readable response code in `[...]`, if present.
    pub code: Option<ResponseCode<'a>>,
    /// Human-readable continuation text.
    pub text: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &[u8] = b"Subject: your code\r\n\r\nOTP 483920";

    fn assert_redacted(rendered: &str) {
        assert!(
            !rendered.contains("483920"),
            "payload text leaked: {rendered}"
        );
        // Derived Debug prints a byte slice as decimal values: `[83, 117, …]`.
        assert!(
            !rendered.contains("83, 117"),
            "payload bytes leaked: {rendered}"
        );
        assert!(
            rendered.contains(&format!("<{} bytes>", BODY.len())),
            "{rendered}"
        );
    }

    #[test]
    fn fetch_attribute_debug_prints_payload_length_not_content() {
        for attr in [
            FetchAttribute::Rfc822(BODY),
            FetchAttribute::Rfc822Header(BODY),
            FetchAttribute::Rfc822Text(BODY),
            FetchAttribute::Envelope(BODY),
            FetchAttribute::Body(BODY),
            FetchAttribute::BodyStructure(BODY),
        ] {
            assert_redacted(&format!("{attr:?}"));
        }
    }

    #[test]
    fn body_section_debug_keeps_section_and_origin_but_not_data() {
        let attr = FetchAttribute::BodySection {
            section: Some("TEXT"),
            origin: Some(0),
            data: Some(BODY),
        };
        let rendered = format!("{attr:?}");
        assert_redacted(&rendered);
        assert!(rendered.contains("TEXT") && rendered.contains("origin: Some(0)"));
    }

    #[test]
    fn fetch_response_debug_redacts_nested_attributes() {
        let response = Response::Data(DataResponse::Fetch {
            seq: 1,
            attributes: vec![FetchAttribute::Uid(9), FetchAttribute::Rfc822(BODY)],
        });
        let rendered = format!("{response:?}");
        assert_redacted(&rendered);
        assert!(rendered.contains("Uid(9)"));
    }
}
