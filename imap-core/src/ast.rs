//! Borrowed AST for IMAP4rev1 / IMAP4rev2 server responses.
//!
//! All `&'a` references point into the original input buffer to preserve
//! the parser's zero-copy contract. Quoted-string escape sequences (`\\`,
//! `\"`) are NOT processed — the raw bytes are returned. Callers that need
//! unescaped values should post-process.

#[derive(Debug, PartialEq, Eq)]
pub enum Response<'a> {
    Status(StatusResponse<'a>),
    Data(DataResponse<'a>),
    Continue(ContinueReq<'a>),
}

#[derive(Debug, PartialEq, Eq)]
pub struct StatusResponse<'a> {
    /// `None` means untagged (`*`).
    pub tag: Option<&'a str>,
    pub status: Status,
    pub code: Option<ResponseCode<'a>>,
    pub text: &'a str,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Status {
    Ok,
    No,
    Bad,
    PreAuth,
    Bye,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResponseCode<'a> {
    Alert,
    BadCharset(Vec<&'a str>),
    Capability(Vec<&'a str>),
    Parse,
    PermanentFlags(Vec<&'a str>),
    ReadOnly,
    ReadWrite,
    TryCreate,
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
    /// Unrecognized response code: `[ATOM]` or `[ATOM SP rest]`.
    Other(&'a str, Option<&'a str>),
}

#[derive(Debug, PartialEq, Eq)]
pub enum DataResponse<'a> {
    Capability(Vec<&'a str>),
    List {
        flags: Vec<&'a str>,
        delimiter: Option<&'a str>,
        name: &'a str,
    },
    Lsub {
        flags: Vec<&'a str>,
        delimiter: Option<&'a str>,
        name: &'a str,
    },
    Status {
        mailbox: &'a str,
        items: Vec<StatusItem>,
    },
    Search(Vec<u32>),
    Flags(Vec<&'a str>),
    Exists(u32),
    Recent(u32),
    Expunge(u32),
    Fetch {
        seq: u32,
        attributes: Vec<FetchAttribute<'a>>,
    },
    /// Unrecognized untagged data response — the raw line bytes (without CRLF).
    Other(&'a [u8]),
}

#[derive(Debug, PartialEq, Eq)]
pub enum StatusItem {
    Messages(u32),
    Recent(u32),
    UidNext(u32),
    UidValidity(u32),
    Unseen(u32),
    /// RFC 7889 / RFC 9051 — newer attributes we surface but don't decode further.
    Other(u32),
}

#[derive(Debug, PartialEq, Eq)]
pub enum FetchAttribute<'a> {
    Flags(Vec<&'a str>),
    InternalDate(&'a str),
    Rfc822Size(u32),
    /// Full RFC822 message (legacy alias for `BODY[]`).
    Rfc822(&'a [u8]),
    Rfc822Header(&'a [u8]),
    Rfc822Text(&'a [u8]),
    /// Parsed-form ENVELOPE bytes (raw, including outer parens).
    Envelope(&'a [u8]),
    /// `BODY` (no section) — non-extensible body structure as raw bytes.
    Body(&'a [u8]),
    /// `BODYSTRUCTURE` — extensible body structure as raw bytes.
    BodyStructure(&'a [u8]),
    /// `BODY[<section>]<<origin>>` with the data as raw bytes.
    BodySection {
        section: Option<&'a str>,
        origin: Option<u32>,
        data: Option<&'a [u8]>,
    },
    Uid(u32),
}

#[derive(Debug, PartialEq, Eq)]
pub struct ContinueReq<'a> {
    pub code: Option<ResponseCode<'a>>,
    pub text: &'a str,
}
