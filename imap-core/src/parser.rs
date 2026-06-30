//! Recursive-descent parser for IMAP4rev1 / IMAP4rev2 server responses.
//!
//! The parser operates on a byte slice and returns borrowed AST nodes
//! pointing back into that slice (zero-copy). It is deliberately tolerant
//! of trailing garbage on a line: anything after a recognized response that
//! still ends in CRLF is consumed and the response is returned. This keeps
//! the framer robust against minor server quirks.
//!
//! ## DoS guard
//!
//! Literals (`{n}\r\n`) are capped at [`MAX_LITERAL_SIZE`] to prevent a
//! hostile server from forcing the client to allocate an arbitrarily large
//! buffer. The cap applies to a single literal; pipelined responses are
//! independent.
//!
//! ## Limitations
//!
//! Quoted-string escape sequences (`\\`, `\"`) are not unescaped — the raw
//! bytes are returned. ENVELOPE / BODY / BODYSTRUCTURE are returned as raw
//! parenthesized byte slices for callers to parse on demand.

use crate::ast::{
    ContinueReq, DataResponse, FetchAttribute, Response, ResponseCode, Status, StatusItem,
    StatusResponse,
};
use crate::error::ParseError;

/// Hard cap on a single literal's declared length, in octets.
/// A server attempting to send a larger literal causes the parser to fail
/// with [`ParseError::LiteralTooLarge`] before any buffer growth occurs.
pub const MAX_LITERAL_SIZE: usize = 64 * 1024 * 1024;

/// Result returned by the parser API.
pub type IResult<'a, T> = Result<(&'a [u8], T), ParseError>;

/// Parse a single IMAP server response from `input`.
///
/// Returns the unparsed remainder and the parsed [`Response`]. If `input`
/// does not yet contain a complete response, returns
/// [`ParseError::Incomplete`].
pub fn parse_response(input: &[u8]) -> IResult<'_, Response<'_>> {
    let mut parser = Parser::new(input);
    let response = parser.parse_response()?;
    Ok((parser.remaining(), response))
}

// ---------------------------------------------------------------------------
// Internal parser
// ---------------------------------------------------------------------------

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn remaining(&self) -> &'a [u8] {
        &self.input[self.pos..]
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn peek(&self) -> Result<u8, ParseError> {
        self.input
            .get(self.pos)
            .copied()
            .ok_or(ParseError::Incomplete)
    }

    fn peek_at(&self, offset: usize) -> Result<u8, ParseError> {
        let idx = self.pos.checked_add(offset).ok_or(ParseError::Incomplete)?;
        self.input.get(idx).copied().ok_or(ParseError::Incomplete)
    }

    fn consume_byte(&mut self, b: u8) -> Result<(), ParseError> {
        if self.peek()? == b {
            self.pos += 1;
            Ok(())
        } else {
            Err(ParseError::InvalidChar(self.pos))
        }
    }

    fn try_consume_byte(&mut self, b: u8) -> bool {
        match self.peek() {
            Ok(c) if c == b => {
                self.pos += 1;
                true
            }
            _ => false,
        }
    }

    /// Match `expected` case-insensitively at the current position. Does
    /// not advance.
    fn matches_ci(&self, expected: &[u8]) -> bool {
        let end = match self.pos.checked_add(expected.len()) {
            Some(e) if e <= self.input.len() => e,
            _ => return false,
        };
        self.input[self.pos..end]
            .iter()
            .zip(expected.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    }

    /// Consume `expected` case-insensitively iff the byte after the match
    /// is a token boundary (SP, CR, LF, `]`, `)`, or EOF). This prevents
    /// `OK` from spuriously matching the prefix of `OKAY`.
    fn try_consume_keyword_ci(&mut self, expected: &[u8]) -> bool {
        if !self.matches_ci(expected) {
            return false;
        }
        let next = self.input.get(self.pos + expected.len()).copied();
        let is_boundary = match next {
            None => true,
            Some(b) => matches!(b, b' ' | b'\r' | b'\n' | b']' | b')'),
        };
        if !is_boundary {
            return false;
        }
        self.pos += expected.len();
        true
    }

    fn consume_crlf(&mut self) -> Result<(), ParseError> {
        if self.peek()? != b'\r' {
            return Err(ParseError::Malformed("expected CR"));
        }
        match self.peek_at(1) {
            Ok(b'\n') => {
                self.pos += 2;
                Ok(())
            }
            Ok(_) => Err(ParseError::Malformed("expected LF after CR")),
            Err(_) => Err(ParseError::Incomplete),
        }
    }

    fn consume_sp(&mut self) -> Result<(), ParseError> {
        self.consume_byte(b' ')
    }

    /// Decimal number — `1*DIGIT`, returned as `u32`.
    fn parse_number(&mut self) -> Result<u32, ParseError> {
        let start = self.pos;
        while let Ok(c) = self.peek() {
            if c.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            // No digits consumed — could be EOF or a non-digit.
            if self.is_eof() {
                return Err(ParseError::Incomplete);
            }
            return Err(ParseError::InvalidNumber);
        }
        let bytes = &self.input[start..self.pos];
        // Bytes are ASCII digits — UTF-8 conversion is infallible.
        let s = match core::str::from_utf8(bytes) {
            Ok(s) => s,
            Err(_) => return Err(ParseError::InvalidNumber),
        };
        s.parse::<u32>().map_err(|_| ParseError::InvalidNumber)
    }

    /// Atom — one or more ATOM-CHARs (RFC 9051): any CHAR except atom-specials
    /// (`(`, `)`, `{`, ` `, CTL, list-wildcards `%` `*`, quoted-specials `"` `\`,
    /// resp-specials `]`).
    fn parse_atom(&mut self) -> Result<&'a str, ParseError> {
        let start = self.pos;
        while let Ok(c) = self.peek() {
            if is_atom_char(c) {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            if self.is_eof() {
                return Err(ParseError::Incomplete);
            }
            return Err(ParseError::Malformed("expected atom"));
        }
        let bytes = &self.input[start..self.pos];
        core::str::from_utf8(bytes).map_err(|_| ParseError::Other("Invalid UTF-8"))
    }

    /// Tag — like atom but `+` is also allowed-after-first-position; in
    /// practice servers echo whatever client sent. We accept any non-SP,
    /// non-CR, non-LF, non-`+` first char and the same body.
    fn parse_tag(&mut self) -> Result<&'a str, ParseError> {
        let start = self.pos;
        while let Ok(c) = self.peek() {
            if c == b' ' || c == b'\r' || c == b'\n' {
                break;
            }
            self.pos += 1;
        }
        if start == self.pos {
            if self.is_eof() {
                return Err(ParseError::Incomplete);
            }
            return Err(ParseError::Malformed("expected tag"));
        }
        core::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| ParseError::Other("Invalid UTF-8"))
    }

    /// Quoted string: `"..."`. Returns the byte content between the quotes.
    /// Escape sequences (`\\`, `\"`) are NOT processed.
    fn parse_quoted(&mut self) -> Result<&'a str, ParseError> {
        self.consume_byte(b'"')?;
        let start = self.pos;
        loop {
            let c = self.peek()?;
            match c {
                b'"' => {
                    let s = core::str::from_utf8(&self.input[start..self.pos])
                        .map_err(|_| ParseError::Other("Invalid UTF-8"))?;
                    self.pos += 1;
                    return Ok(s);
                }
                b'\\' => {
                    // Skip the escape and the next char (must be `"` or `\`).
                    self.pos += 1;
                    let _escaped = self.peek()?;
                    self.pos += 1;
                }
                b'\r' | b'\n' => {
                    return Err(ParseError::Malformed("CR/LF inside quoted string"));
                }
                _ => self.pos += 1,
            }
        }
    }

    /// Literal: `{n}\r\n<n octets>`. Returns the n octets as a byte slice.
    fn parse_literal(&mut self) -> Result<&'a [u8], ParseError> {
        self.consume_byte(b'{')?;
        let n = self.parse_number()? as usize;
        self.consume_byte(b'}')?;
        self.consume_crlf()?;
        if n > MAX_LITERAL_SIZE {
            return Err(ParseError::LiteralTooLarge {
                got: n,
                max: MAX_LITERAL_SIZE,
            });
        }
        let end = self.pos.checked_add(n).ok_or(ParseError::Incomplete)?;
        if end > self.input.len() {
            return Err(ParseError::Incomplete);
        }
        let data = &self.input[self.pos..end];
        self.pos = end;
        Ok(data)
    }

    /// `astring` = atom / string. `string` = quoted / literal. We coerce
    /// literals to `&str` via UTF-8 validation; an invalid-UTF-8 literal in
    /// an astring context returns `Invalid UTF-8`.
    fn parse_astring(&mut self) -> Result<&'a str, ParseError> {
        match self.peek()? {
            b'"' => self.parse_quoted(),
            b'{' => {
                let bytes = self.parse_literal()?;
                core::str::from_utf8(bytes).map_err(|_| ParseError::Other("Invalid UTF-8"))
            }
            _ => self.parse_atom(),
        }
    }

    /// `nstring` = string / NIL. Returns `None` for NIL.
    fn parse_nstring(&mut self) -> Result<Option<&'a str>, ParseError> {
        match self.peek()? {
            b'"' => Ok(Some(self.parse_quoted()?)),
            b'{' => {
                let bytes = self.parse_literal()?;
                let s =
                    core::str::from_utf8(bytes).map_err(|_| ParseError::Other("Invalid UTF-8"))?;
                Ok(Some(s))
            }
            _ => {
                if self.try_consume_keyword_ci(b"NIL") {
                    Ok(None)
                } else {
                    Err(ParseError::Malformed("expected nstring"))
                }
            }
        }
    }

    /// Parse a parenthesized atom list, e.g. `(\Seen \Draft)`.
    fn parse_paren_atom_list(&mut self) -> Result<Vec<&'a str>, ParseError> {
        self.consume_byte(b'(')?;
        let mut items = Vec::new();
        if self.try_consume_byte(b')') {
            return Ok(items);
        }
        loop {
            items.push(self.parse_flag_or_atom()?);
            match self.peek()? {
                b' ' => {
                    self.pos += 1;
                }
                b')' => {
                    self.pos += 1;
                    return Ok(items);
                }
                _ => return Err(ParseError::Malformed("expected SP or ) in list")),
            }
        }
    }

    /// A flag is `\<atom>` or just `<atom>` (keyword). For our purposes we
    /// accept either and return the byte string verbatim.
    fn parse_flag_or_atom(&mut self) -> Result<&'a str, ParseError> {
        let start = self.pos;
        if self.peek()? == b'\\' {
            self.pos += 1;
            // `\*` is the special "all keywords" marker permitted in PERMANENTFLAGS.
            if self.try_consume_byte(b'*') {
                return core::str::from_utf8(&self.input[start..self.pos])
                    .map_err(|_| ParseError::Other("Invalid UTF-8"));
            }
        }
        while let Ok(c) = self.peek() {
            if is_atom_char(c) {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            return Err(ParseError::Malformed("expected flag/atom"));
        }
        core::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| ParseError::Other("Invalid UTF-8"))
    }

    /// Parse a balanced parenthesized expression starting at the current
    /// `(`. Returns the slice including the outer parens. Recognizes literals
    /// inside so they aren't accidentally split. Used to capture ENVELOPE /
    /// BODY / BODYSTRUCTURE for downstream parsing.
    fn parse_balanced_parens(&mut self) -> Result<&'a [u8], ParseError> {
        let start = self.pos;
        self.consume_byte(b'(')?;
        let mut depth: u32 = 1;
        while depth > 0 {
            match self.peek()? {
                b'(' => {
                    self.pos += 1;
                    depth = depth
                        .checked_add(1)
                        .ok_or(ParseError::Other("paren depth overflow"))?;
                }
                b')' => {
                    self.pos += 1;
                    depth -= 1;
                }
                b'"' => {
                    self.parse_quoted()?;
                }
                b'{' => {
                    self.parse_literal()?;
                }
                _ => self.pos += 1,
            }
        }
        Ok(&self.input[start..self.pos])
    }

    /// Read the rest of the current line into a `&str`, stopping at CR. Does
    /// not consume the CRLF.
    fn parse_text(&mut self) -> Result<&'a str, ParseError> {
        let start = self.pos;
        while let Ok(c) = self.peek() {
            if c == b'\r' || c == b'\n' {
                break;
            }
            self.pos += 1;
        }
        core::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| ParseError::Other("Invalid UTF-8"))
    }

    // -----------------------------------------------------------------
    // Top-level dispatch
    // -----------------------------------------------------------------

    fn parse_response(&mut self) -> Result<Response<'a>, ParseError> {
        if self.is_eof() {
            return Err(ParseError::Incomplete);
        }
        match self.peek()? {
            b'+' => self.parse_continue_req(),
            b'*' => self.parse_untagged(),
            _ => self.parse_tagged(),
        }
    }

    fn parse_continue_req(&mut self) -> Result<Response<'a>, ParseError> {
        self.consume_byte(b'+')?;
        self.consume_sp()?;
        let (code, text) = self.parse_resp_text()?;
        self.consume_crlf()?;
        Ok(Response::Continue(ContinueReq { code, text }))
    }

    fn parse_untagged(&mut self) -> Result<Response<'a>, ParseError> {
        self.consume_byte(b'*')?;
        self.consume_sp()?;

        // First, try a status keyword (OK / NO / BAD / PREAUTH / BYE).
        if let Some(status) = self.try_parse_status_keyword() {
            let (code, text) = self.parse_resp_text_after_keyword()?;
            self.consume_crlf()?;
            return Ok(Response::Status(StatusResponse {
                tag: None,
                status,
                code,
                text,
            }));
        }

        // Otherwise: a data response. The first token is either a number
        // (FETCH / EXISTS / RECENT / EXPUNGE) or a name.
        if self.peek()?.is_ascii_digit() {
            return self.parse_numeric_data_response();
        }

        self.parse_named_data_response()
    }

    fn parse_tagged(&mut self) -> Result<Response<'a>, ParseError> {
        let tag = self.parse_tag()?;
        self.consume_sp()?;
        let status = match self.try_parse_status_keyword() {
            Some(s) => s,
            None => {
                // The byte after the tag's SP is required to be a status
                // keyword. If the buffer is too short for any keyword, or
                // its prefix matches one (`A0001 O…`), we're incomplete.
                let rem = &self.input[self.pos..];
                if could_be_status_keyword_prefix(rem) {
                    return Err(ParseError::Incomplete);
                }
                return Err(ParseError::Malformed("expected tagged status keyword"));
            }
        };
        let (code, text) = self.parse_resp_text_after_keyword()?;
        self.consume_crlf()?;
        Ok(Response::Status(StatusResponse {
            tag: Some(tag),
            status,
            code,
            text,
        }))
    }

    /// resp-text following a status keyword. RFC requires `SP resp-text`,
    /// but we tolerate the SP being absent if the line ends immediately
    /// (so an incomplete-buffer `A1 OK\r` is reported as Incomplete via
    /// `consume_crlf`, not as InvalidChar).
    fn parse_resp_text_after_keyword(
        &mut self,
    ) -> Result<(Option<ResponseCode<'a>>, &'a str), ParseError> {
        if self.try_consume_byte(b' ') {
            self.parse_resp_text()
        } else {
            // No SP — treat resp-text as empty. `consume_crlf` will catch
            // truncated buffers as Incomplete.
            Ok((None, ""))
        }
    }

    fn try_parse_status_keyword(&mut self) -> Option<Status> {
        // PREAUTH must be checked before generic OK/NO/BAD/BYE because none
        // of those is a prefix of PREAUTH; the boundary-aware keyword match
        // also prevents `OKAY`-style false positives.
        if self.try_consume_keyword_ci(b"PREAUTH") {
            Some(Status::PreAuth)
        } else if self.try_consume_keyword_ci(b"OK") {
            Some(Status::Ok)
        } else if self.try_consume_keyword_ci(b"NO") {
            Some(Status::No)
        } else if self.try_consume_keyword_ci(b"BAD") {
            Some(Status::Bad)
        } else if self.try_consume_keyword_ci(b"BYE") {
            Some(Status::Bye)
        } else {
            None
        }
    }

    /// resp-text = ["[" resp-text-code "]" SP] text
    fn parse_resp_text(&mut self) -> Result<(Option<ResponseCode<'a>>, &'a str), ParseError> {
        let code = if self.try_consume_byte(b'[') {
            let c = self.parse_resp_text_code()?;
            self.consume_byte(b']')?;
            // RFC: SP follows. Some servers omit it when text is empty.
            let _ = self.try_consume_byte(b' ');
            Some(c)
        } else {
            None
        };
        let text = self.parse_text()?;
        Ok((code, text))
    }

    fn parse_resp_text_code(&mut self) -> Result<ResponseCode<'a>, ParseError> {
        // Read the code atom up to `]` or SP.
        let start = self.pos;
        while let Ok(c) = self.peek() {
            if c == b']' || c == b' ' {
                break;
            }
            self.pos += 1;
        }
        if start == self.pos {
            return Err(ParseError::Malformed("empty response code"));
        }
        let atom_bytes = &self.input[start..self.pos];
        let atom =
            core::str::from_utf8(atom_bytes).map_err(|_| ParseError::Other("Invalid UTF-8"))?;

        let code = match () {
            _ if atom.eq_ignore_ascii_case("ALERT") => ResponseCode::Alert,
            _ if atom.eq_ignore_ascii_case("PARSE") => ResponseCode::Parse,
            _ if atom.eq_ignore_ascii_case("READ-ONLY") => ResponseCode::ReadOnly,
            _ if atom.eq_ignore_ascii_case("READ-WRITE") => ResponseCode::ReadWrite,
            _ if atom.eq_ignore_ascii_case("TRYCREATE") => ResponseCode::TryCreate,
            _ if atom.eq_ignore_ascii_case("UIDNEXT") => {
                self.consume_sp()?;
                ResponseCode::UidNext(self.parse_number()?)
            }
            _ if atom.eq_ignore_ascii_case("UIDVALIDITY") => {
                self.consume_sp()?;
                ResponseCode::UidValidity(self.parse_number()?)
            }
            _ if atom.eq_ignore_ascii_case("UNSEEN") => {
                self.consume_sp()?;
                ResponseCode::Unseen(self.parse_number()?)
            }
            _ if atom.eq_ignore_ascii_case("CAPABILITY") => {
                let mut caps = Vec::new();
                while self.try_consume_byte(b' ') {
                    caps.push(self.parse_atom()?);
                }
                ResponseCode::Capability(caps)
            }
            _ if atom.eq_ignore_ascii_case("PERMANENTFLAGS") => {
                self.consume_sp()?;
                ResponseCode::PermanentFlags(self.parse_paren_atom_list()?)
            }
            _ if atom.eq_ignore_ascii_case("BADCHARSET") => {
                let charsets = if self.try_consume_byte(b' ') {
                    self.parse_paren_atom_list()?
                } else {
                    Vec::new()
                };
                ResponseCode::BadCharset(charsets)
            }
            _ => {
                let extra = if self.try_consume_byte(b' ') {
                    let extra_start = self.pos;
                    while let Ok(c) = self.peek() {
                        if c == b']' {
                            break;
                        }
                        self.pos += 1;
                    }
                    let bytes = &self.input[extra_start..self.pos];
                    Some(
                        core::str::from_utf8(bytes)
                            .map_err(|_| ParseError::Other("Invalid UTF-8"))?,
                    )
                } else {
                    None
                };
                ResponseCode::Other(atom, extra)
            }
        };
        Ok(code)
    }

    // -----------------------------------------------------------------
    // Data responses
    // -----------------------------------------------------------------

    fn parse_numeric_data_response(&mut self) -> Result<Response<'a>, ParseError> {
        let n = self.parse_number()?;
        self.consume_sp()?;
        let kind = self.parse_atom()?;
        let resp = if kind.eq_ignore_ascii_case("EXISTS") {
            DataResponse::Exists(n)
        } else if kind.eq_ignore_ascii_case("RECENT") {
            DataResponse::Recent(n)
        } else if kind.eq_ignore_ascii_case("EXPUNGE") {
            DataResponse::Expunge(n)
        } else if kind.eq_ignore_ascii_case("FETCH") {
            self.consume_sp()?;
            let attributes = self.parse_fetch_msg_att()?;
            DataResponse::Fetch { seq: n, attributes }
        } else {
            // Unknown numeric data response — fall back to Other (raw line).
            return self.finish_other_data_with_prefix(n, kind);
        };
        self.consume_crlf()?;
        Ok(Response::Data(resp))
    }

    /// Salvage path for unrecognized numeric data responses: capture the
    /// rest of the line as raw bytes.
    fn finish_other_data_with_prefix(
        &mut self,
        _n: u32,
        _kind: &'a str,
    ) -> Result<Response<'a>, ParseError> {
        // Roll back to the start of the line — we want to capture the whole line.
        // The prefix is already consumed; just continue scanning to CR.
        let line_start = self.find_current_line_start();
        while let Ok(c) = self.peek() {
            if c == b'\r' {
                break;
            }
            self.pos += 1;
        }
        let line = &self.input[line_start..self.pos];
        self.consume_crlf()?;
        Ok(Response::Data(DataResponse::Other(line)))
    }

    fn find_current_line_start(&self) -> usize {
        // Walk backward until we hit a CRLF or input start.
        let mut i = self.pos;
        while i > 0 && !(i >= 2 && &self.input[i - 2..i] == b"\r\n") {
            i -= 1;
        }
        i
    }

    fn parse_named_data_response(&mut self) -> Result<Response<'a>, ParseError> {
        let line_start = self.pos;
        let name = self.parse_atom()?;

        let resp = if name.eq_ignore_ascii_case("CAPABILITY") {
            let mut caps = Vec::new();
            while self.try_consume_byte(b' ') {
                caps.push(self.parse_atom()?);
            }
            DataResponse::Capability(caps)
        } else if name.eq_ignore_ascii_case("LIST") {
            self.consume_sp()?;
            let (flags, delimiter, name) = self.parse_list_lsub_body()?;
            DataResponse::List {
                flags,
                delimiter,
                name,
            }
        } else if name.eq_ignore_ascii_case("LSUB") {
            self.consume_sp()?;
            let (flags, delimiter, name) = self.parse_list_lsub_body()?;
            DataResponse::Lsub {
                flags,
                delimiter,
                name,
            }
        } else if name.eq_ignore_ascii_case("STATUS") {
            self.consume_sp()?;
            let mailbox = self.parse_astring()?;
            self.consume_sp()?;
            let items = self.parse_status_items()?;
            DataResponse::Status { mailbox, items }
        } else if name.eq_ignore_ascii_case("SEARCH") {
            let mut ids = Vec::new();
            while self.try_consume_byte(b' ') {
                ids.push(self.parse_number()?);
            }
            DataResponse::Search(ids)
        } else if name.eq_ignore_ascii_case("FLAGS") {
            self.consume_sp()?;
            DataResponse::Flags(self.parse_paren_atom_list()?)
        } else {
            // Unknown — capture the raw line.
            while let Ok(c) = self.peek() {
                if c == b'\r' {
                    break;
                }
                self.pos += 1;
            }
            let line = &self.input[line_start..self.pos];
            self.consume_crlf()?;
            return Ok(Response::Data(DataResponse::Other(line)));
        };

        self.consume_crlf()?;
        Ok(Response::Data(resp))
    }

    fn parse_list_lsub_body(
        &mut self,
    ) -> Result<(Vec<&'a str>, Option<&'a str>, &'a str), ParseError> {
        let flags = self.parse_paren_atom_list()?;
        self.consume_sp()?;
        let delimiter = self.parse_nstring()?;
        self.consume_sp()?;
        let name = self.parse_astring()?;
        Ok((flags, delimiter, name))
    }

    fn parse_status_items(&mut self) -> Result<Vec<StatusItem>, ParseError> {
        self.consume_byte(b'(')?;
        let mut items = Vec::new();
        if self.try_consume_byte(b')') {
            return Ok(items);
        }
        loop {
            let key = self.parse_atom()?;
            self.consume_sp()?;
            let value = self.parse_number()?;
            items.push(if key.eq_ignore_ascii_case("MESSAGES") {
                StatusItem::Messages(value)
            } else if key.eq_ignore_ascii_case("RECENT") {
                StatusItem::Recent(value)
            } else if key.eq_ignore_ascii_case("UIDNEXT") {
                StatusItem::UidNext(value)
            } else if key.eq_ignore_ascii_case("UIDVALIDITY") {
                StatusItem::UidValidity(value)
            } else if key.eq_ignore_ascii_case("UNSEEN") {
                StatusItem::Unseen(value)
            } else {
                StatusItem::Other(value)
            });
            match self.peek()? {
                b' ' => {
                    self.pos += 1;
                }
                b')' => {
                    self.pos += 1;
                    return Ok(items);
                }
                _ => return Err(ParseError::Malformed("expected SP or ) in STATUS items")),
            }
        }
    }

    // -----------------------------------------------------------------
    // FETCH attributes
    // -----------------------------------------------------------------

    fn parse_fetch_msg_att(&mut self) -> Result<Vec<FetchAttribute<'a>>, ParseError> {
        self.consume_byte(b'(')?;
        let mut atts = Vec::new();
        if self.try_consume_byte(b')') {
            return Ok(atts);
        }
        loop {
            atts.push(self.parse_one_fetch_att()?);
            match self.peek()? {
                b' ' => {
                    self.pos += 1;
                }
                b')' => {
                    self.pos += 1;
                    return Ok(atts);
                }
                _ => return Err(ParseError::Malformed("expected SP or ) in FETCH atts")),
            }
        }
    }

    fn parse_one_fetch_att(&mut self) -> Result<FetchAttribute<'a>, ParseError> {
        let name = self.parse_fetch_att_name()?;

        if name.eq_ignore_ascii_case("UID") {
            self.consume_sp()?;
            return Ok(FetchAttribute::Uid(self.parse_number()?));
        }
        if name.eq_ignore_ascii_case("FLAGS") {
            self.consume_sp()?;
            return Ok(FetchAttribute::Flags(self.parse_paren_atom_list()?));
        }
        if name.eq_ignore_ascii_case("INTERNALDATE") {
            self.consume_sp()?;
            let s = self.parse_quoted()?;
            return Ok(FetchAttribute::InternalDate(s));
        }
        if name.eq_ignore_ascii_case("RFC822.SIZE") {
            self.consume_sp()?;
            return Ok(FetchAttribute::Rfc822Size(self.parse_number()?));
        }
        if name.eq_ignore_ascii_case("RFC822") {
            self.consume_sp()?;
            return Ok(FetchAttribute::Rfc822(self.parse_nstring_bytes()?));
        }
        if name.eq_ignore_ascii_case("RFC822.HEADER") {
            self.consume_sp()?;
            return Ok(FetchAttribute::Rfc822Header(self.parse_nstring_bytes()?));
        }
        if name.eq_ignore_ascii_case("RFC822.TEXT") {
            self.consume_sp()?;
            return Ok(FetchAttribute::Rfc822Text(self.parse_nstring_bytes()?));
        }
        if name.eq_ignore_ascii_case("ENVELOPE") {
            self.consume_sp()?;
            return Ok(FetchAttribute::Envelope(self.parse_balanced_parens()?));
        }
        if name.eq_ignore_ascii_case("BODYSTRUCTURE") {
            self.consume_sp()?;
            return Ok(FetchAttribute::BodyStructure(self.parse_balanced_parens()?));
        }
        if name.eq_ignore_ascii_case("BODY") {
            // Two cases: `BODY <body>` (= non-extensible body structure) or
            // `BODY[<section>]<<origin>> <nstring>`.
            if self.try_consume_byte(b'[') {
                let section = self.read_until_byte(b']')?;
                self.consume_byte(b']')?;
                let origin = if self.try_consume_byte(b'<') {
                    let n = self.parse_number()?;
                    self.consume_byte(b'>')?;
                    Some(n)
                } else {
                    None
                };
                self.consume_sp()?;
                let data = self.parse_nstring_bytes_optional()?;
                return Ok(FetchAttribute::BodySection {
                    section: if section.is_empty() {
                        None
                    } else {
                        Some(section)
                    },
                    origin,
                    data,
                });
            }
            self.consume_sp()?;
            return Ok(FetchAttribute::Body(self.parse_balanced_parens()?));
        }

        // Unknown attribute — try to skip its value gracefully.
        Err(ParseError::Malformed("unknown FETCH attribute"))
    }

    /// FETCH attribute names can include `.` and `[...]`; we read up to a SP.
    fn parse_fetch_att_name(&mut self) -> Result<&'a str, ParseError> {
        let start = self.pos;
        while let Ok(c) = self.peek() {
            if c == b' ' || c == b'[' || c == b')' {
                break;
            }
            self.pos += 1;
        }
        if start == self.pos {
            return Err(ParseError::Malformed("expected FETCH att name"));
        }
        core::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| ParseError::Other("Invalid UTF-8"))
    }

    fn read_until_byte(&mut self, terminator: u8) -> Result<&'a str, ParseError> {
        let start = self.pos;
        while let Ok(c) = self.peek() {
            if c == terminator {
                break;
            }
            if c == b'\r' || c == b'\n' {
                return Err(ParseError::Malformed("CR/LF before terminator"));
            }
            self.pos += 1;
        }
        core::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| ParseError::Other("Invalid UTF-8"))
    }

    /// nstring → byte slice (literal or quoted). NIL becomes an empty slice.
    fn parse_nstring_bytes(&mut self) -> Result<&'a [u8], ParseError> {
        match self.peek()? {
            b'"' => {
                let s = self.parse_quoted()?;
                Ok(s.as_bytes())
            }
            b'{' => self.parse_literal(),
            _ => {
                if self.try_consume_keyword_ci(b"NIL") {
                    Ok(&self.input[self.pos..self.pos])
                } else {
                    Err(ParseError::Malformed("expected nstring"))
                }
            }
        }
    }

    /// Like `parse_nstring_bytes` but returns `None` for NIL.
    fn parse_nstring_bytes_optional(&mut self) -> Result<Option<&'a [u8]>, ParseError> {
        match self.peek()? {
            b'"' => {
                let s = self.parse_quoted()?;
                Ok(Some(s.as_bytes()))
            }
            b'{' => Ok(Some(self.parse_literal()?)),
            _ => {
                if self.try_consume_keyword_ci(b"NIL") {
                    Ok(None)
                } else {
                    Err(ParseError::Malformed("expected nstring"))
                }
            }
        }
    }
}

/// True iff `bytes` is a (possibly empty) case-insensitive prefix of one
/// of the IMAP status keywords. Used to disambiguate Incomplete from
/// Malformed when the parser is sitting at a known keyword position.
fn could_be_status_keyword_prefix(bytes: &[u8]) -> bool {
    const KEYWORDS: &[&[u8]] = &[b"OK", b"NO", b"BAD", b"BYE", b"PREAUTH"];
    for kw in KEYWORDS {
        if bytes.len() < kw.len()
            && kw[..bytes.len()]
                .iter()
                .zip(bytes.iter())
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            return true;
        }
    }
    false
}

/// True if `c` is a valid ATOM-CHAR per RFC 9051 grammar.
fn is_atom_char(c: u8) -> bool {
    !matches!(
        c,
        // CTL: 0x00-0x1F and 0x7F
        0x00..=0x1F | 0x7F | b'(' | b')' | b'{' | b' ' | b'%' | b'*' | b'"' | b'\\' | b']'
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::*;

    fn ok<'a>(input: &'a [u8]) -> Response<'a> {
        let (rem, r) = parse_response(input).unwrap();
        assert_eq!(rem.len(), 0, "non-empty remainder for input {:?}", input);
        r
    }

    // --- Continue ----------------------------------------------------

    #[test]
    fn test_parse_continue() {
        let r = ok(b"+ ready for data\r\n");
        assert_eq!(
            r,
            Response::Continue(ContinueReq {
                code: None,
                text: "ready for data",
            })
        );
    }

    #[test]
    fn test_parse_continue_with_code() {
        let r = ok(b"+ [ALERT] keep going\r\n");
        if let Response::Continue(c) = r {
            assert_eq!(c.code, Some(ResponseCode::Alert));
            assert_eq!(c.text, "keep going");
        } else {
            panic!("expected continue");
        }
    }

    #[test]
    fn test_parse_continue_invalid_utf8() {
        let res = parse_response(b"+ \xFF\r\n");
        assert!(matches!(res, Err(ParseError::Other("Invalid UTF-8"))));
    }

    #[test]
    fn test_parse_continue_expected_crlf() {
        let res = parse_response(b"+ text\rX");
        assert!(matches!(res, Err(ParseError::Malformed(_))));
    }

    // --- Untagged Status --------------------------------------------

    #[test]
    fn test_parse_untagged_ok() {
        let r = ok(b"* OK IMAP4rev1 Service Ready\r\n");
        assert_eq!(
            r,
            Response::Status(StatusResponse {
                tag: None,
                status: Status::Ok,
                code: None,
                text: "IMAP4rev1 Service Ready",
            })
        );
    }

    #[test]
    fn test_parse_untagged_preauth() {
        let r = ok(b"* PREAUTH already authenticated\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.status, Status::PreAuth);
            assert_eq!(s.text, "already authenticated");
        } else {
            panic!("expected status");
        }
    }

    #[test]
    fn test_parse_bye() {
        let r = ok(b"* BYE Logging out\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.status, Status::Bye);
        } else {
            panic!("expected status");
        }
    }

    #[test]
    fn test_parse_untagged_invalid_utf8() {
        let res = parse_response(b"* OK \xFF\r\n");
        assert!(matches!(res, Err(ParseError::Other("Invalid UTF-8"))));
    }

    // --- Response codes ---------------------------------------------

    #[test]
    fn test_parse_resp_code_uidvalidity() {
        let r = ok(b"* OK [UIDVALIDITY 12345] mailbox open\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.code, Some(ResponseCode::UidValidity(12345)));
            assert_eq!(s.text, "mailbox open");
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_resp_code_uidnext_unseen() {
        let r = ok(b"A1 OK [UIDNEXT 7] done\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.code, Some(ResponseCode::UidNext(7)));
            assert_eq!(s.tag, Some("A1"));
            assert_eq!(s.status, Status::Ok);
        } else {
            panic!();
        }
        let r = ok(b"A1 OK [UNSEEN 4] done\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.code, Some(ResponseCode::Unseen(4)));
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_resp_code_alert() {
        let r = ok(b"* OK [ALERT] System down at midnight\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.code, Some(ResponseCode::Alert));
            assert_eq!(s.text, "System down at midnight");
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_resp_code_capability() {
        let r = ok(b"* OK [CAPABILITY IMAP4rev2 STARTTLS LOGIN] hello\r\n");
        if let Response::Status(s) = r {
            assert_eq!(
                s.code,
                Some(ResponseCode::Capability(vec![
                    "IMAP4rev2",
                    "STARTTLS",
                    "LOGIN"
                ]))
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_resp_code_permanentflags() {
        let r = ok(b"* OK [PERMANENTFLAGS (\\Seen \\Draft \\*)] limited\r\n");
        if let Response::Status(s) = r {
            if let Some(ResponseCode::PermanentFlags(flags)) = s.code {
                assert_eq!(flags, vec!["\\Seen", "\\Draft", "\\*"]);
            } else {
                panic!("wrong code");
            }
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_resp_code_read_states() {
        let r = ok(b"A2 OK [READ-WRITE] selected\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.code, Some(ResponseCode::ReadWrite));
        } else {
            panic!();
        }
        let r = ok(b"A3 OK [READ-ONLY] selected\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.code, Some(ResponseCode::ReadOnly));
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_resp_code_other() {
        let r = ok(b"* OK [APPENDUID 12345 6] appended\r\n");
        if let Response::Status(s) = r {
            if let Some(ResponseCode::Other(name, extra)) = s.code {
                assert_eq!(name, "APPENDUID");
                assert_eq!(extra, Some("12345 6"));
            } else {
                panic!();
            }
        } else {
            panic!();
        }
    }

    // --- Tagged status ----------------------------------------------

    #[test]
    fn test_parse_tagged_ok() {
        let r = ok(b"A1 OK LOGIN completed\r\n");
        assert_eq!(
            r,
            Response::Status(StatusResponse {
                tag: Some("A1"),
                status: Status::Ok,
                code: None,
                text: "LOGIN completed",
            })
        );
    }

    #[test]
    fn test_parse_tagged_no() {
        let r = ok(b"A1 NO LOGIN failed\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.status, Status::No);
            assert_eq!(s.text, "LOGIN failed");
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_tagged_bad() {
        let r = ok(b"A1 BAD bad command\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.status, Status::Bad);
        } else {
            panic!();
        }
    }

    // --- Data responses ---------------------------------------------

    #[test]
    fn test_parse_capability_data() {
        let r = ok(b"* CAPABILITY IMAP4rev2 STARTTLS AUTH=PLAIN\r\n");
        if let Response::Data(DataResponse::Capability(caps)) = r {
            assert_eq!(caps, vec!["IMAP4rev2", "STARTTLS", "AUTH=PLAIN"]);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_list() {
        let r = ok(b"* LIST (\\HasNoChildren) \".\" \"INBOX\"\r\n");
        if let Response::Data(DataResponse::List {
            flags,
            delimiter,
            name,
        }) = r
        {
            assert_eq!(flags, vec!["\\HasNoChildren"]);
            assert_eq!(delimiter, Some("."));
            assert_eq!(name, "INBOX");
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_list_nil_delimiter() {
        let r = ok(b"* LIST () NIL \"INBOX\"\r\n");
        if let Response::Data(DataResponse::List {
            flags,
            delimiter,
            name,
        }) = r
        {
            assert!(flags.is_empty());
            assert_eq!(delimiter, None);
            assert_eq!(name, "INBOX");
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_lsub() {
        let r = ok(b"* LSUB (\\Noselect) \"/\" \"foo\"\r\n");
        if let Response::Data(DataResponse::Lsub { flags, .. }) = r {
            assert_eq!(flags, vec!["\\Noselect"]);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_status_response() {
        let r = ok(b"* STATUS \"INBOX\" (MESSAGES 10 RECENT 1 UNSEEN 3)\r\n");
        if let Response::Data(DataResponse::Status { mailbox, items }) = r {
            assert_eq!(mailbox, "INBOX");
            assert_eq!(
                items,
                vec![
                    StatusItem::Messages(10),
                    StatusItem::Recent(1),
                    StatusItem::Unseen(3)
                ]
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_search_empty() {
        let r = ok(b"* SEARCH\r\n");
        if let Response::Data(DataResponse::Search(ids)) = r {
            assert!(ids.is_empty());
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_search_results() {
        let r = ok(b"* SEARCH 1 2 3 42\r\n");
        if let Response::Data(DataResponse::Search(ids)) = r {
            assert_eq!(ids, vec![1, 2, 3, 42]);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_flags() {
        let r = ok(b"* FLAGS (\\Seen \\Draft)\r\n");
        if let Response::Data(DataResponse::Flags(flags)) = r {
            assert_eq!(flags, vec!["\\Seen", "\\Draft"]);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_exists_recent_expunge() {
        if let Response::Data(DataResponse::Exists(n)) = ok(b"* 5 EXISTS\r\n") {
            assert_eq!(n, 5);
        } else {
            panic!();
        }
        if let Response::Data(DataResponse::Recent(n)) = ok(b"* 1 RECENT\r\n") {
            assert_eq!(n, 1);
        } else {
            panic!();
        }
        if let Response::Data(DataResponse::Expunge(n)) = ok(b"* 10 EXPUNGE\r\n") {
            assert_eq!(n, 10);
        } else {
            panic!();
        }
    }

    // --- FETCH attributes -------------------------------------------

    #[test]
    fn test_parse_fetch_flags() {
        let r = ok(b"* 1 FETCH (FLAGS (\\Seen))\r\n");
        if let Response::Data(DataResponse::Fetch { seq, attributes }) = r {
            assert_eq!(seq, 1);
            assert_eq!(attributes, vec![FetchAttribute::Flags(vec!["\\Seen"])]);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_fetch_uid() {
        let r = ok(b"* 1 FETCH (UID 42)\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(attributes, vec![FetchAttribute::Uid(42)]);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_fetch_internaldate() {
        let r = ok(b"* 1 FETCH (INTERNALDATE \"17-Jul-1996 02:44:25 -0700\")\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(
                attributes,
                vec![FetchAttribute::InternalDate("17-Jul-1996 02:44:25 -0700")]
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_fetch_rfc822_size() {
        let r = ok(b"* 2 FETCH (RFC822.SIZE 4242)\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(attributes, vec![FetchAttribute::Rfc822Size(4242)]);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_fetch_body_section_with_literal() {
        let r = ok(b"* 1 FETCH (BODY[] {10}\r\n0123456789)\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(
                attributes,
                vec![FetchAttribute::BodySection {
                    section: None,
                    origin: None,
                    data: Some(b"0123456789".as_ref()),
                }]
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_fetch_body_section_with_section_and_origin() {
        let r = ok(b"* 1 FETCH (BODY[HEADER.FIELDS (FROM TO)]<0> {7}\r\nFrom: a)\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(
                attributes,
                vec![FetchAttribute::BodySection {
                    section: Some("HEADER.FIELDS (FROM TO)"),
                    origin: Some(0),
                    data: Some(b"From: a".as_ref()),
                }]
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_fetch_body_section_nil() {
        let r = ok(b"* 1 FETCH (BODY[] NIL)\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(
                attributes,
                vec![FetchAttribute::BodySection {
                    section: None,
                    origin: None,
                    data: None,
                }]
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_fetch_multi_attrs_with_literal() {
        let r = ok(b"* 1 FETCH (UID 5 BODY[] {3}\r\nabc FLAGS (\\Seen))\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(
                attributes,
                vec![
                    FetchAttribute::Uid(5),
                    FetchAttribute::BodySection {
                        section: None,
                        origin: None,
                        data: Some(b"abc".as_ref()),
                    },
                    FetchAttribute::Flags(vec!["\\Seen"]),
                ]
            );
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_fetch_envelope_raw() {
        let r = ok(
            b"* 1 FETCH (ENVELOPE (\"Date\" \"Subject\" NIL NIL NIL NIL NIL NIL NIL \"<id>\"))\r\n",
        );
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            if let FetchAttribute::Envelope(bytes) = &attributes[0] {
                assert!(bytes.starts_with(b"("));
                assert!(bytes.ends_with(b")"));
            } else {
                panic!("expected envelope");
            }
        } else {
            panic!();
        }
    }

    #[test]
    fn test_parse_fetch_bodystructure_raw() {
        let r = ok(b"* 1 FETCH (BODYSTRUCTURE (\"text\" \"plain\" NIL NIL NIL \"7BIT\" 12))\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert!(matches!(attributes[0], FetchAttribute::BodyStructure(_)));
        } else {
            panic!();
        }
    }

    // --- Incomplete & error paths -----------------------------------

    #[test]
    fn test_parse_empty_input_incomplete() {
        let res = parse_response(b"");
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_incomplete_no_crlf() {
        let res = parse_response(b"* OK ");
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_incomplete_only_cr() {
        let res = parse_response(b"* OK text\r");
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_literal_incomplete() {
        let res = parse_response(b"* 1 FETCH (BODY[] {10}\r\nabc");
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_literal_too_large() {
        // Use a literal length one byte over the cap.
        let s = format!("* 1 FETCH (BODY[] {{{}}}\r\n", MAX_LITERAL_SIZE + 1);
        let res = parse_response(s.as_bytes());
        assert!(matches!(res, Err(ParseError::LiteralTooLarge { .. })));
    }

    #[test]
    fn test_parse_incomplete_tagged_no_space() {
        let res = parse_response(b"A1");
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_incomplete_tagged_no_crlf() {
        let res = parse_response(b"A1 OK\r");
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_missing_lf_after_cr() {
        let res = parse_response(b"* OK text\rX");
        assert!(matches!(res, Err(ParseError::Malformed(_))));
    }

    #[test]
    fn test_parse_unknown_data_falls_back_to_other() {
        let r = ok(b"* WIBBLE foo bar\r\n");
        if let Response::Data(DataResponse::Other(line)) = r {
            assert_eq!(line, b"WIBBLE foo bar");
        } else {
            panic!();
        }
    }

    // --- Trailing remainder -----------------------------------------

    #[test]
    fn test_parse_returns_remainder() {
        let input = b"* OK first\r\n* OK second\r\n";
        let (rem, _) = parse_response(input).unwrap();
        assert_eq!(rem, b"* OK second\r\n");
    }

    // --- Keyword boundary handling ----------------------------------

    #[test]
    fn test_parse_keyword_prefix_not_status() {
        // "OKAY" must NOT be treated as the "OK" status keyword; it falls
        // through to a named data response captured verbatim.
        let r = ok(b"* OKAY all good\r\n");
        if let Response::Data(DataResponse::Other(line)) = r {
            assert_eq!(line, b"OKAY all good");
        } else {
            panic!("expected Other data, got {r:?}");
        }
    }

    // --- CRLF framing errors ----------------------------------------

    #[test]
    fn test_parse_lf_without_cr_is_malformed() {
        // Bare LF (no preceding CR) trips the "expected CR" guard.
        let res = parse_response(b"* OK text\n");
        assert!(matches!(res, Err(ParseError::Malformed("expected CR"))));
    }

    // --- Number parsing edge cases ----------------------------------

    #[test]
    fn test_parse_number_incomplete_at_eof() {
        let res = parse_response(b"* OK [UIDNEXT ");
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_number_invalid_non_digit() {
        let res = parse_response(b"* OK [UIDNEXT x]\r\n");
        assert!(matches!(res, Err(ParseError::InvalidNumber)));
    }

    // --- Atom parsing edge cases ------------------------------------

    #[test]
    fn test_parse_atom_incomplete_at_eof() {
        // Numeric data response truncated right after the SP.
        let res = parse_response(b"* 5 ");
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_atom_malformed_non_atom_char() {
        let res = parse_response(b"* 5 (\r\n");
        assert!(matches!(res, Err(ParseError::Malformed("expected atom"))));
    }

    // --- Tag parsing edge cases -------------------------------------

    #[test]
    fn test_parse_tag_malformed_empty() {
        // First byte is CR: not '+'/'*' so dispatched as tagged, but the tag
        // is empty.
        let res = parse_response(b"\r\n");
        assert!(matches!(res, Err(ParseError::Malformed("expected tag"))));
    }

    // --- Quoted string escapes & control chars ----------------------

    #[test]
    fn test_parse_quoted_with_escape_sequence() {
        // Escaped quote inside the quoted string is passed through raw.
        let r = ok(b"* 1 FETCH (INTERNALDATE \"a\\\"b\")\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(attributes, vec![FetchAttribute::InternalDate("a\\\"b")]);
        } else {
            panic!("expected fetch, got {r:?}");
        }
    }

    #[test]
    fn test_parse_quoted_with_cr_is_malformed() {
        let res = parse_response(b"* 1 FETCH (INTERNALDATE \"a\rb\")\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("CR/LF inside quoted string"))
        ));
    }

    // --- astring / nstring forms ------------------------------------

    #[test]
    fn test_parse_status_mailbox_as_atom() {
        // Unquoted (atom) mailbox name exercises the astring atom path.
        let r = ok(b"* STATUS INBOX (MESSAGES 1)\r\n");
        if let Response::Data(DataResponse::Status { mailbox, .. }) = r {
            assert_eq!(mailbox, "INBOX");
        } else {
            panic!("expected status, got {r:?}");
        }
    }

    #[test]
    fn test_parse_status_mailbox_as_literal() {
        let r = ok(b"* STATUS {5}\r\nINBOX (MESSAGES 1)\r\n");
        if let Response::Data(DataResponse::Status { mailbox, .. }) = r {
            assert_eq!(mailbox, "INBOX");
        } else {
            panic!("expected status, got {r:?}");
        }
    }

    #[test]
    fn test_parse_list_delimiter_as_literal() {
        let r = ok(b"* LIST () {1}\r\n. \"INBOX\"\r\n");
        if let Response::Data(DataResponse::List {
            delimiter, name, ..
        }) = r
        {
            assert_eq!(delimiter, Some("."));
            assert_eq!(name, "INBOX");
        } else {
            panic!("expected list, got {r:?}");
        }
    }

    #[test]
    fn test_parse_list_delimiter_malformed() {
        let res = parse_response(b"* LIST () X \"INBOX\"\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("expected nstring"))
        ));
    }

    // --- Paren atom list edge cases ---------------------------------

    #[test]
    fn test_parse_flag_list_malformed_no_separator() {
        // No SP between flags after the first one is consumed.
        let res = parse_response(b"* FLAGS (\\Seen\\Draft)\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("expected SP or ) in list"))
        ));
    }

    #[test]
    fn test_parse_flag_list_empty_item_malformed() {
        let res = parse_response(b"* FLAGS (()\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("expected flag/atom"))
        ));
    }

    // --- Balanced parens: nesting & literals ------------------------

    #[test]
    fn test_parse_envelope_with_nested_parens_and_literal() {
        let r = ok(b"* 1 FETCH (ENVELOPE ((\"a\") {2}\r\nbc))\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            if let FetchAttribute::Envelope(bytes) = &attributes[0] {
                assert_eq!(*bytes, b"((\"a\") {2}\r\nbc)".as_ref());
            } else {
                panic!("expected envelope, got {attributes:?}");
            }
        } else {
            panic!("expected fetch, got {r:?}");
        }
    }

    // --- Tagged status keyword disambiguation -----------------------

    #[test]
    fn test_parse_tagged_partial_keyword_incomplete() {
        let res = parse_response(b"A1 O");
        assert!(matches!(res, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_parse_tagged_unknown_keyword_malformed() {
        let res = parse_response(b"A1 ZZ done\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("expected tagged status keyword"))
        ));
    }

    // --- Response code edge cases -----------------------------------

    #[test]
    fn test_parse_resp_code_empty_malformed() {
        let res = parse_response(b"* OK [] text\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("empty response code"))
        ));
    }

    #[test]
    fn test_parse_resp_code_badcharset_with_list() {
        let r = ok(b"* NO [BADCHARSET (UTF-8 KOI8-R)] bad charset\r\n");
        if let Response::Status(s) = r {
            assert_eq!(
                s.code,
                Some(ResponseCode::BadCharset(vec!["UTF-8", "KOI8-R"]))
            );
        } else {
            panic!("expected status, got {r:?}");
        }
    }

    #[test]
    fn test_parse_resp_code_badcharset_without_list() {
        let r = ok(b"* NO [BADCHARSET] bad charset\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.code, Some(ResponseCode::BadCharset(vec![])));
        } else {
            panic!("expected status, got {r:?}");
        }
    }

    #[test]
    fn test_parse_resp_code_other_without_extra() {
        let r = ok(b"* NO [NONEXISTENT] gone\r\n");
        if let Response::Status(s) = r {
            assert_eq!(s.code, Some(ResponseCode::Other("NONEXISTENT", None)));
        } else {
            panic!("expected status, got {r:?}");
        }
    }

    // --- Unknown numeric data salvage -------------------------------

    #[test]
    fn test_parse_unknown_numeric_data_falls_back_to_other() {
        let r = ok(b"* 5 WIBBLE foo bar\r\n");
        if let Response::Data(DataResponse::Other(line)) = r {
            assert_eq!(line, b"* 5 WIBBLE foo bar");
        } else {
            panic!("expected Other data, got {r:?}");
        }
    }

    // --- STATUS items -----------------------------------------------

    #[test]
    fn test_parse_status_empty_items() {
        let r = ok(b"* STATUS \"INBOX\" ()\r\n");
        if let Response::Data(DataResponse::Status { items, .. }) = r {
            assert!(items.is_empty());
        } else {
            panic!("expected status, got {r:?}");
        }
    }

    #[test]
    fn test_parse_status_items_uid_and_other() {
        let r = ok(b"* STATUS \"X\" (UIDNEXT 5 UIDVALIDITY 9 HIGHESTMODSEQ 100)\r\n");
        if let Response::Data(DataResponse::Status { items, .. }) = r {
            assert_eq!(
                items,
                vec![
                    StatusItem::UidNext(5),
                    StatusItem::UidValidity(9),
                    StatusItem::Other(100),
                ]
            );
        } else {
            panic!("expected status, got {r:?}");
        }
    }

    #[test]
    fn test_parse_status_items_malformed_separator() {
        let res = parse_response(b"* STATUS \"X\" (MESSAGES 1Z)\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("expected SP or ) in STATUS items"))
        ));
    }

    #[test]
    fn test_parse_status_items_missing_open_paren() {
        // consume_byte('(') fails with InvalidChar.
        let res = parse_response(b"* STATUS \"X\" MESSAGES 1\r\n");
        assert!(matches!(res, Err(ParseError::InvalidChar(_))));
    }

    // --- FETCH attribute list edge cases ----------------------------

    #[test]
    fn test_parse_fetch_empty_attrs() {
        let r = ok(b"* 1 FETCH ()\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert!(attributes.is_empty());
        } else {
            panic!("expected fetch, got {r:?}");
        }
    }

    #[test]
    fn test_parse_fetch_attrs_malformed_separator() {
        let res = parse_response(b"* 1 FETCH (UID 5Z)\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("expected SP or ) in FETCH atts"))
        ));
    }

    #[test]
    fn test_parse_fetch_unknown_attribute_malformed() {
        let res = parse_response(b"* 1 FETCH (FOOBAR 1)\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("unknown FETCH attribute"))
        ));
    }

    #[test]
    fn test_parse_fetch_empty_att_name_malformed() {
        let res = parse_response(b"* 1 FETCH ( )\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("expected FETCH att name"))
        ));
    }

    // --- RFC822 family ----------------------------------------------

    #[test]
    fn test_parse_fetch_rfc822_literal() {
        let r = ok(b"* 1 FETCH (RFC822 {3}\r\nabc)\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(attributes, vec![FetchAttribute::Rfc822(b"abc")]);
        } else {
            panic!("expected fetch, got {r:?}");
        }
    }

    #[test]
    fn test_parse_fetch_rfc822_header_and_text() {
        let r = ok(b"* 1 FETCH (RFC822.HEADER {2}\r\nhi RFC822.TEXT {2}\r\nyo)\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(
                attributes,
                vec![
                    FetchAttribute::Rfc822Header(b"hi"),
                    FetchAttribute::Rfc822Text(b"yo"),
                ]
            );
        } else {
            panic!("expected fetch, got {r:?}");
        }
    }

    #[test]
    fn test_parse_fetch_rfc822_quoted() {
        let r = ok(b"* 1 FETCH (RFC822 \"hi\")\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(attributes, vec![FetchAttribute::Rfc822(b"hi")]);
        } else {
            panic!("expected fetch, got {r:?}");
        }
    }

    #[test]
    fn test_parse_fetch_rfc822_nil() {
        let r = ok(b"* 1 FETCH (RFC822 NIL)\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(attributes, vec![FetchAttribute::Rfc822(b"")]);
        } else {
            panic!("expected fetch, got {r:?}");
        }
    }

    #[test]
    fn test_parse_fetch_rfc822_malformed() {
        let res = parse_response(b"* 1 FETCH (RFC822 Z)\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("expected nstring"))
        ));
    }

    // --- BODY structure (no section) --------------------------------

    #[test]
    fn test_parse_fetch_body_no_section() {
        let r = ok(b"* 1 FETCH (BODY (\"text\" \"plain\" NIL))\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert!(matches!(attributes[0], FetchAttribute::Body(_)));
        } else {
            panic!("expected fetch, got {r:?}");
        }
    }

    #[test]
    fn test_parse_fetch_body_section_quoted_data() {
        let r = ok(b"* 1 FETCH (BODY[] \"hi\")\r\n");
        if let Response::Data(DataResponse::Fetch { attributes, .. }) = r {
            assert_eq!(
                attributes,
                vec![FetchAttribute::BodySection {
                    section: None,
                    origin: None,
                    data: Some(b"hi".as_ref()),
                }]
            );
        } else {
            panic!("expected fetch, got {r:?}");
        }
    }

    #[test]
    fn test_parse_fetch_body_section_malformed_data() {
        let res = parse_response(b"* 1 FETCH (BODY[] Z)\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("expected nstring"))
        ));
    }

    #[test]
    fn test_parse_fetch_body_section_crlf_in_section() {
        let res = parse_response(b"* 1 FETCH (BODY[HE\r\n");
        assert!(matches!(
            res,
            Err(ParseError::Malformed("CR/LF before terminator"))
        ));
    }
}
