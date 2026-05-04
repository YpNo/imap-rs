//! IMAP server capability set.
//!
//! Backed by [`imap_core::parser`] for accuracy: the legacy substring
//! matcher [`Capabilities::parse`] is preserved for callers that hand us
//! a raw response string, but [`Capabilities::from_atoms`] is preferred —
//! it is fed the already-tokenised capability atoms from the parser, so
//! `IMAP4REV2X` no longer false-matches as `IMAP4REV2`.

use imap_core::ast::{DataResponse, Response, ResponseCode};
use imap_core::parser::parse_response;

#[derive(Debug, Clone, Default)]
pub struct Capabilities {
    pub imap4rev1: bool,
    pub imap4rev2: bool,
    pub starttls: bool,
    pub login_disabled: bool,
    pub idle: bool,
    pub unselect: bool,
    pub condstore: bool,
    pub qresync: bool,
    pub move_ext: bool,
    pub uidplus: bool,
    pub literal_plus: bool,
    pub literal_minus: bool,
    pub enable: bool,
    pub auth_plain: bool,
    pub auth_login: bool,
    pub auth_xoauth2: bool,
    pub auth_oauthbearer: bool,
}

impl Capabilities {
    /// Build from a list of capability atoms (e.g. as produced by the
    /// parser's `* CAPABILITY …` data response). Unknown atoms are
    /// ignored.
    pub fn from_atoms<S: AsRef<str>>(atoms: &[S]) -> Self {
        let mut caps = Capabilities::default();
        for a in atoms {
            caps.set_from_atom(a.as_ref());
        }
        caps
    }

    fn set_from_atom(&mut self, atom: &str) {
        let upper = atom.to_ascii_uppercase();
        match upper.as_str() {
            "IMAP4REV1" => self.imap4rev1 = true,
            "IMAP4REV2" => self.imap4rev2 = true,
            "STARTTLS" => self.starttls = true,
            "LOGINDISABLED" => self.login_disabled = true,
            "IDLE" => self.idle = true,
            "UNSELECT" => self.unselect = true,
            "CONDSTORE" => self.condstore = true,
            "QRESYNC" => self.qresync = true,
            "MOVE" => self.move_ext = true,
            "UIDPLUS" => self.uidplus = true,
            "LITERAL+" => self.literal_plus = true,
            "LITERAL-" => self.literal_minus = true,
            "ENABLE" => self.enable = true,
            "AUTH=PLAIN" => self.auth_plain = true,
            "AUTH=LOGIN" => self.auth_login = true,
            "AUTH=XOAUTH2" => self.auth_xoauth2 = true,
            "AUTH=OAUTHBEARER" => self.auth_oauthbearer = true,
            _ => {}
        }
    }

    /// Update from a parsed [`Response`] if it carries capabilities — either
    /// a `* CAPABILITY …` data response or a `[CAPABILITY …]` response code
    /// on a status response. Returns `true` if anything was updated.
    pub fn try_update_from(&mut self, response: &Response<'_>) -> bool {
        match response {
            Response::Data(DataResponse::Capability(caps)) => {
                *self = Capabilities::from_atoms(caps);
                true
            }
            Response::Status(s) => match &s.code {
                Some(ResponseCode::Capability(caps)) => {
                    *self = Capabilities::from_atoms(caps);
                    true
                }
                _ => false,
            },
            _ => false,
        }
    }

    /// Best-effort parse of a raw frame. Returns `Some(caps)` if the bytes
    /// contain a CAPABILITY response (data or response-code); else `None`.
    pub fn from_frame(frame: &[u8]) -> Option<Self> {
        let (_, response) = parse_response(frame).ok()?;
        let mut caps = Capabilities::default();
        if caps.try_update_from(&response) {
            Some(caps)
        } else {
            None
        }
    }

    /// Substring-based parser kept for backward compatibility. Prefer
    /// [`Self::from_atoms`] or [`Self::from_frame`] — those use the real
    /// parser and avoid prefix collisions like `IMAP4REV2X`.
    pub fn parse(response: &str) -> Self {
        // Try the real parser first.
        if let Some(caps) = Capabilities::from_frame(response.as_bytes()) {
            return caps;
        }
        // Fallback: tokenise on whitespace and feed atoms.
        let mut caps = Capabilities::default();
        for atom in response.split_ascii_whitespace() {
            caps.set_from_atom(atom);
        }
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gmail_caps() {
        let cap_str = "* CAPABILITY IMAP4rev1 UNSELECT IDLE NAMESPACE QUOTA ID XLIST MOVE CONDSTORE ENABLE UTF8=ACCEPT\r\n";
        let caps = Capabilities::parse(cap_str);
        assert!(caps.imap4rev1);
        assert!(!caps.imap4rev2);
        assert!(caps.move_ext);
        assert!(caps.condstore);
        assert!(caps.idle);
        assert!(caps.unselect);
        assert!(caps.enable);
    }

    #[test]
    fn test_parse_rev2_caps() {
        let cap_str = "* CAPABILITY IMAP4rev2 MOVE UIDPLUS LITERAL+\r\n";
        let caps = Capabilities::parse(cap_str);
        assert!(caps.imap4rev2);
        assert!(caps.move_ext);
        assert!(caps.uidplus);
        assert!(caps.literal_plus);
    }

    #[test]
    fn test_capabilities_from_atoms() {
        let caps = Capabilities::from_atoms(&["IMAP4REV2", "STARTTLS", "AUTH=PLAIN"]);
        assert!(caps.imap4rev2);
        assert!(caps.starttls);
        assert!(caps.auth_plain);
    }

    #[test]
    fn test_capabilities_from_response_code() {
        // OK response carrying [CAPABILITY ...] response code.
        let frame = b"A1 OK [CAPABILITY IMAP4rev2 STARTTLS] welcome\r\n";
        let caps = Capabilities::from_frame(frame).unwrap();
        assert!(caps.imap4rev2);
        assert!(caps.starttls);
        assert!(!caps.imap4rev1);
    }

    #[test]
    fn test_no_false_prefix_match() {
        // Hypothetical extension that would have tripped the substring matcher.
        let caps = Capabilities::from_atoms(&["IMAP4REV2X"]);
        assert!(!caps.imap4rev2);
    }

    #[test]
    fn test_parse_legacy_string_falls_back() {
        // No CAPABILITY response wrapper — the substring fallback still works.
        let caps = Capabilities::parse("IMAP4rev2 IDLE STARTTLS");
        assert!(caps.imap4rev2);
        assert!(caps.idle);
        assert!(caps.starttls);
    }
}
