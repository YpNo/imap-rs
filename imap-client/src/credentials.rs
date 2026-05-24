//! Secret credential wrappers.
//!
//! [`Password`] and [`OAuthToken`] are zeroized on drop and redact their
//! contents in `Debug` output, so secrets are never wiped late or leaked
//! through logging.

use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::ClientError;

/// Secret string memory-wiped on drop and obfuscated in `Debug` output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Password(String);

impl Password {
    /// Wrap a plaintext password. The value is zeroized when the
    /// [`Password`] is dropped.
    pub fn new<S: Into<String>>(pass: S) -> Self {
        Self(pass.into())
    }

    /// Borrow the password as a string slice. Use sparingly — the returned
    /// reference is not zeroized.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Render the password as an IMAP `quoted` string (RFC 9051 §4.3),
    /// escaping the two quoted-specials (`\`, `"`).
    ///
    /// Returns [`ClientError::CommandFailed`] if the secret contains a
    /// character that cannot appear inside a quoted string (`CR`, `LF`,
    /// `NUL`, or any 8-bit byte). Callers facing an 8-bit secret should
    /// use [`Session::authenticate_plain`](crate::session::Session) which
    /// transports the secret as base64 over a SASL exchange.
    pub fn as_imap_quoted(&self) -> Result<String, ClientError> {
        imap_quoted(&self.0)
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"***\"")
    }
}

/// Secure wrapper for OAuth bearer tokens.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OAuthToken(String);

impl OAuthToken {
    /// Wrap an OAuth bearer token. The value is zeroized on drop.
    pub fn new<S: Into<String>>(token: S) -> Self {
        Self(token.into())
    }

    /// Borrow the token as a string slice. Use sparingly — the returned
    /// reference is not zeroized.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"***\"")
    }
}

/// Render `s` as an IMAP quoted string with proper escaping. Errors out
/// when `s` contains a character not permitted inside a quoted string.
pub(crate) fn imap_quoted(s: &str) -> Result<String, ClientError> {
    if s.bytes()
        .any(|b| b == b'\r' || b == b'\n' || b == 0 || b > 0x7F)
    {
        return Err(ClientError::CommandFailed(
            "value contains characters disallowed in IMAP quoted string; \
             use AUTHENTICATE for 8-bit or control-byte values"
                .to_string(),
        ));
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_obfuscation() {
        let pass = Password::new("secret_pass");
        let debug_str = format!("{:?}", pass);
        assert_eq!(debug_str, "\"***\"");
        assert!(!debug_str.contains("secret_pass"));
        assert_eq!(pass.as_str(), "secret_pass");
    }

    #[test]
    fn test_oauth_obfuscation() {
        let token = OAuthToken::new("ya29.token");
        let debug_str = format!("{:?}", token);
        assert_eq!(debug_str, "\"***\"");
        assert!(!debug_str.contains("ya29.token"));
        assert_eq!(token.as_str(), "ya29.token");
    }

    #[test]
    fn test_imap_quoted_basic() {
        assert_eq!(imap_quoted("hello").unwrap(), "\"hello\"");
        assert_eq!(imap_quoted("").unwrap(), "\"\"");
    }

    #[test]
    fn test_imap_quoted_escapes() {
        assert_eq!(imap_quoted("a\"b").unwrap(), "\"a\\\"b\"");
        assert_eq!(imap_quoted("a\\b").unwrap(), "\"a\\\\b\"");
        assert_eq!(imap_quoted("a\\\"b").unwrap(), "\"a\\\\\\\"b\"");
    }

    #[test]
    fn test_imap_quoted_rejects_cr_lf() {
        assert!(imap_quoted("with\rCR").is_err());
        assert!(imap_quoted("with\nLF").is_err());
    }

    #[test]
    fn test_imap_quoted_rejects_nul_and_8bit() {
        assert!(imap_quoted("a\0b").is_err());
        assert!(imap_quoted("café").is_err());
    }

    #[test]
    fn test_password_as_imap_quoted_roundtrip() {
        let p = Password::new("p@ss\"with\\specials");
        assert_eq!(p.as_imap_quoted().unwrap(), "\"p@ss\\\"with\\\\specials\"");
    }
}
