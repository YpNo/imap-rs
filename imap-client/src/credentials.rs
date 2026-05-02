use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure wrapper for passwords ensuring memory is wiped on drop
/// and never printed in Debug logs.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Password(String);

impl Password {
    pub fn new<S: Into<String>>(pass: S) -> Self {
        Self(pass.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"***\"")
    }
}

/// Secure wrapper for OAuth tokens.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct OAuthToken(String);

impl OAuthToken {
    pub fn new<S: Into<String>>(token: S) -> Self {
        Self(token.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OAuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"***\"")
    }
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
    }

    #[test]
    fn test_oauth_obfuscation() {
        let token = OAuthToken::new("ya29.token");
        let debug_str = format!("{:?}", token);
        assert_eq!(debug_str, "\"***\"");
        assert!(!debug_str.contains("ya29.token"));
    }
}
