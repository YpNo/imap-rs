# Security Policy

## Reporting a Vulnerability

We take the security of `imap-rs` seriously. If you believe you have found a security vulnerability, please do NOT file a public issue. Instead, send a private email to:

**ypno+security@gmail.com**

Please include as much information as possible, including:
- A description of the vulnerability.
- Steps to reproduce the issue.
- Potential impact.

We will acknowledge your report within 48 hours and provide a timeline for a fix.

## Supported Versions

Only the latest version of `imap-rs` receives security updates.

## Memory Safety

`imap-rs` is built in 100% safe Rust. We ban the use of `unsafe` and avoid C-FFI by using `rustls` exclusively for TLS.
