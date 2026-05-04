//! Type-state IMAP session. Compile-time enforcement of valid state
//! transitions plus credential-vs-cleartext separation.
//!
//! ## States
//!
//! | State          | Allowed commands |
//! |----------------|------------------|
//! | Unauthenticated | `STARTTLS` (PlainText only), `LOGIN` / `AUTHENTICATE` (Tls only), `CAPABILITY`, `LOGOUT`, `NOOP` |
//! | Authenticated  | `SELECT` / `EXAMINE`, `LIST`, `LSUB`, `STATUS`, `LOGOUT`, `NOOP`, `CAPABILITY`, `ENABLE` |
//! | Selected       | All Authenticated commands plus `FETCH`, `STORE`, `SEARCH`, `EXPUNGE`, `IDLE`, `CLOSE`, `UNSELECT`, `MOVE` |
//!
//! ## Capability re-fetch
//!
//! Per RFC 3501 §6.1.1 / RFC 9051 §6.2 capabilities MUST be re-evaluated
//! after STARTTLS and after a successful authentication. The session does
//! this automatically: if the server's tagged OK response carries a
//! `[CAPABILITY …]` response code we use it, otherwise we issue an
//! explicit `CAPABILITY` round-trip.

use std::marker::PhantomData;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use tokio::sync::broadcast;

use crate::capabilities::Capabilities;
use crate::client::RawClient;
use crate::credentials::{Password, imap_quoted};
use crate::error::ClientError;
use crate::flags::{Flag, StoreAction};
use crate::idle::IdleHandle;
use crate::search::SearchQuery;

use imap_core::ast::{DataResponse, FetchAttribute, Response};
use imap_core::parser::parse_response;

// --- State markers -----------------------------------------------------

pub struct Unauthenticated;
pub struct Authenticated;
pub struct Selected;

// --- Transport markers -------------------------------------------------

pub struct PlainText;
pub struct Tls;

/// Generic session enforcing compile-time state transitions.
pub struct Session<State, Transport> {
    raw: RawClient,
    pub capabilities: Capabilities,
    _state: PhantomData<State>,
    _transport: PhantomData<Transport>,
}

#[derive(Debug, Clone)]
pub struct FetchResult {
    pub seq: u32,
    pub uid: Option<u32>,
    pub body: Option<Vec<u8>>,
}

// --- State-agnostic helpers --------------------------------------------

impl<S, T> Session<S, T> {
    fn transition_state<NewState>(self) -> Session<NewState, T> {
        Session {
            raw: self.raw,
            capabilities: self.capabilities,
            _state: PhantomData,
            _transport: PhantomData,
        }
    }

    pub fn transition_transport<NewTransport>(self) -> Session<S, NewTransport> {
        Session {
            raw: self.raw,
            capabilities: self.capabilities,
            _state: PhantomData,
            _transport: PhantomData,
        }
    }

    pub fn events(&self) -> broadcast::Receiver<Vec<u8>> {
        self.raw.events()
    }

    /// Issue an explicit `CAPABILITY` command and update the cached set.
    /// Used after STARTTLS and after authentication when the OK response
    /// did not carry a `[CAPABILITY …]` response code.
    pub async fn refresh_capabilities(&mut self) -> Result<(), ClientError> {
        let mut events = self.raw.events();
        let _resp = self.raw.execute_command("CAPABILITY").await?;
        // The CAPABILITY response is broadcast as an untagged data frame.
        while let Ok(event) = events.try_recv() {
            if let Ok((_, response)) = parse_response(&event)
                && self.capabilities.try_update_from(&response)
            {
                return Ok(());
            }
        }
        Ok(())
    }

    /// If `frame` carries a `[CAPABILITY …]` response code, use it; else
    /// issue an explicit `CAPABILITY` round-trip.
    async fn refresh_capabilities_from_frame(&mut self, frame: &[u8]) -> Result<(), ClientError> {
        if let Ok((_, response)) = parse_response(frame)
            && self.capabilities.try_update_from(&response)
        {
            return Ok(());
        }
        self.refresh_capabilities().await
    }
}

impl<T> Session<Unauthenticated, T> {
    pub fn new(raw: RawClient, capabilities: Capabilities) -> Self {
        Self::new_in_state(raw, capabilities)
    }
}

impl<S, T> Session<S, T> {
    pub(crate) fn new_in_state(raw: RawClient, capabilities: Capabilities) -> Self {
        Self {
            raw,
            capabilities,
            _state: PhantomData,
            _transport: PhantomData,
        }
    }

    /// `LOGOUT` is valid in any state; the session is consumed because the
    /// connection is closed afterwards.
    pub async fn logout(mut self) -> Result<(), ClientError> {
        // Server replies `* BYE` (broadcast) then a tagged OK. Both BYE and
        // ConnectionClosed are acceptable outcomes.
        match self.raw.execute_command("LOGOUT").await {
            Ok(_) | Err(ClientError::ConnectionClosed) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// `NOOP` keeps the connection alive and triggers status updates.
    pub async fn noop(&mut self) -> Result<(), ClientError> {
        self.raw.execute_command("NOOP").await.map(|_| ())
    }
}

// --- Unauthenticated/Tls — login & SASL ---------------------------------

impl Session<Unauthenticated, Tls> {
    /// `LOGIN` over TLS. The username and password are sent as IMAP
    /// quoted strings with proper escaping (`"`, `\`).
    ///
    /// Returns [`ClientError::CommandFailed`] if the credentials cannot be
    /// represented as quoted strings (8-bit, control bytes, CR, LF). Use
    /// [`Self::authenticate_plain`] in that case.
    pub async fn login(
        mut self,
        user: &str,
        pass: Password,
    ) -> Result<Session<Authenticated, Tls>, ClientError> {
        let user_q = imap_quoted(user)?;
        let pass_q = pass.as_imap_quoted()?;
        let cmd = format!("LOGIN {} {}", user_q, pass_q);

        let frame = self.raw.execute_command(&cmd).await?;
        self.refresh_capabilities_from_frame(&frame).await?;
        Ok(self.transition_state())
    }

    /// `AUTHENTICATE PLAIN` (RFC 4616). Credentials travel as base64 over
    /// the SASL exchange — no quoting limitations and 8-bit safe.
    pub async fn authenticate_plain(
        mut self,
        user: &str,
        pass: &Password,
    ) -> Result<Session<Authenticated, Tls>, ClientError> {
        if user.as_bytes().contains(&0) {
            return Err(ClientError::CommandFailed(
                "username must not contain NUL".into(),
            ));
        }
        if pass.as_str().as_bytes().contains(&0) {
            return Err(ClientError::CommandFailed(
                "password must not contain NUL".into(),
            ));
        }

        let mut events = self.raw.events();
        let (_tag, reply_rx) = self.raw.send_command_async("AUTHENTICATE PLAIN").await?;

        // Wait for `+ ...` continuation request.
        wait_for_continuation(&mut events, Duration::from_secs(30)).await?;

        // SASL PLAIN: \0<authzid>\0<authcid>\0<password>; we use empty authzid.
        let mut sasl = Vec::with_capacity(2 + user.len() + pass.as_str().len());
        sasl.push(0);
        sasl.extend_from_slice(user.as_bytes());
        sasl.push(0);
        sasl.extend_from_slice(pass.as_str().as_bytes());
        let mut payload = BASE64_STANDARD.encode(&sasl).into_bytes();
        payload.extend_from_slice(b"\r\n");
        self.raw.send_raw(payload).await?;

        let frame = match reply_rx.await {
            Ok(r) => r?,
            Err(_) => return Err(ClientError::ConnectionClosed),
        };
        self.refresh_capabilities_from_frame(&frame).await?;
        Ok(self.transition_state())
    }
}

// --- Authenticated -----------------------------------------------------

impl<T> Session<Authenticated, T> {
    /// `SELECT` — open a mailbox read-write and transition to `Selected`.
    pub async fn select(mut self, mailbox: &str) -> Result<Session<Selected, T>, ClientError> {
        let mb = imap_quoted(mailbox)?;
        let cmd = format!("SELECT {}", mb);
        self.raw.execute_command(&cmd).await?;
        Ok(self.transition_state())
    }

    /// `EXAMINE` — open a mailbox read-only and transition to `Selected`.
    pub async fn examine(mut self, mailbox: &str) -> Result<Session<Selected, T>, ClientError> {
        let mb = imap_quoted(mailbox)?;
        let cmd = format!("EXAMINE {}", mb);
        self.raw.execute_command(&cmd).await?;
        Ok(self.transition_state())
    }

    /// `LIST` — list mailboxes matching `mailbox_mask` under `reference`.
    pub async fn list(
        &mut self,
        reference: &str,
        mailbox_mask: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let cmd = format!(
            "LIST {} {}",
            imap_quoted(reference)?,
            imap_quoted(mailbox_mask)?
        );
        self.raw.execute_command(&cmd).await
    }
}

// --- Selected ----------------------------------------------------------

impl<T> Session<Selected, T> {
    /// `FETCH` returning the raw tagged-response bytes.
    pub async fn fetch_raw(
        &mut self,
        sequence_set: &str,
        items: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let cmd = format!("FETCH {} {}", sequence_set, items);
        self.raw.execute_command(&cmd).await
    }

    /// `FETCH` returning structured [`FetchResult`] entries derived from
    /// the broadcast untagged FETCH frames.
    pub async fn fetch(
        &mut self,
        sequence_set: &str,
        items: &str,
    ) -> Result<Vec<FetchResult>, ClientError> {
        let mut events = self.raw.events();
        let cmd = format!("FETCH {} {}", sequence_set, items);
        let _resp = self.raw.execute_command(&cmd).await?;

        let mut results = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let Ok((_, Response::Data(DataResponse::Fetch { seq, attributes }))) =
                parse_response(&event)
            {
                let mut uid = None;
                let mut body = None;
                for attr in attributes {
                    match attr {
                        FetchAttribute::Uid(u) => uid = Some(u),
                        FetchAttribute::BodySection { data: Some(d), .. } => {
                            body = Some(d.to_vec())
                        }
                        FetchAttribute::Body(b) => body = Some(b.to_vec()),
                        FetchAttribute::Rfc822(b) => body = Some(b.to_vec()),
                        _ => {}
                    }
                }
                results.push(FetchResult { seq, uid, body });
            }
        }
        Ok(results)
    }

    /// Convenience: fetch the body of the first message in `sequence_set`.
    pub async fn fetch_body(&mut self, sequence_set: &str) -> Result<Option<String>, ClientError> {
        let results = self.fetch(sequence_set, "BODY[]").await?;
        if let Some(res) = results.first()
            && let Some(body) = &res.body
        {
            return Ok(Some(String::from_utf8_lossy(body).into_owned()));
        }
        Ok(None)
    }

    pub async fn search(&mut self, query: SearchQuery) -> Result<Vec<u32>, ClientError> {
        self.run_search(&format!("SEARCH {}", query.build())).await
    }

    pub async fn uid_search(&mut self, query: SearchQuery) -> Result<Vec<u32>, ClientError> {
        self.run_search(&format!("UID SEARCH {}", query.build()))
            .await
    }

    async fn run_search(&mut self, cmd: &str) -> Result<Vec<u32>, ClientError> {
        let mut events = self.raw.events();
        let _resp = self.raw.execute_command(cmd).await?;

        let mut all_ids = Vec::new();
        while let Ok(event) = events.try_recv() {
            if let Ok((_, Response::Data(DataResponse::Search(ids)))) = parse_response(&event) {
                all_ids.extend(ids);
            }
        }
        Ok(all_ids)
    }

    pub async fn store(
        &mut self,
        sequence_set: &str,
        action: StoreAction,
        flags: &[Flag],
    ) -> Result<Vec<u8>, ClientError> {
        let flags_str = flags
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let cmd = format!(
            "STORE {} {} ({})",
            sequence_set,
            action.to_imap_prefix(false),
            flags_str
        );
        self.raw.execute_command(&cmd).await
    }

    pub async fn uid_store(
        &mut self,
        uid_set: &str,
        action: StoreAction,
        flags: &[Flag],
    ) -> Result<Vec<u8>, ClientError> {
        let flags_str = flags
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let cmd = format!(
            "UID STORE {} {} ({})",
            uid_set,
            action.to_imap_prefix(false),
            flags_str
        );
        self.raw.execute_command(&cmd).await
    }

    pub async fn expunge(&mut self) -> Result<Vec<u8>, ClientError> {
        self.raw.execute_command("EXPUNGE").await
    }

    /// `CLOSE` — implicitly expunges deleted messages and transitions back
    /// to `Authenticated`.
    pub async fn close_mailbox(mut self) -> Result<Session<Authenticated, T>, ClientError> {
        self.raw.execute_command("CLOSE").await?;
        Ok(self.transition_state())
    }

    /// `UNSELECT` (RFC 3691) — like `CLOSE` but without expunging. Errors
    /// if the server has not advertised the `UNSELECT` capability.
    pub async fn unselect(mut self) -> Result<Session<Authenticated, T>, ClientError> {
        if !self.capabilities.unselect {
            return Err(ClientError::UnsupportedCapability("UNSELECT"));
        }
        self.raw.execute_command("UNSELECT").await?;
        Ok(self.transition_state())
    }

    /// `CHECK` — implementation-defined housekeeping checkpoint.
    pub async fn check(&mut self) -> Result<(), ClientError> {
        self.raw.execute_command("CHECK").await.map(|_| ())
    }

    /// `IDLE` (RFC 2177). Returns an [`IdleHandle`]; call `stop()` on it
    /// to gracefully terminate. Callers must re-issue IDLE at least every
    /// ~28 minutes — see [`crate::idle`] for details.
    pub async fn idle(&mut self) -> Result<IdleHandle, ClientError> {
        if !self.capabilities.idle {
            return Err(ClientError::UnsupportedCapability("IDLE"));
        }
        let mut events = self.raw.events();
        let writer = self.raw.writer();
        let (_tag, reply_rx) = self.raw.send_command_async("IDLE").await?;
        wait_for_continuation(&mut events, Duration::from_secs(30)).await?;
        Ok(IdleHandle::new(writer, reply_rx))
    }

    /// `MOVE` (RFC 6851). Errors if the server has not advertised `MOVE`.
    pub async fn move_messages(
        &mut self,
        sequence_set: &str,
        mailbox: &str,
    ) -> Result<Vec<u8>, ClientError> {
        if !self.capabilities.move_ext {
            return Err(ClientError::UnsupportedCapability("MOVE"));
        }
        let cmd = format!("MOVE {} {}", sequence_set, imap_quoted(mailbox)?);
        self.raw.execute_command(&cmd).await
    }
}

// --- Helpers -----------------------------------------------------------

/// Wait for the next `+ ...` continuation request on the broadcast
/// channel, dropping any other untagged frames in the interim.
async fn wait_for_continuation(
    events: &mut broadcast::Receiver<Vec<u8>>,
    timeout: Duration,
) -> Result<(), ClientError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(ClientError::Timeout);
        }
        match tokio::time::timeout(deadline - now, events.recv()).await {
            Ok(Ok(frame)) => {
                if frame.starts_with(b"+") {
                    return Ok(());
                }
                // Otherwise it's an unrelated untagged frame — keep waiting.
            }
            Ok(Err(broadcast::error::RecvError::Closed)) => {
                return Err(ClientError::ConnectionClosed);
            }
            Ok(Err(broadcast::error::RecvError::Lagged(_))) => {
                // We may have missed the continuation — the dispatcher's
                // bound is generous, but treat lag as a protocol error
                // rather than guessing.
                return Err(ClientError::CommandFailed(
                    "broadcast lagged; continuation may have been missed".into(),
                ));
            }
            Err(_) => return Err(ClientError::Timeout),
        }
    }
}

// --- Tests -------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Flag, SearchQuery, StoreAction, Tls};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    async fn read_cmd_tag(server: &mut tokio::io::DuplexStream) -> String {
        let mut buf = [0u8; 1024];
        let n = server.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned()
    }

    fn unauth_session(client_io: tokio::io::DuplexStream) -> Session<Unauthenticated, Tls> {
        let raw = RawClient::new(client_io);
        Session::<Unauthenticated, Tls>::new_in_state(raw, Capabilities::default())
    }

    fn auth_session(client_io: tokio::io::DuplexStream) -> Session<Authenticated, Tls> {
        let raw = RawClient::new(client_io);
        Session::<Authenticated, Tls>::new_in_state(raw, Capabilities::default())
    }

    fn selected_session(client_io: tokio::io::DuplexStream) -> Session<Selected, Tls> {
        let raw = RawClient::new(client_io);
        Session::<Selected, Tls>::new_in_state(raw, Capabilities::default())
    }

    fn selected_session_with_caps(
        client_io: tokio::io::DuplexStream,
        caps: Capabilities,
    ) -> Session<Selected, Tls> {
        let raw = RawClient::new(client_io);
        Session::<Selected, Tls>::new_in_state(raw, caps)
    }

    #[tokio::test]
    async fn test_session_login() {
        let (client_io, mut server_io) = duplex(1024);
        let session = unauth_session(client_io);

        let login_task =
            tokio::spawn(async move { session.login("user", Password::new("pass")).await });

        // Server reads `A0001 LOGIN "user" "pass"\r\n`
        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(cmd.contains("LOGIN \"user\" \"pass\""));
        let tag = cmd.split_whitespace().next().unwrap().to_owned();

        server_io
            .write_all(
                format!("{} OK [CAPABILITY IMAP4rev2 IDLE] LOGIN completed\r\n", tag).as_bytes(),
            )
            .await
            .unwrap();

        let auth = login_task.await.unwrap().unwrap();
        // No second CAPABILITY round-trip — caps came from the response code.
        assert!(auth.capabilities.imap4rev2);
        assert!(auth.capabilities.idle);
    }

    #[tokio::test]
    async fn test_session_login_falls_back_to_capability_round_trip() {
        let (client_io, mut server_io) = duplex(1024);
        let session = unauth_session(client_io);

        let login_task =
            tokio::spawn(async move { session.login("user", Password::new("pass")).await });

        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} OK LOGIN completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        // Server now sees CAPABILITY round-trip.
        let tag2 = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(b"* CAPABILITY IMAP4rev2 STARTTLS UNSELECT\r\n")
            .await
            .unwrap();
        server_io
            .write_all(format!("{} OK CAPABILITY done\r\n", tag2).as_bytes())
            .await
            .unwrap();

        let auth = login_task.await.unwrap().unwrap();
        assert!(auth.capabilities.imap4rev2);
        assert!(auth.capabilities.unselect);
    }

    #[tokio::test]
    async fn test_login_escapes_quote_and_backslash() {
        let (client_io, mut server_io) = duplex(1024);
        let session = unauth_session(client_io);

        let login_task = tokio::spawn(async move {
            session
                .login("user\"with\\specials", Password::new("p@ss\"\\"))
                .await
        });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]).into_owned();
        // Both quote and backslash must be escaped on the wire.
        assert!(cmd.contains(r#"LOGIN "user\"with\\specials" "p@ss\"\\""#));
        let tag = cmd.split_whitespace().next().unwrap().to_owned();
        // Include [CAPABILITY] response code to skip the explicit refresh.
        server_io
            .write_all(format!("{} OK [CAPABILITY IMAP4rev2] done\r\n", tag).as_bytes())
            .await
            .unwrap();
        let _ = login_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_login_rejects_8bit_password() {
        let (client_io, _server_io) = duplex(1024);
        let session = unauth_session(client_io);
        let r = session.login("user", Password::new("café")).await;
        assert!(matches!(r, Err(ClientError::CommandFailed(_))));
    }

    #[tokio::test]
    async fn test_login_failure() {
        let (client_io, mut server_io) = duplex(1024);
        let session = unauth_session(client_io);
        let task = tokio::spawn(async move { session.login("user", Password::new("pass")).await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} NO authentication failed\r\n", tag).as_bytes())
            .await
            .unwrap();
        match task.await.unwrap() {
            Err(ClientError::CommandFailed(t)) => assert!(t.contains("authentication")),
            _ => panic!("unexpected variant"),
        }
    }

    #[tokio::test]
    async fn test_authenticate_plain() {
        let (client_io, mut server_io) = duplex(1024);
        let session = unauth_session(client_io);
        let task = tokio::spawn(async move {
            session
                .authenticate_plain("user", &Password::new("pass"))
                .await
        });

        // Server sees `A0001 AUTHENTICATE PLAIN\r\n`
        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(cmd.contains("AUTHENTICATE PLAIN"));
        let tag = cmd.split_whitespace().next().unwrap().to_owned();

        // Send continuation
        server_io.write_all(b"+ \r\n").await.unwrap();

        // Read base64 SASL payload
        let n = server_io.read(&mut buf).await.unwrap();
        let payload_b64 = String::from_utf8_lossy(&buf[..n]).trim_end().to_string();
        let payload = base64::engine::general_purpose::STANDARD
            .decode(payload_b64)
            .unwrap();
        assert_eq!(payload, b"\0user\0pass");

        server_io
            .write_all(format!("{} OK [CAPABILITY IMAP4rev2] auth done\r\n", tag).as_bytes())
            .await
            .unwrap();

        let _auth = task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_authenticate_plain_failure() {
        let (client_io, mut server_io) = duplex(1024);
        let session = unauth_session(client_io);
        let task = tokio::spawn(async move {
            session
                .authenticate_plain("user", &Password::new("pass"))
                .await
        });

        let tag = read_cmd_tag(&mut server_io).await;
        server_io.write_all(b"+ \r\n").await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = server_io.read(&mut buf).await.unwrap();
        server_io
            .write_all(format!("{} NO bad creds\r\n", tag).as_bytes())
            .await
            .unwrap();

        assert!(matches!(
            task.await.unwrap(),
            Err(ClientError::CommandFailed(_))
        ));
    }

    #[tokio::test]
    async fn test_session_select() {
        let (client_io, mut server_io) = duplex(1024);
        let session = auth_session(client_io);
        let task = tokio::spawn(async move { session.select("INBOX").await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} OK SELECT completed\r\n", tag).as_bytes())
            .await
            .unwrap();
        let _selected = task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_session_examine() {
        let (client_io, mut server_io) = duplex(1024);
        let session = auth_session(client_io);
        let task = tokio::spawn(async move { session.examine("INBOX").await });
        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(cmd.contains("EXAMINE \"INBOX\""));
        let tag = cmd.split_whitespace().next().unwrap();
        server_io
            .write_all(format!("{} OK EXAMINE completed\r\n", tag).as_bytes())
            .await
            .unwrap();
        let _ = task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_session_select_failure() {
        let (client_io, mut server_io) = duplex(1024);
        let session = auth_session(client_io);
        let task = tokio::spawn(async move { session.select("BadBox").await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} NO no such mailbox\r\n", tag).as_bytes())
            .await
            .unwrap();
        assert!(matches!(
            task.await.unwrap(),
            Err(ClientError::CommandFailed(_))
        ));
    }

    #[tokio::test]
    async fn test_session_logout() {
        let (client_io, mut server_io) = duplex(1024);
        let session = auth_session(client_io);
        let task = tokio::spawn(async move { session.logout().await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io.write_all(b"* BYE goodbye\r\n").await.unwrap();
        server_io
            .write_all(format!("{} OK LOGOUT completed\r\n", tag).as_bytes())
            .await
            .unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_session_noop() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = auth_session(client_io);
        let task = tokio::spawn(async move {
            let r = session.noop().await;
            (session, r)
        });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} OK NOOP done\r\n", tag).as_bytes())
            .await
            .unwrap();
        let (_session, r) = task.await.unwrap();
        r.unwrap();
    }

    #[tokio::test]
    async fn test_session_close() {
        let (client_io, mut server_io) = duplex(1024);
        let session = selected_session(client_io);
        let task = tokio::spawn(async move { session.close_mailbox().await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} OK CLOSE done\r\n", tag).as_bytes())
            .await
            .unwrap();
        let _ = task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_session_unselect_unsupported() {
        let (client_io, _server_io) = duplex(1024);
        let session = selected_session(client_io);
        // Default Capabilities has unselect=false.
        match session.unselect().await {
            Err(ClientError::UnsupportedCapability("UNSELECT")) => {}
            _ => panic!("unexpected variant"),
        }
    }

    #[tokio::test]
    async fn test_session_unselect_supported() {
        let (client_io, mut server_io) = duplex(1024);
        let caps = Capabilities {
            unselect: true,
            ..Default::default()
        };
        let session = selected_session_with_caps(client_io, caps);
        let task = tokio::spawn(async move { session.unselect().await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} OK UNSELECT done\r\n", tag).as_bytes())
            .await
            .unwrap();
        let _ = task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_session_check() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let task = tokio::spawn(async move {
            let r = session.check().await;
            (session, r)
        });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} OK CHECK done\r\n", tag).as_bytes())
            .await
            .unwrap();
        let (_, r) = task.await.unwrap();
        r.unwrap();
    }

    #[tokio::test]
    async fn test_session_idle_unsupported() {
        let (client_io, _server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        match session.idle().await {
            Err(ClientError::UnsupportedCapability("IDLE")) => {}
            _ => panic!("unexpected variant"),
        }
    }

    #[tokio::test]
    async fn test_session_idle_flow() {
        let (client_io, mut server_io) = duplex(1024);
        let caps = Capabilities {
            idle: true,
            ..Default::default()
        };
        let mut session = selected_session_with_caps(client_io, caps);
        let task = tokio::spawn(async move {
            let h = session.idle().await.unwrap();
            (session, h)
        });

        let tag = read_cmd_tag(&mut server_io).await;
        server_io.write_all(b"+ idling\r\n").await.unwrap();

        let (_session, handle) = task.await.unwrap();

        let stop_task = tokio::spawn(async move { handle.stop().await });
        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"DONE\r\n");
        server_io
            .write_all(format!("{} OK IDLE done\r\n", tag).as_bytes())
            .await
            .unwrap();
        stop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_session_search() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let task = tokio::spawn(async move { session.search(SearchQuery::subject("test")).await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io.write_all(b"* SEARCH 1 2 3\r\n").await.unwrap();
        server_io
            .write_all(format!("{} OK SEARCH completed\r\n", tag).as_bytes())
            .await
            .unwrap();
        assert_eq!(task.await.unwrap().unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_session_uid_search() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let task = tokio::spawn(async move { session.uid_search(SearchQuery::subject("t")).await });
        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(cmd.contains("UID SEARCH"));
        let tag = cmd.split_whitespace().next().unwrap();
        server_io.write_all(b"* SEARCH 4 5 6\r\n").await.unwrap();
        server_io
            .write_all(format!("{} OK done\r\n", tag).as_bytes())
            .await
            .unwrap();
        assert_eq!(task.await.unwrap().unwrap(), vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn test_session_search_failure() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let task = tokio::spawn(async move { session.search(SearchQuery::subject("t")).await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} NO failed\r\n", tag).as_bytes())
            .await
            .unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_session_run_search_multiple_events() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let task = tokio::spawn(async move { session.search(SearchQuery::subject("t")).await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io.write_all(b"* SEARCH 1 2\r\n").await.unwrap();
        server_io.write_all(b"* SEARCH 3 4\r\n").await.unwrap();
        server_io
            .write_all(format!("{} OK done\r\n", tag).as_bytes())
            .await
            .unwrap();
        assert_eq!(task.await.unwrap().unwrap(), vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_session_store_and_uid_store() {
        for (kind, expected_prefix) in [("STORE", "STORE"), ("UID STORE", "UID STORE")] {
            let (client_io, mut server_io) = duplex(1024);
            let mut session = selected_session(client_io);
            let task = tokio::spawn(async move {
                if kind == "STORE" {
                    session.store("1", StoreAction::Add, &[Flag::Seen]).await
                } else {
                    session
                        .uid_store("1", StoreAction::Add, &[Flag::Seen])
                        .await
                }
            });
            let mut buf = [0u8; 1024];
            let n = server_io.read(&mut buf).await.unwrap();
            assert!(String::from_utf8_lossy(&buf[..n]).contains(expected_prefix));
            let tag = String::from_utf8_lossy(&buf[..n])
                .split_whitespace()
                .next()
                .unwrap()
                .to_owned();
            server_io
                .write_all(format!("{} OK done\r\n", tag).as_bytes())
                .await
                .unwrap();
            let _ = task.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn test_session_expunge() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let task = tokio::spawn(async move { session.expunge().await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} OK done\r\n", tag).as_bytes())
            .await
            .unwrap();
        let _ = task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_session_move_unsupported() {
        let (client_io, _server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        match session.move_messages("1", "Archive").await {
            Err(ClientError::UnsupportedCapability("MOVE")) => {}
            _ => panic!("unexpected variant"),
        }
    }

    #[tokio::test]
    async fn test_session_move_supported() {
        let (client_io, mut server_io) = duplex(1024);
        let caps = Capabilities {
            move_ext: true,
            ..Default::default()
        };
        let mut session = selected_session_with_caps(client_io, caps);
        let task = tokio::spawn(async move { session.move_messages("1", "Archive").await });
        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(cmd.contains(r#"MOVE 1 "Archive""#));
        let tag = cmd.split_whitespace().next().unwrap();
        server_io
            .write_all(format!("{} OK done\r\n", tag).as_bytes())
            .await
            .unwrap();
        let _ = task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_session_list() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = auth_session(client_io);
        let task = tokio::spawn(async move { session.list("", "*").await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} OK done\r\n", tag).as_bytes())
            .await
            .unwrap();
        let _ = task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_session_list_failure() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = auth_session(client_io);
        let task = tokio::spawn(async move { session.list("", "*").await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} NO failed\r\n", tag).as_bytes())
            .await
            .unwrap();
        assert!(task.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_session_fetch_raw() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let task = tokio::spawn(async move { session.fetch_raw("1", "ALL").await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{} OK done\r\n", tag).as_bytes())
            .await
            .unwrap();
        let _ = task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_session_fetch_structured() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let task = tokio::spawn(async move { session.fetch("1", "BODY[]").await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(b"* 1 FETCH (BODY[] {10}\r\n0123456789 UID 123)\r\n")
            .await
            .unwrap();
        server_io
            .write_all(format!("{} OK done\r\n", tag).as_bytes())
            .await
            .unwrap();
        let results = task.await.unwrap().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].seq, 1);
        assert_eq!(results[0].uid, Some(123));
        assert_eq!(results[0].body.as_deref(), Some(&b"0123456789"[..]));
    }

    #[tokio::test]
    async fn test_session_fetch_body_helper() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let task = tokio::spawn(async move { session.fetch_body("1").await });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(b"* 1 FETCH (BODY[] {10}\r\n0123456789)\r\n")
            .await
            .unwrap();
        server_io
            .write_all(format!("{} OK done\r\n", tag).as_bytes())
            .await
            .unwrap();
        assert_eq!(task.await.unwrap().unwrap(), Some("0123456789".to_string()));
    }

    #[tokio::test]
    async fn test_session_transition_transport() {
        let (client_io, _server_io) = duplex(1024);
        let session = unauth_session(client_io);
        let _ = session.transition_transport::<crate::PlainText>();
    }

    #[tokio::test]
    async fn test_session_events() {
        let (client_io, _server_io) = duplex(1024);
        let session = unauth_session(client_io);
        let _ = session.events();
    }

    #[tokio::test]
    async fn test_refresh_capabilities_explicit() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = unauth_session(client_io);
        let task = tokio::spawn(async move {
            let r = session.refresh_capabilities().await;
            (session, r)
        });
        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(b"* CAPABILITY IMAP4rev2 IDLE\r\n")
            .await
            .unwrap();
        server_io
            .write_all(format!("{} OK done\r\n", tag).as_bytes())
            .await
            .unwrap();
        let (session, r) = task.await.unwrap();
        r.unwrap();
        assert!(session.capabilities.imap4rev2);
        assert!(session.capabilities.idle);
    }
}
