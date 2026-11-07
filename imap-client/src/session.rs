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

use crate::base64;
use bytes::Bytes;
use tokio::sync::{broadcast, oneshot};

use crate::capabilities::Capabilities;
use crate::client::{CommandStream, RawClient};
use crate::credentials::{Password, imap_quoted};
use crate::error::ClientError;
use crate::flags::{Flag, StoreAction};
use crate::idle::IdleHandle;
use crate::search::SearchQuery;
use crate::wire;

use imap_core::ast::{DataResponse, FetchAttribute, Response};
use imap_core::parser::parse_response;

// --- State markers -----------------------------------------------------

/// Type-state marker: the session has not yet authenticated.
pub struct Unauthenticated;
/// Type-state marker: the session is authenticated but no mailbox is selected.
pub struct Authenticated;
/// Type-state marker: a mailbox is selected and message commands are available.
pub struct Selected;

// --- Transport markers -------------------------------------------------

/// Transport marker: the connection is cleartext (pre-TLS).
pub struct PlainText;
/// Transport marker: the connection is encrypted with TLS.
pub struct Tls;

/// Generic session enforcing compile-time state transitions.
///
/// `State` is one of [`Unauthenticated`], [`Authenticated`], or [`Selected`];
/// `Transport` is [`PlainText`] or [`Tls`]. The type parameters gate which
/// commands are callable — e.g. `LOGIN` only exists on
/// `Session<Unauthenticated, Tls>`.
pub struct Session<State, Transport> {
    raw: RawClient,
    /// Server capabilities known for this session, refreshed after STARTTLS
    /// and after authentication.
    pub capabilities: Capabilities,
    _state: PhantomData<State>,
    _transport: PhantomData<Transport>,
}

/// The decoded result of a `FETCH` for a single message.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// The message sequence number.
    pub seq: u32,
    /// The message UID, if it was included in the fetch.
    pub uid: Option<u32>,
    /// The fetched body bytes (e.g. from `BODY[]`), if requested and present.
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

    /// Re-tag the session's transport type parameter (e.g. `PlainText` → `Tls`
    /// after a STARTTLS upgrade). Performs no I/O.
    pub fn transition_transport<NewTransport>(self) -> Session<S, NewTransport> {
        Session {
            raw: self.raw,
            capabilities: self.capabilities,
            _state: PhantomData,
            _transport: PhantomData,
        }
    }

    /// Subscribe to untagged server frames for this session
    /// (see [`RawClient::events`](crate::client::RawClient::events)).
    pub fn events(&self) -> broadcast::Receiver<Bytes> {
        self.raw.events()
    }

    /// Issue an explicit `CAPABILITY` command and update the cached set.
    /// Used after STARTTLS and after authentication when the OK response
    /// did not carry a `[CAPABILITY …]` response code.
    pub async fn refresh_capabilities(&mut self) -> Result<(), ClientError> {
        let capabilities = &mut self.capabilities;
        self.raw
            .execute_streaming(
                "CAPABILITY",
                Capabilities::is_capability_response,
                |frame| {
                    if let Ok((_, response)) = parse_response(frame) {
                        capabilities.try_update_from(&response);
                    }
                },
            )
            .await?;
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
    /// Wrap a connected [`RawClient`] as a fresh, unauthenticated session with
    /// the given initial capabilities.
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

        let stream = self
            .raw
            .send_command_streaming("AUTHENTICATE PLAIN", is_continuation)
            .await?;
        let reply_rx = await_continuation(stream, self.raw.default_timeout).await?;

        // SASL PLAIN: \0<authzid>\0<authcid>\0<password>; we use empty authzid.
        let mut sasl = Vec::with_capacity(2 + user.len() + pass.as_str().len());
        sasl.push(0);
        sasl.extend_from_slice(user.as_bytes());
        sasl.push(0);
        sasl.extend_from_slice(pass.as_str().as_bytes());
        let mut payload = base64::encode(&sasl).into_bytes();
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
    ///
    /// Returns [`ClientError::InvalidArgument`] without sending anything if `sequence_set` is not a
    /// valid sequence set (`1:5,7,9:*`) or `items` is not a valid FETCH item list (printable ASCII,
    /// balanced `()` / `[]`, no `{`).
    pub async fn fetch_raw(
        &mut self,
        sequence_set: &str,
        items: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let cmd = format!(
            "FETCH {} {}",
            wire::sequence_set(sequence_set)?,
            wire::fetch_items(items)?
        );
        self.raw.execute_command(&cmd).await
    }

    /// `FETCH` returning structured [`FetchResult`] entries derived from
    /// the broadcast untagged FETCH frames.
    ///
    /// Returns [`ClientError::InvalidArgument`] without sending anything if `sequence_set` is not a
    /// valid sequence set or `items` is not a valid FETCH item list.
    pub async fn fetch(
        &mut self,
        sequence_set: &str,
        items: &str,
    ) -> Result<Vec<FetchResult>, ClientError> {
        let cmd = format!(
            "FETCH {} {}",
            wire::sequence_set(sequence_set)?,
            wire::fetch_items(items)?
        );
        let mut results = Vec::new();
        self.raw
            .execute_streaming(&cmd, is_fetch, |frame| {
                if let Some(result) = fetch_result(frame) {
                    results.push(result);
                }
            })
            .await?;
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

    /// `SEARCH` — return the message **sequence numbers** matching `query`.
    ///
    /// Returns [`ClientError::InvalidArgument`] without sending anything if a text criterion in
    /// `query` contains a CR, LF or NUL; quotes and backslashes are escaped.
    pub async fn search(&mut self, query: SearchQuery) -> Result<Vec<u32>, ClientError> {
        self.run_search(&format!("SEARCH {}", query.build())).await
    }

    /// `UID SEARCH` — return the message **UIDs** matching `query`.
    pub async fn uid_search(&mut self, query: SearchQuery) -> Result<Vec<u32>, ClientError> {
        self.run_search(&format!("UID SEARCH {}", query.build()))
            .await
    }

    async fn run_search(&mut self, cmd: &str) -> Result<Vec<u32>, ClientError> {
        let mut all_ids = Vec::new();
        self.raw
            .execute_streaming(cmd, is_search, |frame| {
                if let Ok((_, Response::Data(DataResponse::Search(ids)))) = parse_response(frame) {
                    all_ids.extend(ids);
                }
            })
            .await?;
        Ok(all_ids)
    }

    /// `STORE` — apply a flag `action` (add / remove / set) to the messages in
    /// `sequence_set` (a sequence-number set such as `"1:5"` or `"1,3,5"`).
    ///
    /// Returns [`ClientError::InvalidArgument`] without sending anything if `sequence_set` is not a
    /// valid sequence set, or a [`Flag::Custom`] is not an IMAP keyword (an atom, optionally
    /// prefixed with one `\`).
    pub async fn store(
        &mut self,
        sequence_set: &str,
        action: StoreAction,
        flags: &[Flag],
    ) -> Result<Vec<u8>, ClientError> {
        for flag in flags {
            wire::flag(flag)?;
        }
        let flags_str = flags
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let cmd = format!(
            "STORE {} {} ({})",
            wire::sequence_set(sequence_set)?,
            action.to_imap_prefix(false),
            flags_str
        );
        self.raw.execute_command(&cmd).await
    }

    /// `UID STORE` — like [`store`](Self::store) but addressed by UID set.
    ///
    /// Returns [`ClientError::InvalidArgument`] without sending anything if `uid_set` is not a
    /// valid sequence set or a [`Flag::Custom`] is not an IMAP keyword.
    pub async fn uid_store(
        &mut self,
        uid_set: &str,
        action: StoreAction,
        flags: &[Flag],
    ) -> Result<Vec<u8>, ClientError> {
        for flag in flags {
            wire::flag(flag)?;
        }
        let flags_str = flags
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let cmd = format!(
            "UID STORE {} {} ({})",
            wire::sequence_set(uid_set)?,
            action.to_imap_prefix(false),
            flags_str
        );
        self.raw.execute_command(&cmd).await
    }

    /// `EXPUNGE` — permanently remove messages flagged `\Deleted` from the
    /// selected mailbox.
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
        let writer = self.raw.writer();
        let stream = self
            .raw
            .send_command_streaming("IDLE", is_continuation)
            .await?;
        let reply_rx = await_continuation(stream, self.raw.default_timeout).await?;
        Ok(IdleHandle::new(writer, reply_rx))
    }

    /// `MOVE` (RFC 6851). Errors if the server has not advertised `MOVE`.
    ///
    /// Returns [`ClientError::InvalidArgument`] without sending anything if `sequence_set` is not a
    /// valid sequence set.
    pub async fn move_messages(
        &mut self,
        sequence_set: &str,
        mailbox: &str,
    ) -> Result<Vec<u8>, ClientError> {
        if !self.capabilities.move_ext {
            return Err(ClientError::UnsupportedCapability("MOVE"));
        }
        let cmd = format!(
            "MOVE {} {}",
            wire::sequence_set(sequence_set)?,
            imap_quoted(mailbox)?
        );
        self.raw.execute_command(&cmd).await
    }
}

// --- Helpers -----------------------------------------------------------

fn is_continuation(response: &Response<'_>) -> bool {
    matches!(response, Response::Continue(_))
}

fn is_fetch(response: &Response<'_>) -> bool {
    matches!(response, Response::Data(DataResponse::Fetch { .. }))
}

fn is_search(response: &Response<'_>) -> bool {
    matches!(response, Response::Data(DataResponse::Search(_)))
}

/// Build a [`FetchResult`] from one untagged `FETCH` frame.
fn fetch_result(frame: &[u8]) -> Option<FetchResult> {
    let Ok((_, Response::Data(DataResponse::Fetch { seq, attributes }))) = parse_response(frame)
    else {
        return None;
    };
    let mut uid = None;
    let mut body = None;
    for attr in attributes {
        match attr {
            FetchAttribute::Uid(u) => uid = Some(u),
            FetchAttribute::BodySection { data: Some(d), .. } => body = Some(d.to_vec()),
            FetchAttribute::Body(b) | FetchAttribute::Rfc822(b) => body = Some(b.to_vec()),
            _ => {}
        }
    }
    Some(FetchResult { seq, uid, body })
}

/// Wait for the `+` continuation request of a command sent with an
/// [`is_continuation`] stream, then hand back its tagged-reply receiver.
///
/// If the tagged response arrives first the command has already ended:
/// its `NO`/`BAD` (or connection error) is returned at once, rather than
/// after `timeout`.
async fn await_continuation(
    mut stream: CommandStream,
    timeout: Duration,
) -> Result<oneshot::Receiver<Result<Vec<u8>, ClientError>>, ClientError> {
    match tokio::time::timeout(timeout, stream.next_frame()).await {
        Err(_) => Err(ClientError::Timeout),
        Ok(Some(_continuation)) => Ok(stream.into_reply()),
        Ok(None) => match stream.into_reply().await {
            Ok(Err(e)) => Err(e),
            Ok(Ok(_)) => Err(ClientError::CommandFailed(
                "server completed the command without a continuation request".into(),
            )),
            Err(_) => Err(ClientError::ConnectionClosed),
        },
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

    /// Assert that the client wrote nothing to the server.
    async fn assert_nothing_sent(server: &mut tokio::io::DuplexStream) {
        let mut buf = [0u8; 64];
        let read = tokio::time::timeout(Duration::from_millis(50), server.read(&mut buf)).await;
        assert!(read.is_err(), "client wrote {:?}", read);
    }

    #[tokio::test]
    async fn fetch_raw_with_crlf_in_sequence_set_is_rejected_before_send() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let result = session
            .fetch_raw("1\r\nX1 STORE 1:* +FLAGS (\\Deleted)\r\nX2 EXPUNGE", "ALL")
            .await;
        assert!(
            matches!(result, Err(ClientError::InvalidArgument(_))),
            "{result:?}"
        );
        assert_nothing_sent(&mut server_io).await;
    }

    #[tokio::test]
    async fn fetch_with_literal_marker_in_items_is_rejected_before_send() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let result = session.fetch("1", "BODY[] {20}").await;
        assert!(
            matches!(result, Err(ClientError::InvalidArgument(_))),
            "{result:?}"
        );
        assert_nothing_sent(&mut server_io).await;
    }

    #[tokio::test]
    async fn store_with_flag_list_break_out_is_rejected_before_send() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let result = session
            .store("1", StoreAction::Add, &[Flag::Custom("x \\Deleted".into())])
            .await;
        assert!(
            matches!(result, Err(ClientError::InvalidArgument(_))),
            "{result:?}"
        );
        assert_nothing_sent(&mut server_io).await;
    }

    #[tokio::test]
    async fn uid_store_with_invalid_uid_set_is_rejected_before_send() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let result = session
            .uid_store("1 EXPUNGE", StoreAction::Add, &[Flag::Seen])
            .await;
        assert!(
            matches!(result, Err(ClientError::InvalidArgument(_))),
            "{result:?}"
        );
        assert_nothing_sent(&mut server_io).await;
    }

    #[tokio::test]
    async fn move_messages_with_crlf_in_sequence_set_is_rejected_before_send() {
        let caps = Capabilities {
            move_ext: true,
            ..Capabilities::default()
        };
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session_with_caps(client_io, caps);
        let result = session
            .move_messages("1\r\nX7 EXPUNGE\r\nX8 MOVE 1", "Trash")
            .await;
        assert!(
            matches!(result, Err(ClientError::InvalidArgument(_))),
            "{result:?}"
        );
        assert_nothing_sent(&mut server_io).await;
    }

    #[tokio::test]
    async fn search_with_crlf_in_text_is_rejected_before_send() {
        let (client_io, mut server_io) = duplex(1024);
        let mut session = selected_session(client_io);
        let result = session
            .search(SearchQuery::subject("x\r\nX3 EXPUNGE"))
            .await;
        assert!(
            matches!(result, Err(ClientError::InvalidArgument(_))),
            "{result:?}"
        );
        assert_nothing_sent(&mut server_io).await;
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
        // RFC 4616 PLAIN message "\0user\0pass" (empty authzid), base64-encoded.
        assert_eq!(payload_b64, "AHVzZXIAcGFzcw==");

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

    /// More untagged frames than the event broadcast holds, to show that a
    /// command's own data no longer depends on that ring's capacity.
    const FRAMES_PAST_EVENT_CAPACITY: usize = 1500;

    /// Answer the next command with `frames` then a tagged `OK`, writing
    /// concurrently with the client's reads.
    async fn reply_with_frames(server: &mut tokio::io::DuplexStream, frames: Vec<u8>) {
        let tag = read_cmd_tag(server).await;
        server.write_all(&frames).await.unwrap();
        server
            .write_all(format!("{tag} OK done\r\n").as_bytes())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fetch_more_frames_than_event_capacity_returns_every_message() {
        let (client_io, mut server_io) = duplex(64 * 1024);
        let mut session = selected_session(client_io);
        let task = tokio::spawn(async move { session.fetch("1:*", "UID").await });

        let frames: Vec<u8> = (1..=FRAMES_PAST_EVENT_CAPACITY)
            .flat_map(|n| format!("* {n} FETCH (UID {n})\r\n").into_bytes())
            .collect();
        reply_with_frames(&mut server_io, frames).await;

        let results = task.await.unwrap().unwrap();
        assert_eq!(results.len(), FRAMES_PAST_EVENT_CAPACITY);
        assert_eq!(
            results.last().unwrap().uid,
            Some(FRAMES_PAST_EVENT_CAPACITY as u32)
        );
    }

    #[tokio::test]
    async fn search_more_frames_than_event_capacity_returns_every_id() {
        let (client_io, mut server_io) = duplex(64 * 1024);
        let mut session = selected_session(client_io);
        let task = tokio::spawn(async move { session.search(SearchQuery::subject("t")).await });

        let frames: Vec<u8> = (1..=FRAMES_PAST_EVENT_CAPACITY)
            .flat_map(|n| format!("* SEARCH {n}\r\n").into_bytes())
            .collect();
        reply_with_frames(&mut server_io, frames).await;

        let ids = task.await.unwrap().unwrap();
        assert_eq!(ids.len(), FRAMES_PAST_EVENT_CAPACITY);
    }

    #[tokio::test]
    async fn fetch_keeps_its_data_off_the_event_channel_but_not_unsolicited_frames() {
        let (client_io, mut server_io) = duplex(4096);
        let mut session = selected_session(client_io);
        let mut events = session.events();
        let task = tokio::spawn(async move { session.fetch("1", "UID").await });

        reply_with_frames(
            &mut server_io,
            b"* 1 FETCH (UID 7)\r\n* 4 EXISTS\r\n".to_vec(),
        )
        .await;

        let results = task.await.unwrap().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(&events.recv().await.unwrap()[..], b"* 4 EXISTS\r\n");
        assert!(events.try_recv().is_err(), "FETCH data leaked to events()");
    }

    #[tokio::test]
    async fn idle_tagged_no_instead_of_continuation_fails_without_waiting() {
        let (client_io, mut server_io) = duplex(1024);
        let caps = Capabilities {
            idle: true,
            ..Default::default()
        };
        let mut session = selected_session_with_caps(client_io, caps);
        let task = tokio::spawn(async move { session.idle().await.map(|_| ()) });

        let tag = read_cmd_tag(&mut server_io).await;
        server_io
            .write_all(format!("{tag} NO IDLE refused\r\n").as_bytes())
            .await
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("idle() waited for its timeout instead of the tagged NO")
            .unwrap();
        assert!(
            matches!(&result, Err(ClientError::CommandFailed(text)) if text.contains("refused")),
            "got {result:?}"
        );
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
