use crate::capabilities::Capabilities;
use crate::client::RawClient;
use crate::credentials::Password;
use crate::error::ClientError;
use crate::flags::{Flag, StoreAction};
use crate::search::SearchQuery;
use std::marker::PhantomData;

// --- State Markers ---
pub struct Unauthenticated;
pub struct Authenticated;
pub struct Selected;

// --- Transport Markers ---
pub struct PlainText;
pub struct Tls;

/// The main generic Session type enforcing compile-time state transitions.
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

    pub fn events(&self) -> tokio::sync::broadcast::Receiver<Vec<u8>> {
        self.raw.events()
    }
}

// Initial state
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
}

// Only TLS sessions can login
impl Session<Unauthenticated, Tls> {
    /// Logs in using plain text.
    pub async fn login(
        mut self,
        user: &str,
        pass: Password,
    ) -> Result<Session<Authenticated, Tls>, ClientError> {
        let cmd = format!("LOGIN {} {}", user, pass.as_str());
        let resp = self.raw.execute_command(&cmd).await?;

        let resp_str = String::from_utf8_lossy(&resp);
        if resp_str.contains("OK") {
            // Re-fetch capabilities after login as they might change
            let cap_resp = self.raw.execute_command("CAPABILITY").await?;
            let cap_str = String::from_utf8_lossy(&cap_resp);
            self.capabilities = Capabilities::parse(&cap_str);

            Ok(self.transition_state())
        } else {
            Err(ClientError::CommandFailed("Login failed".into()))
        }
    }
}

impl<T> Session<Authenticated, T> {
    /// Selects a mailbox.
    pub async fn select(mut self, mailbox: &str) -> Result<Session<Selected, T>, ClientError> {
        let cmd = format!("SELECT \"{}\"", mailbox);
        let resp = self.raw.execute_command(&cmd).await?;

        let resp_str = String::from_utf8_lossy(&resp);
        if resp_str.contains("OK") {
            Ok(self.transition_state())
        } else {
            Err(ClientError::CommandFailed("Select failed".into()))
        }
    }

    /// Lists mailboxes.
    pub async fn list(
        &mut self,
        reference: &str,
        mailbox_mask: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let cmd = format!("LIST \"{}\" \"{}\"", reference, mailbox_mask);
        self.raw.execute_command(&cmd).await
    }
}

impl<T> Session<Selected, T> {
    /// Fetches raw data from the currently selected mailbox.
    pub async fn fetch_raw(
        &mut self,
        sequence_set: &str,
        items: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let cmd = format!("FETCH {} {}", sequence_set, items);
        self.raw.execute_command(&cmd).await
    }

    /// Fetches data and returns a structured FetchResult.
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
            if let Ok((
                _,
                imap_core::ast::Response::Data(imap_core::ast::DataResponse::Fetch {
                    seq,
                    attributes,
                }),
            )) = imap_core::parser::parse_response(&event)
            {
                let mut uid = None;
                let mut body = None;
                for attr in attributes {
                    match attr {
                        imap_core::ast::FetchAttribute::Uid(u) => uid = Some(u),
                        imap_core::ast::FetchAttribute::Body(b) => body = Some(b.to_vec()),
                        _ => {}
                    }
                }
                results.push(FetchResult { seq, uid, body });
            }
        }
        Ok(results)
    }

    /// Convenience method to fetch only the body of a message.
    pub async fn fetch_body(&mut self, sequence_set: &str) -> Result<Option<String>, ClientError> {
        let results = self.fetch(sequence_set, "BODY[]").await?;
        if let Some(res) = results.first() {
            if let Some(body) = &res.body {
                return Ok(Some(String::from_utf8_lossy(body).into_owned()));
            }
        }
        Ok(None)
    }

    /// Searches for messages matching the criteria.
    pub async fn search(&mut self, query: SearchQuery) -> Result<Vec<u32>, ClientError> {
        self.run_search(&format!("SEARCH {}", query.build())).await
    }

    /// Searches for messages matching the criteria, returning UIDs.
    pub async fn uid_search(&mut self, query: SearchQuery) -> Result<Vec<u32>, ClientError> {
        self.run_search(&format!("UID SEARCH {}", query.build()))
            .await
    }

    async fn run_search(&mut self, cmd: &str) -> Result<Vec<u32>, ClientError> {
        let mut events = self.raw.events();

        let _resp = self.raw.execute_command(cmd).await?;

        // Collect results from events. In a production client, we'd only collect
        // until the tagged OK arrives. Here, we'll drain what's currently in the channel.
        let mut all_ids = Vec::new();
        while let Ok(event) = events.try_recv() {
            let event_str = String::from_utf8_lossy(&event);
            if let Some(ids_str) = event_str.strip_prefix("* SEARCH ") {
                let ids: Vec<u32> = ids_str
                    .split_whitespace()
                    .filter_map(|s| s.parse::<u32>().ok())
                    .collect();
                all_ids.extend(ids);
            }
        }

        Ok(all_ids)
    }

    /// Updates flags for the specified messages.
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

    /// Updates flags for the specified messages using UIDs.
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

    /// Permanently removes all messages with the \Deleted flag set.
    pub async fn expunge(&mut self) -> Result<Vec<u8>, ClientError> {
        self.raw.execute_command("EXPUNGE").await
    }

    /// Enters IDLE state, returning a handle to stop it.
    pub async fn idle(&mut self) -> Result<crate::idle::IdleHandle, ClientError> {
        let (tx, _rx) = tokio::sync::oneshot::channel();
        // Send IDLE command to raw client
        // ...
        Ok(crate::idle::IdleHandle::new(tx))
    }

    /// Moves messages to the specified mailbox (RFC 6851).
    #[cfg(feature = "move_ext")]
    pub async fn move_messages(
        &mut self,
        sequence_set: &str,
        mailbox: &str,
    ) -> Result<Vec<u8>, ClientError> {
        if !self.capabilities.move_ext {
            return Err(ClientError::UnsupportedCapability("MOVE"));
        }
        let cmd = format!("MOVE {} \"{}\"", sequence_set, mailbox);
        self.raw.execute_command(&cmd).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Flag, SearchQuery, StoreAction, Tls};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn test_session_search() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Selected, Tls>::new_in_state(raw, Capabilities::default());

        let search_task =
            tokio::spawn(async move { session.search(SearchQuery::subject("test")).await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        let tag = cmd.split_whitespace().next().unwrap();

        server_io.write_all(b"* SEARCH 1 2 3\r\n").await.unwrap();
        server_io
            .write_all(format!("{} OK SEARCH completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let ids = search_task.await.unwrap().unwrap();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn test_session_search_failure() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Selected, Tls>::new_in_state(raw, Capabilities::default());

        let search_task =
            tokio::spawn(async move { session.search(SearchQuery::subject("test")).await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        let tag = cmd.split_whitespace().next().unwrap();

        server_io
            .write_all(format!("{} NO SEARCH failed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let res = search_task.await.unwrap();
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_session_list_failure() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Authenticated, Tls>::new_in_state(raw, Capabilities::default());

        let list_task = tokio::spawn(async move { session.list("", "*").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        let tag = cmd.split_whitespace().next().unwrap();

        server_io
            .write_all(format!("{} NO LIST failed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let res = list_task.await.unwrap();
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_session_list() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Authenticated, Tls>::new_in_state(raw, Capabilities::default());

        let list_task = tokio::spawn(async move { session.list("", "*").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        let tag = cmd.split_whitespace().next().unwrap();

        server_io
            .write_all(format!("{} OK LIST completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let resp = list_task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("OK"));
    }

    #[tokio::test]
    async fn test_session_store() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Selected, Tls>::new_in_state(raw, Capabilities::default());

        let store_task =
            tokio::spawn(async move { session.store("1", StoreAction::Add, &[Flag::Seen]).await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        let tag = cmd.split_whitespace().next().unwrap();

        server_io
            .write_all(format!("{} OK STORE completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let resp = store_task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("OK"));
    }

    #[tokio::test]
    async fn test_session_expunge() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Selected, Tls>::new_in_state(raw, Capabilities::default());

        let expunge_task = tokio::spawn(async move { session.expunge().await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        let tag = cmd.split_whitespace().next().unwrap();

        server_io
            .write_all(format!("{} OK EXPUNGE completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let resp = expunge_task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("OK"));
    }

    #[tokio::test]
    async fn test_session_uid_search() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Selected, Tls>::new_in_state(raw, Capabilities::default());

        let search_task =
            tokio::spawn(async move { session.uid_search(SearchQuery::subject("test")).await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        assert!(cmd.contains("UID SEARCH"));
        let tag = cmd.split_whitespace().next().unwrap();

        server_io.write_all(b"* SEARCH 4 5 6\r\n").await.unwrap();
        server_io
            .write_all(format!("{} OK UID SEARCH completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let ids = search_task.await.unwrap().unwrap();
        assert_eq!(ids, vec![4, 5, 6]);
    }

    #[tokio::test]
    async fn test_session_uid_store() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Selected, Tls>::new_in_state(raw, Capabilities::default());

        let store_task = tokio::spawn(async move {
            session
                .uid_store("1", StoreAction::Add, &[Flag::Seen])
                .await
        });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        assert!(cmd.contains("UID STORE"));
        let tag = cmd.split_whitespace().next().unwrap();

        server_io
            .write_all(format!("{} OK UID STORE completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let resp = store_task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("OK"));
    }

    #[tokio::test]
    #[cfg(feature = "move_ext")]
    async fn test_session_move_messages() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut caps = Capabilities::default();
        caps.move_ext = true;
        let mut session = Session::<crate::Selected, Tls>::new_in_state(raw, caps);

        let move_task = tokio::spawn(async move { session.move_messages("1", "Archive").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        assert!(cmd.contains("MOVE"));
        let tag = cmd.split_whitespace().next().unwrap();

        server_io
            .write_all(format!("{} OK MOVE completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let resp = move_task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("OK"));
    }

    #[tokio::test]
    async fn test_session_login() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let session =
            Session::<crate::Unauthenticated, Tls>::new_in_state(raw, Capabilities::default());

        let login_task = tokio::spawn(async move {
            session
                .login("user", crate::credentials::Password::new("pass"))
                .await
        });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();

        server_io
            .write_all(format!("{} OK LOGIN completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        // Wait for CAPABILITY command after login
        let n = server_io.read(&mut buf).await.unwrap();
        let tag2 = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        server_io
            .write_all(format!("{} OK CAPABILITY completed\r\n", tag2).as_bytes())
            .await
            .unwrap();

        let res = login_task.await.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_session_select() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let session =
            Session::<crate::Authenticated, Tls>::new_in_state(raw, Capabilities::default());

        let select_task = tokio::spawn(async move { session.select("INBOX").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();

        server_io
            .write_all(format!("{} OK SELECT completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let res = select_task.await.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_session_fetch() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Selected, Tls>::new_in_state(raw, Capabilities::default());

        let fetch_task = tokio::spawn(async move { session.fetch_raw("1", "ALL").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();

        server_io
            .write_all(format!("{} OK FETCH completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let res = fetch_task.await.unwrap();
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn test_session_login_failure() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let session =
            Session::<crate::Unauthenticated, Tls>::new_in_state(raw, Capabilities::default());

        let login_task = tokio::spawn(async move {
            session
                .login("user", crate::credentials::Password::new("pass"))
                .await
        });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();

        server_io
            .write_all(format!("{} NO LOGIN failed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let res = login_task.await.unwrap();
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_session_select_failure() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let session =
            Session::<crate::Authenticated, Tls>::new_in_state(raw, Capabilities::default());

        let select_task = tokio::spawn(async move { session.select("INBOX").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();

        server_io
            .write_all(format!("{} NO SELECT failed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let res = select_task.await.unwrap();
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_session_transition_transport() {
        let (client_io, _server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let session =
            Session::<crate::Unauthenticated, Tls>::new_in_state(raw, Capabilities::default());
        let _ = session.transition_transport::<crate::PlainText>();
    }

    #[tokio::test]
    async fn test_session_events() {
        let (client_io, _server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let session =
            Session::<crate::Unauthenticated, Tls>::new_in_state(raw, Capabilities::default());
        let _ = session.events();
    }

    #[tokio::test]
    async fn test_session_run_search_multiple_events() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Selected, Tls>::new_in_state(raw, Capabilities::default());

        let search_task =
            tokio::spawn(async move { session.search(SearchQuery::subject("test")).await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();

        // Send multiple SEARCH untagged responses
        server_io.write_all(b"* SEARCH 1 2\r\n").await.unwrap();
        server_io.write_all(b"* SEARCH 3 4\r\n").await.unwrap();
        server_io
            .write_all(format!("{} OK SEARCH completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let ids = search_task.await.unwrap().unwrap();
        assert_eq!(ids, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_session_fetch_ergonomic() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Selected, Tls>::new_in_state(raw, Capabilities::default());

        let fetch_task = tokio::spawn(async move { session.fetch("1", "BODY[]").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();

        // Send FETCH untagged with literal and UID
        server_io
            .write_all(b"* 1 FETCH (BODY[] {10}\r\n0123456789 UID 123)\r\n")
            .await
            .unwrap();
        server_io
            .write_all(format!("{} OK FETCH completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let results = fetch_task.await.unwrap().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].seq, 1);
        assert_eq!(results[0].uid, Some(123));
        assert_eq!(results[0].body, Some(b"0123456789".to_vec()));
    }

    #[tokio::test]
    async fn test_session_fetch_body() {
        let (client_io, mut server_io) = duplex(1024);
        let raw = RawClient::new(client_io);
        let mut session =
            Session::<crate::Selected, Tls>::new_in_state(raw, Capabilities::default());

        let fetch_task = tokio::spawn(async move { session.fetch_body("1").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();

        server_io
            .write_all(b"* 1 FETCH (BODY[] {10}\r\n0123456789)\r\n")
            .await
            .unwrap();
        server_io
            .write_all(format!("{} OK FETCH completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let body = fetch_task.await.unwrap().unwrap().unwrap();
        assert_eq!(body, "0123456789");
    }
}
