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
    /// Fetches data from the currently selected mailbox.
    pub async fn fetch(&mut self, sequence_set: &str, items: &str) -> Result<Vec<u8>, ClientError> {
        let cmd = format!("FETCH {} {}", sequence_set, items);
        self.raw.execute_command(&cmd).await
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
