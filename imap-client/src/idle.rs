//! IDLE (RFC 2177) — long-poll for unsolicited mailbox events.
//!
//! Lifecycle:
//!
//! 1. [`Session::idle`](crate::session::Session) sends `IDLE`, registers
//!    the tag in the dispatcher, and waits for the server's `+ idling`
//!    continuation.
//! 2. The returned [`IdleHandle`] is held by the caller while it consumes
//!    untagged events from the broadcast channel.
//! 3. [`IdleHandle::stop`] sends `DONE\r\n` and awaits the tagged `OK`.
//!
//! ## Refresh
//!
//! Servers MUST forcibly close idle connections after 30 minutes (RFC 2177
//! §3 strongly recommends every 29 minutes). This handle does **not**
//! refresh internally — callers must call [`IdleHandle::stop`] and re-issue
//! [`Session::idle`](crate::session::Session) at least every ~28 minutes.
//! A future revision may move the refresh into a background task.

use std::time::Duration;

use tokio::sync::oneshot;

use crate::client::WriterHandle;
use crate::error::ClientError;

/// Handle to an active IDLE session. Drop it with [`Self::stop`] to
/// gracefully terminate; dropping without calling stop will not send the
/// `DONE` line and the connection may stall until the server's idle cap.
pub struct IdleHandle {
    writer: WriterHandle,
    reply_rx: oneshot::Receiver<Result<Vec<u8>, ClientError>>,
}

impl IdleHandle {
    pub(crate) fn new(
        writer: WriterHandle,
        reply_rx: oneshot::Receiver<Result<Vec<u8>, ClientError>>,
    ) -> Self {
        Self { writer, reply_rx }
    }

    /// Send `DONE` and await the tagged `OK`. Times out at
    /// `done_timeout` to avoid blocking forever if the server is wedged.
    pub async fn stop(self) -> Result<(), ClientError> {
        self.stop_with_timeout(Duration::from_secs(30)).await
    }

    /// Like [`Self::stop`] but with a caller-chosen timeout.
    pub async fn stop_with_timeout(self, done_timeout: Duration) -> Result<(), ClientError> {
        self.writer.send_raw(b"DONE\r\n".to_vec()).await?;
        match tokio::time::timeout(done_timeout, self.reply_rx).await {
            Ok(Ok(Ok(_frame))) => Ok(()),
            Ok(Ok(Err(e))) => Err(e),
            Ok(Err(_)) => Err(ClientError::ConnectionClosed),
            Err(_) => Err(ClientError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RawClient;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn test_idle_stop_sends_done_and_awaits_ok() {
        let (client_io, mut server_io) = duplex(1024);
        let mut raw = RawClient::new(client_io);

        let writer = raw.writer();
        let (_tag, reply_rx) = raw.send_command_async("IDLE").await.unwrap();
        let handle = IdleHandle::new(writer, reply_rx);

        // Server: read IDLE command, send + idling, then expect DONE, send OK.
        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(cmd.contains("IDLE"));
        let tag = cmd.split_whitespace().next().unwrap().to_string();

        server_io.write_all(b"+ idling\r\n").await.unwrap();

        let stop_task = tokio::spawn(async move { handle.stop().await });

        // Read DONE
        let n = server_io.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"DONE\r\n");

        server_io
            .write_all(format!("{} OK IDLE terminated\r\n", tag).as_bytes())
            .await
            .unwrap();

        stop_task.await.unwrap().unwrap();
    }
}
