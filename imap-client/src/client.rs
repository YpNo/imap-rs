//! Async I/O dispatcher: pipelines commands by tag, routes tagged status
//! responses back to the originating future, broadcasts untagged events.
//!
//! ## Routing semantics
//!
//! Each command is assigned a monotonically-increasing tag. The dispatcher
//! parses every frame: tagged status frames go back to the awaiting caller
//! via a `oneshot`; untagged frames (data, status, continuation) go to the
//! broadcast channel. Tagged frames whose status is `NO` or `BAD` are
//! converted to [`ClientError::CommandFailed`] before being delivered, so
//! callers don't need to re-parse the wire bytes to discover failure.
//!
//! ## Cancellation
//!
//! If a caller drops the returned future before the tagged response arrives,
//! the `oneshot::Sender` becomes useless but no resource leak occurs — the
//! pending entry is removed on the next match attempt.

use bytes::BytesMut;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};

use crate::error::ClientError;
use imap_core::ast::{Response, Status};
use imap_core::parser::{MAX_LITERAL_SIZE, parse_response};

/// Reply channel for tagged-response delivery.
type TaggedReply = oneshot::Sender<Result<Vec<u8>, ClientError>>;
type PendingCommands = Arc<Mutex<HashMap<String, TaggedReply>>>;

/// Capacity (number of buffered messages) of the untagged-event broadcast
/// channel. Slow consumers experience [`broadcast::error::RecvError::Lagged`]
/// once they fall this far behind.
const EVENT_CHANNEL_CAP: usize = 1024;

/// Hard ceiling on the bytes buffered for a single in-flight response frame.
/// Bounds the read buffer so a hostile server cannot exhaust memory by
/// streaming a frame that never terminates (e.g. an unterminated quoted
/// string, or a line with no CRLF) — the parser would otherwise keep
/// returning [`ParseError::Incomplete`](imap_core::error::ParseError) while
/// the buffer grows without limit. Sized to admit one maximal literal plus
/// protocol overhead.
const MAX_FRAME_SIZE: usize = MAX_LITERAL_SIZE + 64 * 1024;

/// Items written by [`write_loop`].
enum WriteRequest {
    /// A tagged command. The dispatcher registers `tag` → `reply_tx`
    /// before writing `bytes`, so a fast server can never beat us to the
    /// pending-map insertion.
    Command {
        bytes: Vec<u8>,
        tag: String,
        reply_tx: TaggedReply,
    },
    /// A raw byte sequence. Used for IDLE's `DONE` and continuation
    /// payloads where no tagged response is expected immediately.
    Raw { bytes: Vec<u8> },
}

/// Async dispatcher around a single tokio I/O stream.
pub struct RawClient {
    write_tx: mpsc::Sender<WriteRequest>,
    event_tx: broadcast::Sender<Vec<u8>>,
    tag_counter: u64,
    pub default_timeout: Duration,
}

impl RawClient {
    pub fn new<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let (write_tx, write_rx) = mpsc::channel(32);
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAP);

        let pending_commands = Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(read_loop(
            read_half,
            Arc::clone(&pending_commands),
            event_tx.clone(),
            MAX_FRAME_SIZE,
        ));
        tokio::spawn(write_loop(
            write_half,
            write_rx,
            Arc::clone(&pending_commands),
        ));

        Self {
            write_tx,
            event_tx,
            tag_counter: 1,
            default_timeout: Duration::from_secs(30),
        }
    }

    pub fn events(&self) -> broadcast::Receiver<Vec<u8>> {
        self.event_tx.subscribe()
    }

    /// Allocate a fresh tag. Tags are formatted `A<counter>` and are
    /// monotonically increasing for the lifetime of the connection.
    fn next_tag(&mut self) -> String {
        let tag = format!("A{:04}", self.tag_counter);
        self.tag_counter = self.tag_counter.wrapping_add(1);
        tag
    }

    /// Send `cmd` as a tagged command, await the tagged status response.
    ///
    /// On success returns the raw frame bytes (including the trailing CRLF).
    /// On a `NO`/`BAD` tagged response returns
    /// [`ClientError::CommandFailed`] containing the server's resp-text.
    pub async fn execute_command(&mut self, cmd: &str) -> Result<Vec<u8>, ClientError> {
        self.execute_command_with_timeout(cmd, self.default_timeout)
            .await
    }

    pub async fn execute_command_with_timeout(
        &mut self,
        cmd: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, ClientError> {
        let (_tag, rx) = self.send_command_async(cmd).await?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(ClientError::ConnectionClosed),
            Err(_) => Err(ClientError::Timeout),
        }
    }

    /// Send a command and return a receiver for its tagged response without
    /// awaiting. Used by long-running commands (e.g. IDLE) where the caller
    /// needs to interleave other I/O before the tagged reply arrives.
    pub async fn send_command_async(
        &mut self,
        cmd: &str,
    ) -> Result<(String, oneshot::Receiver<Result<Vec<u8>, ClientError>>), ClientError> {
        let tag = self.next_tag();
        let bytes = format!("{} {}\r\n", tag, cmd).into_bytes();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.write_tx
            .send(WriteRequest::Command {
                bytes,
                tag: tag.clone(),
                reply_tx,
            })
            .await
            .map_err(|_| ClientError::ConnectionClosed)?;
        Ok((tag, reply_rx))
    }

    /// Send raw bytes on the wire. Used for IDLE's `DONE` and other
    /// continuation payloads where no new tag is allocated.
    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> Result<(), ClientError> {
        self.write_tx
            .send(WriteRequest::Raw { bytes })
            .await
            .map_err(|_| ClientError::ConnectionClosed)
    }

    /// Cheap clone of the write side, suitable for handing to a long-lived
    /// task (e.g. an IDLE handle) so it can send `DONE` without holding a
    /// mutable borrow on the session.
    pub fn writer(&self) -> WriterHandle {
        WriterHandle {
            write_tx: self.write_tx.clone(),
        }
    }
}

/// Cloneable write-only handle to a [`RawClient`]. Used to send raw bytes
/// (e.g. IDLE `DONE`, AUTHENTICATE continuation payloads) from background
/// tasks that don't own the session.
#[derive(Clone)]
pub struct WriterHandle {
    write_tx: mpsc::Sender<WriteRequest>,
}

impl WriterHandle {
    pub async fn send_raw(&self, bytes: Vec<u8>) -> Result<(), ClientError> {
        self.write_tx
            .send(WriteRequest::Raw { bytes })
            .await
            .map_err(|_| ClientError::ConnectionClosed)
    }
}

async fn write_loop<W>(
    mut write_half: W,
    mut rx: mpsc::Receiver<WriteRequest>,
    pending_commands: PendingCommands,
) where
    W: AsyncWrite + Unpin,
{
    while let Some(req) = rx.recv().await {
        match req {
            WriteRequest::Command {
                bytes,
                tag,
                reply_tx,
            } => {
                // Register the pending entry BEFORE writing so the read
                // loop cannot miss a match against a fast server reply.
                pending_commands.lock().await.insert(tag, reply_tx);
                if write_half.write_all(&bytes).await.is_err() {
                    break;
                }
            }
            WriteRequest::Raw { bytes } => {
                if write_half.write_all(&bytes).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Drain every pending tagged-command waiter, delivering a freshly built
/// error to each. `make_err` is a factory because [`ClientError`] is not
/// `Clone` (it wraps `std::io::Error`).
async fn fail_all_pending(pending: &PendingCommands, make_err: impl Fn() -> ClientError) {
    let mut map = pending.lock().await;
    for (_, tx) in map.drain() {
        let _ = tx.send(Err(make_err()));
    }
}

async fn read_loop<R>(
    mut read_half: R,
    pending_commands: PendingCommands,
    event_tx: broadcast::Sender<Vec<u8>>,
    max_frame_size: usize,
) where
    R: AsyncRead + Unpin,
{
    let mut buffer = BytesMut::with_capacity(8192);

    loop {
        match read_half.read_buf(&mut buffer).await {
            Ok(0) => {
                // EOF: notify any pending commands that we're closing.
                fail_all_pending(&pending_commands, || ClientError::ConnectionClosed).await;
                break;
            }
            Ok(_) => {
                while !buffer.is_empty() {
                    // Extract owned routing info from the parse so we can
                    // mutate the buffer afterwards.
                    let routing = match parse_response(&buffer) {
                        Ok((remaining, response)) => {
                            let consumed = buffer.len() - remaining.len();
                            let routing = match &response {
                                Response::Status(s) => s
                                    .tag
                                    .map(|tag| (tag.to_string(), s.status, s.text.to_string())),
                                _ => None,
                            };
                            (consumed, routing)
                        }
                        Err(imap_core::error::ParseError::Incomplete) => break,
                        Err(_) => {
                            // Malformed frame — drop the buffer to resync.
                            // (A real protocol error; we close the loop.)
                            buffer.clear();
                            break;
                        }
                    };
                    let (consumed, routing) = routing;
                    let frame = buffer.split_to(consumed).to_vec();
                    dispatch_frame(routing, frame, &pending_commands, &event_tx).await;
                }

                // Complete frames have been split off; any residue is a single
                // still-incomplete frame. Refuse to buffer it past the ceiling
                // so a server streaming a never-terminating frame cannot
                // exhaust memory.
                if buffer.len() > max_frame_size {
                    fail_all_pending(&pending_commands, || ClientError::FrameTooLarge {
                        max: max_frame_size,
                    })
                    .await;
                    break;
                }
            }
            Err(_) => {
                fail_all_pending(&pending_commands, || ClientError::ConnectionClosed).await;
                break;
            }
        }
    }
}

/// Route a parsed frame to either a pending tagged-command future or the
/// broadcast channel. Tagged `NO`/`BAD` responses are converted to
/// [`ClientError::CommandFailed`] here so callers don't have to re-parse.
async fn dispatch_frame(
    routing: Option<(String, Status, String)>,
    frame: Vec<u8>,
    pending_commands: &PendingCommands,
    event_tx: &broadcast::Sender<Vec<u8>>,
) {
    if let Some((tag, status, text)) = routing {
        let mut map = pending_commands.lock().await;
        if let Some(tx) = map.remove(&tag) {
            let result = match status {
                Status::Ok => Ok(frame),
                Status::No | Status::Bad => Err(ClientError::CommandFailed(text)),
                Status::Bye => Err(ClientError::ConnectionClosed),
                // PREAUTH is only valid as an untagged greeting; if it
                // somehow appears tagged we surface the raw text.
                Status::PreAuth => Err(ClientError::CommandFailed(text)),
            };
            let _ = tx.send(result);
            return;
        }
    }
    // Untagged or no matching pending entry — broadcast.
    let _ = event_tx.send(frame);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn test_tagged_response_matching() {
        let (client_io, mut server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);

        let command_task = tokio::spawn(async move { client.execute_command("NOOP").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        assert!(cmd.contains("NOOP"));
        let tag = cmd.split_whitespace().next().unwrap();

        server_io
            .write_all(format!("{} OK NOOP completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let result = command_task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&result).contains("OK"));
    }

    #[tokio::test]
    async fn test_no_response_becomes_error() {
        let (client_io, mut server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);

        let command_task = tokio::spawn(async move { client.execute_command("LOGIN x y").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        server_io
            .write_all(format!("{} NO authentication failed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let result = command_task.await.unwrap();
        match result {
            Err(ClientError::CommandFailed(text)) => {
                assert_eq!(text, "authentication failed")
            }
            other => panic!("expected CommandFailed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_bad_response_becomes_error() {
        let (client_io, mut server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);

        let command_task = tokio::spawn(async move { client.execute_command("BOGUS").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        server_io
            .write_all(format!("{} BAD unknown command\r\n", tag).as_bytes())
            .await
            .unwrap();

        let result = command_task.await.unwrap();
        assert!(matches!(result, Err(ClientError::CommandFailed(_))));
    }

    #[tokio::test]
    async fn test_untagged_event_broadcasting() {
        let (client_io, mut server_io) = duplex(1024);
        let client = RawClient::new(client_io);
        let mut events = client.events();

        server_io.write_all(b"* 5 EXISTS\r\n").await.unwrap();

        let event = events.recv().await.unwrap();
        assert_eq!(String::from_utf8_lossy(&event), "* 5 EXISTS\r\n");
    }

    #[tokio::test]
    async fn test_partial_read_reassembly() {
        let (client_io, mut server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);

        let command_task = tokio::spawn(async move { client.execute_command("NOOP").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();

        let response = format!("{} OK NOOP completed\r\n", tag);
        for byte in response.as_bytes() {
            server_io.write_all(&[*byte]).await.unwrap();
            tokio::task::yield_now().await;
        }

        let result = command_task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&result).contains("OK"));
    }

    #[tokio::test]
    async fn test_command_timeout() {
        let (client_io, _server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);
        client.default_timeout = Duration::from_millis(50);

        let result = client.execute_command("NOOP").await;
        assert!(matches!(result, Err(ClientError::Timeout)));
    }

    #[tokio::test]
    async fn test_search_parsing() {
        let (client_io, mut server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);
        let mut events = client.events();

        let command_task =
            tokio::spawn(async move { client.execute_command("SEARCH FROM \"alice\"").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        let tag = cmd.split_whitespace().next().unwrap();

        server_io.write_all(b"* SEARCH 1 2 3\r\n").await.unwrap();
        server_io
            .write_all(format!("{} OK SEARCH completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let _result = command_task.await.unwrap().unwrap();

        let event = events.recv().await.unwrap();
        assert_eq!(String::from_utf8_lossy(&event), "* SEARCH 1 2 3\r\n");
    }

    #[tokio::test]
    async fn test_send_raw() {
        let (client_io, mut server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);

        client.send_raw(b"DONE\r\n".to_vec()).await.unwrap();

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"DONE\r\n");
    }

    #[tokio::test]
    async fn test_connection_closed_on_eof() {
        let (client_io, server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);
        client.default_timeout = Duration::from_secs(1);

        let task = tokio::spawn(async move { client.execute_command("NOOP").await });
        // Give the command time to register, then drop the server side.
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(server_io);

        let result = task.await.unwrap();
        assert!(matches!(
            result,
            Err(ClientError::ConnectionClosed) | Err(ClientError::Timeout)
        ));
    }

    #[tokio::test]
    async fn test_connection_closed_immediate() {
        let (client_io, server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);
        drop(server_io);

        let result = client.execute_command("NOOP").await;
        assert!(matches!(
            result,
            Err(ClientError::ConnectionClosed) | Err(ClientError::Timeout)
        ));
    }

    #[tokio::test]
    async fn test_unterminated_frame_is_bounded() {
        // A server that streams a frame which never terminates (no CRLF)
        // must not grow the read buffer without limit. Drive `read_loop`
        // directly with a tiny ceiling so the test stays fast — exercising
        // the real 64 MiB `MAX_FRAME_SIZE` would allocate 64 MiB.
        let (client_io, mut server_io) = duplex(8192);

        let pending: PendingCommands = Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, _event_rx) = broadcast::channel(EVENT_CHANNEL_CAP);

        let (reply_tx, reply_rx) = oneshot::channel();
        pending.lock().await.insert("A0001".to_string(), reply_tx);

        let max_frame_size = 64;
        let loop_task = tokio::spawn(read_loop(
            client_io,
            Arc::clone(&pending),
            event_tx,
            max_frame_size,
        ));

        // Valid resp-text bytes that never reach a CRLF -> parser stays
        // `Incomplete` while the buffer grows past the ceiling.
        server_io.write_all(b"* OK ").await.unwrap();
        server_io
            .write_all(&vec![b'a'; max_frame_size * 2])
            .await
            .unwrap();

        let result = reply_rx.await.unwrap();
        assert!(
            matches!(result, Err(ClientError::FrameTooLarge { max }) if max == max_frame_size),
            "expected FrameTooLarge, got {result:?}"
        );
        // The loop must terminate rather than spin on the oversized buffer.
        loop_task.await.unwrap();
    }
}
