//! Async I/O dispatcher: pipelines commands by tag, routes tagged status
//! responses back to the originating future, streams a command's own
//! untagged data to it, and broadcasts every other untagged frame.
//!
//! ## Routing semantics
//!
//! Each command is assigned a monotonically-increasing tag. The dispatcher
//! parses every frame and routes it one of three ways:
//!
//! - A tagged status frame goes back to the awaiting caller via a
//!   `oneshot`. `NO` and `BAD` are converted to [`ClientError::CommandFailed`]
//!   before delivery, so callers don't need to re-parse the wire bytes.
//! - An untagged frame accepted by the [`FrameFilter`] of an in-flight
//!   streaming command ([`RawClient::send_command_streaming`]) goes to that
//!   command's bounded channel. When the channel is full the dispatcher
//!   stops reading until the command consumes it, so a large `FETCH` is
//!   held in memory one bounded batch of frames at a time instead of
//!   piling up.
//! - Every other untagged frame (`EXISTS`, `EXPUNGE`, `[ALERT]`, …) is
//!   broadcast to [`RawClient::events`] subscribers as a shared [`Bytes`],
//!   so subscribers never copy it.
//!
//! ## Cancellation
//!
//! If a caller drops the returned future before the tagged response arrives,
//! the `oneshot::Sender` becomes useless but no resource leak occurs — the
//! pending entry is removed on the next match attempt. Frames a dropped
//! stream would have received are broadcast instead.

use bytes::{Buf, Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use zeroize::Zeroizing;

use crate::error::ClientError;
use imap_core::ast::{Response, Status};
use imap_core::parser::{MAX_LITERAL_SIZE, parse_response};

/// Reply channel for tagged-response delivery.
type TaggedReply = oneshot::Sender<Result<Vec<u8>, ClientError>>;
/// Receiving end of a [`TaggedReply`].
type ReplyReceiver = oneshot::Receiver<Result<Vec<u8>, ClientError>>;
type PendingCommands = Arc<Mutex<Pending>>;

/// Selects the untagged responses that belong to a streaming command; see
/// [`RawClient::send_command_streaming`].
pub type FrameFilter = fn(&Response<'_>) -> bool;

/// Capacity (number of buffered frames) of the untagged-event broadcast
/// channel. Slow consumers experience [`broadcast::error::RecvError::Lagged`]
/// once they fall this far behind. Only unsolicited frames use it: a
/// command's own data travels on its stream, so this stays small to bound
/// what a slow subscriber can make the client retain.
///
/// The bound counts frames, not bytes: each frame may be up to
/// [`MAX_FRAME_SIZE`], so a subscriber that stops reading can still hold
/// this many frames of that size alive until it drops its receiver.
const EVENT_CHANNEL_CAP: usize = 256;

/// Frames buffered for one streaming command before the dispatcher waits
/// for that command to consume them. Like [`EVENT_CHANNEL_CAP`] this counts
/// frames, each up to [`MAX_FRAME_SIZE`].
const STREAM_CHANNEL_CAP: usize = 32;

/// Capacity of the queue between callers and the write loop.
const WRITE_CHANNEL_CAP: usize = 32;

/// Hard ceiling on the bytes buffered for a single in-flight response frame.
/// Bounds the read buffer so a hostile server cannot exhaust memory by
/// streaming a frame that never terminates (e.g. an unterminated quoted
/// string, or a line with no CRLF) — the parser would otherwise keep
/// returning [`ParseError::Incomplete`](imap_core::error::ParseError) while
/// the buffer grows without limit. Sized to admit one maximal literal plus
/// protocol overhead.
const MAX_FRAME_SIZE: usize = MAX_LITERAL_SIZE + 64 * 1024;

/// A streaming command's claim on untagged frames.
struct Collector {
    tag: String,
    wants: FrameFilter,
    tx: mpsc::Sender<Bytes>,
}

/// Commands awaiting their tagged response.
#[derive(Default)]
struct Pending {
    replies: HashMap<String, TaggedReply>,
    /// Streaming commands in write order. An untagged frame goes to the
    /// oldest one still listening whose filter accepts it.
    collectors: VecDeque<Collector>,
}

impl Pending {
    fn collector_for(&self, response: &Response<'_>) -> Option<mpsc::Sender<Bytes>> {
        self.collectors
            .iter()
            .find(|c| !c.tx.is_closed() && (c.wants)(response))
            .map(|c| c.tx.clone())
    }

    /// Take `tag`'s reply sender and end its frame stream, if it has one.
    fn complete(&mut self, tag: &str) -> Option<TaggedReply> {
        self.collectors.retain(|c| c.tag != tag);
        self.replies.remove(tag)
    }
}

/// Where the read loop sends one parsed frame.
enum Route {
    Tagged {
        tag: String,
        status: Status,
        text: String,
    },
    Stream(mpsc::Sender<Bytes>),
    Broadcast,
}

/// Items written by [`write_loop`]. The bytes may hold a credential (a
/// `LOGIN` line, a SASL response), so every request is wiped when dropped:
/// after it is written, or unsent if the connection is gone.
enum WriteRequest {
    /// A tagged command. The dispatcher registers `tag` → `reply_tx` (and
    /// the frame collector, if any) before writing `bytes`, so a fast
    /// server can never beat us to the pending-map insertion.
    Command {
        bytes: Zeroizing<Vec<u8>>,
        tag: String,
        reply_tx: TaggedReply,
        collector: Option<(FrameFilter, mpsc::Sender<Bytes>)>,
    },
    /// A raw byte sequence. Used for IDLE's `DONE` and continuation
    /// payloads where no tagged response is expected immediately.
    Raw { bytes: Zeroizing<Vec<u8>> },
}

/// `<tag> <cmd>\r\n` in one exact-size allocation, so that formatting a
/// command that carries a password leaves no un-wiped copy behind.
fn command_line(tag: &str, cmd: &str) -> Zeroizing<Vec<u8>> {
    const CRLF: &[u8] = b"\r\n";
    let mut line = Zeroizing::new(Vec::with_capacity(tag.len() + 1 + cmd.len() + CRLF.len()));
    line.extend_from_slice(tag.as_bytes());
    line.push(b' ');
    line.extend_from_slice(cmd.as_bytes());
    line.extend_from_slice(CRLF);
    line
}

/// A command whose untagged data arrives on its own bounded stream; returned
/// by [`RawClient::send_command_streaming`].
pub struct CommandStream {
    frames: mpsc::Receiver<Bytes>,
    reply: ReplyReceiver,
    /// Where frames go once the caller stops reading the stream.
    event_tx: broadcast::Sender<Bytes>,
}

impl CommandStream {
    /// The next untagged frame selected for this command, in wire order.
    /// Returns `None` once the command's tagged response has arrived (all of
    /// its frames have then been delivered) or the connection has failed;
    /// [`into_reply`](Self::into_reply) then yields the outcome.
    pub async fn next_frame(&mut self) -> Option<Bytes> {
        self.frames.recv().await
    }

    /// Stop receiving frames and return the tagged-response receiver.
    /// Frames already buffered for this stream, and any later ones it would
    /// have received, are broadcast to [`RawClient::events`] instead.
    /// Dropping the stream without calling this discards buffered frames.
    pub fn into_reply(mut self) -> oneshot::Receiver<Result<Vec<u8>, ClientError>> {
        // Closing first stops new sends, so the drain below is complete and
        // the read loop's next send falls back to the broadcast itself.
        self.frames.close();
        while let Ok(frame) = self.frames.try_recv() {
            let _ = self.event_tx.send(frame);
        }
        self.reply
    }
}

/// Async dispatcher around a single tokio I/O stream.
pub struct RawClient {
    write_tx: mpsc::Sender<WriteRequest>,
    event_tx: broadcast::Sender<Bytes>,
    tag_counter: u64,
    /// Default per-command deadline applied by [`RawClient::execute_command`].
    pub default_timeout: Duration,
}

impl RawClient {
    /// Wrap an async stream, spawning the background read and write loops.
    /// The stream is split internally; commands are pipelined by tag.
    pub fn new<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let (write_tx, write_rx) = mpsc::channel(WRITE_CHANNEL_CAP);
        let (event_tx, _) = broadcast::channel(EVENT_CHANNEL_CAP);

        let pending_commands = PendingCommands::default();

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

    /// Subscribe to untagged server frames that no streaming command claimed
    /// (unsolicited data and status responses, and continuation requests).
    /// Each subscriber gets its own receiver over shared frames; slow
    /// consumers observe `Lagged` once they fall behind the channel capacity.
    pub fn events(&self) -> broadcast::Receiver<Bytes> {
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

    /// Like [`execute_command`](Self::execute_command) but with an explicit
    /// timeout instead of [`default_timeout`](Self::default_timeout).
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

    /// Send `cmd`, pass each untagged frame `wants` accepts to `on_frame` as
    /// it arrives, then return the tagged response as
    /// [`execute_command`](Self::execute_command) does. The whole exchange
    /// runs under [`default_timeout`](Self::default_timeout).
    pub async fn execute_streaming(
        &mut self,
        cmd: &str,
        wants: FrameFilter,
        mut on_frame: impl FnMut(&[u8]),
    ) -> Result<Vec<u8>, ClientError> {
        let mut stream = self.send_command_streaming(cmd, wants).await?;
        let exchange = async move {
            while let Some(frame) = stream.next_frame().await {
                on_frame(&frame);
            }
            stream
                .into_reply()
                .await
                .map_err(|_| ClientError::ConnectionClosed)?
        };
        tokio::time::timeout(self.default_timeout, exchange)
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    /// Send a command and return a receiver for its tagged response without
    /// awaiting. Used by long-running commands (e.g. IDLE) where the caller
    /// needs to interleave other I/O before the tagged reply arrives.
    ///
    /// Returns [`ClientError::InvalidArgument`] without writing anything if
    /// `cmd` contains CR, LF or NUL, which would end the command early and
    /// let the remaining bytes run as further commands.
    pub async fn send_command_async(
        &mut self,
        cmd: &str,
    ) -> Result<(String, oneshot::Receiver<Result<Vec<u8>, ClientError>>), ClientError> {
        self.enqueue_command(cmd, None).await
    }

    /// Send a command whose untagged responses accepted by `wants` are
    /// delivered on the returned [`CommandStream`] instead of
    /// [`events`](Self::events), in wire order and before its tagged reply.
    ///
    /// The stream is bounded: while it is full the connection stops reading,
    /// so read it promptly (or drop it with
    /// [`into_reply`](CommandStream::into_reply)) rather than awaiting other
    /// commands first. Validates `cmd` as
    /// [`send_command_async`](Self::send_command_async) does.
    pub async fn send_command_streaming(
        &mut self,
        cmd: &str,
        wants: FrameFilter,
    ) -> Result<CommandStream, ClientError> {
        let (frames_tx, frames) = mpsc::channel(STREAM_CHANNEL_CAP);
        let (_tag, reply) = self.enqueue_command(cmd, Some((wants, frames_tx))).await?;
        Ok(CommandStream {
            frames,
            reply,
            event_tx: self.event_tx.clone(),
        })
    }

    async fn enqueue_command(
        &mut self,
        cmd: &str,
        collector: Option<(FrameFilter, mpsc::Sender<Bytes>)>,
    ) -> Result<(String, ReplyReceiver), ClientError> {
        crate::wire::reject_line_breaks(cmd)?;
        let tag = self.next_tag();
        let bytes = command_line(&tag, cmd);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.write_tx
            .send(WriteRequest::Command {
                bytes,
                tag: tag.clone(),
                reply_tx,
                collector,
            })
            .await
            .map_err(|_| ClientError::ConnectionClosed)?;
        Ok((tag, reply_rx))
    }

    /// Send raw bytes on the wire. Used for IDLE's `DONE` and other
    /// continuation payloads where no new tag is allocated. The bytes are
    /// wiped once written.
    pub async fn send_raw(&mut self, bytes: Vec<u8>) -> Result<(), ClientError> {
        self.send_secret(Zeroizing::new(bytes)).await
    }

    /// [`send_raw`](Self::send_raw) for bytes already held in a wiped-on-drop
    /// buffer, so the secret is never moved into an unprotected one.
    pub(crate) async fn send_secret(
        &mut self,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<(), ClientError> {
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
    /// Send raw bytes on the connection's write half (e.g. an IDLE `DONE`).
    pub async fn send_raw(&self, bytes: Vec<u8>) -> Result<(), ClientError> {
        self.write_tx
            .send(WriteRequest::Raw {
                bytes: Zeroizing::new(bytes),
            })
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
                collector,
            } => {
                // Register the pending entry BEFORE writing so the read
                // loop cannot miss a match against a fast server reply.
                register(&pending_commands, tag, reply_tx, collector).await;
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

async fn register(
    pending: &PendingCommands,
    tag: String,
    reply_tx: TaggedReply,
    collector: Option<(FrameFilter, mpsc::Sender<Bytes>)>,
) {
    let mut pending = pending.lock().await;
    if let Some((wants, tx)) = collector {
        pending.collectors.push_back(Collector {
            tag: tag.clone(),
            wants,
            tx,
        });
    }
    pending.replies.insert(tag, reply_tx);
}

/// Drain every pending tagged-command waiter, delivering a freshly built
/// error to each, and end every frame stream. `make_err` is a factory
/// because [`ClientError`] is not `Clone` (it wraps `std::io::Error`).
async fn fail_all_pending(pending: &PendingCommands, make_err: impl Fn() -> ClientError) {
    let mut pending = pending.lock().await;
    pending.collectors.clear();
    for (_, tx) in pending.replies.drain() {
        let _ = tx.send(Err(make_err()));
    }
}

async fn read_loop<R>(
    mut read_half: R,
    pending_commands: PendingCommands,
    event_tx: broadcast::Sender<Bytes>,
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
                    let (consumed, route) = match parse_response(&buffer) {
                        Ok((remaining, response)) => {
                            let consumed = buffer.len() - remaining.len();
                            (consumed, route_for(&response, &pending_commands).await)
                        }
                        Err(imap_core::error::ParseError::Incomplete) => break,
                        Err(e) => {
                            // IMAP framing cannot be resynchronised: after a
                            // bad frame the next bytes may be the body of the
                            // message being fetched, written by a third
                            // party, and parsing them would let that party
                            // forge responses. Fail every waiter and stop.
                            fail_all_pending(&pending_commands, || ClientError::Parse(e.clone()))
                                .await;
                            return;
                        }
                    };
                    // One exact-size copy per frame: it shares no allocation
                    // with the read buffer, so a frame a subscriber keeps
                    // cannot pin a buffer grown for an earlier large literal.
                    let frame = Bytes::copy_from_slice(&buffer[..consumed]);
                    buffer.advance(consumed);
                    dispatch_frame(route, frame, &pending_commands, &event_tx).await;
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

/// Decide where a parsed frame goes. Tagged status frames are matched by
/// tag in [`dispatch_frame`]; untagged frames go to the oldest streaming
/// command that wants them, else to the broadcast.
async fn route_for(response: &Response<'_>, pending: &PendingCommands) -> Route {
    if let Response::Status(s) = response
        && let Some(tag) = s.tag
    {
        return Route::Tagged {
            tag: tag.to_string(),
            status: s.status,
            text: s.text.to_string(),
        };
    }
    match pending.lock().await.collector_for(response) {
        Some(tx) => Route::Stream(tx),
        None => Route::Broadcast,
    }
}

/// Deliver a frame along its [`Route`]. Tagged `NO`/`BAD` responses are
/// converted to [`ClientError::CommandFailed`] here so callers don't have
/// to re-parse. A tagged frame with no waiter, or a frame whose stream was
/// dropped, is broadcast.
async fn dispatch_frame(
    route: Route,
    frame: Bytes,
    pending_commands: &PendingCommands,
    event_tx: &broadcast::Sender<Bytes>,
) {
    let unclaimed = match route {
        Route::Tagged { tag, status, text } => {
            let Some(tx) = pending_commands.lock().await.complete(&tag) else {
                let _ = event_tx.send(frame);
                return;
            };
            let result = match status {
                Status::Ok => Ok(frame.to_vec()),
                Status::No | Status::Bad => Err(ClientError::command_failed(&text)),
                Status::Bye => Err(ClientError::ConnectionClosed),
                // PREAUTH is only valid as an untagged greeting; if it
                // somehow appears tagged we surface its text.
                Status::PreAuth => Err(ClientError::command_failed(&text)),
            };
            let _ = tx.send(result);
            return;
        }
        // Awaiting here is the backpressure: the read loop pauses until the
        // command consumes its stream.
        Route::Stream(tx) => match tx.send(frame).await {
            Ok(()) => return,
            Err(unsent) => unsent.0,
        },
        Route::Broadcast => frame,
    };
    let _ = event_tx.send(unclaimed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use imap_core::ast::DataResponse;
    use imap_core::error::ParseError;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn is_fetch(response: &Response<'_>) -> bool {
        matches!(response, Response::Data(DataResponse::Fetch { .. }))
    }

    #[test]
    fn command_line_is_built_without_reallocation() {
        let line: Zeroizing<Vec<u8>> = command_line("A0001", "LOGIN \"a\" \"secret\"");
        assert_eq!(&line[..], b"A0001 LOGIN \"a\" \"secret\"\r\n");
        assert_eq!(line.capacity(), line.len());
    }

    #[tokio::test]
    async fn events_subscribers_share_one_frame_allocation() {
        let (client_io, mut server_io) = duplex(1024);
        let client = RawClient::new(client_io);
        let mut first = client.events();
        let mut second = client.events();

        server_io.write_all(b"* 3 EXISTS\r\n").await.unwrap();

        let a = first.recv().await.unwrap();
        let b = second.recv().await.unwrap();
        assert_eq!(&a[..], b"* 3 EXISTS\r\n");
        assert_eq!(a.as_ptr(), b.as_ptr(), "each subscriber got its own copy");
    }

    #[tokio::test]
    async fn into_reply_rebroadcasts_frames_already_buffered_for_the_stream() {
        let (client_io, mut server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);
        let mut events = client.events();
        let mut stream = client
            .send_command_streaming("IDLE", |r| matches!(r, Response::Continue(_)))
            .await
            .unwrap();

        let mut buf = [0u8; 64];
        let _ = server_io.read(&mut buf).await.unwrap();
        server_io.write_all(b"+ a\r\n+ b\r\n").await.unwrap();
        assert_eq!(&stream.next_frame().await.unwrap()[..], b"+ a\r\n");
        let _reply = stream.into_reply();

        let frame = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("a buffered frame was discarded")
            .unwrap();
        assert_eq!(&frame[..], b"+ b\r\n");
    }

    #[tokio::test]
    async fn streamed_frames_go_to_events_once_the_stream_is_dropped() {
        let (client_io, mut server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);
        let mut events = client.events();
        let stream = client
            .send_command_streaming("IDLE", |r| matches!(r, Response::Continue(_)))
            .await
            .unwrap();
        let _reply = stream.into_reply();

        let mut buf = [0u8; 64];
        let _ = server_io.read(&mut buf).await.unwrap();
        server_io.write_all(b"+ idling\r\n").await.unwrap();

        let frame = tokio::time::timeout(Duration::from_secs(2), events.recv())
            .await
            .expect("frame was swallowed by a dropped stream")
            .unwrap();
        assert_eq!(&frame[..], b"+ idling\r\n");
    }

    #[tokio::test]
    async fn tagged_no_text_is_sanitised_before_reaching_the_error() {
        let (client_io, mut server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);
        let task = tokio::spawn(async move { client.execute_command("NOOP").await });

        let mut buf = [0u8; 64];
        let _ = server_io.read(&mut buf).await.unwrap();
        server_io
            .write_all(b"A0001 NO \x1b[2J\x1b[31mFAKE ALERT\x07\r\n")
            .await
            .unwrap();

        let err = task.await.unwrap().unwrap_err();
        let shown = err.to_string();
        assert!(!shown.chars().any(char::is_control), "{shown:?}");
        assert!(shown.contains("FAKE ALERT"));
    }

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

    /// A server-sent frame that is not merely incomplete (here a literal
    /// over the size cap) must end the connection. IMAP framing cannot be
    /// resynchronised: the bytes that follow are the body of the message
    /// being fetched, written by whoever sent that e-mail, and must never be
    /// interpreted as protocol responses.
    #[tokio::test]
    async fn read_loop_malformed_frame_fails_pending_and_stops_parsing() {
        let (client_io, mut server_io) = duplex(4096);
        let mut client = RawClient::new(client_io);
        let mut events = client.events();

        let server = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server_io.read(&mut buf).await.unwrap();
            server_io
                .write_all(b"* 1 FETCH (BODY[] {100000000}\r\n")
                .await
                .unwrap();
            // Let the client read and reject the first frame on its own, so the
            // forged bytes arrive in a later read, as they would mid-message.
            tokio::time::sleep(Duration::from_millis(20)).await;
            // Attacker-authored message body shaped like protocol traffic.
            server_io
                .write_all(b"* 999 EXISTS\r\nA0001 OK injected\r\n")
                .await
                .unwrap();
            server_io
        });

        let result = client.execute_command("FETCH 1 BODY[]").await;
        assert!(
            matches!(
                result,
                Err(ClientError::Parse(ParseError::LiteralTooLarge { .. }))
            ),
            "pending command must fail with the parse error, got {result:?}"
        );

        let _server_io = server.await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            matches!(
                events.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
                    | Err(broadcast::error::TryRecvError::Closed)
            ),
            "no frame after the malformed one may be broadcast"
        );
    }

    /// Regression for the benign side of the same defect: a long FETCH
    /// burst delivered in chunks that split frames mid-attribute-name must
    /// arrive intact, with the tagged completion routed to its command.
    #[tokio::test]
    async fn read_loop_fetch_burst_split_mid_attribute_delivers_every_frame() {
        const FRAMES: usize = 1000;
        const CHUNK: usize = 37;
        let (client_io, mut server_io) = duplex(1 << 20);
        let mut client = RawClient::new(client_io);

        let mut wire = Vec::new();
        for n in 1..=FRAMES {
            wire.extend_from_slice(format!("* {n} FETCH (FLAGS (\\Seen) UID {n})\r\n").as_bytes());
        }
        wire.extend_from_slice(b"A0001 OK FETCH completed\r\n");

        let server = tokio::spawn(async move {
            let mut buf = [0u8; 256];
            let _ = server_io.read(&mut buf).await.unwrap();
            // An odd chunk size lands cuts at every offset, including inside
            // `FLAGS` and `UID`; yielding lets each chunk be read separately.
            for chunk in wire.chunks(CHUNK) {
                server_io.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
            server_io
        });

        let mut received = 0;
        let result = client
            .execute_streaming("FETCH 1:* (FLAGS UID)", is_fetch, |frame| {
                assert!(frame.ends_with(b"\r\n"));
                received += 1;
            })
            .await;
        assert!(result.is_ok(), "tagged OK must be routed, got {result:?}");
        let _server_io = server.await.unwrap();
        assert_eq!(received, FRAMES);
    }

    #[tokio::test]
    async fn test_unterminated_frame_is_bounded() {
        // A server that streams a frame which never terminates (no CRLF)
        // must not grow the read buffer without limit. Drive `read_loop`
        // directly with a tiny ceiling so the test stays fast — exercising
        // the real 64 MiB `MAX_FRAME_SIZE` would allocate 64 MiB.
        let (client_io, mut server_io) = duplex(8192);

        let pending = PendingCommands::default();
        let (event_tx, _event_rx) = broadcast::channel(EVENT_CHANNEL_CAP);

        let (reply_tx, reply_rx) = oneshot::channel();
        register(&pending, "A0001".to_string(), reply_tx, None).await;

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
