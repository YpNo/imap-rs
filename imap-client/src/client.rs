use bytes::BytesMut;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};

use crate::error::ClientError;

type CommandResponse = oneshot::Sender<Result<Vec<u8>, ClientError>>;
type PendingCommands = Arc<Mutex<HashMap<String, CommandResponse>>>;

/// Core client that manages the background dispatcher and provides a generic
/// interface to send commands and receive responses.
pub struct RawClient {
    command_tx: mpsc::Sender<(String, CommandResponse)>,
    event_tx: broadcast::Sender<Vec<u8>>,
    tag_counter: u32,
    pub default_timeout: Duration,
}

impl RawClient {
    pub fn new<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let (command_tx, command_rx) = mpsc::channel(32);
        let (event_tx, _) = broadcast::channel(128);

        let pending_commands = Arc::new(Mutex::new(HashMap::new()));

        let _read_task = tokio::spawn(read_loop(
            read_half,
            Arc::clone(&pending_commands),
            event_tx.clone(),
        ));
        let _write_task = tokio::spawn(write_loop(
            write_half,
            command_rx,
            Arc::clone(&pending_commands),
        ));

        Self {
            command_tx,
            event_tx,
            tag_counter: 1,
            default_timeout: Duration::from_secs(30),
        }
    }

    pub fn events(&self) -> broadcast::Receiver<Vec<u8>> {
        self.event_tx.subscribe()
    }

    pub async fn execute_command(&mut self, cmd: &str) -> Result<Vec<u8>, ClientError> {
        self.execute_command_with_timeout(cmd, self.default_timeout)
            .await
    }

    pub async fn execute_command_with_timeout(
        &mut self,
        cmd: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>, ClientError> {
        let tag = format!("A{:04}", self.tag_counter);
        self.tag_counter += 1;

        let full_cmd = format!("{} {}\r\n", tag, cmd);
        let (tx, rx) = oneshot::channel();

        self.command_tx
            .send((full_cmd, tx))
            .await
            .map_err(|_| ClientError::ConnectionClosed)?;

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(ClientError::ConnectionClosed),
            Err(_) => Err(ClientError::Timeout),
        }
    }
}

async fn write_loop<W>(
    mut write_half: W,
    mut command_rx: mpsc::Receiver<(String, CommandResponse)>,
    pending_commands: PendingCommands,
) where
    W: AsyncWrite + Unpin,
{
    while let Some((cmd, reply_tx)) = command_rx.recv().await {
        // Extract tag from the command
        let tag = cmd.split_whitespace().next().unwrap_or("").to_string();

        pending_commands.lock().await.insert(tag, reply_tx);

        if write_half.write_all(cmd.as_bytes()).await.is_err() {
            break;
        }
    }
}

async fn read_loop<R>(
    mut read_half: R,
    pending_commands: PendingCommands,
    event_tx: broadcast::Sender<Vec<u8>>,
) where
    R: AsyncRead + Unpin,
{
    let mut buffer = BytesMut::with_capacity(8192);

    loop {
        match read_half.read_buf(&mut buffer).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                // Try to parse as many responses as possible from the buffer
                while !buffer.is_empty() {
                    let (consumed, tag, is_status) =
                        match imap_core::parser::parse_response(&buffer) {
                            Ok((remaining, response)) => {
                                let consumed = buffer.len() - remaining.len();
                                let (tag, is_status) = match response {
                                    imap_core::ast::Response::Status(s) => {
                                        (s.tag.map(|t| t.to_string()), true)
                                    }
                                    _ => (None, false),
                                };
                                (consumed, tag, is_status)
                            }
                            Err(imap_core::error::ParseError::Incomplete) => break,
                            Err(_) => {
                                buffer.clear();
                                break;
                            }
                        };

                    let frame = buffer.split_to(consumed).to_vec();

                    if is_status {
                        if let Some(tag) = tag {
                            let mut map = pending_commands.lock().await;
                            if let Some(tx) = map.remove(&tag) {
                                let _ = tx.send(Ok(frame));
                            } else {
                                let _ = event_tx.send(frame);
                            }
                        } else {
                            let _ = event_tx.send(frame);
                        }
                    } else {
                        let _ = event_tx.send(frame);
                    }
                }
            }
            Err(_) => break,
        }
    }
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

        // Server receives: A0001 NOOP\r\n
        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        assert!(cmd.contains("NOOP"));
        let tag = cmd.split_whitespace().next().unwrap();

        // Server sends tagged response
        server_io
            .write_all(format!("{} OK NOOP completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let result = command_task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&result).contains("OK"));
    }

    #[tokio::test]
    async fn test_untagged_event_broadcasting() {
        let (client_io, mut server_io) = duplex(1024);
        let client = RawClient::new(client_io);
        let mut events = client.events();

        // Server sends untagged response
        server_io.write_all(b"* 5 EXISTS\r\n").await.unwrap();

        let event = events.recv().await.unwrap();
        assert_eq!(String::from_utf8_lossy(&event), "* 5 EXISTS\r\n");
    }

    #[tokio::test]
    async fn test_partial_read_reassembly() {
        let (client_io, mut server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);

        let command_task = tokio::spawn(async move { client.execute_command("NOOP").await });

        // Consume the command
        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let tag = String::from_utf8_lossy(&buf[..n])
            .split_whitespace()
            .next()
            .unwrap()
            .to_string();

        // Send response in tiny chunks
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

        // Send untagged SEARCH results AND tagged OK
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
    async fn test_store_command() {
        let (client_io, mut server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);

        let command_task =
            tokio::spawn(async move { client.execute_command("STORE 1 +FLAGS (\\Seen)").await });

        let mut buf = [0u8; 1024];
        let n = server_io.read(&mut buf).await.unwrap();
        let cmd = String::from_utf8_lossy(&buf[..n]);
        assert!(cmd.contains("STORE 1 +FLAGS (\\Seen)"));
        let tag = cmd.split_whitespace().next().unwrap();

        server_io
            .write_all(format!("{} OK STORE completed\r\n", tag).as_bytes())
            .await
            .unwrap();

        let result = command_task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&result).contains("OK"));
    }

    #[tokio::test]
    async fn test_connection_closed() {
        let (client_io, server_io) = duplex(1024);
        let mut client = RawClient::new(client_io);
        drop(server_io); // Close the connection

        let result = client.execute_command("NOOP").await;
        // Depending on timing, this could be Timeout or ConnectionClosed
        assert!(matches!(result, Err(ClientError::ConnectionClosed) | Err(ClientError::Timeout)));
    }

    #[tokio::test]
    async fn test_read_loop_eof() {
        let (client_io, server_io) = duplex(1024);
        let _client = RawClient::new(client_io);
        
        drop(server_io); // EOF
        
        // broadcast receiver will get RecvError::Closed if the sender is dropped,
        // but here the sender is in RawClient, which is still alive.
        // However, the read loop will exit.
        tokio::task::yield_now().await;
    }
}
