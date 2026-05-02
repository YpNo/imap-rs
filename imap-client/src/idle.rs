use crate::error::ClientError;
use tokio::sync::oneshot;

/// Handle to manage an active IDLE session.
pub struct IdleHandle {
    done_tx: oneshot::Sender<()>,
}

impl IdleHandle {
    pub fn new(done_tx: oneshot::Sender<()>) -> Self {
        Self { done_tx }
    }

    /// Sends the DONE continuation to the server to terminate the IDLE session.
    pub async fn stop(self) -> Result<(), ClientError> {
        let _ = self.done_tx.send(());
        // In a complete implementation, this would wait for the final OK response.
        Ok(())
    }
}
