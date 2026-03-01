use std::sync::Arc;

use tokio::sync::broadcast;
use tracing::instrument;

use super::types::AuthEvent;

const BUS_CAPACITY: usize = 256;

/// Async broadcast event bus.
///
/// Plugins subscribe at startup and receive every event emitted during
/// request processing. Receivers that fall behind drop old events (broadcast
/// semantics — no backpressure, no blocking on slow listeners).
#[derive(Clone)]
pub struct EventBus {
    sender: Arc<broadcast::Sender<AuthEvent>>,
}

impl EventBus {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(BUS_CAPACITY);
        Self { sender: Arc::new(sender) }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AuthEvent> {
        self.sender.subscribe()
    }

    #[instrument(skip(self, event), fields(event = event.name()))]
    pub fn emit(&self, event: AuthEvent) {
        let name = event.name();
        match self.sender.send(event) {
            Ok(n)  => tracing::debug!(listeners = n, event = name, "event emitted"),
            Err(_) => tracing::debug!(event = name, "no listeners for event"),
        }
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
