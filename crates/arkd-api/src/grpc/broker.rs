//! Event broker for streaming round lifecycle events to clients.

use std::sync::Arc;
use tokio::sync::broadcast;

/// Broadcasts round lifecycle events to connected stream clients.
#[derive(Clone)]
pub struct EventBroker {
    sender: broadcast::Sender<crate::proto::ark_v1::RoundEvent>,
}

impl EventBroker {
    /// Create a new EventBroker with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish an event to all connected subscribers.
    pub fn publish(&self, event: crate::proto::ark_v1::RoundEvent) {
        let _ = self.sender.send(event);
    }

    /// Subscribe to the event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<crate::proto::ark_v1::RoundEvent> {
        self.sender.subscribe()
    }
}

/// Shared reference to an EventBroker.
pub type SharedEventBroker = Arc<EventBroker>;
