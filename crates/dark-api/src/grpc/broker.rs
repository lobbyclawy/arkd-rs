//! Event brokers for streaming events to clients.

use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};

/// Broadcasts round lifecycle events to connected stream clients.
/// Buffers the last BatchStarted event so new subscribers don't miss it
/// if they connect after RegisterIntent but before the event was published.
#[derive(Clone)]
pub struct EventBroker {
    sender: broadcast::Sender<crate::proto::ark_v1::RoundEvent>,
    /// Buffered BatchStarted event for replay to late subscribers.
    last_batch_started: Arc<Mutex<Option<crate::proto::ark_v1::RoundEvent>>>,
}

impl EventBroker {
    /// Create a new EventBroker with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self {
            sender,
            last_batch_started: Arc::new(Mutex::new(None)),
        }
    }

    /// Publish an event to all connected subscribers. Returns the number of receivers.
    /// BatchStarted events are buffered for replay; other round events clear the buffer.
    pub fn publish(&self, event: crate::proto::ark_v1::RoundEvent) -> usize {
        if let Some(ref inner) = event.event {
            use crate::proto::ark_v1::round_event::Event;
            match inner {
                Event::BatchStarted(_) => {
                    // Buffer for replay to late subscribers
                    let buf = self.last_batch_started.clone();
                    let evt = event.clone();
                    tokio::spawn(async move {
                        *buf.lock().await = Some(evt);
                    });
                }
                _ => {
                    // Any other round event (finalized, skipped, etc.)
                    // means the batch is no longer active — clear the buffer.
                    let buf = self.last_batch_started.clone();
                    tokio::spawn(async move {
                        *buf.lock().await = None;
                    });
                }
            }
        }
        self.sender.send(event).unwrap_or(0)
    }

    /// Subscribe and receive the buffered BatchStarted event (if any).
    pub async fn subscribe_with_replay(
        &self,
    ) -> (
        broadcast::Receiver<crate::proto::ark_v1::RoundEvent>,
        Option<crate::proto::ark_v1::RoundEvent>,
    ) {
        let rx = self.sender.subscribe();
        let buffered = self.last_batch_started.lock().await.clone();
        (rx, buffered)
    }

    /// Subscribe to the event stream (without replay).
    pub fn subscribe(&self) -> broadcast::Receiver<crate::proto::ark_v1::RoundEvent> {
        self.sender.subscribe()
    }
}

/// Shared reference to an EventBroker.
pub type SharedEventBroker = Arc<EventBroker>;

/// Broadcasts transaction events to connected stream clients.
#[derive(Clone)]
pub struct TransactionEventBroker {
    sender: broadcast::Sender<crate::proto::ark_v1::TransactionEvent>,
}

impl TransactionEventBroker {
    /// Create a new TransactionEventBroker with the given channel capacity.
    pub fn new(capacity: usize) -> Self {
        let (sender, _) = broadcast::channel(capacity);
        Self { sender }
    }

    /// Publish a transaction event to all connected subscribers.
    pub fn publish(&self, event: crate::proto::ark_v1::TransactionEvent) {
        let _ = self.sender.send(event);
    }

    /// Subscribe to the transaction event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<crate::proto::ark_v1::TransactionEvent> {
        self.sender.subscribe()
    }
}

/// Shared reference to a TransactionEventBroker.
pub type SharedTransactionEventBroker = Arc<TransactionEventBroker>;
