// Graceful Shutdown Handler (Phase 7)
//
// Manages the graceful shutdown lifecycle. When triggered:
//   1. Sets the shutdown flag (new requests get 503)
//   2. Notifies all waiters (via tokio::sync::Notify)
//   3. Waits for the drain timeout for in-flight requests to complete
//   4. Forces exit after drain timeout
//
// Usage:
//   let state = ShutdownState::new(30);
//   // In an async context:
//   tokio::select! {
//       _ = server => {}
//       _ = state.notified() => { /* shutdown triggered */ }
//   }
//   // ... when SIGTERM received:
//   state.initiate();

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Graceful shutdown state.
#[derive(Clone)]
pub struct ShutdownState {
    pub shutting_down: Arc<AtomicBool>,
    pub drain_timeout: Duration,
    /// Async notification for tokio::select! based shutdown.
    /// Callers can await `notified()` to be woken when shutdown begins.
    notify: Arc<tokio::sync::Notify>,
}

impl ShutdownState {
    pub fn new(drain_timeout_secs: u64) -> Self {
        Self {
            shutting_down: Arc::new(AtomicBool::new(false)),
            drain_timeout: Duration::from_secs(drain_timeout_secs),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Relaxed)
    }

    /// Initiate graceful shutdown.
    ///
    /// Sets the flag (ring health checks return 503) and
    /// notifies all async waiters via the internal Notify.
    pub fn initiate(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
        self.notify.notify_waiters();
        tracing::info!(
            timeout_secs = self.drain_timeout.as_secs(),
            "graceful shutdown initiated"
        );
    }

    /// Returns a future that resolves when `initiate()` is called.
    ///
    /// Use in `tokio::select!` to react to shutdown signals:
    ///   tokio::select! {
    ///       _ = server => {}
    ///       _ = shutdown.notified() => { /* handle shutdown */ }
    ///   }
    pub fn notified(&self) -> impl std::future::Future<Output = ()> + Send + '_ {
        self.notify.notified()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_state() {
        let state = ShutdownState::new(30);
        assert!(!state.is_shutting_down());
        state.initiate();
        assert!(state.is_shutting_down());
    }

    #[tokio::test]
    async fn notified_resolves_on_initiate() {
        let state = ShutdownState::new(30);
        let state_clone = state.clone();

        let handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            state_clone.initiate();
        });

        // This should resolve within ~50ms.
        state.notified().await;
        assert!(state.is_shutting_down());
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn clone_shares_notify() {
        let state = ShutdownState::new(30);
        let clone = state.clone();

        let state2 = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            state2.initiate();
        });

        clone.notified().await;
        assert!(clone.is_shutting_down());
    }
}
