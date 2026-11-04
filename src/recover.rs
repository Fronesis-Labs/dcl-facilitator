//! Background recovery of persisted `SettlementUnknown` attempts.
//!
//! The worker starts with the process and does not wait for another
//! `/settle` request. It uses the settlement receipt path. A rebroadcast
//! sends only the stored signed bytes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::chain::{BaseRpc, Relayer};
use crate::settle::{self, Pass, SettleEnv};
use crate::store::Store;

pub const BACKOFF_BASE: Duration = Duration::from_millis(200);
pub const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// Next delay after an inconclusive pass. The wait doubles and stops at
/// [`BACKOFF_CAP`].
pub fn next_backoff(current: Duration) -> Duration {
    let doubled = current.checked_mul(2).unwrap_or(BACKOFF_CAP);
    if doubled < BACKOFF_BASE {
        BACKOFF_BASE
    } else {
        doubled.min(BACKOFF_CAP)
    }
}

pub struct Handle {
    shutdown: watch::Sender<bool>,
    stop: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

impl Handle {
    pub fn spawn(
        rpc: BaseRpc,
        store: Store,
        relayer: Relayer,
        oracle: [u8; 20],
        max_fee_per_gas: u128,
        receipt_timeout: Duration,
        now: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
    ) -> Self {
        let (shutdown, watch_rx) = watch::channel(false);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_task = Arc::clone(&stop);
        let join = tokio::spawn(async move {
            run(
                rpc,
                store,
                relayer,
                oracle,
                max_fee_per_gas,
                receipt_timeout,
                now,
                watch_rx,
                stop_for_task,
            )
            .await;
        });
        Self {
            shutdown,
            stop,
            join,
        }
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.shutdown.send(true);
    }

    /// Wakes the worker from a shutdown task that does not own the join handle.
    pub fn stopper(&self) -> impl Fn() + Send + Sync + 'static {
        let shutdown = self.shutdown.clone();
        let stop = Arc::clone(&self.stop);
        move || {
            stop.store(true, Ordering::SeqCst);
            let _ = shutdown.send(true);
        }
    }

    pub async fn shutdown(self) {
        self.request_stop();
        let _ = self.join.await;
    }
}

pub fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

async fn run(
    rpc: BaseRpc,
    store: Store,
    relayer: Relayer,
    oracle: [u8; 20],
    max_fee_per_gas: u128,
    receipt_timeout: Duration,
    now: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
    mut shutdown: watch::Receiver<bool>,
    stop: Arc<AtomicBool>,
) {
    tracing::info!("settlement recovery worker started");
    let mut delay = BACKOFF_BASE;
    loop {
        if stop.load(Ordering::SeqCst) || *shutdown.borrow() {
            break;
        }
        let Some(now) = now() else {
            delay = next_backoff(delay);
            if !wait_or_stop(&mut shutdown, &stop, delay).await {
                break;
            }
            continue;
        };
        let env = SettleEnv {
            rpc: &rpc,
            store: &store,
            relayer: &relayer,
            oracle,
            max_fee_per_gas,
            receipt_timeout,
            stop: Some(stop.as_ref()),
        };
        let pass = settle::recover_pass(&env, now).await;
        if stop.load(Ordering::SeqCst) {
            break;
        }
        delay = match pass {
            Pass::Inconclusive => next_backoff(delay),
            Pass::Idle | Pass::Progress => BACKOFF_BASE,
        };
        if !wait_or_stop(&mut shutdown, &stop, delay).await {
            break;
        }
    }
    tracing::info!("settlement recovery worker stopped");
}

async fn wait_or_stop(
    shutdown: &mut watch::Receiver<bool>,
    stop: &AtomicBool,
    delay: Duration,
) -> bool {
    if stop.load(Ordering::SeqCst) || *shutdown.borrow() {
        return false;
    }
    tokio::select! {
        _ = tokio::time::sleep(delay) => true,
        changed = shutdown.changed() => changed.is_ok() && !*shutdown.borrow() && !stop.load(Ordering::SeqCst),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_stops_at_the_cap() {
        assert_eq!(next_backoff(Duration::ZERO), BACKOFF_BASE);
        assert_eq!(next_backoff(BACKOFF_BASE), Duration::from_millis(400));
        assert_eq!(next_backoff(Duration::from_secs(20)), BACKOFF_CAP);
        assert_eq!(next_backoff(BACKOFF_CAP), BACKOFF_CAP);
    }
}
