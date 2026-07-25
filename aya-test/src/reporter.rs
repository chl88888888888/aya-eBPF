//! Periodic statistics reporter.
//!
//! Spawns an async task that prints four panels every `interval_secs`:
//! overall latency distribution (with QPS & bandwidth), per-command
//! breakdown, per-client-IP summary, and self-monitoring overhead.

use crate::monitor::ProcessMonitor;
use crate::stats::{ClientStats, CommandStats, LatencyStats};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Spawns an async task that prints statistics every `interval_secs`.
///
/// When `cmd_stats` or `client_stats` are `None`, the corresponding
/// report panels are silently skipped.
pub fn spawn_reporter(
    stats: Arc<Mutex<LatencyStats>>,
    cmd_stats: Option<Arc<Mutex<CommandStats>>>,
    client_stats: Option<Arc<Mutex<ClientStats>>>,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        let mut monitor = ProcessMonitor::new();
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        loop {
            interval.tick().await;
            stats.lock().unwrap().report(interval_secs);
            if let Some(ref cs) = cmd_stats {
                cs.lock().unwrap().report();
            }
            if let Some(ref cs) = client_stats {
                cs.lock().unwrap().report();
            }
            monitor.report();
        }
    });
}
