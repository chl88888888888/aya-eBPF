//! Ring buffer reader tasks.
//!
//! Spawns async tasks that use epoll (via [`AsyncFd`]) to wait for
//! eBPF ring buffer data and feed it into the shared statistics and
//! flame-graph sample collections — no busy-waiting, no thread::sleep.

use crate::resp::classify_command;
use crate::stats::{ClientStats, CommandStats, LatencyStats};
use aya::maps::RingBuf;
use aya_test_common::{LatencyEvent, StackEvent};
use std::mem::size_of;
use std::sync::{Arc, Mutex};
use tokio::io::unix::AsyncFd;

/// Drains the [`RingBuf`] indefinitely from an async task, awaiting
/// kernel wake-ups via epoll when no data is available.
///
/// Events are collected into a batch first (no locks), then processed
/// with a single lock acquisition per cycle — reducing per-event
/// mutex overhead by ~99.6% (256× amortisation).
pub fn spawn_ringbuf_reader(
    ring_buf: RingBuf<aya::maps::MapData>,
    stats: Arc<Mutex<LatencyStats>>,
    cmd_stats: Arc<Mutex<CommandStats>>,
    client_stats: Arc<Mutex<ClientStats>>,
) {
    let mut ring_buf = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)
        .expect("Failed to create AsyncFd for LATENCY_RINGBUF");

    tokio::spawn(async move {
        // Reusable batch buffer — avoids per-event allocations.
        let mut batch: Vec<LatencyEvent> = Vec::with_capacity(256);
        loop {
            let mut guard = ring_buf.readable_mut().await.unwrap();

            // ── Phase 1: collect (zero locks, zero allocations) ──
            while let Some(item) = guard.get_inner_mut().next() {
                let bytes: &[u8] = &item;
                if bytes.len() < size_of::<LatencyEvent>() {
                    continue;
                }
                let ev: LatencyEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const LatencyEvent) };
                batch.push(ev);
            }
            guard.clear_ready();

            // ── Phase 2: process batch (lock once) ──
            if !batch.is_empty() {
                let mut s = stats.lock().unwrap();
                let mut cs = cmd_stats.lock().unwrap();
                let mut cl = client_stats.lock().unwrap();
                for ev in batch.drain(..) {
                    let cmd = classify_command(&ev.req_data);
                    s.record(ev.latency_ns, ev.bytes as u64);
                    cs.record(cmd.as_ref(), ev.latency_ns, ev.bytes as u64);
                    if ev.client_ip != 0 {
                        cl.record(ev.client_ip, ev.bytes as u64);
                    }
                }
            }
        }
    });
}

/// Drains the `STACK_RINGBUF` into `samples` from an async task.
///
/// Stack events are batched and pushed with a single lock acquisition
/// per epoll cycle.
pub fn spawn_stack_reader(
    ring: RingBuf<aya::maps::MapData>,
    samples: Arc<Mutex<Vec<StackEvent>>>,
) {
    let mut ring = AsyncFd::with_interest(ring, tokio::io::Interest::READABLE)
        .expect("Failed to create AsyncFd for STACK_RINGBUF");

    tokio::spawn(async move {
        // Reusable batch buffer.
        let mut batch: Vec<StackEvent> = Vec::with_capacity(256);
        loop {
            let mut guard = ring.readable_mut().await.unwrap();

            // ── Phase 1: collect ──
            while let Some(item) = guard.get_inner_mut().next() {
                let bytes: &[u8] = &item;
                if bytes.len() < size_of::<StackEvent>() {
                    continue;
                }
                let ev: StackEvent =
                    unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const StackEvent) };
                batch.push(ev);
            }
            guard.clear_ready();

            // ── Phase 2: push batch (lock once) ──
            if !batch.is_empty() {
                let mut s = samples.lock().unwrap();
                s.extend(batch.drain(..));
            }
        }
    });
}
