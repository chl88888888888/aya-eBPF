//! Userspace collector for the Redis eBPF performance tracing system.
//!
//! # Data flow
//!
//! ```text
//! [eBPF kprobe] ──RingBuf──> [AsyncFd/epoll reader] ──(LatencyEvent)──> [LatencyStats]
//!                                                                    ├─ [CommandStats]
//!                                                                    ├─ [ClientStats]
//!                                                                    └─ [ProcessMonitor]
//! [perf_event]  ──STACK_RINGBUF──> [AsyncFd/epoll reader] ──(StackEvent)──> [flamegraph]
//! ```
//!
//! # Module layout
//!
//! | Module         | Purpose                                            |
//! |----------------|----------------------------------------------------|
//! | [`resp`]       | Lightweight RESP command extraction                |
//! | [`stats`]      | HDR histogram latency, QPS/BW, per-cmd/per-IP stats|
//! | [`config`]     | TOML file + CLI argument resolution                |
//! | [`bootstrap`]  | memlock, log drain, PID pinning                    |
//! | [`reader`]     | Epoll-driven RingBuf drainers                      |
//! | [`reporter`]   | Periodic multi-panel stats printer                 |
//! | [`monitor`]    | Self-monitoring via /proc/self/stat                |
//! | [`probes`]     | kprobe & perf_event attachment                     |
//! | [`flamegraph`] | SVG flame graph via inferno                        |
//! | [`symbolizer`] | IP → symbol resolution via /proc/kallsyms          |

mod bootstrap;
mod config;
mod flamegraph;
mod monitor;
mod probes;
mod reader;
mod reporter;
mod resp;
mod stats;
mod symbolizer;

use aya::maps::RingBuf;
use aya::{include_bytes_aligned, Ebpf};
use aya_test_common::StackEvent;
use clap::Parser;
use config::Config;
use log::{info, warn};
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::sync::{Arc, Mutex};
use tokio::signal;


// Entry point


#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = config::Cli::parse();
    let cfg = Config::load(&cli)?;
    info!("Configuration: {:?}", cfg);

    // Redirect stdout to a persistent log file when --output is set.
    if let Some(path) = &cfg.output_file {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let fd = file.as_raw_fd();
        unsafe { libc::dup2(fd, libc::STDOUT_FILENO) };
    }

    bootstrap::raise_memlock();

    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/aya-test"
    )))?;

    bootstrap::spawn_log_drain(&mut ebpf)?;
    bootstrap::pin_target_pid(&mut ebpf, &cfg.pid_file)?;
    probes::attach_probes(&mut ebpf)?;

    // ── Latency RingBuf ────────────────────────────────────────────
    let ring_buf: RingBuf<_> =
        RingBuf::try_from(ebpf.take_map("LATENCY_RINGBUF").unwrap())?;

    let stats = Arc::new(Mutex::new(stats::LatencyStats::new()));
    let cmd_stats = Arc::new(Mutex::new(stats::CommandStats::new()));
    let client_stats = Arc::new(Mutex::new(stats::ClientStats::new()));

    reader::spawn_ringbuf_reader(ring_buf, stats.clone(), cmd_stats.clone(), client_stats.clone());
    reporter::spawn_reporter(stats, Some(cmd_stats), Some(client_stats), cfg.interval_secs);

    // ── Flame graph: perf_event CPU sampling ───────────────────────
    let flame_samples = Arc::new(Mutex::new(Vec::<StackEvent>::new()));

    // Resolve Redis PID: prefer pid_file, fall back to /proc scan.
    let redis_pid: u32 = resolve_redis_pid(&cfg.pid_file);

    match probes::attach_perf_event(&mut ebpf, redis_pid, cfg.frequency_hz) {
        Ok(_) => {
            probes::enable_flamegraph(&mut ebpf)?;

            let stack_ring: RingBuf<_> =
                RingBuf::try_from(ebpf.take_map("STACK_RINGBUF").unwrap())?;
            reader::spawn_stack_reader(stack_ring, flame_samples.clone());

            info!("Flame-graph CPU sampling enabled ({} Hz)", cfg.frequency_hz);
        }
        Err(e) => warn!("Perf-event attach failed (no flame graph): {:#}", e),
    }

    println!(">>> Redis eBPF Performance Tracing System started");
    println!(
        ">>> Printing stats every {}s, press Ctrl-C to exit\n",
        cfg.interval_secs
    );

    signal::ctrl_c().await?;
    println!("\n>>> Exiting...");

    // ── Generate flame graph on exit ───────────────────────────────
    {
        let samples = flame_samples.lock().unwrap();
        if !samples.is_empty() {
            if let Err(e) = flamegraph::generate_flamegraph_svg(&samples, &cfg.flamegraph_output) {
                warn!("Failed to generate flame graph: {}", e);
            }
        } else {
            info!("No stack samples collected — skipping flame graph");
        }
    }

    Ok(())
}

/// Resolve the Redis process PID.
///
/// Tries the PID file first; if that fails, scans /proc for a process
/// named `valkey-server` or `redis-server` listening on the default port.
fn resolve_redis_pid(pid_file: &str) -> u32 {
    use std::fs;

    // 1. Try the PID file.
    if let Ok(s) = fs::read_to_string(pid_file) {
        if let Ok(pid) = s.trim().parse::<u32>() {
            if pid > 1 && fs::metadata(&format!("/proc/{}", pid)).is_ok() {
                return pid;
            }
        }
    }

    // 2. Fallback: scan /proc for valkey-server or redis-server.
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let comm_path = entry.path().join("comm");
            if let Ok(comm) = fs::read_to_string(&comm_path) {
                let comm = comm.trim();
                if comm == "valkey-server" || comm == "redis-server" {
                    if let Some(pid_str) = entry.file_name().to_str() {
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            if pid > 1 {
                                info!("Auto-detected {} PID {} from /proc", comm, pid);
                                return pid;
                            }
                        }
                    }
                }
            }
        }
    }

    warn!("Cannot resolve Redis PID — flame graph will be unavailable");
    0
}

