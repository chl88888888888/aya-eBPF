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

    // Read Redis PID for explicit perf-event targeting.
    let redis_pid: u32 = std::fs::read_to_string(&cfg.pid_file)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

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

