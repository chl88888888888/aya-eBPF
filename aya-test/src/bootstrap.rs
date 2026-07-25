//! Bootstrap helpers for the eBPF tracing system.
//!
//! Provides resource limit setup, log-pipe draining, and Redis PID
//! pinning so the eBPF probe filters on the target process.

use aya::maps::Array as AyaArray;
use aya::Ebpf;
use aya_log::EbpfLogger;
use log::{info, warn};

/// Raises the `RLIMIT_MEMLOCK` soft limit to infinity so large eBPF maps
/// can be created.
pub fn raise_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("setrlimit(RLIMIT_MEMLOCK) failed: {}", ret);
    }
}

/// Spawns an async task that drains the aya-log pipe (if the eBPF program
/// emits log statements).  Failure is non-fatal.
pub fn spawn_log_drain(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    match EbpfLogger::init(ebpf) {
        Ok(logger) => {
            let mut logger = tokio::io::unix::AsyncFd::with_interest(
                logger,
                tokio::io::Interest::READABLE,
            )?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
        Err(e) => warn!("eBPF logger init failed: {}", e),
    }
    Ok(())
}

/// Reads the PID file at `pid_file` and writes its value into the
/// `TARGET_PID` eBPF map so the probe filters to that process only.
/// If the file does not exist the function is a no-op.
pub fn pin_target_pid(ebpf: &mut Ebpf, pid_file: &str) -> anyhow::Result<()> {
    let pid_str = match std::fs::read_to_string(pid_file) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    let pid: u32 = pid_str.trim().parse()?;
    let mut pid_map: AyaArray<_, u32> =
        AyaArray::try_from(ebpf.map_mut("TARGET_PID").unwrap())?;
    let _ = pid_map.set(0, pid, 0);
    info!("Target Redis PID: {}", pid);
    Ok(())
}
