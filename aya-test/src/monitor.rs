//! Self-monitoring for the aya-test process.
//!
//! Reads `/proc/self/stat` periodically to track CPU%, RSS, VSZ, and
//! thread count, so users can quantify the overhead of eBPF tracing.

use std::time::Instant;

/// Snapshots `/proc/self/stat` and computes CPU utilisation as the delta
/// between two consecutive readings.
pub struct ProcessMonitor {
    prev: Option<(Instant, u64)>, // (wall_time, cpu_ticks)
}

impl ProcessMonitor {
    pub fn new() -> Self {
        Self { prev: None }
    }

    // ── /proc/self/stat reader ────────────────────────────────────
    //
    // Field layout after the `)` that closes `(comm)`:
    //
    //  [11]  utime        (u64, user   ticks)
    //  [12]  stime        (u64, system ticks)
    //  [17]  num_threads  (i64)
    //  [20]  vsize        (u64, bytes)
    //  [21]  rss          (i64, pages)

    #[rustfmt::skip]
    fn read_stat(&self) -> Option<(u64, u64, i64, u64, u64)> {
        let raw = std::fs::read_to_string("/proc/self/stat").ok()?;
        let after = raw.find(')')?; // skip pid & (comm)
        let rest = &raw[after + 2..]; // skip ") "
        let f: Vec<&str> = rest.split_whitespace().collect();

        let utime:  u64 = f.get(11)?.parse().ok()?;
        let stime:  u64 = f.get(12)?.parse().ok()?;
        let threads: i64 = f.get(17)?.parse().ok()?;
        let vsize:  u64 = f.get(20)?.parse().ok()?;
        let rss_pg:  i64 = f.get(21)?.parse().ok()?;

        let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        let rss = rss_pg as u64 * page_sz;

        Some((utime, stime, threads, vsize, rss))
    }

    /// Prints CPU%, RSS, VSZ, threads, and uptime since this struct was
    /// first created.  CPU% is the fraction of *one* CPU core used since
    /// the previous call (may exceed 100 % for multi-threaded programs).
    pub fn report(&mut self) {
        let now = Instant::now();
        let (utime, stime, threads, vsize, rss) = match self.read_stat() {
            Some(v) => v,
            None => return,
        };
        let ticks = utime + stime;

        let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;

        let cpu_pct = if let Some((prev_inst, prev_ticks)) = self.prev {
            let dw = (now - prev_inst).as_secs_f64();
            let dt = ticks.saturating_sub(prev_ticks) as f64;
            if dw > 0.0 { (dt / clk_tck) / dw * 100.0 } else { 0.0 }
        } else {
            0.0
        };

        self.prev = Some((now, ticks));

        let rss_mb  = rss as f64 / 1_048_576.0;
        let vsize_mb = vsize as f64 / 1_048_576.0;

        println!(
            "\
┌──────────────────────────────────────────────────┐\
\n│  Self-Monitoring (aya-test overhead)             │\
\n├──────────────────────────────────────────────────┤\
\n│  CPU:   {cpu:>11.2} %                            │\
\n│  RSS:  {rss:>11.2} MB                            │\
\n│  VSZ:  {vsz:>11.2} MB                            │\
\n│  Threads: {thr:>9}                               │\
\n└──────────────────────────────────────────────────┘\
\n",
            cpu = cpu_pct,
            rss = rss_mb,
            vsz = vsize_mb,
            thr = threads,
        );
    }
}
