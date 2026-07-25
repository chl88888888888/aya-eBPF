//! Latency, throughput, and connection-level statistics.
//!
//! - [`LatencyStats`] — HDR histogram + QPS & bandwidth deltas
//! - [`CommandStats`] — per-command latency breakdown (dynamic keys)
//! - [`ClientStats`] — per-client-IP request count & byte volume

use std::collections::HashMap;


// Formatting helpers


/// Formats a microsecond value with the best-fit unit.
///
/// - < 10 ms  → `"  73.45 us"`
/// - < 10 s   → `"  11.88 ms"`
/// - ≥ 10 s   → `"   1.63 s "`
fn fmt_latency(us: f64) -> String {
    if us < 10_000.0 {
        format!("{:>11.2} us", us)
    } else if us < 10_000_000.0 {
        format!("{:>11.2} ms", us / 1000.0)
    } else {
        format!("{:>11.2} s ", us / 1_000_000.0)
    }
}

/// Formats a throughput value (req/s) with auto-scaled units, always
/// producing a 15-column-wide cell.
fn fmt_throughput(rps: f64) -> String {
    if rps < 1000.0 {
        format!("{:>11.2} /s", rps)
    } else if rps < 1_000_000.0 {
        format!("{:>11.2} K/s", rps / 1000.0)
    } else {
        format!("{:>11.2} M/s", rps / 1_000_000.0)
    }
}

/// Formats bytes-per-second with auto-scaled units, always producing a
/// 15-column-wide cell.
fn fmt_bytes_per_sec(bps: f64) -> String {
    if bps < 1024.0 {
        format!("{:>11.2} B/s", bps)
    } else if bps < 1_048_576.0 {
        format!("{:>11.2} KB/s", bps / 1024.0)
    } else {
        format!("{:>11.2} MB/s", bps / 1_048_576.0)
    }
}

/// Truncates `name` to at most `max` bytes.  Redis command names are
/// always ASCII, so byte-length ≈ char-count.
fn truncate_cmd(name: &str, max: usize) -> &str {
    if name.len() <= max {
        name
    } else {
        &name[..max]
    }
}


// Latency statistics (HDR Histogram)


/// Wraps an [`hdrhistogram::Histogram`] and tracks total sample count.
pub struct LatencyStats {
    histogram: hdrhistogram::Histogram<u64>,
    total: u64,
    total_bytes: u64,
    prev_total: u64,
    prev_bytes: u64,
}

impl LatencyStats {
    /// Creates a histogram covering 1 ns .. 10 s with 3 significant digits.
    pub fn new() -> Self {
        Self {
            histogram: hdrhistogram::Histogram::<u64>::new_with_bounds(
                1,
                10_000_000_000,
                3,
            )
            .expect("Failed to create HDR histogram"),
            total: 0,
            total_bytes: 0,
            prev_total: 0,
            prev_bytes: 0,
        }
    }

    /// Records a single latency sample (in nanoseconds).
    #[inline]
    pub fn record(&mut self, latency_ns: u64, bytes: u64) {
        let _ = self.histogram.record(latency_ns);
        self.total += 1;
        self.total_bytes += bytes;
    }

    /// Returns the total number of recorded samples.
    #[inline]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Prints a formatted latency summary to stdout, including QPS.
    pub fn report(&mut self, interval_secs: u64) {
        if self.total == 0 {
            return;
        }

        let h = &self.histogram;

        // QPS + throughput = deltas since last report
        let delta = self.total.saturating_sub(self.prev_total);
        let delta_bytes = self.total_bytes.saturating_sub(self.prev_bytes);
        let qps_str = fmt_throughput(delta as f64 / interval_secs as f64);
        let bw_str = fmt_bytes_per_sec(delta_bytes as f64 / interval_secs as f64);
        self.prev_total = self.total;
        self.prev_bytes = self.total_bytes;

        let avg = fmt_latency(h.mean() / 1000.0);
        let p50 = fmt_latency(self.pct(50.0));
        let p90 = fmt_latency(self.pct(90.0));
        let p95 = fmt_latency(self.pct(95.0));
        let p99 = fmt_latency(self.pct(99.0));
        let p999 = fmt_latency(self.pct(99.9));
        let min = fmt_latency(h.min() as f64 / 1000.0);
        let max = fmt_latency(h.max() as f64 / 1000.0);

        println!(
            "\
┌──────────────────────────────────────────────────┐
│  Redis Latency Stats ({req:>10} requests)        │
├──────────────────────────────────────────────────┤
│  QPS:  {qps}                             │
│  BW:   {bw}                              │
│  Avg:  {avg}                             │
│  P50:  {p50}                             │
│  P90:  {p90}                             │
│  P95:  {p95}                             │
│  P99:  {p99}                             │
│  P999: {p999}                             │
│  Min:  {min}                             │
│  Max:  {max}                             │
└──────────────────────────────────────────────────┘",
            req = self.total,
            qps = qps_str,
            bw = bw_str,
            avg = avg,
            p50 = p50,
            p90 = p90,
            p95 = p95,
            p99 = p99,
            p999 = p999,
            min = min,
            max = max,
        );
    }

    /// Returns the value at the given percentile in microseconds.
    #[inline]
    pub fn pct(&self, p: f64) -> f64 {
        self.histogram.value_at_quantile(p / 100.0) as f64 / 1000.0
    }

    /// Returns a reference to the underlying histogram.
    #[inline]
    pub fn histogram(&self) -> &hdrhistogram::Histogram<u64> {
        &self.histogram
    }
}


// Command-level statistics


/// Maintains a per-command [`LatencyStats`] map keyed by command name.
pub struct CommandStats {
    commands: HashMap<String, LatencyStats>,
}

impl CommandStats {
    pub fn new() -> Self {
        Self {
            commands: HashMap::new(),
        }
    }

    /// Routes a sample to the correct per-command bucket.
    ///
    /// First does a cheap `get_mut` to avoid allocation when the
    /// command is already known (the common case).  Only allocates
    /// a `String` key on first encounter of a new command.
    #[inline]
    pub fn record(&mut self, cmd_name: &str, latency_ns: u64, bytes: u64) {
        if let Some(stats) = self.commands.get_mut(cmd_name) {
            stats.record(latency_ns, bytes);
        } else {
            let mut s = LatencyStats::new();
            s.record(latency_ns, bytes);
            self.commands.insert(cmd_name.to_string(), s);
        }
    }

    /// Prints per-command latency breakdown to stdout.
    pub fn report(&self) {
        let mut entries: Vec<(&String, &LatencyStats)> = self
            .commands
            .iter()
            .filter(|(_, s)| s.total() > 0)
            .collect();
        entries.sort_by(|(_, a), (_, b)| b.total().cmp(&a.total()));
        if entries.is_empty() {
            return;
        }

        println!(
            "\
┌──────────────────────────────────────────────────────┐
│  Redis Command-Level Latency                         │
├──────────────────────────────────────────────────────┤
│  {:<14} {:>6}  {:>15}  {:>15}  {:>15} │
├──────────────────────────────────────────────────────┤",
            "Command", "Count", "Avg", "P95", "P99"
        );

        for (cmd, stats) in &entries {
            let avg = fmt_latency(stats.histogram().mean() / 1000.0);
            let p95 = fmt_latency(stats.pct(95.0));
            let p99 = fmt_latency(stats.pct(99.0));
            println!(
                "│  {:<14} {:>6}  {}  {}  {} │",
                truncate_cmd(cmd, 14),
                stats.total(),
                avg,
                p95,
                p99,
            );
        }
        println!("└──────────────────────────────────────────────────────┘\n");
    }
}


// Client-level statistics (per source IP)


/// Per-client aggregate stored under an IPv4 address key.
struct ClientInfo {
    count: u64,
    total_bytes: u64,
}

/// Tracks request count and bytes per client IPv4 address.
pub struct ClientStats {
    clients: HashMap<u32, ClientInfo>,
}

impl ClientStats {
    pub fn new() -> Self {
        Self { clients: HashMap::new() }
    }

    /// Records one request from the given client.
    #[inline]
    pub fn record(&mut self, ip: u32, bytes: u64) {
        let entry = self.clients.entry(ip).or_insert(ClientInfo {
            count: 0,
            total_bytes: 0,
        });
        entry.count += 1;
        entry.total_bytes += bytes;
    }

    /// Prints a per-client summary (top 10 by request count).
    pub fn report(&self) {
        if self.clients.is_empty() {
            return;
        }
        let mut entries: Vec<(&u32, &ClientInfo)> =
            self.clients.iter().collect();
        entries.sort_by(|(_, a), (_, b)| b.count.cmp(&a.count));
        let top = entries.iter().take(10);

        println!(
            "\
┌─────────────────────────────────────────────────────────────┐\
\n│  Client Stats (top 10 by requests)                          │\
\n├─────────────────────────────────────────────────────────────┤\
\n│  {:<15} {:>8} {:>15} {:>12} │\
\n├─────────────────────────────────────────────────────────────┤",
            "Client IP", "Requests", "Total Bytes", "Share %"
        );

        let total: u64 = entries.iter().map(|(_, i)| i.count).sum();
        for (ip, info) in top {
            let share = if total > 0 {
                info.count as f64 / total as f64 * 100.0
            } else {
                0.0
            };
            let bw = fmt_bytes_cell(info.total_bytes);
            println!(
                "│  {:<15} {:>8} {:>15} {:>11.1}% │",
                ipv4_str(**ip),
                info.count,
                bw,
                share,
            );
        }
        println!("└─────────────────────────────────────────────────────────────┘\n");
    }
}

/// Formats a byte count as a right-aligned 15-column cell with
/// auto-scaled unit (B / KB / MB / GB).
fn fmt_bytes_cell(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{:>12} B", bytes)
    } else if bytes < 1_048_576 {
        format!("{:>11.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1_073_741_824 {
        format!("{:>11.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{:>11.2} GB", bytes as f64 / 1_073_741_824.0)
    }
}

/// Renders a u32 IPv4 address in dotted-decimal format.
fn ipv4_str(ip: u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF,
    )
}
