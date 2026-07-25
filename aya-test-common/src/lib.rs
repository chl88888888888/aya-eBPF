//! Shared data structures for the Redis eBPF performance tracing system.
//!
//! This crate defines types used by both the eBPF kernel-space probe
//! (`aya-test-ebpf`) and the userspace collector (`aya-test`).
//! All structs are `#[repr(C)]` to guarantee a stable ABI across the
//! kernel/userspace boundary.

#![no_std]

/// Legacy command enumeration — **no longer used by userspace**.
///
/// Command classification is now fully dynamic via userspace RESP
/// parsing.  This enum is kept for the `command: u8` field in
/// [`LatencyEvent`] to maintain ABI compatibility; the probe always
/// writes `0` and userspace ignores it.
#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum RedisCommand {
    Unknown = 0,
    GET     = 1,
    SET     = 2,
    DEL     = 3,
    INCR    = 4,
    HGET    = 5,
    HSET    = 6,
    LPUSH   = 7,
    PUBLISH = 8,
    PING    = 9,
    INFO    = 10,
    MGET    = 11,
    MSET    = 12,
}

impl RedisCommand {
    #[inline]
    pub fn name(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::GET     => "GET",
            Self::SET     => "SET",
            Self::DEL     => "DEL",
            Self::INCR    => "INCR",
            Self::HGET    => "HGET",
            Self::HSET    => "HSET",
            Self::LPUSH   => "LPUSH",
            Self::PUBLISH => "PUBLISH",
            Self::PING    => "PING",
            Self::INFO    => "INFO",
            Self::MGET    => "MGET",
            Self::MSET    => "MSET",
        }
    }
}

/// A single request-response latency sample produced by the eBPF probe.
///
/// Flows from kernel RingBuf to the userspace collector.
///
/// # Fields
///
/// | Field         | Source                              |
/// |---------------|-------------------------------------|
/// | `pid`/`tid`   | Probe context                       |
/// | `latency_ns`  | recvmsg → sendmsg time delta        |
/// | `bytes`       | sendmsg return value                |
/// | `client_ip`   | Extracted from `sk` in recvmsg      |
/// | `client_port` | Extracted from `sk` in recvmsg      |
/// | `req_data`    | First 32 bytes of user buffer       |
#[derive(Copy, Clone)]
#[repr(C)]
pub struct LatencyEvent {
    pub pid: u32,
    pub tid: u32,
    pub latency_ns: u64,
    /// Bytes written back to the client.
    pub bytes: u32,
    /// Client IPv4 address (host byte order).
    pub client_ip: u32,
    /// Client source port (host byte order).
    pub client_port: u16,
    /// Legacy field — reserved for future eBPF-side classification.
    pub command: u8,
    /// Non-zero when sendmsg returned an error.
    pub is_error: u8,
    /// Raw request bytes captured from the TCP receive buffer.
    pub req_data: [u8; 32],
}

const _LATENCY_SIZE_CHECK: () =
    assert!(core::mem::size_of::<LatencyEvent>() <= 64);

/// A TCP connection lifecycle event (connect / close).
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ConnEvent {
    pub pid: u32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    /// `0` for connect, `1` for close.
    pub event_type: u8,
    pub padding: [u8; 3],
    pub timestamp_ns: u64,
}

/// Per-CPU I/O counters aggregated by the kernel probe.
///
/// Because this is stored in a [`PerCpuArray`], the userspace collector
/// must sum across all CPUs to obtain global totals.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct PerCpuCounters {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub connect_ops: u64,
    pub close_ops: u64,
    pub error_ops: u64,
}

/// A single syscall trace event.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SyscallEvent {
    pub pid: u32,
    pub syscall_id: u32,
    pub latency_ns: u64,
    pub retval: i64,
}

/// Maximum number of stack frames captured per sample.
pub const MAX_STACK_FRAMES: usize = 20;

/// A stack sample captured by the perf_event CPU sampling probe.
///
/// `bpf_get_stack()` fills `kstack_ips` (kernel frames) and
/// `ustack_ips` (user frames).  The `_len` fields report how many
/// u64 entries are valid; `-1` means the stack walk failed.
///
/// Total struct size ≈ 24 (header) + 320 (IPs) = 344 bytes — well
/// within the 512-byte eBPF stack budget.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct StackEvent {
    pub pid: u32,
    pub cpu: u32,
    /// Number of kernel IPs, or `-1` on error.
    pub kstack_len: i32,
    /// Number of user IPs, or `-1` on error.
    pub ustack_len: i32,
    /// Nanosecond timestamp when the sample was taken.
    pub timestamp_ns: u64,
    /// Raw kernel instruction pointers (0-padded).
    pub kstack_ips: [u64; MAX_STACK_FRAMES],
    /// Raw user instruction pointers (0-padded).
    pub ustack_ips: [u64; MAX_STACK_FRAMES],
}

/// Compile-time guard: `StackEvent` must not exceed 512 bytes.
const _STACK_SIZE_CHECK: () =
    assert!(core::mem::size_of::<StackEvent>() <= 512);

/// Control-plane commands sent from userspace to the eBPF program.
#[repr(u32)]
pub enum EbpfCommand {
    EnableLatencyTracing  = 1,
    EnableFlameGraph      = 2,
    EnableProtocolParsing = 3,
    EnableAll             = 0xFFFFFFFF,
}


// userspace-only helper: RESP protocol command detection


#[cfg(feature = "user")]
impl RedisCommand {
    /// Attempts to classify a raw RESP-encoded request payload.
    ///
    /// Returns [`RedisCommand::Unknown`] if the payload is too short or
    /// does not start with the RESP array prefix `*`.
    pub fn detect(data: &[u8]) -> Self {
        if data.len() < 3 || data.first() != Some(&b'*') {
            return Self::Unknown;
        }

        // Static lookup table: (keyword_bytes, command_variant).
        // Iteration is cheap (13 entries) and avoids a long if-else chain.
        const TABLE: &[(&[u8], RedisCommand)] = &[
            (b"GET",     RedisCommand::GET),
            (b"SET",     RedisCommand::SET),
            (b"DEL",     RedisCommand::DEL),
            (b"INCR",    RedisCommand::INCR),
            (b"HGET",    RedisCommand::HGET),
            (b"HSET",    RedisCommand::HSET),
            (b"LPUSH",   RedisCommand::LPUSH),
            (b"PUBLISH", RedisCommand::PUBLISH),
            (b"PING",    RedisCommand::PING),
            (b"INFO",    RedisCommand::INFO),
            (b"MGET",    RedisCommand::MGET),
            (b"MSET",    RedisCommand::MSET),
        ];

        TABLE
            .iter()
            .find(|(keyword, _)| data.windows(keyword.len()).any(|w| w == *keyword))
            .map(|(_, cmd)| *cmd)
            .unwrap_or(Self::Unknown)
    }
}
