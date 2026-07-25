//! eBPF kernel-space probes for Redis latency tracing (fentry/fexit).
//!
//! Hooks `tcp_recvmsg` (fentry + fexit) and `tcp_sendmsg` (fexit)
//! with a single consolidated `ReqCtx` map keyed by TID.

#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{fentry, fexit, map, perf_event},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, FExitContext, PerfEventContext},
    EbpfContext,
};
use aya_ebpf_bindings::helpers::{
    bpf_get_smp_processor_id, bpf_get_stack, bpf_ktime_get_ns,
    bpf_probe_read_kernel, bpf_probe_read_user,
};
use aya_ebpf_bindings::bindings::BPF_F_USER_STACK;
use aya_test_common::LatencyEvent;

#[inline]
fn now_ns() -> u64 { unsafe { bpf_ktime_get_ns() } }


// Data structures


const MAX_STACK_FRAMES: usize = 20;

#[derive(Copy, Clone)]
#[repr(C)]
struct StackEvent {
    pid: u32, cpu: u32, kstack_len: i32, ustack_len: i32,
    timestamp_ns: u64,
    kstack_ips: [u64; MAX_STACK_FRAMES],
    ustack_ips: [u64; MAX_STACK_FRAMES],
}

/// Consolidated per-request context.
#[derive(Copy, Clone)]
#[repr(C)]
struct ReqCtx {
    start_ns: u64,
    iov_base: u64,
    client_packed: u64,
    req_data: [u8; 32],
}


// eBPF maps

#[map]
static REQ_CTX: HashMap<u32, ReqCtx> = HashMap::with_max_entries(10240, 0);

#[map]
static LATENCY_RINGBUF: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

#[map]
static TARGET_PID: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static STACK_RINGBUF: RingBuf = RingBuf::with_byte_size(2 * 1024 * 1024, 0);

#[map]
static FLAMEGRAPH_ON: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

#[map]
static BATCH_CNT: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

const BATCH_SIZE: u32 = 16;
const BPF_RB_NO_WAKEUP: u64 = 1;
const BPF_RB_FORCE_WAKEUP: u64 = 2;


// fentry : tcp_recvmsg


#[fentry(function = "tcp_recvmsg")]
pub fn on_tcp_recvmsg(ctx: FEntryContext) -> u32 {
    match unsafe { try_on_recvmsg(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_on_recvmsg(ctx: &FEntryContext) -> Result<u32, i64> {
    if !is_target_pid(ctx.pid()) { return Ok(0); }

    let tid = ctx.tgid();
    let now = now_ns();

    let mut client_packed: u64 = 0;
    let mut iov_base: u64 = 0;

    let sk_ptr = ctx.arg::<u64>(0);
    if sk_ptr != 0 {
        use core::ffi::c_void;
        let mut ip: u32 = 0; let mut port: u16 = 0;
        let _ = bpf_probe_read_kernel(&raw mut ip as *mut _ as *mut c_void, 4, (sk_ptr + 4) as *const c_void);
        let _ = bpf_probe_read_kernel(&raw mut port as *mut _ as *mut c_void, 2, (sk_ptr + 12) as *const c_void);
        client_packed = (u32::from_be(ip) as u64) << 16 | (u16::from_be(port) as u64);
    }

    let msg = ctx.arg::<u64>(1);
    if msg != 0 {
        use core::ffi::c_void;
        let ret = bpf_probe_read_kernel(&raw mut iov_base as *mut _ as *mut c_void, 8, (msg as *const u8).add(32) as *const c_void);
        if ret < 0 { iov_base = 0; }
    }

    let ctx_val = ReqCtx { start_ns: now, iov_base, client_packed, req_data: [0u8; 32] };
    let _ = REQ_CTX.insert(&tid, &ctx_val, 0);

    Ok(0)
}


// fexit : tcp_recvmsg


#[fexit(function = "tcp_recvmsg")]
pub fn on_tcp_recvmsg_ret(ctx: FExitContext) -> u32 {
    match unsafe { try_on_recvmsg_ret(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_on_recvmsg_ret(_ctx: &FExitContext) -> Result<u32, i64> {
    if !is_target_pid(_ctx.pid()) { return Ok(0); }

    use core::ffi::c_void;
    let tid = _ctx.tgid();

    // Step A: read iov_base via immutable get (no lock across helpers)
    let iov_base = match REQ_CTX.get(&tid) {
        Some(ctx) => ctx.iov_base,
        None => return Ok(0),
    };
    if iov_base == 0 { return Ok(0); }

    // Step B: bpf_probe_read_user into stack — no map lock held
    let mut data = [0u8; 32];
    unsafe { bpf_probe_read_user(data.as_mut_ptr() as *mut c_void, 32, iov_base as *const c_void); }

    // Step C: write result in-place — brief lock
    if let Some(ctx) = REQ_CTX.get_ptr_mut(&tid) {
        unsafe { (*ctx).req_data = data; (*ctx).iov_base = 0; }
    }

    Ok(0)
}


// fexit : tcp_sendmsg


#[fexit(function = "tcp_sendmsg")]
pub fn on_tcp_sendmsg(ctx: FExitContext) -> u32 {
    match unsafe { try_on_sendmsg(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_on_sendmsg(ctx: &FExitContext) -> Result<u32, i64> {
    if !is_target_pid(ctx.pid()) { return Ok(0); }

    let tid = ctx.tgid();
    let now = now_ns();
    let retval: i64 = ctx.ret::<i64>().unwrap_or(0);

    let ctx_val = unsafe { REQ_CTX.get(&tid).copied() };
    let ctx_val = match ctx_val { Some(v) => v, None => return Ok(0) };
    let _ = REQ_CTX.remove(&tid);

    let latency = now.wrapping_sub(ctx_val.start_ns);
    if latency > 10_000_000_000 { return Ok(0); }

    let client_ip   = (ctx_val.client_packed >> 16) as u32;
    let client_port = (ctx_val.client_packed & 0xFFFF) as u16;

    let event = LatencyEvent {
        pid: ctx.pid(), tid,
        latency_ns: latency,
        bytes: if retval > 0 { retval as u32 } else { 0 },
        client_ip, client_port,
        command: 0, is_error: u8::from(retval < 0),
        req_data: ctx_val.req_data,
    };

    // ── Batched wakeup: only wake userspace every 8th event ──
    let cnt_ptr = match unsafe { BATCH_CNT.get_ptr_mut(0) } {
        Some(p) => p,
        None => return Ok(0),
    };
    let cur = unsafe { *cnt_ptr };
    let flags = if cur + 1 >= BATCH_SIZE {
        unsafe { *cnt_ptr = 0 };
        BPF_RB_FORCE_WAKEUP
    } else {
        unsafe { *cnt_ptr = cur + 1 };
        BPF_RB_NO_WAKEUP
    };
    let _ = LATENCY_RINGBUF.output::<LatencyEvent>(&event, flags);

    Ok(0)
}


// fentry : tcp_connect

#[fentry(function = "tcp_connect")]
pub fn on_tcp_connect(ctx: FEntryContext) -> u32 {
    match unsafe { try_on_connect(&ctx) } {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

unsafe fn try_on_connect(_ctx: &FEntryContext) -> Result<u32, i64> {
    if !is_target_pid(_ctx.pid()) { return Ok(0); }
    Ok(0)
}

#[inline]
fn is_target_pid(pid: u32) -> bool {
    // Array always has index 0; default 0 means "trace everything".
    if let Some(&target) = TARGET_PID.get(0) {
        if target != 0 { return pid == target; }
    }
    true
}

#[inline]
fn flamegraph_enabled() -> bool {
    unsafe { FLAMEGRAPH_ON.get(&0).map(|&v| v != 0).unwrap_or(false) }
}


// perf_event : CPU stack sampling

#[perf_event]
pub fn on_cpu_sample(ctx: PerfEventContext) -> u32 {
    match unsafe { try_cpu_sample(&ctx) } { Ok(ret) => ret, Err(_) => 0 }
}

unsafe fn try_cpu_sample(ctx: &PerfEventContext) -> Result<u32, i64> {
    use core::ffi::c_void;
    let pid = ctx.pid();
    if !is_target_pid(pid) || !flamegraph_enabled() { return Ok(0); }

    let mut event = StackEvent {
        pid, cpu: unsafe { bpf_get_smp_processor_id() },
        kstack_len: -1, ustack_len: -1, timestamp_ns: now_ns(),
        kstack_ips: [0u64; MAX_STACK_FRAMES], ustack_ips: [0u64; MAX_STACK_FRAMES],
    };
    let ctx_ptr: *mut c_void = ctx.as_ptr();

    let kret = unsafe { bpf_get_stack(ctx_ptr, event.kstack_ips.as_mut_ptr() as *mut c_void, (MAX_STACK_FRAMES * 8) as u32, 0) };
    event.kstack_len = if kret >= 0 { (kret as i32) / 8 } else { -1 };

    let uret = unsafe { bpf_get_stack(ctx_ptr, event.ustack_ips.as_mut_ptr() as *mut c_void, (MAX_STACK_FRAMES * 8) as u32, BPF_F_USER_STACK as u64) };
    event.ustack_len = if uret >= 0 { (uret as i32) / 8 } else { -1 };

    if event.kstack_len > 0 || event.ustack_len > 0 {
        // Stack samples are low-frequency (e.g. 99 Hz) — wakeup cost
        // is negligible; use NO_WAKEUP and let latency events gate
        // userspace notification.
        let _ = STACK_RINGBUF.output::<StackEvent>(&event, BPF_RB_NO_WAKEUP);
    }
    Ok(0)
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! { loop {} }

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
