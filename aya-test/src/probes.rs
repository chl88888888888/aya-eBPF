//! eBPF program loading and probe attachment (fentry/fexit + BTF).
//!
//! Uses BTF-based fentry/fexit instead of kprobes for ~10× lower
//! per-invocation overhead.  Probe logic is unchanged — same fields,
//! same maps, same RingBuf output.

use aya::maps::HashMap as AyaHashMap;
use aya::programs::fentry::FEntry;
use aya::programs::fexit::FExit;
use aya::programs::perf_event::{
    PerfEvent, PerfEventConfig, PerfEventScope, SamplePolicy, SoftwareEvent,
};
use aya::{Btf, Ebpf};
use log::info;

/// Loads and attaches fentry/fexit programs for TCP send/recv tracing.
pub fn attach_probes(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let btf = Btf::from_sys_fs()?;

    let recvmsg: &mut FEntry =
        ebpf.program_mut("on_tcp_recvmsg").unwrap().try_into()?;
    recvmsg.load("tcp_recvmsg", &btf)?;
    recvmsg.attach()?;
    info!("fentry/tcp_recvmsg attached");

    let recvmsg_ret: &mut FExit =
        ebpf.program_mut("on_tcp_recvmsg_ret").unwrap().try_into()?;
    recvmsg_ret.load("tcp_recvmsg", &btf)?;
    recvmsg_ret.attach()?;
    info!("fexit/tcp_recvmsg attached");

    let sendmsg: &mut FExit =
        ebpf.program_mut("on_tcp_sendmsg").unwrap().try_into()?;
    sendmsg.load("tcp_sendmsg", &btf)?;
    sendmsg.attach()?;
    info!("fexit/tcp_sendmsg attached");

    Ok(())
}

/// Loads and attaches the `on_cpu_sample` perf-event program.
/// Uses `OneProcess` scope targeting the Redis PID, because
/// `AllProcessesOneCpu` with per-task `CpuClock` only measures
/// the calling process, not all processes on the CPU.
pub fn attach_perf_event(ebpf: &mut Ebpf, target_pid: u32, frequency_hz: u64) -> anyhow::Result<()> {
    let prog: &mut PerfEvent =
        ebpf.program_mut("on_cpu_sample").unwrap().try_into()?;
    prog.load()?;

    let config = PerfEventConfig::Software(SoftwareEvent::CpuClock);
    prog.attach(
        config,
        PerfEventScope::OneProcess { pid: target_pid, cpu: None },
        SamplePolicy::Frequency(frequency_hz),
        true,
    )?;
    Ok(())
}

/// Writes `1` to the `FLAMEGRAPH_ON` eBPF map to enable stack sampling.
pub fn enable_flamegraph(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    let mut map: AyaHashMap<_, u32, u32> =
        AyaHashMap::try_from(ebpf.map_mut("FLAMEGRAPH_ON").unwrap())?;
    let _ = map.insert(0, 1, 0);
    Ok(())
}
