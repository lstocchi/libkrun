// SPDX-License-Identifier: Apache-2.0

//! Lightweight performance counters for diagnosing VM-wide latency.
//!
//! Counters are always incremented (a single relaxed atomic add each, so the
//! overhead is negligible); a reporting thread is only spawned when the
//! `LIBKRUN_PERF_STATS` environment variable is set. It logs a summary line
//! every few seconds at info level under the "perf" log target. The optional
//! value of the variable is the reporting interval in seconds (default 5).
//!
//! The intended use is to run a workload inside the guest for a while and
//! compare the counters against the wall time: a vCPU that spends most of the
//! uptime sleeping in the Halt exit path, or an fs request rate far below what
//! the host-side processing time would allow, points at where the time goes.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::thread;
use std::time::Duration;

/// The available counters. The `*Ns`/`*Ms` variants accumulate durations.
#[derive(Clone, Copy)]
pub enum Counter {
    /// vCPU exits with the Halt reason.
    VcpuExitHalt = 0,
    /// Total milliseconds the vCPU threads spent sleeping in the Halt path.
    VcpuExitHaltSleepMs = 1,
    /// vCPU exits with the ApicEoi reason.
    VcpuExitApicEoi = 2,
    /// vCPU exits with the InterruptWindow reason.
    VcpuExitInterruptWindow = 3,
    /// vCPU exits with the Canceled reason.
    VcpuExitCanceled = 4,
    /// vCPU exits with the IoPortAccess reason.
    VcpuExitIoPort = 5,
    /// vCPU exits with the MemoryAccess (MMIO) reason.
    VcpuExitMemory = 6,
    /// Interrupts injected into the guest through the emulated IOAPIC.
    IrqInjected = 7,
    /// Times the virtio-fs worker woke from its epoll wait.
    FsWorkerWake = 8,
    /// virtio-fs requests handled.
    FsRequest = 9,
    /// Total nanoseconds spent handling virtio-fs requests.
    FsRequestNs = 10,
}

const NUM_COUNTERS: usize = 11;

static COUNTERS: [AtomicU64; NUM_COUNTERS] = [const { AtomicU64::new(0) }; NUM_COUNTERS];

// Per-FUSE-opcode accounting, indexed by the wire opcode (all are < 64).
const FS_OP_MAX: usize = 64;
static FS_OP_COUNT: [AtomicU64; FS_OP_MAX] = [const { AtomicU64::new(0) }; FS_OP_MAX];
static FS_OP_NS: [AtomicU64; FS_OP_MAX] = [const { AtomicU64::new(0) }; FS_OP_MAX];

/// Record one handled FUSE request of `opcode` that took `duration`.
pub fn fs_op(opcode: u32, duration: Duration) {
    let index = opcode as usize;
    if index < FS_OP_MAX {
        FS_OP_COUNT[index].fetch_add(1, Ordering::Relaxed);
        FS_OP_NS[index].fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    }
}

/// Names of the FUSE opcodes, for the reporter output. The numbering follows
/// the `Opcode` enum in `devices::virtio::fs::fuse` (the values the server
/// dispatches on), which is what the wire carries.
const FS_OP_NAMES: [&str; FS_OP_MAX] = [
    "??",
    "lookup",
    "forget",
    "getattr",
    "setattr",
    "readlink",
    "symlink",
    "?7",
    "mknod",
    "mkdir",
    "unlink",
    "rmdir",
    "rename",
    "link",
    "open",
    "read",
    "write",
    "statfs",
    "release",
    "?19",
    "fsync",
    "setxattr",
    "getxattr",
    "listxattr",
    "removexattr",
    "flush",
    "init",
    "opendir",
    "readdir",
    "releasedir",
    "fsyncdir",
    "getlk",
    "setlk",
    "setlkw",
    "access",
    "create",
    "interrupt",
    "bmap",
    "destroy",
    "ioctl",
    "poll",
    "notify_reply",
    "batch_forget",
    "fallocate",
    "readdirplus",
    "rename2",
    "lseek",
    "copy_file_range",
    "setupmapping",
    "removemapping",
    "?50",
    "?51",
    "?52",
    "?53",
    "?54",
    "?55",
    "?56",
    "?57",
    "?58",
    "?59",
    "?60",
    "?61",
    "?62",
    "?63",
];

fn log_fs_ops() {
    let mut ops = (0..FS_OP_MAX)
        .filter(|&i| FS_OP_COUNT[i].load(Ordering::Relaxed) > 0)
        .map(|i| {
            (
                FS_OP_NAMES[i],
                FS_OP_COUNT[i].load(Ordering::Relaxed),
                FS_OP_NS[i].load(Ordering::Relaxed),
            )
        })
        .collect::<Vec<_>>();
    ops.sort_by_key(|(_, _, ns)| *ns);
    ops.reverse();
    let summary = ops
        .into_iter()
        .map(|(name, count, ns)| {
            format!("{name}={count} ({:.0} us avg, {} ms total)", ns / count / 1000, ns / 1_000_000)
        })
        .collect::<Vec<_>>()
        .join(", ");
    if !summary.is_empty() {
        log::info!(target: "perf", "fs ops (sorted by total time): {summary}");
    }
}

/// Increment a counter by one.
pub fn inc(counter: Counter) {
    COUNTERS[counter as usize].fetch_add(1, Ordering::Relaxed);
}

/// Add a value (a duration, for the `*Ns`/`*Ms` counters) to a counter.
pub fn add(counter: Counter, value: u64) {
    COUNTERS[counter as usize].fetch_add(value, Ordering::Relaxed);
}

/// Read a counter.
pub fn get(counter: Counter) -> u64 {
    COUNTERS[counter as usize].load(Ordering::Relaxed)
}

/// Spawn the periodic reporter when `LIBKRUN_PERF_STATS` is set. Idempotent;
/// safe to call from every vCPU and device worker start.
pub fn init() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let Some(spec) = std::env::var_os("LIBKRUN_PERF_STATS") else {
            return;
        };
        let interval = spec
            .to_string_lossy()
            .parse::<u64>()
            .ok()
            .filter(|secs| *secs > 0)
            .unwrap_or(5);

        thread::Builder::new()
            .name("perf-stats".into())
            .spawn(move || {
                let start = std::time::Instant::now();
                loop {
                    thread::sleep(Duration::from_secs(interval));
                    let halt = get(Counter::VcpuExitHalt);
                    let halt_sleep = get(Counter::VcpuExitHaltSleepMs);
                    let reqs = get(Counter::FsRequest);
                    let req_ms = get(Counter::FsRequestNs) / 1_000_000;
                    log::info!(target: "perf",
                        "uptime={:.0}s \
                         vcpu_exits: halt={halt} (slept {halt_sleep} ms) apic_eoi={} \
                         int_window={} canceled={} io={} mmio={} | irqs={} | \
                         fs: wakes={} reqs={reqs} req_time={req_ms} ms",
                        start.elapsed().as_secs_f64(),
                        get(Counter::VcpuExitApicEoi),
                        get(Counter::VcpuExitInterruptWindow),
                        get(Counter::VcpuExitCanceled),
                        get(Counter::VcpuExitIoPort),
                        get(Counter::VcpuExitMemory),
                        get(Counter::IrqInjected),
                        get(Counter::FsWorkerWake),
                    );
                    log_fs_ops();
                }
            })
            .ok();
    });
}
