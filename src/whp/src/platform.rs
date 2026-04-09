// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::mem::{self, MaybeUninit};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use log::{debug, error};
use windows_sys::Win32::Foundation::S_OK;
use windows_sys::Win32::System::Hypervisor::{
    WHV_CAPABILITY, WHV_EMULATOR_CALLBACKS, WHV_EMULATOR_STATUS, WHV_MEMORY_ACCESS_CONTEXT, WHV_PARTITION_HANDLE, WHV_PARTITION_PROPERTY, WHV_PARTITION_PROPERTY_CODE, WHV_REGISTER_NAME, WHV_REGISTER_VALUE, WHV_RUN_VP_EXIT_CONTEXT, WHV_VP_EXIT_CONTEXT, WHV_X64_CPUID_RESULT, WHV_X64_IO_PORT_ACCESS_CONTEXT, WHvCancelRunVirtualProcessor, WHvCapabilityCodeHypervisorPresent, WHvCreatePartition, WHvCreateVirtualProcessor, WHvDeletePartition, WHvDeleteVirtualProcessor, WHvEmulatorCreateEmulator, WHvEmulatorDestroyEmulator, WHvEmulatorTryIoEmulation, WHvEmulatorTryMmioEmulation, WHvGetCapability, WHvGetVirtualProcessorRegisters, WHvMapGpaRange, WHvMapGpaRangeFlagExecute, WHvMapGpaRangeFlagRead, WHvMapGpaRangeFlagWrite, WHvPartitionPropertyCodeCpuidExitList, WHvPartitionPropertyCodeCpuidResultList, WHvPartitionPropertyCodeExtendedVmExits, WHvPartitionPropertyCodeLocalApicEmulationMode, WHvPartitionPropertyCodeProcessorCount, WHvRequestInterrupt, WHvRunVirtualProcessor, WHvRunVpExitReasonCanceled, WHvRunVpExitReasonInvalidVpRegisterValue, WHvRunVpExitReasonMemoryAccess, WHvRunVpExitReasonUnrecoverableException, WHvRunVpExitReasonUnsupportedFeature, WHvRunVpExitReasonX64Cpuid, WHvRunVpExitReasonX64Halt, WHvRunVpExitReasonX64InterruptWindow, WHvRunVpExitReasonX64IoPortAccess, WHvRunVpExitReasonX64MsrAccess, WHvSetPartitionProperty, WHvSetVirtualProcessorRegisters, WHvSetupPartition, WHvX64LocalApicEmulationModeXApic, WHvX64RegisterRax, WHvX64RegisterRbx, WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRflags, WHvX64RegisterRip
};
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

#[derive(Debug)]
pub enum Error {
    CheckCapability(i32),
    HypervisorNotPresent,
    CreatePartition(i32),
    SetPartitionProperty(i32),
    SetupPartition(i32),
    DeletePartition(i32),
    MapGpaRange(i32),
    RequestInterrupt(i32),
    CreateVirtualProcessor(i32),
    DeleteVirtualProcessor(i32),
    RunVirtualProcessor(i32),
    GetRegisters(i32),
    SetRegisters(i32),
    MemoryAlignment,
    CreateEmulator(i32),
    DestroyEmulator(i32),
    IoEmulation(i32),
    MmioEmulation(i32),
    EmulationFailed(u32),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use Error::*;
        match self {
            CheckCapability(hr) => write!(f, "WHvGetCapability failed: HRESULT 0x{hr:08x}"),
            HypervisorNotPresent => write!(f, "WHP hypervisor is not present on this system"),
            CreatePartition(hr) => write!(f, "WHvCreatePartition failed: HRESULT 0x{hr:08x}"),
            SetPartitionProperty(hr) => {
                write!(f, "WHvSetPartitionProperty failed: HRESULT 0x{hr:08x}")
            }
            SetupPartition(hr) => write!(f, "WHvSetupPartition failed: HRESULT 0x{hr:08x}"),
            DeletePartition(hr) => write!(f, "WHvDeletePartition failed: HRESULT 0x{hr:08x}"),
            MapGpaRange(hr) => write!(f, "WHvMapGpaRange failed: HRESULT 0x{hr:08x}"),
            RequestInterrupt(hr) => write!(f, "WHvRequestInterrupt failed: HRESULT 0x{hr:08x}"),
            CreateVirtualProcessor(hr) => {
                write!(f, "WHvCreateVirtualProcessor failed: HRESULT 0x{hr:08x}")
            }
            DeleteVirtualProcessor(hr) => {
                write!(f, "WHvDeleteVirtualProcessor failed: HRESULT 0x{hr:08x}")
            }
            RunVirtualProcessor(hr) => {
                write!(f, "WHvRunVirtualProcessor failed: HRESULT 0x{hr:08x}")
            }
            GetRegisters(hr) => {
                write!(
                    f,
                    "WHvGetVirtualProcessorRegisters failed: HRESULT 0x{hr:08x}"
                )
            }
            SetRegisters(hr) => {
                write!(
                    f,
                    "WHvSetVirtualProcessorRegisters failed: HRESULT 0x{hr:08x}"
                )
            }
            MemoryAlignment => write!(f, "WHP memory mapping must be 4KB aligned"),
            CreateEmulator(hr) => {
                write!(f, "WHvEmulatorCreateEmulator failed: HRESULT 0x{hr:08x}")
            }
            DestroyEmulator(hr) => {
                write!(f, "WHvEmulatorDestroyEmulator failed: HRESULT 0x{hr:08x}")
            }
            IoEmulation(hr) => {
                write!(f, "WHvEmulatorTryIoEmulation failed: HRESULT 0x{hr:08x}")
            }
            MmioEmulation(hr) => {
                write!(
                    f,
                    "WHvEmulatorTryMmioEmulation failed: HRESULT 0x{hr:08x}"
                )
            }
            EmulationFailed(status) => {
                let reason = match *status {
                    s if s & (1 << 1) != 0 => "internal emulation failure",
                    s if s & (1 << 2) != 0 => "I/O port callback failed",
                    s if s & (1 << 3) != 0 => "memory callback failed",
                    s if s & (1 << 4) != 0 => "translate GVA page callback failed",
                    s if s & (1 << 5) != 0 => "translated GPA page is not aligned",
                    s if s & (1 << 6) != 0 => "get VP registers callback failed",
                    s if s & (1 << 7) != 0 => "set VP registers callback failed",
                    s if s & (1 << 8) != 0 => "interrupt caused intercept",
                    s if s & (1 << 9) != 0 => "guest cannot be faulted",
                    _ => "unknown",
                };
                write!(
                    f,
                    "Instruction emulation failed: {reason} (status 0x{status:08x})"
                )
            }
        }
    }
}


/// Verifies that the Windows Hypervisor Platform is available.
pub fn check_hypervisor() -> Result<(), Error> {
    let mut capability = MaybeUninit::<WHV_CAPABILITY>::uninit();
    let mut written_size: u32 = 0;        

    let hr = unsafe {
            WHvGetCapability(
            WHvCapabilityCodeHypervisorPresent,
            capability.as_mut_ptr() as *mut _,
            mem::size_of::<WHV_CAPABILITY>() as u32,
            &mut written_size,
        )
    };
    if hr != S_OK {
        return Err(Error::CheckCapability(hr));
    }

    let cap: WHV_CAPABILITY = unsafe { capability.assume_init() };
    let present = unsafe { cap.HypervisorPresent };
    if present == 0 {
        Err(Error::HypervisorNotPresent)
    } else {
        debug!("WHP hypervisor is present");
        Ok(())
    }
}

/// Parsed CPUID exit context returned by [`WhpVcpu::cpuid_exit_info`].
#[derive(Debug, Clone)]
pub struct CpuidExitInfo {
    pub leaf: u64,
    pub subleaf: u64,
    pub default_eax: u64,
    pub default_ebx: u64,
    pub default_ecx: u64,
    pub default_edx: u64,
}

/// Parsed MSR exit context returned by [`WhpVcpu::msr_exit_info`].
#[derive(Debug, Clone)]
pub struct MsrExitInfo {
    pub msr_number: u32,
    pub is_write: bool,
    pub rax: u64,
    pub rdx: u64,
}

/// Per-VM state for Hyper-V enlightenments (synthetic CPUID / MSR interface).
///
/// When running a Linux guest on WHP, the guest kernel has no built-in
/// knowledge of the Windows Hypervisor Platform.  Without help it falls back
/// to legacy clocksources (PIT, HPET, ACPI PM timer) that require a VM exit
/// on every time read — a significant performance bottleneck since the kernel
/// reads the clock thousands of times per second for scheduling, timers, and
/// `gettimeofday()`.
///
/// By presenting the standard Hyper-V hypervisor interface (CPUID leaves
/// `0x40000000`–`0x40000005` with the "Microsoft Hv" signature, plus a set of
/// synthetic MSRs) we enable the Linux `hyperv_clocksource` driver.  Its
/// centrepiece is the **Reference TSC Page**: a shared-memory page containing
/// calibration constants that let the guest compute wall-clock time purely
/// from `RDTSC` — no VM exit required.  This is the fastest clocksource
/// available under any Windows-hosted hypervisor.
pub struct HyperVState {
    /// `HV_X64_MSR_GUEST_OS_ID` — the guest identifies itself to the hypervisor.
    guest_os_id: AtomicU64,
    /// Raw value last written to `HV_X64_MSR_REFERENCE_TSC` (bit 0 = enable,
    /// bits 12:63 = page frame number).
    tsc_reference_msr: AtomicU64,
    /// Host TSC value captured at VM creation (for TSC page calibration).
    vm_start_tsc: u64,
    /// Host monotonic instant captured at VM creation (for `TIME_REF_COUNT`).
    vm_start_instant: Instant,
    /// Host TSC frequency in Hz, used for time conversions.
    tsc_freq_hz: u64,
    /// Synthetic timer 0 config (direct mode, vector, enable, periodic).
    stimer0_config: AtomicU64,
    /// Synthetic timer 0 count — absolute expiration in 100 ns units (one-shot)
    /// or period (periodic).  0 means disarmed.
    stimer0_count: AtomicU64,
}

impl HyperVState {
    fn new(tsc_freq_hz: u64) -> Self {
        Self {
            guest_os_id: AtomicU64::new(0),
            tsc_reference_msr: AtomicU64::new(0),
            vm_start_tsc: unsafe { core::arch::x86_64::_rdtsc() },
            vm_start_instant: Instant::now(),
            tsc_freq_hz,
            stimer0_config: AtomicU64::new(0),
            stimer0_count: AtomicU64::new(0),
        }
    }

    pub fn guest_os_id(&self) -> u64 {
        self.guest_os_id.load(Ordering::Relaxed)
    }

    pub fn set_guest_os_id(&self, val: u64) {
        self.guest_os_id.store(val, Ordering::Relaxed);
    }

    pub fn tsc_reference_msr(&self) -> u64 {
        self.tsc_reference_msr.load(Ordering::Relaxed)
    }

    pub fn set_tsc_reference_msr(&self, val: u64) {
        self.tsc_reference_msr.store(val, Ordering::Relaxed);
    }

    pub fn vm_start_tsc(&self) -> u64 {
        self.vm_start_tsc
    }

    pub fn vm_start_instant(&self) -> Instant {
        self.vm_start_instant
    }

    pub fn tsc_freq_hz(&self) -> u64 {
        self.tsc_freq_hz
    }

    pub fn stimer0_config(&self) -> u64 {
        self.stimer0_config.load(Ordering::Relaxed)
    }

    pub fn set_stimer0_config(&self, val: u64) {
        self.stimer0_config.store(val, Ordering::Relaxed);
    }

    pub fn stimer0_count(&self) -> u64 {
        self.stimer0_count.load(Ordering::Relaxed)
    }

    pub fn set_stimer0_count(&self, val: u64) {
        self.stimer0_count.store(val, Ordering::Relaxed);
    }

    /// Compute the Hyper-V reference time counter (100 ns units) from the
    /// current host TSC.
    pub fn reference_time(&self) -> u64 {
        let elapsed_tsc = unsafe { core::arch::x86_64::_rdtsc() } - self.vm_start_tsc;
        if self.tsc_freq_hz == 0 {
            return 0;
        }
        ((elapsed_tsc as u128) * 10_000_000 / self.tsc_freq_hz as u128) as u64
    }
}

pub struct WhpVm {
    handle: WHV_PARTITION_HANDLE,
    hyperv: HyperVState,
}

#[repr(C)]
struct WhvInterruptControl {
    type_and_flags: u64,
    destination: u32,
    vector: u32,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum InterruptType {
    Fixed = 0,
    LowestPriority = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum InterruptDestinationMode {
    Physical = 0,
    Logical = 1,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum InterruptTriggerMode {
    Edge = 0,
    Level = 1,
}

#[derive(Debug, Clone)]
pub struct InterruptRequest {
    pub interrupt_type: InterruptType,
    pub destination_mode: InterruptDestinationMode,
    pub trigger_mode: InterruptTriggerMode,
    pub destination: u32,
    pub vector: u32,
}

impl WhpVm {
    /// Creates a new WHP partition.
    /// WHP has a create → configure → finalize model
    /// WHvCreatePartition — allocates the partition object but it's not yet usable.
    /// WHvSetPartitionProperty — sets properties like processor count, APIC emulation mode, etc. 
    ///                           These properties can only be set before finalization.
    /// WHvSetupPartition — finalizes the partition. After this call, configuration is locked and you can start creating vCPUs. 
    ///                     You cannot change the config (like processor count) after this call.
    pub fn new(vcpu_count: u32) -> Result<Self, Error> {
        let handle = unsafe {
            let mut h: WHV_PARTITION_HANDLE = 0;
            let hr = WHvCreatePartition(&mut h);
            if hr != S_OK {
                return Err(Error::CreatePartition(hr));
            }
            h
        };

        let tsc_freq_hz = Self::detect_tsc_frequency();

        if let Err(e) = Self::configure_partition(handle, vcpu_count, tsc_freq_hz) {
            let _ = unsafe { WHvDeletePartition(handle) };
            return Err(e);
        }

        debug!("WHP partition created with {vcpu_count} vCPU(s)");
        Ok(WhpVm {
            handle,
            hyperv: HyperVState::new(tsc_freq_hz),
        })
    }

    fn configure_partition(
        handle: WHV_PARTITION_HANDLE,
        vcpu_count: u32,
        tsc_freq_hz: u64,
    ) -> Result<(), Error> {
        Self::set_property(handle, WHvPartitionPropertyCodeProcessorCount, |p| {
            p.ProcessorCount = vcpu_count;
        })?;

        Self::set_property(
            handle,
            WHvPartitionPropertyCodeLocalApicEmulationMode,
            |p| {
                p.LocalApicEmulationMode = WHvX64LocalApicEmulationModeXApic;
            },
        )?;

        // Enable CPUID exits (bit 0) and MSR exits (bit 1) so the
        // CpuidExitList/Hyper-V MSR interception work.
        // https://github.com/google/crosvm/blob/main/hypervisor/src/whpx/whpx_sys/WinHvPlatformDefs.h#L74
        Self::set_property(handle, WHvPartitionPropertyCodeExtendedVmExits, |p| unsafe {
            p.ExtendedVmExits.AsUINT64 = 0b11; // bit 0 = X64CpuidExit, bit 1 = X64MsrExit
        })?;

        let mut cpuid_results: Vec<WHV_X64_CPUID_RESULT> = Vec::new();

        // ── Hyper-V enlightenment leaves ──
        // WHP does NOT expose Hyper-V CPUID to the guest automatically;
        // we must provide 0x40000000+ via CpuidResultList.  WHP handles
        // the underlying MSRs (SynIC, stimers, reference TSC) internally.

        // 0x40000000 — Hypervisor signature: "Microsoft Hv"
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000000,
            Reserved: [0; 3],
            Eax: 0x40000006,
            Ebx: 0x7263694D, // "Micr"
            Ecx: 0x666F736F, // "osof"
            Edx: 0x76482074, // "t Hv"
        });

        // 0x40000001 — Interface identification: "Hv#1"
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000001,
            Reserved: [0; 3],
            Eax: 0x31237648, // "Hv#1"
            Ebx: 0,
            Ecx: 0,
            Edx: 0,
        });

        // 0x40000002 — Version (minimal)
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000002,
            Reserved: [0; 3],
            Eax: 0,
            Ebx: 0x000A_0000, // version 10.0
            Ecx: 0,
            Edx: 0,
        });

        // 0x40000003 — Feature identification (Hyper-V TLFS §2.4)
        //   EAX: partition privilege flags
        //   EDX: misc features
        const ACCESS_VP_RUNTIME: u32 = 1 << 0;
        const ACCESS_REF_COUNTER: u32 = 1 << 1;
        const ACCESS_SYNIC_REGS: u32 = 1 << 2;
        const ACCESS_STIMER: u32 = 1 << 3;
        const ACCESS_VP_INDEX: u32 = 1 << 6;
        const ACCESS_REF_TSC: u32 = 1 << 9;
        const ACCESS_FREQ_REGS: u32 = 1 << 11;

        const DIRECT_TIMER_MODE: u32 = 1 << 19;

        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000003,
            Reserved: [0; 3],
            Eax: ACCESS_VP_RUNTIME
                | ACCESS_REF_COUNTER
                | ACCESS_SYNIC_REGS
                | ACCESS_STIMER
                | ACCESS_VP_INDEX
                | ACCESS_REF_TSC
                | ACCESS_FREQ_REGS,
            Ebx: 0,
            Ecx: 0,
            Edx: DIRECT_TIMER_MODE,
        });

        // 0x40000004 — Recommendations
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000004,
            Reserved: [0; 3],
            Eax: 1 << 5, // RelaxedTiming
            Ebx: 0,
            Ecx: 0,
            Edx: 0,
        });

        // 0x40000005 — Implementation limits
        cpuid_results.push(WHV_X64_CPUID_RESULT {
            Function: 0x40000005,
            Reserved: [0; 3],
            Eax: 64, // max virtual processors
            Ebx: 0,
            Ecx: 0,
            Edx: 0,
        });

        // ── Standard Intel CPUID leaves (SDM Vol. 2A) ──
        if tsc_freq_hz > 0 {
            debug!("Providing TSC frequency to guest: {} Hz", tsc_freq_hz);

            // CPUID 0x15 — TSC / Core Crystal Clock (Intel SDM)
            // TSC frequency in Hz = ECX * (EBX / EAX).
            // We use a 1 Hz crystal with EBX = tsc_freq_hz to avoid rounding.
            cpuid_results.push(WHV_X64_CPUID_RESULT {
                Function: 0x15,
                Reserved: [0; 3],
                Eax: 1,
                Ebx: tsc_freq_hz as u32,
                Ecx: 1,
                Edx: 0,
            });
        }

        // Force CPUID leaf 1 to exit so we can set the hypervisor-present
        // bit (ECX.31).  Without it the guest ignores 0x40000000+ leaves.
        let cpuid_exit_list: [u32; 1] = [1];
        let hr = unsafe {
            WHvSetPartitionProperty(
                handle,
                WHvPartitionPropertyCodeCpuidExitList,
                cpuid_exit_list.as_ptr() as *const _,
                (cpuid_exit_list.len() * mem::size_of::<u32>()) as u32,
            )
        };
        if hr != S_OK {
            error!("CpuidExitList failed: HRESULT 0x{hr:08x}");
            return Err(Error::SetPartitionProperty(hr));
        }

        let hr = unsafe {
            WHvSetPartitionProperty(
                handle,
                WHvPartitionPropertyCodeCpuidResultList,
                cpuid_results.as_ptr() as *const _,
                (cpuid_results.len() * mem::size_of::<WHV_X64_CPUID_RESULT>()) as u32,
            )
        };
        if hr != S_OK {
            error!("CpuidResultList failed: HRESULT 0x{hr:08x}");
            return Err(Error::SetPartitionProperty(hr));
        }
        debug!("CpuidResultList set ({} entries)", cpuid_results.len());

        let hr = unsafe { WHvSetupPartition(handle) };
        if hr != S_OK {
            Err(Error::SetupPartition(hr))
        } else {
            Ok(())
        }
    }

    fn set_property(
        handle: WHV_PARTITION_HANDLE,
        code: WHV_PARTITION_PROPERTY_CODE,
        configure: impl FnOnce(&mut WHV_PARTITION_PROPERTY),
    ) -> Result<(), Error> {
        let mut prop = unsafe { MaybeUninit::<WHV_PARTITION_PROPERTY>::zeroed().assume_init() };
        configure(&mut prop);
        let hr = unsafe {
            WHvSetPartitionProperty(
                handle,
                code,
                &prop as *const _ as *const _,
                mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
            )
        };
        if hr != S_OK {
            Err(Error::SetPartitionProperty(hr))
        } else {
            Ok(())
        }
    }

    /// Detect the host TSC frequency in Hz.
    /// Tries CPUID 0x15, then 0x16 (Intel), then falls back to measuring
    /// via RDTSC over a short sleep (works on AMD and all other x86_64).
    fn detect_tsc_frequency() -> u64 {
        unsafe {
            let cpuid15 = core::arch::x86_64::__cpuid(0x15);
            if cpuid15.eax != 0 && cpuid15.ebx != 0 && cpuid15.ecx != 0 {
                let freq = (cpuid15.ecx as u64 * cpuid15.ebx as u64) / cpuid15.eax as u64;
                debug!("TSC frequency from CPUID 0x15: {} Hz", freq);
                return freq;
            }

            let cpuid16 = core::arch::x86_64::__cpuid(0x16);
            if cpuid16.eax != 0 {
                let freq = cpuid16.eax as u64 * 1_000_000;
                debug!("TSC frequency from CPUID 0x16: {} Hz", freq);
                return freq;
            }
        }

        debug!("CPUID 0x15/0x16 unavailable, measuring TSC frequency via QPC");

        let mut qpc_freq = 0;
        let mut start_qpc = 0;
        let mut end_qpc = 0;

        unsafe {
            QueryPerformanceFrequency(&mut qpc_freq);
            QueryPerformanceCounter(&mut start_qpc);
        }

        let start_tsc = unsafe { core::arch::x86_64::_rdtsc() };

        // Spin for ~10ms. Tight loops avoid OS scheduler suspension jitter.
        let target_qpc = start_qpc + (qpc_freq / 100);
        loop {
            unsafe { QueryPerformanceCounter(&mut end_qpc) };
            if end_qpc >= target_qpc {
                break;
            }
        }

        let end_tsc = unsafe { core::arch::x86_64::_rdtsc() };
        let qpc_elapsed = end_qpc - start_qpc;

        if qpc_elapsed > 0 {
            let tsc_elapsed = end_tsc.wrapping_sub(start_tsc);
            // Calculate utilizing u128 to prevent overflow before dividing
            let freq = (tsc_elapsed as u128 * qpc_freq as u128 / qpc_elapsed as u128) as u64;
            debug!("TSC frequency measured: {} Hz ({} MHz)", freq, freq / 1_000_000);
            return freq;
        }

        error!("Could not determine TSC frequency");
        0
    }

    /// Maps a host memory region into the guest physical address space.
    pub unsafe fn map_memory(
        &self,
        host_addr: *mut c_void,
        guest_addr: u64,
        size: u64,
    ) -> Result<(), Error> {
        // Validation: WHP requires 4KB alignment
        if (host_addr as usize | guest_addr as usize | size as usize) & 0xFFF != 0 {
            // Technically a logic error in the caller
            return Err(Error::MemoryAlignment);
        }

        let hr = unsafe { 
            WHvMapGpaRange(
                self.handle,
                host_addr as *const _,
                guest_addr,
                size,
                WHvMapGpaRangeFlagRead | WHvMapGpaRangeFlagWrite | WHvMapGpaRangeFlagExecute,
            )
        };
        if hr != S_OK {
            Err(Error::MapGpaRange(hr))
        } else {
            Ok(())
        }
    }

    /// Injects an interrupt into a virtual processor's local APIC.
    /// http://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvrequestinterrupt
    pub fn request_interrupt(&self, req: &InterruptRequest) -> Result<(), Error> {
        let ctrl = WhvInterruptControl {
            type_and_flags: (req.interrupt_type as u64)
                | ((req.destination_mode as u64) << 8)
                | ((req.trigger_mode as u64) << 12),
            destination: req.destination,
            vector: req.vector,
        };

        let hr = unsafe {
            WHvRequestInterrupt(
                self.handle,
                &ctrl as *const _ as *const _,
                mem::size_of::<WhvInterruptControl>() as u32,
            )
        };
        if hr != S_OK {
            Err(Error::RequestInterrupt(hr))
        } else {
            Ok(())
        }
    }

    /// Fire a fixed, edge-triggered interrupt to APIC ID 0 with the given vector.
    pub fn inject_vector(&self, vector: u32) {
        let ctrl = WhvInterruptControl {
            type_and_flags: 0, // Fixed, Physical, Edge
            destination: 0,
            vector,
        };
        let hr = unsafe {
            WHvRequestInterrupt(
                self.handle,
                &ctrl as *const _ as *const _,
                mem::size_of::<WhvInterruptControl>() as u32,
            )
        };
        if hr != S_OK {
            error!("inject_vector(0x{vector:02x}) failed: HRESULT 0x{hr:08x}");
        }
    }

    /// Cancel a running `WHvRunVirtualProcessor` call so the vCPU thread
    /// exits with `Canceled`.  Required after `request_interrupt` to wake a
    /// vCPU that is blocked in HLT.
    pub fn cancel_vcpu(&self, vp_index: u32) {
        let hr = unsafe { WHvCancelRunVirtualProcessor(self.handle, vp_index, 0) };
        if hr != S_OK {
            error!("WHvCancelRunVirtualProcessor({vp_index}) failed: HRESULT 0x{hr:08x}");
        }
    }

    pub fn partition_handle(&self) -> WHV_PARTITION_HANDLE {
        self.handle
    }

    pub fn hyperv(&self) -> &HyperVState {
        &self.hyperv
    }
}

impl Drop for WhpVm {
    fn drop(&mut self) {        
        let hr = unsafe { WHvDeletePartition(self.handle) };
        if hr != S_OK {
            error!("WHvDeletePartition failed: HRESULT 0x{hr:08x}");
        }        
    }
}

unsafe impl Send for WhpVm {}
unsafe impl Sync for WhpVm {}

/// Wraps a `WHV_EMULATOR_HANDLE` (one per vCPU).
///
/// The caller provides the `WHV_EMULATOR_CALLBACKS` with five `extern "system"`
/// function pointers.  The opaque `*const c_void` context passed to
/// `try_io_emulation` / `try_mmio_emulation` is forwarded into each callback.
pub struct WhpEmulator {
    handle: *mut c_void,
}

fn check_emulation_result(
    hr: i32,
    status: WHV_EMULATOR_STATUS,
    hresult_err: fn(i32) -> Error,
) -> Result<(), Error> {
    if hr != S_OK {
        return Err(hresult_err(hr));
    }
    let bits = unsafe { status.AsUINT32 };
    if bits & 1 == 0 {
        return Err(Error::EmulationFailed(bits));
    }
    Ok(())
}

impl WhpEmulator {
    pub fn new(callbacks: WHV_EMULATOR_CALLBACKS) -> Result<Self, Error> {
        let mut handle: *mut c_void = std::ptr::null_mut();
        let hr = unsafe { WHvEmulatorCreateEmulator(&callbacks, &mut handle) };
        if hr != S_OK {
            Err(Error::CreateEmulator(hr))
        } else {
            Ok(WhpEmulator { handle })
        }
    }

    // https://learn.microsoft.com/en-us/virtualization/api/hypervisor-instruction-emulator/funcs/whvemulatortryemulation
    pub unsafe fn try_io_emulation(
        &self,
        context: *const c_void,
        vp_context: *const WHV_VP_EXIT_CONTEXT,
        io_context: *const WHV_X64_IO_PORT_ACCESS_CONTEXT,
    ) -> Result<(), Error> {
        let mut status: WHV_EMULATOR_STATUS = mem::zeroed();
        let hr = WHvEmulatorTryIoEmulation(
            self.handle,
            context,
            vp_context,
            io_context,
            &mut status,
        );
        check_emulation_result(hr, status, Error::IoEmulation)
    }

    /// Same as [`try_io_emulation`].
    pub unsafe fn try_mmio_emulation(
        &self,
        context: *const c_void,
        vp_context: *const WHV_VP_EXIT_CONTEXT,
        mmio_context: *const WHV_MEMORY_ACCESS_CONTEXT,
    ) -> Result<(), Error> {
        let mut status: WHV_EMULATOR_STATUS = mem::zeroed();
        let hr = WHvEmulatorTryMmioEmulation(
            self.handle,
            context,
            vp_context,
            mmio_context,
            &mut status,
        );
        check_emulation_result(hr, status, Error::MmioEmulation)
    }
}

impl Drop for WhpEmulator {
    fn drop(&mut self) {
        let hr = unsafe { WHvEmulatorDestroyEmulator(self.handle) };
        if hr != S_OK {
            error!("WHvEmulatorDestroyEmulator failed: HRESULT 0x{hr:08x}");
        }
    }
}

unsafe impl Send for WhpEmulator {}

#[derive(Debug)]
pub enum VcpuExitReason {
    IoPortAccess,
    MemoryAccess,
    Halt,
    Canceled,
    CpuidAccess,
    MsrAccess,
    InterruptWindow,
    UnrecoverableException,
    InvalidVpRegisterValue,
    UnsupportedFeature,
    Unknown(u32),
}

pub struct WhpVcpu {
    vm: Arc<WhpVm>,
    index: u32,
    exit_context: WHV_RUN_VP_EXIT_CONTEXT,
}

impl WhpVcpu {
    /// Creates a new virtual processor within the given partition.
    pub fn new(vm: Arc<WhpVm>, index: u32) -> Result<Self, Error> {
        let hr = unsafe { WHvCreateVirtualProcessor(vm.partition_handle(), index, 0) };
        if hr != S_OK {
            return Err(Error::CreateVirtualProcessor(hr));
        }

        debug!("Created WHP vCPU {index}");
        Ok(WhpVcpu {
            vm,
            index,
            exit_context: unsafe { mem::zeroed() },
        })
    }

    /// Runs the virtual processor until a VM exit occurs.
    ///
    /// The raw exit context is stored internally and can be accessed via
    /// [`vp_exit_context`], [`io_port_access_context`], and
    /// [`memory_access_context`] for passing to the instruction emulator.
    pub fn run(&mut self) -> Result<VcpuExitReason, Error> {
        let hr = unsafe {
            WHvRunVirtualProcessor(
                self.vm.partition_handle(),
                self.index,
                &mut self.exit_context as *mut _ as *mut _,
                mem::size_of::<WHV_RUN_VP_EXIT_CONTEXT>() as u32,
            )
        };
        if hr != S_OK {
            return Err(Error::RunVirtualProcessor(hr));
        }

        Ok(Self::decode_reason(&self.exit_context))
    }

    pub fn vp_exit_context(&self) -> *const WHV_VP_EXIT_CONTEXT {
        &self.exit_context.VpContext
    }

    pub fn io_port_access_context(&self) -> *const WHV_X64_IO_PORT_ACCESS_CONTEXT {
        unsafe { &self.exit_context.Anonymous.IoPortAccess }
    }

    pub fn memory_access_context(&self) -> *const WHV_MEMORY_ACCESS_CONTEXT {
        unsafe { &self.exit_context.Anonymous.MemoryAccess }
    }

    /// Returns parsed CPUID exit info. Only valid after a `CpuidAccess` exit.
    pub fn cpuid_exit_info(&self) -> CpuidExitInfo {
        let ctx = unsafe { &self.exit_context.Anonymous.CpuidAccess };
        CpuidExitInfo {
            leaf: ctx.Rax,
            subleaf: ctx.Rcx,
            default_eax: ctx.DefaultResultRax,
            default_ebx: ctx.DefaultResultRbx,
            default_ecx: ctx.DefaultResultRcx,
            default_edx: ctx.DefaultResultRdx,
        }
    }

    /// Returns parsed MSR exit info. Only valid after an `MsrAccess` exit.
    pub fn msr_exit_info(&self) -> MsrExitInfo {
        let ctx = unsafe { &self.exit_context.Anonymous.MsrAccess };
        MsrExitInfo {
            msr_number: ctx.MsrNumber,
            is_write: unsafe { ctx.AccessInfo.Anonymous._bitfield } & 1 != 0,
            rax: ctx.Rax,
            rdx: ctx.Rdx,
        }
    }

    /// RIP at the time of the VM exit.
    pub fn exit_rip(&self) -> u64 {
        self.exit_context.VpContext.Rip
    }

    /// Instruction length from the exit context (lower 4 bits of the packed byte).
    pub fn instruction_length(&self) -> u8 {
        self.exit_context.VpContext._bitfield & 0x0F
    }

    /// Advances RIP past the faulting instruction using the instruction length
    /// from the exit context.
    pub fn advance_rip(&self) -> Result<(), Error> {
        let new_rip = self.exit_context.VpContext.Rip + self.instruction_length() as u64;
        self.set_reg64(WHvX64RegisterRip, new_rip)
    }

    /// Sets RAX, RBX, RCX, RDX and advances RIP in a single register write.
    /// Used by CPUID exit handling.
    pub fn complete_cpuid(
        &self,
        eax: u64,
        ebx: u64,
        ecx: u64,
        edx: u64,
    ) -> Result<(), Error> {
        let new_rip = self.exit_context.VpContext.Rip + self.instruction_length() as u64;
        let names = [
            WHvX64RegisterRax,
            WHvX64RegisterRbx,
            WHvX64RegisterRcx,
            WHvX64RegisterRdx,
            WHvX64RegisterRip,
        ];
        let values: [WHV_REGISTER_VALUE; 5] = [
            WHV_REGISTER_VALUE { Reg64: eax },
            WHV_REGISTER_VALUE { Reg64: ebx },
            WHV_REGISTER_VALUE { Reg64: ecx },
            WHV_REGISTER_VALUE { Reg64: edx },
            WHV_REGISTER_VALUE { Reg64: new_rip },
        ];
        self.set_registers(&names, &values)
    }

    /// Sets RAX and RDX (MSR read result) then advances RIP.
    pub fn complete_msr_read(&self, rax: u64, rdx: u64) -> Result<(), Error> {
        let new_rip = self.exit_context.VpContext.Rip + self.instruction_length() as u64;
        let names = [
            WHvX64RegisterRax,
            WHvX64RegisterRdx,
            WHvX64RegisterRip,
        ];
        let values: [WHV_REGISTER_VALUE; 3] = [
            WHV_REGISTER_VALUE { Reg64: rax },
            WHV_REGISTER_VALUE { Reg64: rdx },
            WHV_REGISTER_VALUE { Reg64: new_rip },
        ];
        self.set_registers(&names, &values)
    }

    pub fn get_registers(
        &self,
        names: &[WHV_REGISTER_NAME],
        values: &mut [WHV_REGISTER_VALUE],
    ) -> Result<(), Error> {
        assert_eq!(names.len(), values.len());
        let count = names.len() as u32;

        let hr = unsafe {
            WHvGetVirtualProcessorRegisters(
                self.vm.partition_handle(),
                self.index,
                names.as_ptr(),
                count,
                values.as_mut_ptr(),
            )
        };
        if hr != S_OK {
            Err(Error::GetRegisters(hr))
        } else {
            Ok(())
        }
    }

    pub fn get_reg64(&self, name: WHV_REGISTER_NAME) -> Result<u64, Error> {
        let mut values = [unsafe { mem::zeroed::<WHV_REGISTER_VALUE>() }];
        self.get_registers(&[name], &mut values)?;
        Ok(unsafe { values[0].Reg64 })
    }

    pub fn set_registers(
        &self,
        names: &[WHV_REGISTER_NAME],
        values: &[WHV_REGISTER_VALUE],
    ) -> Result<(), Error> {
        assert_eq!(names.len(), values.len());
        let count = names.len() as u32;

        let hr = unsafe {
            WHvSetVirtualProcessorRegisters(
                self.vm.partition_handle(),
                self.index,
                names.as_ptr(),
                count,
                values.as_ptr(),
            )
        };
        if hr != S_OK {
            Err(Error::SetRegisters(hr))
        } else {
            Ok(())
        }
    }

    pub fn set_reg64(&self, name: WHV_REGISTER_NAME, val: u64) -> Result<(), Error> {
        let mut value: WHV_REGISTER_VALUE = unsafe { mem::zeroed() };
        value.Reg64 = val;
        self.set_registers(&[name], &[value])
    }

    pub fn vm(&self) -> &Arc<WhpVm> {
        &self.vm
    }

    pub fn partition_handle(&self) -> WHV_PARTITION_HANDLE {
        self.vm.partition_handle()
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    /// Clear the `HaltSuspend` flag so a halted vCPU can process a pending
    /// interrupt.  `WHvRequestInterrupt` queues the interrupt in the LAPIC
    /// but does **not** clear this flag, so the vCPU stays frozen in HLT
    /// until we explicitly reset it.
    pub fn clear_halt_suspend(&self) -> Result<(), Error> {
        const WHV_REGISTER_INTERNAL_ACTIVITY_STATE: WHV_REGISTER_NAME = 0x00004004;
        let mut values = [unsafe { mem::zeroed::<WHV_REGISTER_VALUE>() }];
        self.get_registers(&[WHV_REGISTER_INTERNAL_ACTIVITY_STATE], &mut values)?;
        let activity = unsafe { values[0].Reg64 };
        if activity & 2 != 0 {
            values[0].Reg64 = activity & !2;
            self.set_registers(&[WHV_REGISTER_INTERNAL_ACTIVITY_STATE], &values)?;
        }
        Ok(())
    }

    /// Ask WHP to exit the next time the guest becomes interruptible
    /// (IF transitions 0→1 via STI / IRET).  This is required when an
    /// interrupt is pending in the LAPIC but the guest currently has
    /// interrupts disabled (RFLAGS.IF=0).  Without this, a guest sitting
    /// in a tight CLI loop (e.g. TSC calibration) will never see the
    /// LAPIC interrupt because no VM-exit occurs to let WHP deliver it.
    pub fn request_interrupt_window(&self) -> Result<(), Error> {
        const WHV_REG_DELIVERABILITY_NOTIFICATIONS: WHV_REGISTER_NAME = 0x80000004u32 as i32;
        // Bit 1 = InterruptNotification
        self.set_reg64(WHV_REG_DELIVERABILITY_NOTIFICATIONS, 0x2)
    }

    /// Clear the deliverability-notification request so WHP stops exiting
    /// on every STI instruction.  Called after an InterruptWindow exit.
    pub fn clear_interrupt_window(&self) -> Result<(), Error> {
        const WHV_REG_DELIVERABILITY_NOTIFICATIONS: WHV_REGISTER_NAME = 0x80000004u32 as i32;
        self.set_reg64(WHV_REG_DELIVERABILITY_NOTIFICATIONS, 0x0)
    }

    #[allow(non_upper_case_globals)]
    fn decode_reason(ctx: &WHV_RUN_VP_EXIT_CONTEXT) -> VcpuExitReason {
        match ctx.ExitReason {
            WHvRunVpExitReasonX64IoPortAccess => VcpuExitReason::IoPortAccess,
            WHvRunVpExitReasonMemoryAccess => VcpuExitReason::MemoryAccess,
            WHvRunVpExitReasonX64Halt => VcpuExitReason::Halt,
            WHvRunVpExitReasonCanceled => VcpuExitReason::Canceled,
            WHvRunVpExitReasonX64Cpuid => VcpuExitReason::CpuidAccess,
            WHvRunVpExitReasonX64MsrAccess => VcpuExitReason::MsrAccess,
            WHvRunVpExitReasonX64InterruptWindow => VcpuExitReason::InterruptWindow,
            WHvRunVpExitReasonUnrecoverableException => VcpuExitReason::UnrecoverableException,
            WHvRunVpExitReasonInvalidVpRegisterValue => VcpuExitReason::InvalidVpRegisterValue,
            WHvRunVpExitReasonUnsupportedFeature => VcpuExitReason::UnsupportedFeature,
            _ => VcpuExitReason::Unknown(ctx.ExitReason as u32),
        }
    }
}

impl Drop for WhpVcpu {
    fn drop(&mut self) {
        let hr = unsafe { WHvDeleteVirtualProcessor(self.vm.partition_handle(), self.index) };
        if hr != S_OK {
            error!(
                "WHvDeleteVirtualProcessor({}) failed: HRESULT 0x{hr:08x}",
                self.index
            );
        }        
    }
}
