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
    WHV_CAPABILITY, WHV_EMULATOR_CALLBACKS, WHV_EMULATOR_STATUS, WHV_MEMORY_ACCESS_CONTEXT,
    WHV_PARTITION_HANDLE, WHV_PARTITION_PROPERTY, WHV_PARTITION_PROPERTY_CODE, WHV_REGISTER_NAME,
    WHV_REGISTER_VALUE, WHV_RUN_VP_EXIT_CONTEXT, WHV_VP_EXIT_CONTEXT,
    WHV_X64_IO_PORT_ACCESS_CONTEXT, WHvCapabilityCodeHypervisorPresent, WHvCreatePartition,
    WHvCreateVirtualProcessor, WHvDeletePartition, WHvDeleteVirtualProcessor,
    WHvEmulatorCreateEmulator, WHvEmulatorDestroyEmulator, WHvEmulatorTryIoEmulation,
    WHvEmulatorTryMmioEmulation, WHvGetCapability, WHvGetVirtualProcessorRegisters,
    WHvMapGpaRange, WHvMapGpaRangeFlagExecute, WHvMapGpaRangeFlagRead, WHvMapGpaRangeFlagWrite,
    WHvPartitionPropertyCodeCpuidExitList, WHvPartitionPropertyCodeLocalApicEmulationMode,
    WHvPartitionPropertyCodeProcessorCount, WHvRequestInterrupt, WHvRunVirtualProcessor,
    WHvRunVpExitReasonCanceled, WHvRunVpExitReasonInvalidVpRegisterValue,
    WHvRunVpExitReasonMemoryAccess, WHvRunVpExitReasonUnrecoverableException,
    WHvRunVpExitReasonUnsupportedFeature, WHvRunVpExitReasonX64Cpuid,
    WHvRunVpExitReasonX64Halt, WHvRunVpExitReasonX64IoPortAccess,
    WHvRunVpExitReasonX64MsrAccess, WHvSetPartitionProperty, WHvSetVirtualProcessorRegisters,
    WHvSetupPartition, WHvX64LocalApicEmulationModeXApic, WHvX64RegisterRax,
    WHvX64RegisterRbx, WHvX64RegisterRcx, WHvX64RegisterRdx, WHvX64RegisterRip,
};

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
    /// GPA of the Hyper-V Reference TSC Page, or `None` if not yet enabled.
    tsc_reference_gpa: Mutex<Option<u64>>,
    /// Host TSC value captured at VM creation (for TSC page calibration).
    vm_start_tsc: u64,
    /// Host monotonic instant captured at VM creation (for `TIME_REF_COUNT`).
    vm_start_instant: Instant,
}

impl HyperVState {
    fn new() -> Self {
        Self {
            guest_os_id: AtomicU64::new(0),
            tsc_reference_gpa: Mutex::new(None),
            vm_start_tsc: unsafe { core::arch::x86_64::_rdtsc() },
            vm_start_instant: Instant::now(),
        }
    }

    pub fn guest_os_id(&self) -> u64 {
        self.guest_os_id.load(Ordering::Relaxed)
    }

    pub fn set_guest_os_id(&self, val: u64) {
        self.guest_os_id.store(val, Ordering::Relaxed);
    }

    pub fn tsc_reference_gpa(&self) -> Option<u64> {
        *self.tsc_reference_gpa.lock().unwrap()
    }

    pub fn set_tsc_reference_gpa(&self, gpa: Option<u64>) {
        *self.tsc_reference_gpa.lock().unwrap() = gpa;
    }

    pub fn vm_start_tsc(&self) -> u64 {
        self.vm_start_tsc
    }

    pub fn vm_start_instant(&self) -> Instant {
        self.vm_start_instant
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

        let result = Self::configure_partition(handle, vcpu_count);
        if let Err(e) = result {
            let _ = unsafe { WHvDeletePartition(handle) };
            return Err(e);
        }

        debug!("WHP partition created with {vcpu_count} vCPU(s)");
        Ok(WhpVm {
            handle,
            hyperv: HyperVState::new(),
        })
    }

    fn configure_partition(handle: WHV_PARTITION_HANDLE, vcpu_count: u32) -> Result<(), Error> {
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

        // Intercept Hyper-V enlightenment CPUID leaves so we can present
        // synthetic hypervisor identity and feature flags to the guest.
        let cpuid_exit_list: [u32; 6] = [
            0x40000000, 0x40000001, 0x40000002,
            0x40000003, 0x40000004, 0x40000005,
        ];
        let hr = unsafe {
            WHvSetPartitionProperty(
                handle,
                WHvPartitionPropertyCodeCpuidExitList,
                cpuid_exit_list.as_ptr() as *const _,
                (cpuid_exit_list.len() * mem::size_of::<u32>()) as u32,
            )
        };
        if hr != S_OK {
            return Err(Error::SetPartitionProperty(hr));
        }

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

    /// Maps a host memory region into the guest physical address space.
    pub fn map_memory(
        &self,
        host_addr: *const u8,
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
        let value: WHV_REGISTER_VALUE = unsafe { mem::zeroed() };
        self.get_registers(&[name], &mut [value])?;
        Ok(unsafe { value.Reg64 })
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

    #[allow(non_upper_case_globals)]
    fn decode_reason(ctx: &WHV_RUN_VP_EXIT_CONTEXT) -> VcpuExitReason {
        match ctx.ExitReason {
            WHvRunVpExitReasonX64IoPortAccess => VcpuExitReason::IoPortAccess,
            WHvRunVpExitReasonMemoryAccess => VcpuExitReason::MemoryAccess,
            WHvRunVpExitReasonX64Halt => VcpuExitReason::Halt,
            WHvRunVpExitReasonCanceled => VcpuExitReason::Canceled,
            WHvRunVpExitReasonX64Cpuid => VcpuExitReason::CpuidAccess,
            WHvRunVpExitReasonX64MsrAccess => VcpuExitReason::MsrAccess,
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
