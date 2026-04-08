// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Windows Hypervisor Platform (WHP) virtual-machine and vCPU management.
//!
//! This module follows the same structure as `linux/vstate.rs` and
//! `macos/vstate.rs`: it consumes `whp::{WhpVm, WhpVcpu, VcpuExitReason}`
//! and routes I/O and MMIO exits through the WHP instruction emulator.

use log::{debug, error, warn};
use std::ffi::c_void;
use std::fmt::{Display, Formatter};
use std::io;
use std::mem;
use std::result;
use std::sync::Arc;
use std::thread;

use crate::windows::synic_timer::SynicTimer;
use crate::windows::{HV_MSR_APIC_FREQUENCY, HV_MSR_GUEST_OS_ID, HV_MSR_HYPERCALL, HV_MSR_REFERENCE_TSC, HV_MSR_STIMER0_CONFIG, HV_MSR_STIMER0_COUNT, HV_MSR_TIME_REF_COUNT, HV_MSR_TSC_FREQUENCY, HV_MSR_TSC_INVARIANT_CONTROL, HV_MSR_VP_INDEX, HV_MSR_VP_RUNTIME};

use super::super::{FC_EXIT_CODE_GENERIC_ERROR, FC_EXIT_CODE_OK};

use crossbeam_channel::{unbounded, Receiver, Sender, TryRecvError};
use utils::eventfd::EventFd;
use vm_memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryError, GuestMemoryMmap,
    GuestMemoryRegion,
};
use whp::{self, CpuidExitInfo, MsrExitInfo, VcpuExitReason, WhpEmulator, WhpVcpu, WhpVm};
use windows_sys::Win32::Foundation::S_OK;
use windows_sys::Win32::System::Hypervisor::{
    WHV_EMULATOR_CALLBACKS, WHV_EMULATOR_IO_ACCESS_INFO, WHV_EMULATOR_MEMORY_ACCESS_INFO,
    WHV_PARTITION_HANDLE, WHV_REGISTER_NAME, WHV_REGISTER_VALUE, WHV_TRANSLATE_GVA_FLAGS,
    WHV_TRANSLATE_GVA_RESULT, WHV_TRANSLATE_GVA_RESULT_CODE, WHvGetVirtualProcessorRegisters,
    WHvSetVirtualProcessorRegisters, WHvTranslateGva,
};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    /// Cannot create the instruction emulator.
    CreateEmulator(whp::Error),
    /// Instruction emulation failed.
    Emulation(whp::Error),
    /// Invalid guest memory configuration.
    GuestMemoryMmap(GuestMemoryError),
    /// The number of configured slots is bigger than the maximum reported by WHP.
    NotEnoughMemorySlots,
    /// Cannot set the memory regions.
    SetUserMemoryRegion(whp::Error),
    /// Failed to signal Vcpu.
    SignalVcpu(io::Error),
    /// vCPU count is not initialized.
    VcpuCountNotInitialized,
    /// Cannot run the VCPUs.
    VcpuRun(whp::Error),
    /// Cannot spawn a new vCPU thread.
    VcpuSpawn(io::Error),
    /// Unexpected VM exit reason.
    VcpuUnhandledExit,
    /// Cannot configure the microvm.
    VmSetup(whp::Error),
    /// WHP hypervisor not available.
    WhpNotAvailable(whp::Error),
    /// Error configuring the general purpose registers.
    REGSConfiguration(arch::x86_64::regs::Error),
    /// Error configuring the FPU registers.
    FPUConfiguration(arch::x86_64::regs::Error),
    /// Error configuring the special registers.
    SREGSConfiguration(arch::x86_64::regs::Error),
    /// Error configuring the MSR registers.
    MSRSConfiguration(arch::x86_64::msr::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use Error::*;
        match self {
            CreateEmulator(e) => write!(f, "Cannot create instruction emulator: {e}"),
            Emulation(e) => write!(f, "Instruction emulation failed: {e}"),
            GuestMemoryMmap(e) => write!(f, "Guest memory error: {e:?}"),
            NotEnoughMemorySlots => write!(f, "Not enough memory slots"),
            SetUserMemoryRegion(e) => write!(f, "Cannot set memory regions: {e}"),
            SignalVcpu(e) => write!(f, "Failed to signal vCPU: {e}"),
            VcpuCountNotInitialized => write!(f, "vCPU count is not initialized"),
            VcpuRun(e) => write!(f, "Cannot run vCPU: {e}"),
            VcpuSpawn(e) => write!(f, "Cannot spawn vCPU thread: {e}"),
            VcpuUnhandledExit => write!(f, "Unexpected VM exit reason"),
            VmSetup(e) => write!(f, "Cannot configure the VM: {e}"),
            WhpNotAvailable(e) => write!(f, "WHP hypervisor not available: {e}"),
            REGSConfiguration(e) => write!(f, "Error configuring registers: {e:?}"),
            FPUConfiguration(e) => write!(f, "Error configuring FPU: {e:?}"),
            SREGSConfiguration(e) => write!(f, "Error configuring special registers: {e:?}"),
            MSRSConfiguration(e) => write!(f, "Error configuring MSRs: {e:?}"),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

pub struct Vm {
    whp_vm: Arc<WhpVm>,
}

impl Vm {
    pub fn new(vcpu_count: u8) -> Result<Self> {
        whp::check_hypervisor().map_err(Error::WhpNotAvailable)?;
        let whp_vm = Arc::new(WhpVm::new(vcpu_count as u32).map_err(Error::VmSetup)?);
        Ok(Vm { whp_vm })
    }

    pub fn memory_init(
        &mut self,
        guest_mem: &GuestMemoryMmap,
    ) -> Result<()> {
        for region in guest_mem.iter() {
            // It's safe to unwrap because the guest address is valid.
            let host_addr = guest_mem.get_host_address(region.start_addr()).unwrap();
            debug!(
                "Guest memory host_addr={:x?} guest_addr={:x?} len={:x?}",
                host_addr,
                region.start_addr().raw_value(),
                region.len()
            );
            (unsafe { self.whp_vm
                .map_memory(
                    host_addr as *mut c_void,
                    region.start_addr().raw_value(),
                    region.len(),
                )
                .map_err(Error::SetUserMemoryRegion) })?;
        }
        Ok(())
    }

    pub fn whp_vm(&self) -> &Arc<WhpVm> {
        &self.whp_vm
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct VcpuConfig {
    pub vcpu_count: u8,
}

/// Passed as the opaque `*const c_void` context to every emulator callback.
///
/// For I/O emulation `bus` points to the I/O port bus; for MMIO emulation it
/// points to the memory-mapped bus.  `guest_mem` is always set so the memory
/// callback can fetch instruction bytes from guest RAM when WHP doesn't supply
/// them in the exit context.
#[repr(C)]
struct CallbackContext {
    partition_handle: WHV_PARTITION_HANDLE,
    vp_index: u32,
    bus: *const devices::Bus,
    guest_mem: *const GuestMemoryMmap,
}

unsafe extern "system" fn io_port_callback(
    context: *const c_void,
    io_access: *mut WHV_EMULATOR_IO_ACCESS_INFO,
) -> i32 {
    let ctx = &*(context as *const CallbackContext);
    let io = &mut *io_access;
    let bus = &*ctx.bus;
    if io.Direction != 0 {
        let data_bytes = io.Data.to_le_bytes();
        bus.write(ctx.vp_index as u64, io.Port as u64, &data_bytes[..io.AccessSize as usize]);
    } else {
        let mut data_bytes = [0u8; 4];
        bus.read(ctx.vp_index as u64, io.Port as u64, &mut data_bytes[..io.AccessSize as usize]);
        io.Data = u32::from_le_bytes(data_bytes);
    }
    S_OK
}

unsafe extern "system" fn memory_callback(
    context: *const c_void,
    mem_access: *mut WHV_EMULATOR_MEMORY_ACCESS_INFO,
) -> i32 {
    let ctx = &*(context as *const CallbackContext);
    let ma = &mut *mem_access;
    let gpa = GuestAddress(ma.GpaAddress);
    let size = ma.AccessSize as usize;

    // Try guest RAM first. If the GPA is in a RAM region succeeds immediately. 
    // Otherwise it's an actual MMIO access and we fall through to the MMIO bus.
    if !ctx.guest_mem.is_null() {
        let mem = &*ctx.guest_mem;
        if ma.Direction != 0 {
            if mem.write_slice(&ma.Data[..size], gpa).is_ok() {
                return S_OK;
            }
        } else if mem.read_slice(&mut ma.Data[..size], gpa).is_ok() {
            return S_OK;
        }
    }

    // GPA is not in a RAM region -- dispatch to the MMIO bus.
    if ctx.bus.is_null() {
        return S_OK;
    }
    let bus = &*ctx.bus;

    if ma.Direction != 0 {
        bus.write(ctx.vp_index as u64, ma.GpaAddress, &ma.Data[..size]);
    } else {
        bus.read(ctx.vp_index as u64, ma.GpaAddress, &mut ma.Data[..size]);
    }
    S_OK
}

unsafe extern "system" fn get_vp_registers_callback(
    context: *const c_void,
    register_names: *const WHV_REGISTER_NAME,
    register_count: u32,
    register_values: *mut WHV_REGISTER_VALUE,
) -> i32 {
    let ctx = &*(context as *const CallbackContext);
    WHvGetVirtualProcessorRegisters(
        ctx.partition_handle,
        ctx.vp_index,
        register_names,
        register_count,
        register_values,
    )
}

unsafe extern "system" fn set_vp_registers_callback(
    context: *const c_void,
    register_names: *const WHV_REGISTER_NAME,
    register_count: u32,
    register_values: *const WHV_REGISTER_VALUE,
) -> i32 {
    let ctx = &*(context as *const CallbackContext);
    WHvSetVirtualProcessorRegisters(
        ctx.partition_handle,
        ctx.vp_index,
        register_names,
        register_count,
        register_values,
    )
}

unsafe extern "system" fn translate_gva_callback(
    context: *const c_void,
    gva: u64,
    translate_flags: WHV_TRANSLATE_GVA_FLAGS,
    translation_result: *mut WHV_TRANSLATE_GVA_RESULT_CODE,
    gpa: *mut u64,
) -> i32 {
    let ctx = &*(context as *const CallbackContext);
    let mut result = WHV_TRANSLATE_GVA_RESULT::default();
    let hr = WHvTranslateGva(
        ctx.partition_handle,
        ctx.vp_index,
        gva,
        translate_flags,
        &mut result,
        gpa,
    );
    if hr == S_OK {
        *translation_result = result.ResultCode;
    }
    hr
}

fn build_emulator_callbacks() -> WHV_EMULATOR_CALLBACKS {
    WHV_EMULATOR_CALLBACKS {
        Size: mem::size_of::<WHV_EMULATOR_CALLBACKS>() as u32,
        Reserved: 0,
        WHvEmulatorIoPortCallback: Some(io_port_callback),
        WHvEmulatorMemoryCallback: Some(memory_callback),
        WHvEmulatorGetVirtualProcessorRegisters: Some(get_vp_registers_callback),
        WHvEmulatorSetVirtualProcessorRegisters: Some(set_vp_registers_callback),
        WHvEmulatorTranslateGvaPage: Some(translate_gva_callback),
    }
}

pub struct Vcpu {
    whp_vcpu: WhpVcpu,
    emulator: WhpEmulator,
    guest_mem: GuestMemoryMmap,
    io_bus: devices::Bus,
    mmio_bus: Option<devices::Bus>,
    exit_evt: EventFd,
    stimer: SynicTimer,

    event_receiver: Receiver<VcpuEvent>,
    event_sender: Option<Sender<VcpuEvent>>,
    response_receiver: Option<Receiver<VcpuResponse>>,
    response_sender: Sender<VcpuResponse>,
}

impl Vcpu {
    /// No-op on Windows -- cancellation uses `WHvCancelRunVirtualProcessor`.
    pub fn register_kick_signal_handler() {}

    pub fn new_x86_64(
        id: u8,
        vm: Arc<WhpVm>,
        guest_mem: GuestMemoryMmap,
        io_bus: devices::Bus,
        exit_evt: EventFd,
    ) -> Result<Self> {
        let stimer = SynicTimer::new(vm.clone(), id as u32);
        let whp_vcpu = WhpVcpu::new(vm, id as u32).map_err(Error::VcpuRun)?;
        let emulator =
            WhpEmulator::new(build_emulator_callbacks()).map_err(Error::CreateEmulator)?;
        
        let (event_sender, event_receiver) = unbounded();
        let (response_sender, response_receiver) = unbounded();

        Ok(Vcpu {
            whp_vcpu,
            emulator,
            guest_mem,
            io_bus,
            mmio_bus: None,
            exit_evt,
            stimer,
            event_receiver,
            event_sender: Some(event_sender),
            response_receiver: Some(response_receiver),
            response_sender,
        })
    }

    pub fn configure_x86_64(
        &mut self,
        guest_mem: &GuestMemoryMmap,
        kernel_start_addr: GuestAddress,
        kernel_boot: bool,
    ) -> Result<()> {
        if kernel_boot {
            arch::x86_64::regs::setup_regs(&self.whp_vcpu, kernel_start_addr.raw_value())
                .map_err(Error::REGSConfiguration)?;

            arch::x86_64::regs::setup_sregs(guest_mem, &self.whp_vcpu)
                .map_err(Error::SREGSConfiguration)?;

            if self.cpu_index() == 0 {
                arch::x86_64::regs::setup_fpu(&self.whp_vcpu)
                    .map_err(Error::FPUConfiguration)?;

                arch::x86_64::msr::setup_msrs(&self.whp_vcpu)
                    .map_err(Error::MSRSConfiguration)?;
            }
        }

        Ok(())
    }

    pub fn cpu_index(&self) -> u8 {
        self.whp_vcpu.index() as u8
    }

    pub fn set_mmio_bus(&mut self, mmio_bus: devices::Bus) {
        self.mmio_bus = Some(mmio_bus);
    }

    /// Moves the vcpu to its own thread and constructs a VcpuHandle.
    /// The handle can be used to control the remote vCPU.
    pub fn start_threaded(mut self) -> Result<VcpuHandle> {
        let event_sender = self.event_sender.take().unwrap();
        let response_receiver = self.response_receiver.take().unwrap();

        let vm = self.whp_vcpu.vm().clone();
        let vp_index = self.whp_vcpu.index();

        let _vcpu_thread = thread::Builder::new()
            .name(format!("fc_vcpu {}", self.cpu_index()))
            .spawn(move || {
                self.run();
            })
            .map_err(Error::VcpuSpawn)?;

        Ok(VcpuHandle {
            event_sender,
            response_receiver,
            vm,
            vp_index,
        })
    }

    fn run(&mut self) {
        self.wait_for_resume();

        loop {
            match self.event_receiver.try_recv() {
                Ok(VcpuEvent::Resume) => {
                    self.response_sender
                        .send(VcpuResponse::Resumed)
                        .expect("failed to send Resumed");
                }
                Ok(VcpuEvent::Pause) => {
                    self.response_sender
                        .send(VcpuResponse::Paused)
                        .expect("failed to send Paused");
                    self.wait_for_resume();
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => break,
            }

            match self.run_emulation() {
                Ok(VcpuEmulation::Handled) => {}
                Ok(VcpuEmulation::Stopped) => {
                    self.exit(FC_EXIT_CODE_OK);
                    break;
                }
                Ok(VcpuEmulation::Interrupted) => {}
                Err(_) => {
                    self.exit(FC_EXIT_CODE_GENERIC_ERROR);
                    break;
                }
            }
        }
    }

    fn wait_for_resume(&mut self) {
        loop {
            match self.event_receiver.recv() {
                Ok(VcpuEvent::Resume) => {
                    self.response_sender
                        .send(VcpuResponse::Resumed)
                        .expect("failed to send Resumed");
                    return;
                }
                Ok(VcpuEvent::Pause) => continue,
                Err(_) => return,
            }
        }
    }

    fn callback_context(&self, bus: *const devices::Bus) -> CallbackContext {
        CallbackContext {
            partition_handle: self.whp_vcpu.partition_handle(),
            vp_index: self.whp_vcpu.index(),
            bus,
            guest_mem: &self.guest_mem as *const GuestMemoryMmap,
        }
    }

    fn run_emulation(&mut self) -> Result<VcpuEmulation> {
        let reason = self.whp_vcpu.run().map_err(Error::VcpuRun)?;
        let result = match reason {
            VcpuExitReason::IoPortAccess => {
                let ctx = self.callback_context(&self.io_bus as *const devices::Bus);
                unsafe {
                    self.emulator
                        .try_io_emulation(
                            &ctx as *const _ as *const c_void,
                            self.whp_vcpu.vp_exit_context(),
                            self.whp_vcpu.io_port_access_context(),
                        )
                        .map_err(Error::Emulation)?;
                }
                Ok(VcpuEmulation::Handled)
            }
            VcpuExitReason::MemoryAccess => {
                let bus = self
                    .mmio_bus
                    .as_ref()
                    .map_or(std::ptr::null(), |b| b as *const devices::Bus);
                let ctx = self.callback_context(bus);
                unsafe {
                    self.emulator
                        .try_mmio_emulation(
                            &ctx as *const _ as *const c_void,
                            self.whp_vcpu.vp_exit_context(),
                            self.whp_vcpu.memory_access_context(),
                        )
                        .map_err(Error::Emulation)?;
                }
                Ok(VcpuEmulation::Handled)
            }
            VcpuExitReason::CpuidAccess => {
                let info = self.whp_vcpu.cpuid_exit_info();
                self.handle_cpuid(&info)?;
                Ok(VcpuEmulation::Handled)
            }
            VcpuExitReason::MsrAccess => {
                let info = self.whp_vcpu.msr_exit_info();
                self.handle_msr_access(&info)?;
                Ok(VcpuEmulation::Handled)
            }
            VcpuExitReason::Halt => {
                // A Linux guest hits HLT when idle. 
                // WHP handles most HLT states internally (if interrupts are enabled), 
                // but if we land here, the vCPU is truly stalled.
                
                // Check if we should actually be shutting down.
                if self.exit_evt.is_signaled() {
                    return Ok(VcpuEmulation::Stopped);
                }

                // Be a good host citizen. yield_now() prevents our thread from 
                // spinning at 100% CPU while the guest is "sleeping".
                thread::yield_now();
                Ok(VcpuEmulation::Handled)
            }
            VcpuExitReason::InterruptWindow => {
                // We don't need to do anything specific here because the 
                // next call to WHvRunVirtualProcessor will allow the hardware 
                // to deliver any pending interrupts we've requested via STimer or IPIs.
                Ok(VcpuEmulation::Handled)
            }
            VcpuExitReason::Canceled => {
                // WHvRequestInterrupt does NOT clear HaltSuspend — the vCPU
                // stays frozen in HLT even with a pending LAPIC interrupt.
                // Clear it here so the next WHvRunVirtualProcessor call can
                // actually deliver the interrupt the kick thread injected.
                let _ = self.whp_vcpu.clear_halt_suspend();
                Ok(VcpuEmulation::Handled)
            }
            VcpuExitReason::UnrecoverableException => {
                error!("vCPU {} unrecoverable exception", self.cpu_index());
                Err(Error::VcpuUnhandledExit)
            }
            VcpuExitReason::InvalidVpRegisterValue => {
                error!("vCPU {} invalid register value", self.cpu_index());
                Err(Error::VcpuUnhandledExit)
            }
            VcpuExitReason::UnsupportedFeature => {
                error!("vCPU {} unsupported feature", self.cpu_index());
                Err(Error::VcpuUnhandledExit)
            }
            VcpuExitReason::Unknown(code) => {
                error!("vCPU {} unknown exit reason 0x{:x}", self.cpu_index(), code);
                Err(Error::VcpuUnhandledExit)
            }
        };

        // If a shutdown device (i8042, ACPI PM, …) signaled exit_evt --
        // possibly from this vCPU or from another -- stop immediately.
        if self.exit_evt.is_signaled() {
            return Ok(VcpuEmulation::Stopped);
        }

        result
    }

    /// Handle a CPUID exit.
    ///
    /// Hyper-V enlightenment leaves (0x40000000+) and TSC leaves (0x15) are
    /// injected via `CpuidResultList` in platform.rs and never reach here.
    /// The only leaf in the `CpuidExitList` is leaf 1, which we intercept
    /// to set the hypervisor-present bit (ECX.31).
    fn handle_cpuid(&self, info: &CpuidExitInfo) -> Result<()> {
        let eax = info.default_eax;
        let ebx = info.default_ebx;
        let mut ecx = info.default_ecx;
        let edx = info.default_edx;

        if info.leaf == 1 {
            ecx |= 1 << 31;
        }

        self.whp_vcpu
            .complete_cpuid(eax, ebx, ecx, edx)
            .map_err(Error::Emulation)
    }

    /// Handle an MSR read/write exit for Hyper-V synthetic MSRs.
    fn handle_msr_access(&self, info: &MsrExitInfo) -> Result<()> {
        let hv = self.whp_vcpu.vm().hyperv();

        let mut rax = 0u64;
        let mut rdx = 0u64;

        match info.msr_number {
            HV_MSR_GUEST_OS_ID => {
                // HV_X64_MSR_GUEST_OS_ID
                if info.is_write {
                    hv.set_guest_os_id((info.rdx << 32) | (info.rax & 0xFFFF_FFFF));
                } else {
                    let id = hv.guest_os_id();
                    rax = id & 0xFFFF_FFFF;
                    rdx = id >> 32;
                }
            }
            HV_MSR_HYPERCALL => {
                // HV_X64_MSR_HYPERCALL
                // hypercall is not supported yet
                if !info.is_write {
                    rax = 0;
                }
            }
            HV_MSR_VP_INDEX => {
                if !info.is_write {
                    rax = self.cpu_index() as u64; // Low 32 bits
                    rdx = 0;                       // High 32 bits
                }
            }
            HV_MSR_VP_RUNTIME => {
                if !info.is_write {
                    let runtime = hv.vm_start_instant().elapsed().as_nanos() as u64 / 100;
                    rax = runtime & 0xFFFF_FFFF;
                    rdx = runtime >> 32;
                }
            }
            HV_MSR_TIME_REF_COUNT => {
                // HV_X64_MSR_TIME_REF_COUNT (read-only, 100ns ticks since boot)
                if !info.is_write {
                    let ticks = hv.vm_start_instant().elapsed().as_nanos() / 100;
                    rax = (ticks & 0xFFFF_FFFF) as u64;
                    rdx = ((ticks >> 32) & 0xFFFF_FFFF) as u64;
                }
            }
            HV_MSR_REFERENCE_TSC => {
                if info.is_write {
                    let msr_value = (info.rdx << 32) | (info.rax & 0xFFFF_FFFF);
                    hv.set_tsc_reference_msr(msr_value);
                    if msr_value & 1 != 0 {
                        let gpa = msr_value & !0xFFF;
                        self.write_tsc_reference_page(gpa);
                    }
                } else {
                    let val = hv.tsc_reference_msr();
                    rax = val & 0xFFFF_FFFF;
                    rdx = val >> 32;
                }
            }
            HV_MSR_STIMER0_CONFIG => { // HV_X64_MSR_STIMER0_CONFIG
                if info.is_write {
                    let val = (info.rdx << 32) | (info.rax & 0xFFFF_FFFF);
                    hv.set_stimer0_config(val);
                    self.stimer.write_config(val);
                } else {
                    let val = hv.stimer0_config();
                    rax = val & 0xFFFF_FFFF;
                    rdx = val >> 32;
                }
            }
            HV_MSR_STIMER0_COUNT => { // HV_X64_MSR_STIMER0_COUNT
                if info.is_write {
                    let val = (info.rdx << 32) | (info.rax & 0xFFFF_FFFF);
                    hv.set_stimer0_count(val);
                    self.stimer.write_count(val);
                } else {
                    let val = hv.stimer0_count();
                    rax = val & 0xFFFF_FFFF;
                    rdx = val >> 32;
                }
            }
            HV_MSR_TSC_FREQUENCY => {
                if !info.is_write {
                    let freq = hv.tsc_freq_hz();
                    rax = freq & 0xFFFF_FFFF;
                    rdx = freq >> 32;
                }
            }
            HV_MSR_APIC_FREQUENCY => {
                if !info.is_write {
                    rax = 1_000_000;
                    rdx = 0;
                }
            }
            HV_MSR_TSC_INVARIANT_CONTROL => {
                // HV_X64_MSR_TSC_INVARIANT_CONTROL — simple read/write store.
                // Stored per-VM since all vCPUs share the invariant-TSC setting.
                // We reuse guest_os_id's pattern with a dedicated atomic, but
                // since this is rarely accessed we just accept the write and
                // return 0 on read (the guest only checks the enable bit).
                if !info.is_write {
                    rax = 0;
                    rdx = 0;
                }
            }
            _ => {
                debug!(
                    "vCPU {} unhandled MSR 0x{:x} {}",
                    self.cpu_index(),
                    info.msr_number,
                    if info.is_write { "write" } else { "read" }
                );
            }
        }

        if info.is_write {
            self.whp_vcpu.advance_rip().map_err(Error::Emulation)
        } else {
            self.whp_vcpu
                .complete_msr_read(rax, rdx)
                .map_err(Error::Emulation)
        }
    }

    /// Write the Hyper-V Reference TSC Page at the given GPA.
    ///
    /// Layout (see TLFS §12.5):
    /// offset 0:  u32  tsc_sequence   — non-zero means calibration is valid
    /// offset 4:  u32  (reserved)
    /// offset 8:  u64  tsc_scale      — fractional multiplier  (time = tsc * scale >> 64)
    /// offset 16: i64  tsc_offset     — added after scaling (in 100 ns units)
    fn write_tsc_reference_page(&self, gpa: u64) {
        let freq = self.whp_vcpu.vm().hyperv().tsc_freq_hz();
        if freq == 0 {
            warn!("TSC frequency unknown — cannot set up reference TSC page");
            return;
        }

        // tsc_scale: guest computes  time_100ns = (rdtsc() * scale) >> 64
        // So  scale = (10_000_000 << 64) / tsc_freq_hz
        let scale: u64 = ((10_000_000u128 << 64) / freq as u128) as u64;

        // tsc_offset: how many 100 ns units to add.  We anchor at 0 so the
        // VM starts with reference_time ~= 0.  The kernel adds its own
        // boot-time offset on top.
        let start_tsc = self.whp_vcpu.vm().hyperv().vm_start_tsc();
        let offset: i64 = -((start_tsc as u128 * scale as u128 >> 64) as i64);

        let mut page = [0u8; 4096];
        
        // tsc_sequence = 1 (valid)
        page[0..4].copy_from_slice(&1u32.to_le_bytes());
        // reserved
        page[4..8].copy_from_slice(&0u32.to_le_bytes());
        // tsc_scale
        page[8..16].copy_from_slice(&scale.to_le_bytes());
        // tsc_offset
        page[16..24].copy_from_slice(&offset.to_le_bytes());

        let addr = GuestAddress(gpa);
        if let Err(e) = self.guest_mem.write_slice(&page, addr) {
            error!("Failed to write TSC reference page at GPA 0x{gpa:x}: {e}");
        } else {
            debug!(
                "TSC reference page at GPA 0x{gpa:x}: scale=0x{scale:016x} offset={offset} freq={freq}Hz",
            );
        }
    }

    fn exit(&mut self, exit_code: u8) {
        self.response_sender
            .send(VcpuResponse::Exited(exit_code))
            .expect("failed to send Exited status");

        if let Err(e) = self.exit_evt.write(1) {
            error!("Failed signaling vcpu exit event: {e}");
        }
    }
}




// Allow currently unused Pause and Exit events. These will be used by the vmm later on.
#[allow(unused)]
#[derive(Debug)]
/// List of events that the Vcpu can receive.
pub enum VcpuEvent {
    /// Pause the Vcpu.
    Pause,
    /// Event that should resume the Vcpu.
    Resume,
}

#[derive(Debug, Eq, PartialEq)]
/// List of responses that the Vcpu reports.
pub enum VcpuResponse {
    /// Vcpu is paused.
    Paused,
    /// Vcpu is resumed.
    Resumed,
    /// Vcpu is stopped.
    Exited(u8),
}

/// Wrapper over Vcpu that hides the underlying interactions with the Vcpu thread.
pub struct VcpuHandle {
    /// The transmitting end of the events channel which will be given to the handler.
    event_sender: Sender<VcpuEvent>,
    /// The receiving end of the responses channel which will be given to the handler.
    response_receiver: Receiver<VcpuResponse>,
    /// The VM that the vCPU belongs to.
    vm: Arc<WhpVm>,
    /// The index of the vCPU.
    vp_index: u32,
}

impl VcpuHandle {
    pub fn send_event(&self, event: VcpuEvent) -> Result<()> {
        self.event_sender
            .send(event)
            .expect("event sender channel closed on vcpu end.");

        // Interrupt WHvRunVirtualProcessor so the vCPU picks up the event.
        unsafe {
            let hr = windows_sys::Win32::System::Hypervisor::WHvCancelRunVirtualProcessor(
                self.vm.partition_handle(),
                self.vp_index,
                0,
            );
            if hr != windows_sys::Win32::Foundation::S_OK {
                error!("WHvCancelRunVirtualProcessor failed: HRESULT 0x{hr:08x}");
            }
        }

        Ok(())
    }

    pub fn response_receiver(&self) -> &Receiver<VcpuResponse> {
        &self.response_receiver
    }
}

enum VcpuEmulation {
    Handled,
    Interrupted,
    Stopped,
}
