// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use vm_memory::GuestMemoryMmap;

use super::super::gdt::SegmentDescriptor;
use super::super::regs::{
    compute_page_tables, compute_segments, Error, EFER_LMA, EFER_LME, X86_CR0_PE,
};
use windows_sys::Win32::System::Hypervisor::*;

type Result<T> = std::result::Result<T, Error>;

/// Configure Floating-Point Unit (FPU) registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the WHP VCPU.
pub fn setup_fpu(vcpu: &whp::WhpVcpu) -> Result<()> {    
    let mut names = Vec::new();
    let mut values = Vec::new();

    let mut push_reg = |name: WHV_REGISTER_NAME, val: u64| {
        names.push(name);
        let mut v: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
        v.Reg64 = val;
        values.push(v);
    };

    push_reg(WHvX64RegisterFpControlStatus, 0x37f);
    push_reg(WHvX64RegisterXmmControlStatus, 0x1f80);

    vcpu.set_registers(&names, &values)
        .map_err(Error::SetWhpRegisters)
}

/// Configure base registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the WHP VCPU.
/// * `boot_ip` - Starting instruction pointer.
pub fn setup_regs(vcpu: &whp::WhpVcpu, boot_ip: u64) -> Result<()> {
    let mut names = Vec::new();
    let mut values = Vec::new();

    let mut push_reg = |name: WHV_REGISTER_NAME, val: u64| {
        names.push(name);
        let mut v: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
        v.Reg64 = val;
        values.push(v);
    };

    push_reg(WHvX64RegisterRflags, 0x0000_0000_0000_0002u64);

    if vcpu.index() == 0 {
        push_reg(WHvX64RegisterRip, boot_ip);
        // Frame pointer. It gets a snapshot of the stack pointer (rsp) so that when adjustments are
        // made to rsp (i.e. reserving space for local variables or pushing values on to the stack),
        // local variables and function parameters are still accessible from a constant offset from rbp.
        push_reg(
            WHvX64RegisterRsp,
            super::super::layout::BOOT_STACK_POINTER,
        );
        // Starting stack pointer.
        push_reg(
            WHvX64RegisterRbp,
            super::super::layout::BOOT_STACK_POINTER,
        );
        // Must point to zero page address per Linux ABI. This is x86_64 specific.
        push_reg(
            WHvX64RegisterRsi,
            super::super::layout::ZERO_PAGE_START,
        );
    } else if cfg!(feature = "tee") {
        push_reg(
            WHvX64RegisterRip,
            super::super::layout::RESET_VECTOR_SEV_AP,
        );
    } else {
        push_reg(
            WHvX64RegisterRip,
            super::super::layout::AP_TRAMPOLINE_START,
        );
    }

    vcpu.set_registers(&names, &values)
        .map_err(Error::SetWhpRegisters)
}

/// Configures the segment registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu` - Structure for the VCPU that holds the WHP VCPU.
pub fn setup_sregs(mem: &GuestMemoryMmap, vcpu: &whp::WhpVcpu) -> Result<()> {
    if vcpu.index() != 0 {
        if cfg!(feature = "tee") {
            return Ok(());
        }
        return setup_ap_segments(vcpu);
    }

    let segs = compute_segments(mem)?;
    let pt = compute_page_tables(mem)?;

    let mut names = Vec::new();
    let mut values = Vec::new();

    let push_segment = |names: &mut Vec<WHV_REGISTER_NAME>,
                        values: &mut Vec<WHV_REGISTER_VALUE>,
                        name: WHV_REGISTER_NAME,
                        seg: &SegmentDescriptor| {
        names.push(name);
        let mut v: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
        let s = unsafe { &mut v.Segment };
        s.Base = seg.base;
        s.Limit = seg.limit;
        s.Selector = seg.selector;
        s.Anonymous.Anonymous._bitfield = (seg.type_ as u16)
            | ((seg.s as u16) << 4)
            | ((seg.dpl as u16) << 5)
            | ((seg.present as u16) << 7)
            | ((seg.avl as u16) << 12)
            | ((seg.l as u16) << 13)
            | ((seg.db as u16) << 14)
            | ((seg.g as u16) << 15);
        values.push(v);
    };

    push_segment(&mut names, &mut values, WHvX64RegisterCs, &segs.code_seg);
    push_segment(&mut names, &mut values, WHvX64RegisterDs, &segs.data_seg);
    push_segment(&mut names, &mut values, WHvX64RegisterEs, &segs.data_seg);
    push_segment(&mut names, &mut values, WHvX64RegisterFs, &segs.data_seg);
    push_segment(&mut names, &mut values, WHvX64RegisterGs, &segs.data_seg);
    push_segment(&mut names, &mut values, WHvX64RegisterSs, &segs.data_seg);
    push_segment(&mut names, &mut values, WHvX64RegisterTr, &segs.tss_seg);

    let push_table = |names: &mut Vec<WHV_REGISTER_NAME>,
                      values: &mut Vec<WHV_REGISTER_VALUE>,
                      name: WHV_REGISTER_NAME,
                      base: u64,
                      limit: u16| {
        names.push(name);
        let mut v: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
        let t = unsafe { &mut v.Table };
        t.Base = base;
        t.Limit = limit;
        values.push(v);
    };

    push_table(
        &mut names,
        &mut values,
        WHvX64RegisterGdtr,
        segs.gdt_base,
        segs.gdt_limit,
    );
    push_table(
        &mut names,
        &mut values,
        WHvX64RegisterIdtr,
        segs.idt_base,
        segs.idt_limit,
    );

    // Read current CR0, CR4 and EFER in a single call so we can OR in the
    // bits we need, preserving any defaults the hypervisor has set (e.g. CR0.ET).
    let cr_names = [
        WHvX64RegisterCr0,
        WHvX64RegisterCr4,
        WHvX64RegisterEfer,
    ];
    let mut cr_vals: [WHV_REGISTER_VALUE; 3] = unsafe { std::mem::zeroed() };
    vcpu.get_registers(&cr_names, &mut cr_vals)
        .map_err(Error::GetWhpRegisters)?;
    let cr0 = unsafe { cr_vals[0].Reg64 };
    let cr4 = unsafe { cr_vals[1].Reg64 };
    let efer = unsafe { cr_vals[2].Reg64 };

    let mut push_reg = |name: WHV_REGISTER_NAME, val: u64| {
        names.push(name);
        let mut v: WHV_REGISTER_VALUE = unsafe { std::mem::zeroed() };
        v.Reg64 = val;
        values.push(v);
    };

    push_reg(WHvX64RegisterCr0, cr0 | X86_CR0_PE | pt.cr0_bits);
    push_reg(WHvX64RegisterCr3, pt.cr3);
    push_reg(WHvX64RegisterCr4, cr4 | pt.cr4_bits);
    push_reg(WHvX64RegisterEfer, efer | EFER_LME | EFER_LMA);

    vcpu.set_registers(&names, &values)
        .map_err(Error::SetWhpRegisters)
}

/// Reset CS.base to 0 for an AP vCPU so that RIP addresses land in low
/// memory rather than at the default reset CS.base of 0xFFFF_0000.
/// All other segment registers and control registers stay at their
/// power-on defaults (real mode).
fn setup_ap_segments(vcpu: &whp::WhpVcpu) -> Result<()> {
    let names = [WHvX64RegisterCs];
    let mut values: [WHV_REGISTER_VALUE; 1] = unsafe { std::mem::zeroed() };
    vcpu.get_registers(&names, &mut values)
        .map_err(Error::GetWhpRegisters)?;
    values[0].Segment.Base = 0;
    values[0].Segment.Selector = 0;    
    vcpu.set_registers(&names, &values)
        .map_err(Error::SetWhpRegisters)
}
