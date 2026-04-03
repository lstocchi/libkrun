// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use kvm_bindings::{kvm_fpu, kvm_regs, kvm_segment, kvm_sregs};
use kvm_ioctls::VcpuFd;
use vm_memory::GuestMemoryMmap;

use super::super::gdt::SegmentDescriptor;
use super::super::regs::{
    compute_page_tables, compute_segments, Error, EFER_LMA, EFER_LME, X86_CR0_PE,
};

type Result<T> = std::result::Result<T, Error>;

fn kvm_segment_from(seg: &SegmentDescriptor) -> kvm_segment {
    kvm_segment {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector,
        type_: seg.type_,
        present: seg.present,
        dpl: seg.dpl,
        db: seg.db,
        s: seg.s,
        l: seg.l,
        g: seg.g,
        avl: seg.avl,
        padding: 0,
        unusable: seg.unusable,
    }
}

/// Configure Floating-Point Unit (FPU) registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
pub fn setup_fpu(vcpu: &VcpuFd) -> Result<()> {
    let fpu: kvm_fpu = kvm_fpu {
        fcw: 0x37f,
        mxcsr: 0x1f80,
        ..Default::default()
    };
    vcpu.set_fpu(&fpu).map_err(Error::SetFPURegisters)
}

/// Configure base registers for a given CPU.
///
/// # Arguments
///
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `boot_ip` - Starting instruction pointer.
pub fn setup_regs(vcpu: &VcpuFd, boot_ip: u64, id: u8) -> Result<()> {
    let regs: kvm_regs = if id == 0 || cfg!(not(feature = "tee")) {
        kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: boot_ip,
            // Frame pointer. It gets a snapshot of the stack pointer (rsp) so that when adjustments are
            // made to rsp (i.e. reserving space for local variables or pushing values on to the stack),
            // local variables and function parameters are still accessible from a constant offset from rbp.
            rsp: super::super::layout::BOOT_STACK_POINTER,
            rbp: super::super::layout::BOOT_STACK_POINTER,
            rsi: super::super::layout::ZERO_PAGE_START,
            ..Default::default()
        }
    } else {
        kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: super::super::layout::RESET_VECTOR_SEV_AP,
            ..Default::default()
        }
    };
    vcpu.set_regs(&regs).map_err(Error::SetBaseRegisters)
}

/// Configures the segment registers and system page tables for a given CPU.
///
/// # Arguments
///
/// * `mem` - The memory that will be passed to the guest.
/// * `vcpu` - Structure for the VCPU that holds the VCPU's fd.
/// * `id` - The ID of the CPU.
pub fn setup_sregs(mem: &GuestMemoryMmap, vcpu: &VcpuFd, id: u8) -> Result<()> {
    let mut sregs: kvm_sregs = vcpu.get_sregs().map_err(Error::GetStatusRegisters)?;

    if cfg!(not(feature = "tee")) {
        configure_segments_and_sregs(mem, &mut sregs)?;
        setup_page_tables(mem, &mut sregs)?; // TODO(dgreid) - Can this be done once per system instead
    } else if id != 0 {
        //sregs.cs.selector = 0x9100;
        //sregs.cs.base = 0x91000;
    }

    vcpu.set_sregs(&sregs).map_err(Error::SetStatusRegisters)
}

fn configure_segments_and_sregs(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    let segs = compute_segments(mem)?;

    sregs.cs = kvm_segment_from(&segs.code_seg);
    sregs.ds = kvm_segment_from(&segs.data_seg);
    sregs.es = kvm_segment_from(&segs.data_seg);
    sregs.fs = kvm_segment_from(&segs.data_seg);
    sregs.gs = kvm_segment_from(&segs.data_seg);
    sregs.ss = kvm_segment_from(&segs.data_seg);
    sregs.tr = kvm_segment_from(&segs.tss_seg);

    sregs.gdt.base = segs.gdt_base;
    sregs.gdt.limit = segs.gdt_limit;
    sregs.idt.base = segs.idt_base;
    sregs.idt.limit = segs.idt_limit;

    sregs.cr0 |= X86_CR0_PE;
    sregs.efer |= EFER_LME | EFER_LMA;

    Ok(())
}

fn setup_page_tables(mem: &GuestMemoryMmap, sregs: &mut kvm_sregs) -> Result<()> {
    let pt = compute_page_tables(mem)?;
    sregs.cr3 = pt.cr3;
    sregs.cr4 |= pt.cr4_bits;
    sregs.cr0 |= pt.cr0_bits;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::super::regs::{BOOT_GDT_OFFSET, BOOT_IDT_OFFSET};
    use super::*;
    use kvm_bindings::kvm_sregs;
    use kvm_ioctls::Kvm;
    use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

    fn create_guest_mem() -> GuestMemoryMmap {
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap()
    }

    fn read_u64(gm: &GuestMemoryMmap, offset: u64) -> u64 {
        let read_addr = GuestAddress(offset);
        gm.read_obj(read_addr).unwrap()
    }

    fn validate_segments_and_sregs(gm: &GuestMemoryMmap, sregs: &kvm_sregs) {
        assert_eq!(0x0, read_u64(gm, BOOT_GDT_OFFSET));
        assert_eq!(0xaf_9b00_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 8));
        assert_eq!(0xcf_9300_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 16));
        assert_eq!(0x8f_8b00_0000_ffff, read_u64(gm, BOOT_GDT_OFFSET + 24));
        assert_eq!(0x0, read_u64(gm, BOOT_IDT_OFFSET));

        assert_eq!(0, sregs.cs.base);
        assert_eq!(0xfffff, sregs.ds.limit);
        assert_eq!(0x10, sregs.es.selector);
        assert_eq!(1, sregs.fs.present);
        assert_eq!(1, sregs.gs.g);
        assert_eq!(0, sregs.ss.avl);
        assert_eq!(0, sregs.tr.base);
        assert_eq!(0xfffff, sregs.tr.limit);
        assert_eq!(0, sregs.tr.avl);
        assert!(sregs.cr0 & X86_CR0_PE != 0);
        assert!(sregs.efer & EFER_LME != 0 && sregs.efer & EFER_LMA != 0);
    }

    #[test]
    fn test_configure_segments_and_sregs() {
        let mut sregs: kvm_sregs = Default::default();
        let gm = create_guest_mem();
        configure_segments_and_sregs(&gm, &mut sregs).unwrap();

        validate_segments_and_sregs(&gm, &sregs);
    }

    #[test]
    fn test_setup_fpu() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        setup_fpu(&vcpu).unwrap();

        let expected_fpu: kvm_fpu = kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        };
        let actual_fpu: kvm_fpu = vcpu.get_fpu().unwrap();
        assert_eq!(expected_fpu.fcw, actual_fpu.fcw);
    }

    #[test]
    fn test_setup_regs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();

        let expected_regs: kvm_regs = kvm_regs {
            rflags: 0x0000_0000_0000_0002u64,
            rip: 1,
            rsp: super::super::layout::BOOT_STACK_POINTER,
            rbp: super::super::layout::BOOT_STACK_POINTER,
            rsi: super::super::layout::ZERO_PAGE_START,
            ..Default::default()
        };

        setup_regs(&vcpu, expected_regs.rip, 1).unwrap();

        let actual_regs: kvm_regs = vcpu.get_regs().unwrap();
        assert_eq!(actual_regs, expected_regs);
    }

    #[test]
    fn test_setup_sregs() {
        let kvm = Kvm::new().unwrap();
        let vm = kvm.create_vm().unwrap();
        let vcpu = vm.create_vcpu(0).unwrap();
        let gm = create_guest_mem();

        assert!(vcpu.set_sregs(&Default::default()).is_ok());
        setup_sregs(&gm, &vcpu, 1).unwrap();

        let mut sregs: kvm_sregs = vcpu.get_sregs().unwrap();
        sregs.gs.g = 1;

        validate_segments_and_sregs(&gm, &sregs);
    }
}
