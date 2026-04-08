// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Adapted from crosvm's devices/src/irqchip/pic.rs for libkrun/WHP.
// Original: https://github.com/google/crosvm/blob/main/devices/src/irqchip/pic.rs

//! Software 8259A PIC emulation, adapted from crosvm for WHP.
//!
//! # Why a PIC is needed
//!
//! WHP provides neither an in-kernel 8259 PIC nor an in-kernel IOAPIC;
//! both must be emulated in userspace.  During early Linux boot the kernel
//! operates in "Virtual Wire" mode (advertised via the MP table's ExtINT
//! entry) and relies on the PIC to receive PIT timer ticks (IRQ 0) before
//! it switches to APIC mode and programs the IOAPIC.  Without a PIC those
//! early timer interrupts are lost and boot stalls indefinitely.
//!
//! Once the kernel transitions to Symmetric I/O mode it masks the PIC and
//! routes timer interrupts through the IOAPIC instead.  The PIT worker
//! fires IRQ 0 through both paths on every tick — this mirrors real
//! hardware where the PIT output is wired to IOAPIC pin 0 and PIC IRQ 0
//! simultaneously — and the kernel decides which path is active by
//! masking/unmasking each controller independently.
//!
//! # Differences from crosvm
//!
//! In crosvm the PIC sets an `interrupt_request` flag that the vCPU thread
//! polls.  Under WHP there is no in-kernel injection path, so instead
//! [`Pic::update_irq`] calls [`WHvRequestInterrupt`] +
//! [`WHvCancelRunVirtualProcessor`] directly whenever a deliverable
//! interrupt is found.
//!
//! Resample events and snapshot/suspend support have been removed as they
//! are not needed for the libkrun use-case.

use std::sync::{Arc, Mutex};

use whp::{InterruptDestinationMode, InterruptRequest, InterruptTriggerMode, InterruptType, WhpVm};

use crate::bus::BusDevice;

// ── Local equivalents of crosvm's hypervisor types ─────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PicSelect {
    Primary = 0,
    Secondary = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PicInitState {
    Icw1,
    Icw2,
    Icw3,
    Icw4,
}

impl Default for PicInitState {
    fn default() -> Self {
        PicInitState::Icw1
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PicState {
    last_irr: u8,
    irr: u8,
    imr: u8,
    isr: u8,
    priority_add: u8,
    irq_base: u8,
    read_reg_select: bool,
    poll: bool,
    special_mask: bool,
    init_state: PicInitState,
    auto_eoi: bool,
    rotate_on_auto_eoi: bool,
    special_fully_nested_mode: bool,
    use_4_byte_icw: bool,
    elcr: u8,
    elcr_mask: u8,
}

// ── Constants (from crosvm / Intel 8259A spec) ─────────────────────

const INVALID_PRIORITY: u8 = 8;
const SPURIOUS_IRQ: u8 = 0x07;
const PRIMARY_PIC_CASCADE_PIN: u8 = 2;
const PRIMARY_PIC_CASCADE_PIN_MASK: u8 = 0x04;
const PRIMARY_PIC_MAX_IRQ: u8 = 7;

const ICW1_MASK: u8 = 0x10;
const OCW3_MASK: u8 = 0x08;

const ICW1_NEED_ICW4: u8 = 0x01;
const ICW1_SINGLE_PIC_MODE: u8 = 0x02;
const ICW1_LEVEL_TRIGGER_MODE: u8 = 0x08;

const ICW2_IRQ_BASE_MASK: u8 = 0xf8;

const ICW4_SPECIAL_FULLY_NESTED_MODE: u8 = 0x10;
const ICW4_AUTO_EOI: u8 = 0x02;

const OCW2_IRQ_MASK: u8 = 0x07;
const OCW2_COMMAND_MASK: u8 = 0xe0;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Ocw2 {
    RotateAutoEoiClear = 0x00,
    NonSpecificEoi = 0x20,
    NoOp = 0x40,
    SpecificEoi = 0x60,
    RotateAutoEoiSet = 0x80,
    RotateNonSpecificEoi = 0xa0,
    SetPriority = 0xc0,
    RotateSpecificEoi = 0xe0,
}

impl Ocw2 {
    fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(Ocw2::RotateAutoEoiClear),
            0x20 => Some(Ocw2::NonSpecificEoi),
            0x40 => Some(Ocw2::NoOp),
            0x60 => Some(Ocw2::SpecificEoi),
            0x80 => Some(Ocw2::RotateAutoEoiSet),
            0xa0 => Some(Ocw2::RotateNonSpecificEoi),
            0xc0 => Some(Ocw2::SetPriority),
            0xe0 => Some(Ocw2::RotateSpecificEoi),
            _ => None,
        }
    }
}

const OCW3_POLL_COMMAND: u8 = 0x04;
const OCW3_READ_REGISTER: u8 = 0x02;
const OCW3_READ_ISR: u8 = 0x01;
const OCW3_SPECIAL_MASK: u8 = 0x40;
const OCW3_SPECIAL_MASK_VALUE: u8 = 0x20;

pub struct Pic {
    pics: [PicState; 2],
    vm: Option<Arc<WhpVm>>,
}

impl Pic {
    pub fn new(vm: Arc<WhpVm>) -> Self {
        let mut primary: PicState = Default::default();
        let mut secondary: PicState = Default::default();

        // IRQs 0, 1, 8, 13 are dedicated to system-board devices and are
        // always edge-triggered.  IRQ 2 is the cascade line.
        primary.elcr_mask = !((1 << 0) | (1 << 1) | (1 << 2));
        secondary.elcr_mask = !((1 << 0) | (1 << 5));

        Pic {
            pics: [primary, secondary],
            vm: Some(vm),
        }
    }

    /// Assert or de-assert an IRQ line.  Returns whether an interrupt was
    /// injected into the vCPU.
    pub fn service_irq(&mut self, irq: u8, level: bool) -> bool {
        assert!(irq <= 15, "unexpectedly high irq: {irq}");

        let pic = if irq <= PRIMARY_PIC_MAX_IRQ {
            PicSelect::Primary
        } else {
            PicSelect::Secondary
        };
        Pic::set_irq_internal(&mut self.pics[pic as usize], irq & 7, level);
        self.update_irq()
    }

    /// Convenience: pulse an IRQ line (assert + de-assert) for
    /// edge-triggered devices like the PIT.
    pub fn raise_irq(&mut self, irq: u8) {
        self.service_irq(irq, true);
        self.service_irq(irq, false);
    }

    /// Whether the primary PIC is fully masked.
    pub fn masked(&self) -> bool {
        self.pics[PicSelect::Primary as usize].imr == 0xFF
    }

    /// Whether the PIC has a pending interrupt.
    pub fn has_interrupt(&self) -> bool {
        self.get_irq(PicSelect::Primary).is_some()
    }

    /// Acknowledge and return the next external interrupt vector, if any.
    pub fn get_external_interrupt(&mut self) -> Option<u8> {
        let irq_primary = self.get_irq(PicSelect::Primary)?;

        self.interrupt_ack(PicSelect::Primary, irq_primary);
        let int_num = if irq_primary == PRIMARY_PIC_CASCADE_PIN {
            let irq_secondary = if let Some(irq) = self.get_irq(PicSelect::Secondary) {
                self.interrupt_ack(PicSelect::Secondary, irq);
                irq
            } else {
                SPURIOUS_IRQ
            };
            self.pics[PicSelect::Secondary as usize].irq_base + irq_secondary
        } else {
            self.pics[PicSelect::Primary as usize].irq_base + irq_primary
        };

        self.update_irq();
        Some(int_num)
    }

    // ── Register-level handlers (called by PicPort wrappers) ───────

    fn pic_read_command(&mut self, pic_type: PicSelect) -> u8 {
        if self.pics[pic_type as usize].poll {
            let (ret, update_irq_needed) = self.poll_read(pic_type);
            self.pics[pic_type as usize].poll = false;
            if update_irq_needed {
                self.update_irq();
            }
            ret
        } else if self.pics[pic_type as usize].read_reg_select {
            self.pics[pic_type as usize].isr
        } else {
            self.pics[pic_type as usize].irr
        }
    }

    fn pic_read_data(&mut self, pic_type: PicSelect) -> u8 {
        if self.pics[pic_type as usize].poll {
            let (ret, update_needed) = self.poll_read(pic_type);
            self.pics[pic_type as usize].poll = false;
            if update_needed {
                self.update_irq();
            }
            ret
        } else {
            self.pics[pic_type as usize].imr
        }
    }

    fn pic_read_elcr(&self, pic_type: PicSelect) -> u8 {
        self.pics[pic_type as usize].elcr
    }

    fn pic_write_command(&mut self, pic_type: PicSelect, value: u8) {
        if value & ICW1_MASK != 0 {
            self.init_command_word_1(pic_type, value);
        } else if value & OCW3_MASK != 0 {
            Pic::operation_command_word_3(&mut self.pics[pic_type as usize], value);
        } else {
            self.operation_command_word_2(pic_type, value);
        }
    }

    fn pic_write_data(&mut self, pic_type: PicSelect, value: u8) {
        match self.pics[pic_type as usize].init_state {
            PicInitState::Icw1 => {
                self.pics[pic_type as usize].imr = value;
                self.update_irq();
            }
            PicInitState::Icw2 => {
                self.pics[pic_type as usize].irq_base = value & ICW2_IRQ_BASE_MASK;
                self.pics[pic_type as usize].init_state = PicInitState::Icw3;
            }
            PicInitState::Icw3 => {
                if self.pics[pic_type as usize].use_4_byte_icw {
                    self.pics[pic_type as usize].init_state = PicInitState::Icw4;
                } else {
                    self.pics[pic_type as usize].init_state = PicInitState::Icw1;
                }
            }
            PicInitState::Icw4 => {
                self.pics[pic_type as usize].special_fully_nested_mode =
                    (value & ICW4_SPECIAL_FULLY_NESTED_MODE) != 0;
                self.pics[pic_type as usize].auto_eoi = (value & ICW4_AUTO_EOI) != 0;
                self.pics[pic_type as usize].init_state = PicInitState::Icw1;
            }
        }
    }

    fn pic_write_elcr(&mut self, pic_type: PicSelect, value: u8) {
        self.pics[pic_type as usize].elcr = value & self.pics[pic_type as usize].elcr_mask;
    }

    // ── Internal logic (from crosvm) ───────────────────────────────

    fn reset_pic(&mut self, pic_type: PicSelect) {
        let pic = &mut self.pics[pic_type as usize];

        let edge_irr = pic.irr & !pic.elcr;

        pic.last_irr = 0;
        pic.irr &= pic.elcr;
        pic.imr = 0;
        pic.priority_add = 0;
        pic.special_mask = false;
        pic.read_reg_select = false;
        if !pic.use_4_byte_icw {
            pic.special_fully_nested_mode = false;
            pic.auto_eoi = false;
        }
        pic.init_state = PicInitState::Icw2;

        for irq in 0..8 {
            if edge_irr & (1 << irq) != 0 {
                self.clear_isr(pic_type, irq);
            }
        }
    }

    fn poll_read(&mut self, pic_type: PicSelect) -> (u8, bool) {
        if let Some(irq) = self.get_irq(pic_type) {
            if pic_type == PicSelect::Secondary {
                self.pics[PicSelect::Primary as usize].isr &= !PRIMARY_PIC_CASCADE_PIN_MASK;
                self.pics[PicSelect::Primary as usize].irr &= !PRIMARY_PIC_CASCADE_PIN_MASK;
            }
            self.pics[pic_type as usize].irr &= !(1 << irq);
            self.clear_isr(pic_type, irq);
            let update_irq_needed =
                pic_type == PicSelect::Secondary && irq != PRIMARY_PIC_CASCADE_PIN;
            (irq, update_irq_needed)
        } else {
            (SPURIOUS_IRQ, true)
        }
    }

    fn get_irq(&self, pic_type: PicSelect) -> Option<u8> {
        let pic = &self.pics[pic_type as usize];
        let mut irq_bitmap = pic.irr & !pic.imr;
        let priority = Pic::get_priority(pic, irq_bitmap)?;

        irq_bitmap = pic.isr;
        if pic_type == PicSelect::Primary && pic.special_fully_nested_mode {
            irq_bitmap &= !PRIMARY_PIC_CASCADE_PIN_MASK;
        }
        let new_priority = Pic::get_priority(pic, irq_bitmap).unwrap_or(INVALID_PRIORITY);
        if priority < new_priority {
            Some((priority + pic.priority_add) & 7)
        } else {
            None
        }
    }

    fn clear_isr(&mut self, pic_type: PicSelect, irq: u8) {
        assert!(irq <= 7, "unexpectedly high irq: {irq}");
        let pic = &mut self.pics[pic_type as usize];
        pic.isr &= !(1 << irq);
        Pic::set_irq_internal(pic, irq, false);
    }

    /// If secondary has a pending IRQ, signal the primary's cascade line.
    /// If primary then has a deliverable interrupt, inject it into the vCPU
    /// via WHP.
    fn update_irq(&mut self) -> bool {
        if self.get_irq(PicSelect::Secondary).is_some() {
            Pic::set_irq_internal(
                &mut self.pics[PicSelect::Primary as usize],
                PRIMARY_PIC_CASCADE_PIN,
                true,
            );
            Pic::set_irq_internal(
                &mut self.pics[PicSelect::Primary as usize],
                PRIMARY_PIC_CASCADE_PIN,
                false,
            );
        }

        if self.get_irq(PicSelect::Primary).is_some() {
            self.deliver_to_whp();
            true
        } else {
            false
        }
    }

    /// Acknowledge the highest-priority pending interrupt and inject it
    /// into vCPU 0 via WHvRequestInterrupt.  No-op when `vm` is `None`
    /// (tests).
    fn deliver_to_whp(&mut self) {
        let vm = match &self.vm {
            Some(v) => v.clone(),
            None => return,
        };

        if let Some(vector) = self.get_external_interrupt() {
            let req = InterruptRequest {
                interrupt_type: InterruptType::Fixed,
                destination_mode: InterruptDestinationMode::Physical,
                trigger_mode: InterruptTriggerMode::Edge,
                destination: 0,
                vector: vector as u32,
            };
            if let Err(e) = vm.request_interrupt(&req) {
                error!("PIC: WHvRequestInterrupt failed: {e}");
                return;
            }
            vm.cancel_vcpu(0);
        }
    }

    fn set_irq_internal(pic: &mut PicState, irq: u8, level: bool) {
        assert!(irq <= 7, "unexpectedly high irq: {irq}");
        let irq_bitmap = 1 << irq;
        if (pic.elcr & irq_bitmap) != 0 {
            // Level-triggered.
            if level {
                pic.irr |= irq_bitmap;
                pic.last_irr |= irq_bitmap;
            } else {
                pic.irr &= !irq_bitmap;
                pic.last_irr &= !irq_bitmap;
            }
        } else {
            // Edge-triggered.
            if level {
                if (pic.last_irr & irq_bitmap) == 0 {
                    pic.irr |= irq_bitmap;
                }
                pic.last_irr |= irq_bitmap;
            } else {
                pic.last_irr &= !irq_bitmap;
            }
        }
    }

    fn get_priority(pic: &PicState, irq_bitmap: u8) -> Option<u8> {
        if irq_bitmap == 0 {
            None
        } else {
            let mut priority = 0;
            let mut priority_mask = 1 << ((priority + pic.priority_add) & 7);
            while (irq_bitmap & priority_mask) == 0 {
                priority += 1;
                priority_mask = 1 << ((priority + pic.priority_add) & 7);
            }
            Some(priority)
        }
    }

    fn interrupt_ack(&mut self, pic_type: PicSelect, irq: u8) {
        assert!(irq <= 7, "unexpectedly high irq: {irq}");
        let pic = &mut self.pics[pic_type as usize];
        let irq_bitmap = 1 << irq;
        pic.isr |= irq_bitmap;

        if (pic.elcr & irq_bitmap) == 0 {
            pic.irr &= !irq_bitmap;
        }

        if pic.auto_eoi {
            if pic.rotate_on_auto_eoi {
                pic.priority_add = (irq + 1) & 7;
            }
            self.clear_isr(pic_type, irq);
        }
    }

    fn init_command_word_1(&mut self, pic_type: PicSelect, value: u8) {
        let pic = &mut self.pics[pic_type as usize];
        pic.use_4_byte_icw = (value & ICW1_NEED_ICW4) != 0;
        if (value & ICW1_SINGLE_PIC_MODE) != 0 {
            debug!("PIC: single-PIC mode not supported");
        }
        if (value & ICW1_LEVEL_TRIGGER_MODE) != 0 {
            debug!("PIC: level-triggered IRQ not supported via ICW1");
        }
        self.reset_pic(pic_type);
    }

    fn operation_command_word_2(&mut self, pic_type: PicSelect, value: u8) {
        let mut irq = value & OCW2_IRQ_MASK;
        if let Some(cmd) = Ocw2::from_u8(value & OCW2_COMMAND_MASK) {
            match cmd {
                Ocw2::RotateAutoEoiSet => self.pics[pic_type as usize].rotate_on_auto_eoi = true,
                Ocw2::RotateAutoEoiClear => {
                    self.pics[pic_type as usize].rotate_on_auto_eoi = false
                }
                Ocw2::NonSpecificEoi | Ocw2::RotateNonSpecificEoi => {
                    if let Some(priority) = Pic::get_priority(
                        &self.pics[pic_type as usize],
                        self.pics[pic_type as usize].isr,
                    ) {
                        irq = (priority + self.pics[pic_type as usize].priority_add) & 7;
                        if cmd == Ocw2::RotateNonSpecificEoi {
                            self.pics[pic_type as usize].priority_add = (irq + 1) & 7;
                        }
                        self.clear_isr(pic_type, irq);
                        self.update_irq();
                    }
                }
                Ocw2::SpecificEoi => {
                    self.clear_isr(pic_type, irq);
                    self.update_irq();
                }
                Ocw2::SetPriority => {
                    self.pics[pic_type as usize].priority_add = (irq + 1) & 7;
                    self.update_irq();
                }
                Ocw2::RotateSpecificEoi => {
                    self.pics[pic_type as usize].priority_add = (irq + 1) & 7;
                    self.clear_isr(pic_type, irq);
                    self.update_irq();
                }
                Ocw2::NoOp => {}
            }
        }
    }

    fn operation_command_word_3(pic: &mut PicState, value: u8) {
        if value & OCW3_POLL_COMMAND != 0 {
            pic.poll = true;
        }
        if value & OCW3_READ_REGISTER != 0 {
            pic.read_reg_select = value & OCW3_READ_ISR != 0;
        }
        if value & OCW3_SPECIAL_MASK != 0 {
            pic.special_mask = value & OCW3_SPECIAL_MASK_VALUE != 0;
        }
    }
}

// ── BusDevice wrapper ──────────────────────────────────────────────
//
// libkrun's I/O bus passes an offset relative to the registered base
// address.  Since the primary PIC (0x20) and secondary PIC (0xA0) are
// registered as separate bus entries, we use a thin wrapper that knows
// which PicSelect to forward to.

pub struct PicPort {
    pic: Arc<Mutex<Pic>>,
    select: PicSelect,
}

impl PicPort {
    pub fn new(pic: Arc<Mutex<Pic>>, select: PicSelect) -> Self {
        PicPort { pic, select }
    }
}

impl BusDevice for PicPort {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        let mut pic = self.pic.lock().unwrap();
        data[0] = match offset {
            0 => pic.pic_read_command(self.select),
            1 => pic.pic_read_data(self.select),
            _ => 0,
        };
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut pic = self.pic.lock().unwrap();
        match offset {
            0 => pic.pic_write_command(self.select, data[0]),
            1 => pic.pic_write_data(self.select, data[0]),
            _ => {}
        }
    }
}

// ── Tests (adapted from crosvm) ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const FULLY_NESTED_NO_AUTO_EOI: u8 = 0x11;

    fn new_test_pic() -> Pic {
        let mut primary: PicState = Default::default();
        let mut secondary: PicState = Default::default();
        primary.elcr_mask = !((1 << 0) | (1 << 1) | (1 << 2));
        secondary.elcr_mask = !((1 << 0) | (1 << 5));
        Pic {
            pics: [primary, secondary],
            vm: None,
        }
    }

    fn icw_init(pic: &mut Pic, sel: PicSelect, icw1: u8, icw2: u8, icw3: u8, icw4: u8) {
        pic.pic_write_command(sel, icw1);
        pic.pic_write_data(sel, icw2);
        pic.pic_write_data(sel, icw3);
        pic.pic_write_data(sel, icw4);
    }

    fn icw_init_primary(pic: &mut Pic) {
        icw_init(pic, PicSelect::Primary, 0x11, 0x08, 0xff, 0x13);
    }

    fn icw_init_secondary(pic: &mut Pic) {
        icw_init(pic, PicSelect::Secondary, 0x11, 0x70, 0xff, 0x13);
    }

    fn icw_init_both_with_icw4(pic: &mut Pic, icw4: u8) {
        icw_init(pic, PicSelect::Primary, 0x11, 0x08, 0xff, icw4);
        icw_init(pic, PicSelect::Secondary, 0x11, 0x70, 0xff, icw4);
    }

    fn icw_init_both(pic: &mut Pic) {
        icw_init_primary(pic);
        icw_init_secondary(pic);
    }

    #[test]
    fn write_read_elcr() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);

        pic.pic_write_elcr(PicSelect::Primary, 0xf8);
        assert_eq!(pic.pic_read_elcr(PicSelect::Primary), 0xf8);

        pic.pic_write_elcr(PicSelect::Secondary, 0xde);
        assert_eq!(pic.pic_read_elcr(PicSelect::Secondary), 0xde);
    }

    #[test]
    fn icw_2_step() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);

        // ICW1 without ICW4
        pic.pic_write_command(PicSelect::Primary, 0x10);
        pic.pic_write_data(PicSelect::Primary, 0x08);
        pic.pic_write_data(PicSelect::Primary, 0xff);

        assert_eq!(pic.pics[PicSelect::Primary as usize].init_state, PicInitState::Icw1);
        assert_eq!(pic.pics[PicSelect::Primary as usize].irq_base, 0x08);
        assert!(!pic.pics[PicSelect::Primary as usize].use_4_byte_icw);
    }

    #[test]
    fn initial_values() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        icw_init_primary(&mut pic);

        let p = &pic.pics[PicSelect::Primary as usize];
        assert_eq!(p.last_irr, 0);
        assert_eq!(p.irr, 0);
        assert_eq!(p.imr, 0);
        assert_eq!(p.isr, 0);
        assert_eq!(p.priority_add, 0);
        assert_eq!(p.irq_base, 0x08);
        assert!(!p.read_reg_select);
        assert!(!p.poll);
        assert!(!p.special_mask);
        assert_eq!(p.init_state, PicInitState::Icw1);
        assert!(p.auto_eoi);
        assert!(!p.rotate_on_auto_eoi);
        assert!(p.special_fully_nested_mode);
        assert!(p.use_4_byte_icw);
    }

    #[test]
    fn ocw() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_secondary(&mut pic);

        // OCW1: Write to IMR
        pic.pic_write_data(PicSelect::Secondary, 0x5f);
        // OCW2: Set rotate on auto EOI
        pic.pic_write_command(PicSelect::Secondary, 0x80);
        // OCW2: Set priority
        pic.pic_write_command(PicSelect::Secondary, 0xc0);
        // OCW3: Change flags
        pic.pic_write_command(PicSelect::Secondary, 0x6b);

        assert_eq!(pic.pic_read_data(PicSelect::Secondary), 0x5f);

        let s = &pic.pics[PicSelect::Secondary as usize];
        assert_eq!(s.imr, 0x5f);
        assert!(s.rotate_on_auto_eoi);
        assert_eq!(s.priority_add, 1);
        assert!(s.special_mask);
        assert!(!s.poll);
        assert!(s.read_reg_select);
    }

    #[test]
    fn ocw_auto_rotate_set_and_clear() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_secondary(&mut pic);

        pic.pic_write_command(PicSelect::Secondary, 0x80);
        assert!(pic.pics[PicSelect::Secondary as usize].rotate_on_auto_eoi);

        pic.pic_write_command(PicSelect::Secondary, 0x00);
        assert!(!pic.pics[PicSelect::Secondary as usize].rotate_on_auto_eoi);
    }

    #[test]
    fn auto_eoi() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both(&mut pic);

        pic.service_irq(12, true);

        assert_eq!(pic.pics[PicSelect::Secondary as usize].irr, 1 << 4);
        assert_eq!(pic.pics[PicSelect::Secondary as usize].isr, 0);
        assert_eq!(pic.pics[PicSelect::Primary as usize].irr, 1 << 2);
        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 0);

        assert_eq!(pic.get_external_interrupt(), Some(0x70 + 4));

        assert_eq!(pic.pics[PicSelect::Secondary as usize].irr, 0);
        assert_eq!(pic.pics[PicSelect::Secondary as usize].isr, 0);
        assert_eq!(pic.pics[PicSelect::Primary as usize].irr, 0);
        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 0);
    }

    #[test]
    fn fully_nested_mode_on() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both_with_icw4(&mut pic, FULLY_NESTED_NO_AUTO_EOI);

        pic.service_irq(12, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x70 + 4));

        pic.service_irq(8, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x70 + 0));

        assert_eq!(pic.pics[PicSelect::Secondary as usize].irr, 0);
        assert_eq!(
            pic.pics[PicSelect::Secondary as usize].isr,
            (1 << 4) + (1 << 0)
        );
        assert_eq!(pic.pics[PicSelect::Primary as usize].irr, 0);
        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 1 << 2);
    }

    #[test]
    fn fully_nested_mode_off() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both_with_icw4(&mut pic, 0x01);

        pic.service_irq(12, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x70 + 4));

        pic.service_irq(8, true);
        assert_eq!(pic.get_external_interrupt(), None);

        assert_eq!(pic.pics[PicSelect::Secondary as usize].irr, 1 << 0);
        assert_eq!(pic.pics[PicSelect::Secondary as usize].isr, 1 << 4);
        assert_eq!(pic.pics[PicSelect::Primary as usize].irr, 1 << 2);
        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 1 << 2);

        // Non-specific EOI on both
        pic.pic_write_command(PicSelect::Primary, 0x20);
        pic.pic_write_command(PicSelect::Secondary, 0x20);

        assert_eq!(pic.get_external_interrupt(), Some(0x70 + 0));

        assert_eq!(pic.pics[PicSelect::Secondary as usize].irr, 0);
        assert_eq!(pic.pics[PicSelect::Secondary as usize].isr, 1 << 0);
        assert_eq!(pic.pics[PicSelect::Primary as usize].irr, 0);
        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 1 << 2);
    }

    #[test]
    fn mask_irq() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both_with_icw4(&mut pic, FULLY_NESTED_NO_AUTO_EOI);

        // Mask IRQ 14 (line 6 on secondary)
        pic.pic_write_data(PicSelect::Secondary, 0x40);

        pic.service_irq(14, true);
        assert_eq!(pic.get_external_interrupt(), None);

        assert_eq!(pic.pics[PicSelect::Secondary as usize].irr, 1 << 6);
        assert_eq!(pic.pics[PicSelect::Secondary as usize].isr, 0);

        // Unmask
        pic.pic_write_data(PicSelect::Secondary, 0x00);
        assert_eq!(pic.get_external_interrupt(), Some(0x70 + 6));
    }

    #[test]
    fn mask_multiple_irq() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both(&mut pic);

        // Mask all
        pic.pic_write_data(PicSelect::Primary, 0xff);
        pic.pic_write_data(PicSelect::Secondary, 0xff);

        pic.service_irq(14, true);
        pic.service_irq(4, true);
        pic.service_irq(12, true);

        assert_eq!(pic.get_external_interrupt(), None);

        // Unmask secondary
        pic.pic_write_data(PicSelect::Secondary, 0x00);
        assert_eq!(pic.get_external_interrupt(), None); // cascade still masked

        // Unmask cascade on primary
        pic.pic_write_data(PicSelect::Primary, 0xfb);
        assert_eq!(pic.get_external_interrupt(), Some(0x70 + 4));
        assert_eq!(pic.get_external_interrupt(), Some(0x70 + 6));

        // Unmask all primary
        pic.pic_write_data(PicSelect::Primary, 0x00);
        assert_eq!(pic.get_external_interrupt(), Some(0x08 + 4));
    }

    #[test]
    fn ocw3_poll() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both_with_icw4(&mut pic, FULLY_NESTED_NO_AUTO_EOI);

        pic.service_irq(5, true);
        pic.service_irq(4, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x08 + 4));

        // Read IRR
        pic.pic_write_command(PicSelect::Primary, 0x0a);
        assert_eq!(pic.pic_read_command(PicSelect::Primary), 1 << 5);

        // Read ISR
        pic.pic_write_command(PicSelect::Primary, 0x0b);
        assert_eq!(pic.pic_read_command(PicSelect::Primary), 1 << 4);

        // Non-specific EOI
        pic.pic_write_command(PicSelect::Primary, 0x20);

        // Poll
        pic.pic_write_command(PicSelect::Primary, 0x0c);
        assert_eq!(pic.pic_read_command(PicSelect::Primary), 5);
    }

    #[test]
    fn fake_irq_on_primary_irq2() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both_with_icw4(&mut pic, FULLY_NESTED_NO_AUTO_EOI);

        pic.service_irq(2, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x70 + 7));
    }

    #[test]
    fn edge_trigger_mode() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both_with_icw4(&mut pic, FULLY_NESTED_NO_AUTO_EOI);

        pic.service_irq(4, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x08 + 4));

        pic.service_irq(4, true);

        // In edge-triggered mode, no new IRQ after the second assert.
        pic.pic_write_command(PicSelect::Primary, 0x20);
    }

    #[test]
    fn level_trigger_mode() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both_with_icw4(&mut pic, FULLY_NESTED_NO_AUTO_EOI);

        // IRQ 4 to level-triggered
        pic.pic_write_elcr(PicSelect::Primary, 0x10);

        pic.service_irq(4, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x08 + 4));

        pic.service_irq(4, true);

        // Level-triggered: another IRQ after EOI
        pic.pic_write_command(PicSelect::Primary, 0x20);
    }

    #[test]
    fn specific_eoi() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both_with_icw4(&mut pic, FULLY_NESTED_NO_AUTO_EOI);

        pic.service_irq(4, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x08 + 4));

        // Specific EOI on wrong IRQ (3) — ISR unaffected
        pic.pic_write_command(PicSelect::Primary, 0x63);
        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 1 << 4);

        // Specific EOI on correct IRQ (4)
        pic.pic_write_command(PicSelect::Primary, 0x64);
        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 0);
    }

    #[test]
    fn rotate_on_auto_eoi() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both(&mut pic);

        // Clear rotate on auto EOI
        pic.pic_write_command(PicSelect::Primary, 0x00);

        pic.service_irq(5, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x08 + 5));
        pic.service_irq(5, false);

        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 0);
        assert_eq!(pic.pics[PicSelect::Primary as usize].priority_add, 0);

        // Set rotate on auto EOI
        pic.pic_write_command(PicSelect::Primary, 0x80);

        pic.service_irq(5, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x08 + 5));
        pic.service_irq(5, false);

        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 0);
        assert_eq!(pic.pics[PicSelect::Primary as usize].priority_add, 6);
    }

    #[test]
    fn rotate_on_specific_eoi() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both_with_icw4(&mut pic, FULLY_NESTED_NO_AUTO_EOI);

        pic.service_irq(5, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x08 + 5));
        pic.service_irq(5, false);

        // Rotate specific EOI on wrong IRQ (4) — ISR unaffected
        pic.pic_write_command(PicSelect::Primary, 0xe4);
        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 1 << 5);

        // Rotate specific EOI on correct IRQ (5)
        pic.pic_write_command(PicSelect::Primary, 0xe5);
        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 0);
        assert_eq!(pic.pics[PicSelect::Primary as usize].priority_add, 6);
    }

    #[test]
    fn rotate_non_specific_eoi() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both_with_icw4(&mut pic, FULLY_NESTED_NO_AUTO_EOI);

        pic.service_irq(5, true);
        assert_eq!(pic.get_external_interrupt(), Some(0x08 + 5));
        pic.service_irq(5, false);

        // Rotate non-specific EOI
        pic.pic_write_command(PicSelect::Primary, 0xa0);
        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 0);
        assert_eq!(pic.pics[PicSelect::Primary as usize].priority_add, 6);
    }

    #[test]
    fn cascade_irq() {
        let mut pic = new_test_pic();
        pic.pic_write_elcr(PicSelect::Primary, 0);
        pic.pic_write_elcr(PicSelect::Secondary, 0);
        icw_init_both_with_icw4(&mut pic, FULLY_NESTED_NO_AUTO_EOI);

        pic.service_irq(12, true);
        assert_eq!(pic.pics[PicSelect::Primary as usize].irr, 1 << 2);
        assert_eq!(pic.pics[PicSelect::Secondary as usize].irr, 1 << 4);

        assert_eq!(pic.get_external_interrupt(), Some(0x70 + 4));
        assert_eq!(pic.pics[PicSelect::Secondary as usize].irr, 0);
        assert_eq!(pic.pics[PicSelect::Secondary as usize].isr, 1 << 4);

        // Two non-specific EOIs (primary cascade + secondary)
        pic.pic_write_command(PicSelect::Primary, 0x20);
        pic.pic_write_command(PicSelect::Secondary, 0xa0);

        assert_eq!(pic.pics[PicSelect::Primary as usize].isr, 0);
        assert_eq!(pic.pics[PicSelect::Secondary as usize].isr, 0);
        assert_eq!(pic.pics[PicSelect::Secondary as usize].priority_add, 5);
    }
}
