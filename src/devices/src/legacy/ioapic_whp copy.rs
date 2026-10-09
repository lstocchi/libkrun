// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! WHP IOAPIC backend.
//!
//! WHP emulates the LAPIC but NOT the IOAPIC. This backend provides
//! interrupt injection through `WHvRequestInterrupt`, plugging into the
//! common IOAPIC register emulation in [`super::ioapic`].

use std::io;
use std::sync::Arc;

use log::info;

use whp::{InterruptDestinationMode, InterruptRequest, InterruptTriggerMode, InterruptType, WhpVm};

use crate::Error as DeviceError;
use utils::eventfd::EventFd;

use super::ioapic::{
    IOAPIC_DM_EXTINT, IOAPIC_DM_MASK, IOAPIC_LVT_DELIV_MODE_SHIFT, IOAPIC_LVT_DEST_MODE_SHIFT,
    IOAPIC_LVT_MASKED_SHIFT, IOAPIC_LVT_REMOTE_IRR, IOAPIC_LVT_TRIGGER_MODE_SHIFT, IOAPIC_NUM_PINS,
    IOAPIC_TRIGGER_EDGE, IOAPIC_VECTOR_MASK, IoApicBackend, IoApicRegs, Ioapic,
};

const IOAPIC_LVT_DEST_IDX_SHIFT: u64 = 56;

pub struct WhpIoapicBackend {
    vm: Arc<WhpVm>,
    interrupt_count: u64,
}

impl WhpIoapicBackend {
    fn service(&mut self, regs: &mut IoApicRegs) {
        for i in 0..IOAPIC_NUM_PINS {
            let mask = 1u32 << i;
            if regs.irr & mask == 0 {
                continue;
            }

            let entry = regs.ioredtbl[i];
            if (entry >> IOAPIC_LVT_MASKED_SHIFT) & 1 != 0 {
                continue;
            }

            let vector = (entry & IOAPIC_VECTOR_MASK) as u32;
            let dest = ((entry >> IOAPIC_LVT_DEST_IDX_SHIFT) & 0xff) as u32;
            let dest_mode = ((entry >> IOAPIC_LVT_DEST_MODE_SHIFT) & 1) as u8;
            let trigger = (entry >> IOAPIC_LVT_TRIGGER_MODE_SHIFT) & 1;
            let deliv_mode = ((entry >> IOAPIC_LVT_DELIV_MODE_SHIFT) & IOAPIC_DM_MASK) as u8;

            if deliv_mode as u64 == IOAPIC_DM_EXTINT {
                error!("ioapic: ExtINT delivery mode not supported (pin {i})");
                continue;
            }

            if trigger == IOAPIC_TRIGGER_EDGE {
                regs.irr &= !mask;
            } else {
                if entry & IOAPIC_LVT_REMOTE_IRR != 0 {
                    continue;
                }
                regs.ioredtbl[i] |= IOAPIC_LVT_REMOTE_IRR;
                // Clear IRR to prevent infinite interrupt storms since we don't
                // have a mechanism to track line de-assertion for level-triggered IRQs.
                regs.irr &= !mask;
            }

            let req = InterruptRequest {
                interrupt_type: match deliv_mode {
                    1 => InterruptType::LowestPriority,
                    4 => InterruptType::Nmi,
                    5 => InterruptType::Init,
                    6 => InterruptType::Sipi,
                    _ => InterruptType::Fixed,
                },
                destination_mode: if dest_mode == 0 {
                    InterruptDestinationMode::Physical
                } else {
                    InterruptDestinationMode::Logical
                },
                trigger_mode: if trigger == IOAPIC_TRIGGER_EDGE {
                    InterruptTriggerMode::Edge
                } else {
                    InterruptTriggerMode::Level
                },
                destination: dest,
                vector,
            };

            if let Err(e) = self.vm.request_interrupt(&req) {
                error!("ioapic: WHvRequestInterrupt failed for pin {i}: {e}");
            } else {
                self.interrupt_count += 1;
                log::debug!(
                    "WHP IOAPIC injected IRQ (count={}, pin={i}, vector={vector:#x}, destination={dest})",
                    self.interrupt_count
                );
                if self.interrupt_count == 1 || self.interrupt_count.is_multiple_of(1000) {
                    info!(
                        "WHP IOAPIC injected IRQ (count={}, pin={i}, vector={vector:#x}, destination={dest})",
                        self.interrupt_count
                    );
                }
            }
        }
    }
}

impl IoApicBackend for WhpIoapicBackend {
    fn on_entry_changed(&mut self, regs: &mut IoApicRegs, _index: usize) {
        self.service(regs);
    }

    fn on_eoi(&mut self, regs: &mut IoApicRegs) {
        self.service(regs);
    }

    fn set_irq(
        &mut self,
        irq_line: Option<u32>,
        _interrupt_evt: Option<&EventFd>,
        regs: &mut IoApicRegs,
    ) -> Result<(), DeviceError> {
        let irq = irq_line.ok_or_else(|| {
            DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::InvalidData,
                "IRQ line not configured",
            ))
        })?;

        if irq as usize >= IOAPIC_NUM_PINS {
            return Err(DeviceError::FailedSignalingUsedQueue(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("IRQ {irq} out of IOAPIC pin range"),
            )));
        }

        regs.irr |= 1 << irq;
        self.service(regs);
        Ok(())
    }
}

pub type WhpIoapic = Ioapic<WhpIoapicBackend>;

impl Ioapic<WhpIoapicBackend> {
    pub fn new(vm: Arc<WhpVm>) -> Self {
        Ioapic::from_backend(WhpIoapicBackend {
            vm,
            interrupt_count: 0,
        })
    }
}
