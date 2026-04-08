// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! WHP IOAPIC backend.
//!
//! WHP emulates the LAPIC but NOT the IOAPIC. This backend provides
//! interrupt injection through `WHvRequestInterrupt`, plugging into the
//! common IOAPIC register emulation in [`super::ioapic`].

use std::io;
use std::sync::Arc;

use whp::{InterruptDestinationMode, InterruptRequest, InterruptTriggerMode, InterruptType, WhpVm};

use crate::Error as DeviceError;
use utils::eventfd::EventFd;

use super::ioapic::{
    Ioapic, IoapicBackend, IoapicRegs, IOAPIC_DM_EXTINT, IOAPIC_DM_MASK,
    IOAPIC_LVT_DELIV_MODE_SHIFT, IOAPIC_LVT_DEST_IDX_SHIFT, IOAPIC_LVT_DEST_MODE_SHIFT,
    IOAPIC_LVT_MASKED_SHIFT, IOAPIC_LVT_REMOTE_IRR, IOAPIC_LVT_TRIGGER_MODE_SHIFT,
    IOAPIC_NUM_PINS, IOAPIC_VECTOR_MASK,
};

pub struct WhpIoapicBackend {
    vm: Arc<WhpVm>,
}

impl WhpIoapicBackend {
    fn service(regs: &mut IoapicRegs, vm: &WhpVm) {
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
            let trigger = ((entry >> IOAPIC_LVT_TRIGGER_MODE_SHIFT) & 1) as u8;
            let deliv_mode = ((entry >> IOAPIC_LVT_DELIV_MODE_SHIFT) & IOAPIC_DM_MASK) as u8;

            if deliv_mode as u64 == IOAPIC_DM_EXTINT {
                error!("ioapic: ExtINT delivery mode not supported (pin {i})");
                continue;
            }

            if trigger == 0 {
                regs.irr &= !mask;
            } else {
                if entry & IOAPIC_LVT_REMOTE_IRR != 0 {
                    continue;
                }
                regs.ioredtbl[i] |= IOAPIC_LVT_REMOTE_IRR;
            }

            let req = InterruptRequest {
                interrupt_type: match deliv_mode {
                    1 => InterruptType::LowestPriority,
                    _ => InterruptType::Fixed,
                },
                destination_mode: if dest_mode == 0 {
                    InterruptDestinationMode::Physical
                } else {
                    InterruptDestinationMode::Logical
                },
                trigger_mode: if trigger == 0 {
                    InterruptTriggerMode::Edge
                } else {
                    InterruptTriggerMode::Level
                },
                destination: dest,
                vector,
            };

            if let Err(e) = vm.request_interrupt(&req) {
                error!("ioapic: WHvRequestInterrupt failed for pin {i}: {e}");
                continue;
            }

            vm.cancel_vcpu(dest);
        }
    }
}

impl IoapicBackend for WhpIoapicBackend {
    fn on_entry_changed(&mut self, regs: &mut IoapicRegs, _index: usize) {
        Self::service(regs, &self.vm);
    }

    fn set_irq(
        &mut self,
        irq_line: Option<u32>,
        _interrupt_evt: Option<&EventFd>,
        regs: &mut IoapicRegs,
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
        Self::service(regs, &self.vm);
        Ok(())
    }
}

pub type WhpIoapic = Ioapic<WhpIoapicBackend>;

impl Ioapic<WhpIoapicBackend> {
    pub fn new(vm: Arc<WhpVm>) -> Self {
        Ioapic::from_backend(WhpIoapicBackend { vm })
    }
}
