//! Common IOAPIC register emulation, shared across hypervisor backends.
//!
//! The generic [`Ioapic<B>`] struct handles all MMIO register reads/writes
//! (ioregsel, iowin, redirection table).  Backend-specific interrupt
//! injection is delegated through the [`IoapicBackend`] trait.

use std::sync::Mutex;

use crate::bus::BusDevice;
use crate::legacy::irqchip::IrqChipT;
use crate::Error as DeviceError;
use utils::eventfd::EventFd;

// ── IOAPIC register constants ───────────────────────────────────────

const IOAPIC_BASE: u64 = 0xfec0_0000;
pub(crate) const IOAPIC_NUM_PINS: usize = 24;

const IO_REG_SEL: u64 = 0x00;
const IO_WIN: u64 = 0x10;
const IO_EOI: u64 = 0x40;

const IO_APIC_ID: u8 = 0x00;
const IO_APIC_VER: u8 = 0x01;
const IO_APIC_ARB: u8 = 0x02;

pub(crate) const IOAPIC_LVT_DELIV_MODE_SHIFT: u64 = 8;
pub(crate) const IOAPIC_LVT_DEST_MODE_SHIFT: u64 = 11;
const IOAPIC_LVT_DELIV_STATUS_SHIFT: u64 = 12;
const IOAPIC_LVT_REMOTE_IRR_SHIFT: u64 = 14;
pub(crate) const IOAPIC_LVT_TRIGGER_MODE_SHIFT: u64 = 15;
pub(crate) const IOAPIC_LVT_MASKED_SHIFT: u64 = 16;
pub(crate) const IOAPIC_LVT_DEST_IDX_SHIFT: u64 = 56;

const IOAPIC_VER_ENTRIES_SHIFT: u32 = 16;
const IOAPIC_ID_SHIFT: u32 = 24;

pub(crate) const IOAPIC_LVT_REMOTE_IRR: u64 = 1 << IOAPIC_LVT_REMOTE_IRR_SHIFT;
const IOAPIC_LVT_TRIGGER_MODE: u64 = 1 << IOAPIC_LVT_TRIGGER_MODE_SHIFT;
const IOAPIC_LVT_DELIV_STATUS: u64 = 1 << IOAPIC_LVT_DELIV_STATUS_SHIFT;

const IOAPIC_RO_BITS: u64 = IOAPIC_LVT_REMOTE_IRR | IOAPIC_LVT_DELIV_STATUS;
const IOAPIC_RW_BITS: u64 = !IOAPIC_RO_BITS;

const IOAPIC_ID_MASK: u32 = 0xf;
pub(crate) const IOAPIC_VECTOR_MASK: u64 = 0xff;
pub(crate) const IOAPIC_DM_MASK: u64 = 0x7;
pub(crate) const IOAPIC_DM_EXTINT: u64 = 0x7;
const IOAPIC_REG_REDTBL_BASE: u64 = 0x10;

// ── Common IOAPIC register state ────────────────────────────────────

pub(crate) struct IoapicRegs {
    pub(crate) id: u8,
    pub(crate) ioregsel: u8,
    pub(crate) irr: u32,
    pub(crate) ioredtbl: [u64; IOAPIC_NUM_PINS],
    pub(crate) version: u8,
}

impl IoapicRegs {
    fn new() -> Self {
        Self {
            id: 0,
            ioregsel: 0,
            irr: 0,
            ioredtbl: [1 << IOAPIC_LVT_MASKED_SHIFT; IOAPIC_NUM_PINS],
            version: 0x20,
        }
    }
}

// ── Backend trait ────────────────────────────────────────────────────
//
// Implemented per hypervisor to handle interrupt injection and routing.

pub(crate) trait IoapicBackend: Send {
    /// Called after the guest updates a redirection table entry.
    fn on_entry_changed(&mut self, regs: &mut IoapicRegs, index: usize);

    /// Called from `IrqChipT::set_irq` to assert an interrupt line.
    fn set_irq(
        &mut self,
        irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
        regs: &mut IoapicRegs,
    ) -> Result<(), DeviceError>;
}

// ── Generic IOAPIC (register emulation) ─────────────────────────────

struct IoapicInner<B: IoapicBackend> {
    regs: IoapicRegs,
    backend: B,
}

pub struct Ioapic<B: IoapicBackend> {
    inner: Mutex<IoapicInner<B>>,
}

impl<B: IoapicBackend> Ioapic<B> {
    pub(crate) fn from_backend(backend: B) -> Self {
        Self {
            inner: Mutex::new(IoapicInner {
                regs: IoapicRegs::new(),
                backend,
            }),
        }
    }
}

impl<B: IoapicBackend + 'static> IrqChipT for Ioapic<B> {
    fn get_mmio_addr(&self) -> u64 {
        IOAPIC_BASE
    }

    fn get_mmio_size(&self) -> u64 {
        0x1000
    }

    fn set_irq(
        &self,
        irq_line: Option<u32>,
        interrupt_evt: Option<&EventFd>,
    ) -> Result<(), DeviceError> {
        let mut inner = self.inner.lock().unwrap();
        let IoapicInner { regs, backend } = &mut *inner;
        backend.set_irq(irq_line, interrupt_evt, regs)
    }
}

impl<B: IoapicBackend + 'static> BusDevice for Ioapic<B> {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let inner = self.inner.lock().unwrap();
        let regs = &inner.regs;

        let val = match offset {
            IO_REG_SEL => {
                debug!("ioapic: read: ioregsel");
                regs.ioregsel as u32
            }
            IO_WIN => {
                // the data needs to be 32-bits in size
                if data.len() != 4 {
                    error!("ioapic: bad read size {}", data.len());
                    return;
                }
                match regs.ioregsel {
                    IO_APIC_ID | IO_APIC_ARB => {
                        debug!("ioapic: read: IOAPIC ID");
                        (regs.id as u32) << IOAPIC_ID_SHIFT
                    }
                    IO_APIC_VER => {
                        debug!("ioapic: read: IOAPIC version");
                        regs.version as u32
                            | ((IOAPIC_NUM_PINS as u32 - 1) << IOAPIC_VER_ENTRIES_SHIFT)
                    }
                    _ => {
                        let index = (regs.ioregsel as u64 - IOAPIC_REG_REDTBL_BASE) >> 1;
                        debug!("ioapic: read: ioredtbl register {index}");

                        // we can only read from this register in 32-bit chunks.
                        // Therefore, we need to check if we are reading the
                        // upper 32 bits or the lower
                        if index < IOAPIC_NUM_PINS as u64 {
                            if regs.ioregsel & 1 > 0 {
                                // read upper 32 bits
                                (regs.ioredtbl[index as usize] >> 32) as u32
                            } else {
                                // read lower 32 bits
                                (regs.ioredtbl[index as usize] & 0xffff_ffff) as u32
                            }
                        } else {
                            0
                        }
                    }
                }
            }
            _ => unreachable!(),
        };

        // turn the value into native endian byte order and put that value into `data`
        let out_arr = val.to_ne_bytes();
        for i in 0..4 {
            if i < data.len() {
                data[i] = out_arr[i];
            }
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        // data needs to be 32-bits in size
        if data.len() != 4 {
            error!("ioapic: bad write size {}", data.len());
            return;
        }

        // convert data into a u32 int with native endianness
        let arr = [data[0], data[1], data[2], data[3]];
        let val = u32::from_ne_bytes(arr);
        let mut inner = self.inner.lock().unwrap();
        let IoapicInner { regs, backend } = &mut *inner;

        match offset {
            IO_REG_SEL => {
                debug!("ioapic: write: ioregsel");
                regs.ioregsel = val as u8;
            }
            IO_WIN => match regs.ioregsel {
                IO_APIC_ID => {
                    debug!("ioapic: write: IOAPIC ID");
                    regs.id = ((val >> IOAPIC_ID_SHIFT) & IOAPIC_ID_MASK) as u8;
                }
                // NOTE: these are read-only registers, so they should never be written to
                IO_APIC_VER | IO_APIC_ARB => debug!("ioapic: write: IOAPIC VERSION"),
                _ => {
                    if regs.ioregsel < IO_WIN as u8 {
                        debug!("invalid write; ignored");
                        return;
                    }

                    let index = (regs.ioregsel as u64 - IOAPIC_REG_REDTBL_BASE) >> 1;
                    debug!("ioapic: write: ioredtbl register {index}");
                    if index >= IOAPIC_NUM_PINS as u64 {
                        warn!("ioapic: write to out-of-range pin {index}");
                        return;
                    }
                    let i = index as usize;

                    let ro_bits = regs.ioredtbl[i] & IOAPIC_RO_BITS;
                    if regs.ioregsel & 1 > 0 {
                        regs.ioredtbl[i] &= 0xffff_ffff;
                        regs.ioredtbl[i] |= (val as u64) << 32;
                    } else {
                        regs.ioredtbl[i] &= !0xffff_ffff_u64;
                        regs.ioredtbl[i] |= val as u64;
                    }

                    // restore RO bits
                    regs.ioredtbl[i] &= IOAPIC_RW_BITS;
                    regs.ioredtbl[i] |= ro_bits;

                    // Clear Remote IRR for edge-triggered entries
                    if regs.ioredtbl[i] & IOAPIC_LVT_TRIGGER_MODE == 0 {
                        regs.ioredtbl[i] &= !IOAPIC_LVT_REMOTE_IRR;
                    }

                    backend.on_entry_changed(regs, i);
                }
            }
            IO_EOI => todo!(),
            _ => unreachable!(),
        }
    }
}
