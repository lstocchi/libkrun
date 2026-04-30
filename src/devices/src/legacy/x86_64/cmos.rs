// Copyright 2025 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::cmp::min;

use chrono::{Datelike, Timelike, Utc};

use crate::bus::BusDevice;

const INDEX_MASK: u8 = 0x7f;
const INDEX_OFFSET: u64 = 0x0;
const DATA_OFFSET: u64 = 0x1;
const DATA_LEN: usize = 128;

pub struct Cmos {
    index: u8,
    data: [u8; DATA_LEN],
}

impl Cmos {
    pub fn new(mem_below_4g: u64, mem_above_4g: u64) -> Cmos {
        debug!("cmos: mem_below_4g={mem_below_4g} mem_above_4g={mem_above_4g}");

        let mut data = [0u8; DATA_LEN];

        // Extended memory from 16 MB to 4 GB in units of 64 KB
        let ext_mem = min(
            0xFFFF,
            mem_below_4g.saturating_sub(16 * 1024 * 1024) / (64 * 1024),
        );
        data[0x34] = ext_mem as u8;
        data[0x35] = (ext_mem >> 8) as u8;

        // High memory (> 4GB) in units of 64 KB
        let high_mem = min(0xFFFFFF, mem_above_4g / (64 * 1024));
        data[0x5b] = high_mem as u8;
        data[0x5c] = (high_mem >> 8) as u8;
        data[0x5d] = (high_mem >> 16) as u8;

        data[0x0B] = 0x02;

        Cmos { index: 0, data }
    }
}

impl BusDevice for Cmos {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        fn to_bcd(v: u8) -> u8 {
            assert!(v < 100);
            ((v / 10) << 4) | (v % 10)
        }
        
        if data.len() != 1 {
            error!("cmos: unsupported read length");
            return;
        }

        data[0] = match offset {
            INDEX_OFFSET => {
                debug!("cmos: read index offset");
                self.index
            }
            DATA_OFFSET => {
                // Fetch current UTC time using chrono
                let now = Utc::now();
                
                let seconds = now.second();
                let minutes = now.minute();
                let hours = now.hour();
                let week_day = now.weekday().number_from_sunday(); // Sunday = 1
                let day = now.day();
                let month = now.month();
                let year = now.year();

                // Update in Progress bit (UIP)
                const NANOSECONDS_PER_SECOND: u32 = 1_000_000_000;
                
                // FIX 2: Widen the UIP hold length from ~244 microseconds to 16 milliseconds. 
                // This ensures the Windows timer (which ticks roughly every 1-15ms) won't 
                // completely skip over the UIP window, preventing the guest kernel from 
                // getting stuck in an infinite polling loop.
                const UIP_HOLD_LENGTH: u32 = 16_000_000; 
                
                let update_in_progress = now.nanosecond() >= (NANOSECONDS_PER_SECOND - UIP_HOLD_LENGTH);

                match self.index {
                    0x00 => to_bcd(seconds as u8),
                    0x02 => to_bcd(minutes as u8),
                    0x04 => to_bcd(hours as u8),
                    0x06 => to_bcd(week_day as u8),
                    0x07 => to_bcd(day as u8),
                    0x08 => to_bcd(month as u8),
                    0x09 => to_bcd((year % 100) as u8),
                    0x0a => (1 << 5) | ((update_in_progress as u8) << 7),
                    0x0d => 1 << 7,
                    0x32 => to_bcd((year / 100) as u8),
                    _ => self.data[(self.index & INDEX_MASK) as usize],
                }
            }
            _ => {
                debug!("cmos: unsupported read offset");
                0
            }
        };
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            error!("cmos: unsupported write length");
            return;
        }

        match offset {
            INDEX_OFFSET => {
                debug!("cmos: update index");
                self.index = data[0] & INDEX_MASK;
            }
            DATA_OFFSET => {
                if self.index == 0x8f && data[0] == 0 {
                    info!("CMOS reset");
                    // .signal() is the cross-platform way to trigger the event
                    /* self.reset_evt.write(1).unwrap(); 
                    
                    if let Some(vcpus_kill_signalled) = self.vcpus_kill_signalled.take() {
                        while !vcpus_kill_signalled.load(Ordering::SeqCst) {
                            thread::sleep(std::time::Duration::from_millis(1));
                        }
                    } */
                } else {
                    self.data[(self.index & INDEX_MASK) as usize] = data[0];
                }
            }
            _ => debug!("cmos: ignoring unsupported write to CMOS"),
        }
    }
}
