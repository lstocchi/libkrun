// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//
// Adapted from crosvm's devices/pit.rs for libkrun.
// Original: https://chromium.googlesource.com/crosvm/crosvm/+/refs/heads/main/devices/src/pit.rs

//! i8254 Programmable Interval Timer (PIT) emulation.
//!
//! On Windows the PIT worker thread fires IRQ 0 through two paths on
//! every tick:
//!
//!  1. The IOAPIC (`intc.set_irq`) — active once the kernel programmes
//!     IOAPIC pin 0 with a valid vector and unmasks it.
//!  2. The 8259 PIC (`pic.raise_irq`) — active during early boot before
//!     the kernel switches to Symmetric I/O mode.
//!
//! This dual-fire mirrors real hardware where the PIT output line is
//! physically wired to both IOAPIC pin 0 and PIC IRQ 0.  The kernel
//! decides which path is live by masking one controller or the other.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::bus::BusDevice;
use crate::legacy::irqchip::IrqChip;
use crate::legacy::pic::Pic;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{
    WaitForSingleObject, INFINITE,
};
use utils::windows::wake_event::WakeEvent;

// ── i8254 constants ─────────────────────────────────────────────────

const FREQUENCY_HZ: u64 = 1_193_182;
const NANOS_PER_SEC: u64 = 1_000_000_000;
const MAX_TIMER_FREQ: u32 = 65536;
const NUM_COUNTERS: usize = 3;

// ── Control-word bit-fields ─────────────────────────────────────────

const CMD_BCD: u8 = 0x01;
const CMD_MODE: u8 = 0x0e;
const CMD_RW: u8 = 0x30;
const CMD_SC: u8 = 0xc0;

const SC_READBACK: u8 = 0xc0;

const RW_LATCH: u8 = 0x00;
const RW_LEAST: u8 = 0x10;
const RW_MOST: u8 = 0x20;
const RW_BOTH: u8 = 0x30;

const MODE_INTERRUPT: u8 = 0x00;
const MODE_HW_ONESHOT: u8 = 0x02;
const MODE_RATE_GEN: u8 = 0x04;
const MODE_SQUARE_WAVE: u8 = 0x06;
const MODE_SW_STROBE: u8 = 0x08;
const MODE_HW_STROBE: u8 = 0x0a;

const RB_LATCH_BITS: u8 = 0x30;
const RB_LATCH_COUNT: u8 = 0x10;
const RB_LATCH_STATUS: u8 = 0x20;

const RB_CTR0: u8 = 0x02;
const RB_CTR1: u8 = 0x04;
const RB_CTR2: u8 = 0x08;

const RB_OUTPUT: u8 = 0x80;
const RB_NULL_COUNT: u8 = 0x40;

// ── Speaker port (0x61) bit-fields ──────────────────────────────────

const SPEAKER_GATE: u8 = 0x01;
const SPEAKER_DATA: u8 = 0x02;
const SPEAKER_REFRESH_CLOCK: u8 = 0x10;
const SPEAKER_OUTPUT: u8 = 0x20;

// ── Timer worker state ──────────────────────────────────────────────

struct TimerState {
    armed: bool,
    repeating: bool,
    period: Duration,
    deadline: Instant,
    kill: bool,
}

fn adjust_count(count: u32) -> u32 {
    if count == 0 { MAX_TIMER_FREQ } else { count }
}

// ── PIT counter ─────────────────────────────────────────────────────

pub struct PitCounter {
    reload_value: u16,
    latched_value: u16,
    command: u8,
    status: u8,
    start: Option<Instant>,
    creation_time: Instant,
    #[allow(dead_code)]
    counter_id: usize,
    wrote_low_byte: bool,
    read_low_byte: bool,
    latched: bool,
    status_latched: bool,
    gate: bool,
    speaker_on: bool,
    count: u32,
}

impl PitCounter {
    fn new(counter_id: usize) -> Self {
        PitCounter {
            reload_value: 0,
            latched_value: 0,
            command: 0,
            status: 0,
            start: None,
            creation_time: Instant::now(),
            counter_id,
            wrote_low_byte: false,
            read_low_byte: false,
            latched: false,
            status_latched: false,
            gate: false,
            speaker_on: false,
            count: MAX_TIMER_FREQ,
        }
    }

    fn get_access_mode(&self) -> u8 {
        self.command & CMD_RW
    }

    fn get_command_mode(&self) -> u8 {
        self.command & CMD_MODE
    }

    fn get_ticks_passed(&self) -> u64 {
        match self.start {
            None => 0,
            Some(t) => {
                let dur = Instant::now().duration_since(t);
                let dur_ns = dur.as_secs() * NANOS_PER_SEC + u64::from(dur.subsec_nanos());
                dur_ns * FREQUENCY_HZ / NANOS_PER_SEC
            }
        }
    }

    fn get_output(&self) -> bool {
        let ticks_passed = self.get_ticks_passed();
        let count = self.count as u64;
        match self.get_command_mode() {
            MODE_INTERRUPT => ticks_passed >= count,
            MODE_HW_ONESHOT => ticks_passed < count,
            MODE_RATE_GEN => ticks_passed != 0 && ticks_passed % count == 0,
            MODE_SQUARE_WAVE => ticks_passed < count.div_ceil(2),
            MODE_SW_STROBE | MODE_HW_STROBE => ticks_passed == count,
            _ => {
                warn!("pit: invalid command mode: {:#x}", self.command);
                false
            }
        }
    }

    fn get_read_value(&self) -> u16 {
        match self.start {
            None => 0,
            Some(_) => {
                let count = adjust_count(self.reload_value as u32) as u64;
                let ticks_passed = self.get_ticks_passed();
                match self.get_command_mode() {
                    MODE_INTERRUPT | MODE_HW_ONESHOT | MODE_SW_STROBE | MODE_HW_STROBE => {
                        if ticks_passed > count {
                            0
                        } else {
                            ((count - ticks_passed) & 0xFFFF) as u16
                        }
                    }
                    MODE_RATE_GEN => (count - (ticks_passed % count)) as u16,
                    MODE_SQUARE_WAVE => (count - ((ticks_passed * 2) % count)) as u16,
                    _ => {
                        warn!("pit: invalid command mode: {:#x}", self.command);
                        0
                    }
                }
            }
        }
    }

    pub fn read_counter(&mut self) -> u8 {
        if self.status_latched {
            self.status_latched = false;
            return self.status;
        }
        let data_value = if self.latched {
            self.latched_value
        } else {
            self.get_read_value()
        };

        match (self.get_access_mode(), self.read_low_byte) {
            (RW_LEAST, _) => {
                self.latched = false;
                (data_value & 0xff) as u8
            }
            (RW_BOTH, false) => {
                self.read_low_byte = true;
                (data_value & 0xff) as u8
            }
            (RW_BOTH, true) | (RW_MOST, _) => {
                self.read_low_byte = false;
                self.latched = false;
                (data_value >> 8) as u8
            }
            _ => 0,
        }
    }

    /// Write a data byte to the counter. Returns `Some(count)` when the
    /// counter has been fully loaded and the timer should be (re-)armed.
    pub fn write_counter(&mut self, datum: u8) -> Option<u32> {
        let d = datum as u16;
        let mut should_start = true;
        self.reload_value = match self.get_access_mode() {
            RW_LEAST => d,
            RW_MOST => d << 8,
            RW_BOTH => {
                if self.wrote_low_byte {
                    self.wrote_low_byte = false;
                    self.reload_value | (d << 8)
                } else {
                    self.wrote_low_byte = true;
                    should_start = false;
                    d
                }
            }
            _ => {
                should_start = false;
                self.reload_value
            }
        };
        if should_start {
            let reload = self.reload_value as u32;
            self.load_and_start(reload);
            Some(self.count)
        } else {
            None
        }
    }

    fn load_and_start(&mut self, initial_count: u32) {
        self.count = adjust_count(initial_count);
        self.start = Some(Instant::now());
    }

    fn latch_counter(&mut self) {
        if self.latched {
            return;
        }
        self.latched_value = self.get_read_value();
        self.latched = true;
        self.read_low_byte = false;
    }

    fn latch_status(&mut self) {
        self.status = self.command & (CMD_RW | CMD_MODE | CMD_BCD);
        if self.start.is_none() {
            self.status |= RB_NULL_COUNT;
        }
        if self.get_output() {
            self.status |= RB_OUTPUT;
        }
        self.status_latched = true;
    }

    fn read_back_command(&mut self, control_word: u8) {
        match control_word & RB_LATCH_BITS {
            RB_LATCH_COUNT => self.latch_counter(),
            RB_LATCH_STATUS => self.latch_status(),
            _ => warn!("pit: unexpected read-back latch: {:#x}", control_word),
        }
    }

    fn store_command(&mut self, datum: u8) {
        self.command = datum;
        self.latched = false;
        self.start = None;
        self.wrote_low_byte = false;
        self.read_low_byte = false;
    }

    pub fn read_speaker(&self) -> u8 {
        let us = Instant::now()
            .duration_since(self.creation_time)
            .subsec_micros();
        let refresh_clock = us % 15 == 0;
        let mut val: u8 = 0;
        if self.gate {
            val |= SPEAKER_GATE;
        }
        if self.speaker_on {
            val |= SPEAKER_DATA;
        }
        if refresh_clock {
            val |= SPEAKER_REFRESH_CLOCK;
        }
        if self.get_output() {
            val |= SPEAKER_OUTPUT;
        }
        val
    }

    pub fn write_speaker(&mut self, datum: u8) {
        let new_gate = datum & SPEAKER_GATE != 0;
        match self.get_command_mode() {
            MODE_INTERRUPT | MODE_SW_STROBE => {}
            MODE_HW_ONESHOT | MODE_RATE_GEN | MODE_SQUARE_WAVE | MODE_HW_STROBE => {
                if new_gate && !self.gate {
                    self.start = Some(Instant::now());
                }
            }
            _ => {
                warn!("pit: invalid command mode: {:#x}", self.command);
                return;
            }
        }
        self.speaker_on = datum & SPEAKER_DATA != 0;
        self.gate = new_gate;
    }
}

// ── PIT device (ports 0x40 – 0x43) ──────────────────────────────────

type PicRef = Option<Arc<Mutex<Pic>>>;

pub struct Pit {
    counters: [Arc<Mutex<PitCounter>>; NUM_COUNTERS],
    worker: Option<JoinHandle<()>>,
    timer_state: Arc<(Mutex<TimerState>, WakeEvent)>,
    kill_flag: Arc<AtomicBool>,
}

impl Pit {
    pub fn new(intc: IrqChip) -> Self {
        Self::build(intc, None)
    }

    pub fn new_with_pic(intc: IrqChip, pic: Arc<Mutex<Pic>>) -> Self {
        Self::build(intc, Some(pic))
    }

    fn build(intc: IrqChip, pic: PicRef) -> Self {
        let counters = [
            Arc::new(Mutex::new(PitCounter::new(0))),
            Arc::new(Mutex::new(PitCounter::new(1))),
            Arc::new(Mutex::new(PitCounter::new(2))),
        ];

        let timer_state = Arc::new((
            Mutex::new(TimerState {
                armed: false,
                repeating: false,
                period: Duration::ZERO,
                deadline: Instant::now(),
                kill: false,
            }),
            WakeEvent::new(),
        ));

        let kill_flag = Arc::new(AtomicBool::new(false));

        let ts = timer_state.clone();
        let kf = kill_flag.clone();
        let worker = thread::Builder::new()
            .name("pit-timer".into())
            .spawn(move || pit_worker(ts, kf, intc, pic))
            .expect("failed to spawn PIT timer thread");

        Pit {
            counters,
            worker: Some(worker),
            timer_state,
            kill_flag,
        }
    }

    /// Returns a shared reference to counter 2, used by the speaker port
    /// (I/O port 0x61) in the i8042 device.
    pub fn counter2(&self) -> Arc<Mutex<PitCounter>> {
        self.counters[2].clone()
    }

    fn arm_timer(&self, count: u32, mode: u8) {
        let period = Duration::from_nanos(count as u64 * NANOS_PER_SEC / FREQUENCY_HZ);
        // Anti-starvation clamp: Force a minimum 1ms period. 
        // Prevents the guest from accidentally DOS-ing the VMM with microsecond IRQ storms.
        let period = period.max(Duration::from_millis(1));

        let repeating = matches!(mode, MODE_RATE_GEN | MODE_SQUARE_WAVE);
        let (lock, wake) = &*self.timer_state;
        let mut ts = lock.lock().unwrap();
        ts.armed = true;
        ts.repeating = repeating;
        ts.period = period;
        ts.deadline = Instant::now() + period;
        drop(ts);

        wake.signal();
    }

    fn command_write(&self, control_word: u8) {
        let sc = control_word & CMD_SC;
        let counter_index = (sc >> 6) as usize;

        if sc == SC_READBACK {
            if control_word & RB_CTR0 != 0 {
                self.counters[0].lock().unwrap().read_back_command(control_word);
            }
            if control_word & RB_CTR1 != 0 {
                self.counters[1].lock().unwrap().read_back_command(control_word);
            }
            if control_word & RB_CTR2 != 0 {
                self.counters[2].lock().unwrap().read_back_command(control_word);
            }
        } else if control_word & CMD_RW == RW_LATCH {
            self.counters[counter_index]
                .lock()
                .unwrap()
                .latch_counter();
        } else {
            self.counters[counter_index]
                .lock()
                .unwrap()
                .store_command(control_word);
        }
    }

    fn write_counter_and_maybe_arm(&self, index: usize, datum: u8) {
        let mode;
        let result;
        {
            let mut ctr = self.counters[index].lock().unwrap();
            mode = ctr.get_command_mode();
            result = ctr.write_counter(datum);
        };
        if index == 0 {
            if let Some(count) = result {
                self.arm_timer(count, mode);
            }
        }
    }
}

impl Drop for Pit {
    fn drop(&mut self) {
        self.kill_flag.store(true, Ordering::SeqCst);
        {
            let (lock, wake) = &*self.timer_state;
            let mut ts = lock.lock().unwrap();
            ts.kill = true;
            drop(ts);
            wake.signal();
        }
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

impl BusDevice for Pit {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            warn!("pit: bad read size: {}", data.len());
            return;
        }
        data[0] = match offset {
            0 => self.counters[0].lock().unwrap().read_counter(),
            1 => self.counters[1].lock().unwrap().read_counter(),
            2 => self.counters[2].lock().unwrap().read_counter(),
            3 => {
                warn!("pit: ignoring read from command register");
                0
            }
            _ => {
                warn!("pit: bad read offset: {offset}");
                0
            }
        };
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            warn!("pit: bad write size: {}", data.len());
            return;
        }
        match offset {
            0 => self.write_counter_and_maybe_arm(0, data[0]),
            1 => self.write_counter_and_maybe_arm(1, data[0]),
            2 => self.write_counter_and_maybe_arm(2, data[0]),
            3 => self.command_write(data[0]),
            _ => warn!("pit: bad write offset: {offset}"),
        }
    }
}

// ── Timer worker thread ─────────────────────────────────────────────

/// Advance `ts.deadline` by one period, skipping forward if the thread
/// has fallen behind by more than one full period to avoid burst-firing.
fn advance_deadline(ts: &mut TimerState, now: Instant) {
    ts.deadline += ts.period;
    if ts.deadline <= now {
        let behind = (now - ts.deadline).as_nanos();
        let period_ns = ts.period.as_nanos();
        let skip = ((behind / period_ns) + 1).min(u32::MAX as u128) as u32;
        ts.deadline += ts.period * skip;
    }
}

/// Simple timer worker using an auto-reset `WakeEvent`.
/// `WaitForSingleObject(event, timeout_ms)` sleeps until either the
/// timeout expires or `arm_timer`/`Drop` signals the event.
fn pit_worker(
    state: Arc<(Mutex<TimerState>, WakeEvent)>,
    kill: Arc<AtomicBool>,
    intc: IrqChip,
    pic: PicRef,
) {
    let (lock, wake) = &*state;

    loop {
        let (armed, deadline, should_kill) = {
            let ts = lock.lock().unwrap();
            (ts.armed, ts.deadline, ts.kill)
        };

        if should_kill || kill.load(Ordering::SeqCst) {
            break;
        }

        if !armed {
            unsafe {
                WaitForSingleObject(wake.handle(), INFINITE);
            }
            continue;
        }

        let now = Instant::now();
        if deadline > now {
            // Never pass 0: WaitForSingleObject(h, 0) is a non-blocking
            // poll that returns immediately, causing a CPU-burning spin
            // when the remaining time truncates below 1 ms.
            let wait_ms = (deadline - now).as_millis().min(u32::MAX as u128).max(1) as u32;
            unsafe {
                WaitForSingleObject(wake.handle(), wait_ms);
            }
        }

        if kill.load(Ordering::SeqCst) {
            break;
        }

        let should_fire = {
            let mut ts = lock.lock().unwrap();
            if ts.kill {
                break;
            }
            let now = Instant::now();
            if ts.armed && now >= ts.deadline {
                if ts.repeating {
                    advance_deadline(&mut ts, now);
                } else {
                    ts.armed = false;
                }
                true
            } else {
                false
            }
        };

        if should_fire {
            if let Err(e) = intc.lock().unwrap().set_irq(Some(0), None) {
                error!("pit: failed to inject IRQ 0 via IOAPIC: {:?}", e);
            }
            if let Some(ref pic) = pic {
                pic.lock().unwrap().raise_irq(0);
            }
        }
    }
}