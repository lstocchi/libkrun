// Copyright 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use utils::eventfd::EventFd;

use crate::bus::BusDevice;

const PIT_FREQUENCY_HZ: u64 = 1_193_182;

#[derive(Clone, Copy)]
enum AccessMode {
    Low,
    High,
    LowHigh,
}

struct Channel {
    access: AccessMode,
    mode: u8,
    reload: u32,
    write_latch: u16,
    write_low: bool,
    read_low: bool,
    latched: Option<u16>,
    started: Instant,
    gate: bool,
    one_shot_fired: bool,
}

impl Channel {
    fn new(gate: bool) -> Self {
        Self {
            access: AccessMode::LowHigh,
            mode: 0,
            reload: 0,
            write_latch: 0,
            write_low: true,
            read_low: true,
            latched: None,
            started: Instant::now(),
            gate,
            one_shot_fired: false,
        }
    }

    fn load(&mut self, value: u16) {
        self.reload = if value == 0 { 0x1_0000 } else { value as u32 };
        self.started = Instant::now();
        self.latched = None;
        self.read_low = true;
        self.one_shot_fired = false;
    }

    fn write(&mut self, value: u8) -> bool {
        match self.access {
            AccessMode::Low => {
                let count = (self.reload as u16 & 0xff00) | value as u16;
                self.load(count);
                true
            }
            AccessMode::High => {
                let count = (self.reload as u16 & 0x00ff) | ((value as u16) << 8);
                self.load(count);
                true
            }
            AccessMode::LowHigh if self.write_low => {
                self.write_latch = value as u16;
                self.write_low = false;
                false
            }
            AccessMode::LowHigh => {
                let count = self.write_latch | ((value as u16) << 8);
                self.write_low = true;
                self.load(count);
                true
            }
        }
    }

    fn elapsed_ticks(&self) -> u64 {
        let nanos = self.started.elapsed().as_nanos();
        ((nanos * PIT_FREQUENCY_HZ as u128) / 1_000_000_000) as u64
    }

    fn current_count(&self) -> u16 {
        if self.reload == 0 || !self.gate {
            return self.reload as u16;
        }

        let elapsed = self.elapsed_ticks();
        let count = match self.mode {
            2 | 3 => self.reload - (elapsed % self.reload as u64) as u32,
            _ => self
                .reload
                .saturating_sub(elapsed.min(self.reload as u64) as u32),
        };
        count as u16
    }

    fn read(&mut self) -> u8 {
        let count = self.latched.unwrap_or_else(|| self.current_count());
        match self.access {
            AccessMode::Low => {
                self.latched = None;
                count as u8
            }
            AccessMode::High => {
                self.latched = None;
                (count >> 8) as u8
            }
            AccessMode::LowHigh if self.read_low => {
                self.read_low = false;
                count as u8
            }
            AccessMode::LowHigh => {
                self.read_low = true;
                self.latched = None;
                (count >> 8) as u8
            }
        }
    }

    fn output(&self) -> bool {
        if self.reload == 0 || !self.gate {
            return false;
        }

        let position = (self.elapsed_ticks() % self.reload as u64) as u32;
        match self.mode {
            2 => position + 1 != self.reload,
            3 => position < self.reload.div_ceil(2),
            _ => self.elapsed_ticks() >= self.reload as u64,
        }
    }

    fn next_interrupt(&self) -> Option<Duration> {
        if self.reload == 0 || !self.gate {
            return None;
        }

        let elapsed_ticks = self.elapsed_ticks();
        let remaining_ticks = match self.mode {
            0 | 4 if !self.one_shot_fired => self
                .reload
                .saturating_sub(elapsed_ticks.min(self.reload as u64) as u32)
                as u64,
            2 | 3 => {
                let position = elapsed_ticks % self.reload as u64;
                self.reload as u64 - position
            }
            _ => return None,
        };
        Some(Duration::from_nanos(
            (remaining_ticks as u64 * 1_000_000_000).div_ceil(PIT_FREQUENCY_HZ),
        ))
    }
}

struct PitState {
    channels: [Channel; 3],
    speaker_control: u8,
    generation: u64,
}

impl PitState {
    fn new() -> Self {
        Self {
            channels: [Channel::new(true), Channel::new(true), Channel::new(false)],
            speaker_control: 0,
            generation: 0,
        }
    }
}

pub struct Pit {
    state: Arc<(Mutex<PitState>, Condvar)>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Pit {
    pub fn new(interrupt_evt: EventFd) -> io::Result<Self> {
        let state = Arc::new((Mutex::new(PitState::new()), Condvar::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_state = state.clone();
        let worker_stop = stop.clone();
        let worker = thread::Builder::new()
            .name("pit".to_string())
            .spawn(move || Self::run_timer(worker_state, worker_stop, interrupt_evt))?;

        Ok(Self {
            state,
            stop,
            worker: Some(worker),
        })
    }

    fn run_timer(state: Arc<(Mutex<PitState>, Condvar)>, stop: Arc<AtomicBool>, evt: EventFd) {
        let (lock, wake) = &*state;
        let mut state = lock.lock().unwrap();

        while !stop.load(Ordering::Relaxed) {
            let generation = state.generation;
            let Some(delay) = state.channels[0].next_interrupt() else {
                state = wake.wait(state).unwrap();
                continue;
            };

            let (new_state, timeout) = wake.wait_timeout(state, delay).unwrap();
            state = new_state;
            if timeout.timed_out() && generation == state.generation {
                if matches!(state.channels[0].mode, 0 | 4) {
                    state.channels[0].one_shot_fired = true;
                }
                drop(state);
                if let Err(err) = evt.write(1) {
                    error!("PIT failed to signal IRQ0: {err}");
                }
                state = lock.lock().unwrap();
            }
        }
    }

    fn configure(&mut self, control: u8) {
        let channel = (control >> 6) as usize;
        let (lock, wake) = &*self.state;
        let mut state = lock.lock().unwrap();

        if channel == 3 {
            if control & 0x20 == 0 {
                for index in 0..3 {
                    if control & (1 << (index + 1)) == 0 {
                        state.channels[index].latched = Some(state.channels[index].current_count());
                    }
                }
            }
            return;
        }

        let access = (control >> 4) & 3;
        if access == 0 {
            state.channels[channel].latched = Some(state.channels[channel].current_count());
            return;
        }

        state.channels[channel].access = match access {
            1 => AccessMode::Low,
            2 => AccessMode::High,
            _ => AccessMode::LowHigh,
        };
        let mode = (control >> 1) & 7;
        state.channels[channel].mode = if mode >= 6 { mode - 4 } else { mode };
        state.channels[channel].write_low = true;
        state.channels[channel].read_low = true;
        state.channels[channel].latched = None;
        if channel == 0 {
            state.generation = state.generation.wrapping_add(1);
            wake.notify_one();
        }
    }

    pub fn read_speaker_port(&self) -> u8 {
        let state = self.state.0.lock().unwrap();
        state.speaker_control | ((state.channels[2].output() as u8) << 5)
    }

    pub fn write_speaker_port(&mut self, value: u8) {
        let mut state = self.state.0.lock().unwrap();
        let old_gate = state.channels[2].gate;
        state.speaker_control = value & 3;
        state.channels[2].gate = value & 1 != 0;
        if !old_gate && state.channels[2].gate {
            state.channels[2].started = Instant::now();
        }
    }
}

impl BusDevice for Pit {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if data.len() != 1 {
            return;
        }

        if offset < 3 {
            data[0] = self.state.0.lock().unwrap().channels[offset as usize].read();
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if data.len() != 1 {
            return;
        }

        match offset {
            0..=2 => {
                let (lock, wake) = &*self.state;
                let mut state = lock.lock().unwrap();
                if state.channels[offset as usize].write(data[0]) && offset == 0 {
                    state.generation = state.generation.wrapping_add(1);
                    wake.notify_one();
                }
            }
            3 => self.configure(data[0]),
            _ => {}
        }
    }
}

impl Drop for Pit {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.state.1.notify_one();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::eventfd::EFD_NONBLOCK;

    #[test]
    fn channel_zero_periodic_interrupts() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let mut pit = Pit::new(evt.try_clone().unwrap()).unwrap();

        pit.write(0, 3, &[0x34]);
        pit.write(0, 0, &[0xa9]);
        pit.write(0, 0, &[0x04]);

        thread::sleep(Duration::from_millis(50));
        assert!(evt.read().unwrap() >= 1);
    }

    #[test]
    fn channel_two_drives_speaker_output() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let mut pit = Pit::new(evt).unwrap();

        pit.write(0, 3, &[0xb6]);
        pit.write(0, 2, &[2]);
        pit.write(0, 2, &[0]);
        pit.write_speaker_port(1);

        assert_eq!(pit.read_speaker_port() & 3, 1);
    }

    #[test]
    fn channel_zero_one_shot_interrupts_once() {
        let evt = EventFd::new(EFD_NONBLOCK).unwrap();
        let mut pit = Pit::new(evt.try_clone().unwrap()).unwrap();

        pit.write(0, 3, &[0x30]);
        pit.write(0, 0, &[0xa9]);
        pit.write(0, 0, &[0x04]);

        thread::sleep(Duration::from_millis(50));
        assert_eq!(evt.read().unwrap(), 1);
        thread::sleep(Duration::from_millis(20));
        assert!(matches!(evt.read(), Err(err) if err.kind() == io::ErrorKind::WouldBlock));
    }
}
