use std::sync::{Arc, Mutex, Condvar};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use whp::WhpVm;

struct TimerState {
    config: u64,
    count: u64,
    armed: bool,
    stop: bool,
}

pub struct SynicTimer {
    state: Arc<(Mutex<TimerState>, Condvar)>,
    _thread: JoinHandle<()>,
}

impl SynicTimer {
    pub fn new(vm: Arc<WhpVm>, vp_index: u32) -> Self {
        let state = Arc::new((
            Mutex::new(TimerState {
                config: 0, count: 0, armed: false, stop: false,
            }),
            Condvar::new(),
        ));

        let thread_state = state.clone();
        let _thread = thread::Builder::new()
            .name(format!("vcpu-{}-stimer", vp_index))
            .spawn(move || Self::timer_loop(vm, vp_index, thread_state))
            .unwrap();

        Self { state, _thread }
    }

    pub fn write_config(&self, config: u64) {
        let (lock, cvar) = &*self.state;
        let mut s = lock.lock().unwrap();
        s.config = config;
        
        // Bit 0: Enable. If cleared, disarm the timer immediately.
        if config & 1 == 0 {
            s.armed = false;
        }
        cvar.notify_one();
    }

    pub fn write_count(&self, count: u64) {
        let (lock, cvar) = &*self.state;
        let mut s = lock.lock().unwrap();
        s.count = count;
        
        // Bit 3: AutoEnable. Writing to count arms it automatically.
        // Otherwise, it only arms if the Enable bit (0) is already set.
        if (s.config & (1 << 3)) != 0 || (s.config & 1) != 0 {
            s.armed = true;
        }
        cvar.notify_one();
    }

    pub fn stop(&self) {
        let (lock, cvar) = &*self.state;
        let mut s = lock.lock().unwrap();
        s.stop = true;
        cvar.notify_one();
    }

    fn timer_loop(vm: Arc<WhpVm>, vp_index: u32, state: Arc<(Mutex<TimerState>, Condvar)>) {
        let (lock, cvar) = &*state;
        let mut s = lock.lock().unwrap();

        loop {
            if s.stop { break; }

            if !s.armed {
                s = cvar.wait(s).unwrap();
                continue;
            }

            let is_periodic = (s.config & (1 << 1)) != 0;
            // DirectMode (Bit 12) uses APIC Vector (Bits 4-11)
            let vector = ((s.config >> 4) & 0xFF) as u32;

            let sleep_dur = if is_periodic {
                Duration::from_nanos(s.count * 100)
            } else {
                let now_100ns = vm.hyperv().reference_time();
                if s.count > now_100ns {
                    Duration::from_nanos((s.count - now_100ns) * 100)
                } else {
                    Duration::ZERO // Deadline passed
                }
            };

            let (new_s, timeout_res) = cvar.wait_timeout(s, sleep_dur).unwrap();
            s = new_s;

            if s.stop { break; }

            // If we timed out, it means the sleep completed without being interrupted 
            // by a new MSR write. Time to fire the interrupt!
            if timeout_res.timed_out() && s.armed {
                if vector > 0 {
                    vm.inject_vector(vector);
                    vm.cancel_vcpu(vp_index);
                }
                
                if !is_periodic {
                    s.armed = false; // One-shot timers disarm after firing
                }
            }
        }
    }
}

impl Drop for SynicTimer {
    fn drop(&mut self) {
        self.stop();
    }
}