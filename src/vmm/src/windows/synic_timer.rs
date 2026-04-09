use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use whp::WhpVm;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{
    WaitForSingleObject, INFINITE,
};
use utils::windows::wake_event::WakeEvent;

struct TimerState {
    config: u64,
    count: u64,
    armed: bool,
    stop: bool,
}

pub struct SynicTimer {
    state: Arc<(Mutex<TimerState>, WakeEvent)>,
    _thread: JoinHandle<()>,
}

impl SynicTimer {
    pub fn new(vm: Arc<WhpVm>, vp_index: u32) -> Self {
        let state = Arc::new((
            Mutex::new(TimerState {
                config: 0, count: 0, armed: false, stop: false,
            }),
            WakeEvent::new(),
        ));

        let thread_state = state.clone();
        let _thread = thread::Builder::new()
            .name(format!("vcpu-{}-stimer", vp_index))
            .spawn(move || Self::timer_loop(vm, vp_index, thread_state))
            .unwrap();

        Self { state, _thread }
    }

    pub fn write_config(&self, config: u64) {
        let (lock, wake) = &*self.state;
        let mut s = lock.lock().unwrap();
        s.config = config;
        
        // Bit 0: Enable. If cleared, disarm the timer immediately.
        if config & 1 == 0 {
            s.armed = false;
        }
        drop(s);
        wake.signal();
    }

    pub fn write_count(&self, count: u64) {
        let (lock, wake) = &*self.state;
        let mut s = lock.lock().unwrap();
        s.count = count;
        
        // Bit 3: AutoEnable. Writing to count arms it automatically.
        // Otherwise, it only arms if the Enable bit (0) is already set.
        if (s.config & (1 << 3)) != 0 || (s.config & 1) != 0 {
            s.armed = true;
        }
        drop(s);
        wake.signal();
    }

    pub fn stop(&self) {
        let (lock, wake) = &*self.state;
        let mut s = lock.lock().unwrap();
        s.stop = true;
        drop(s);
        wake.signal();
    }

    fn timer_loop(
        vm: Arc<WhpVm>,
        vp_index: u32,
        state: Arc<(Mutex<TimerState>, WakeEvent)>,
    ) {
        let (lock, wake) = &*state;

        loop {
            let (armed, stop, config, count) = {
                let s = lock.lock().unwrap();
                (s.armed, s.stop, s.config, s.count)
            };

            if stop {
                break;
            }

            if !armed {
                unsafe { WaitForSingleObject(wake.handle(), INFINITE); }
                continue;
            }

            let is_periodic = (config & (1 << 1)) != 0;
            let vector = ((config >> 4) & 0xFF) as u32;

            let wait_ms = if is_periodic {
                let nanos = count.saturating_mul(100);
                Duration::from_nanos(nanos).as_millis().min(u32::MAX as u128) as u32
            } else {
                let now_100ns = vm.hyperv().reference_time();
                if count > now_100ns {
                    let nanos = (count - now_100ns).saturating_mul(100);
                    Duration::from_nanos(nanos).as_millis().min(u32::MAX as u128) as u32
                } else {
                    0
                }
            };

            if wait_ms > 0 {
                unsafe { WaitForSingleObject(wake.handle(), wait_ms); }
            }

            let mut s = lock.lock().unwrap();
            if s.stop {
                break;
            }
            if !s.armed {
                continue;
            }

            let should_fire = if is_periodic {
                true
            } else {
                let now_100ns = vm.hyperv().reference_time();
                now_100ns >= s.count
            };

            if should_fire && vector > 0 {
                if !is_periodic {
                    s.armed = false;
                }
                drop(s);

                vm.inject_vector(vector);
                vm.cancel_vcpu(vp_index);
            }
        }
    }
}

impl Drop for SynicTimer {
    fn drop(&mut self) {
        self.stop();
    }
}
