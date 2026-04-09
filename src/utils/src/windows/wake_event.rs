use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent
};

pub struct WakeEvent(HANDLE);

unsafe impl Send for WakeEvent {}
unsafe impl Sync for WakeEvent {}

impl WakeEvent {
    pub fn new() -> Self {
        let h = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
        assert!(!h.is_null(), "failed to create wake event");
        Self(h)
    }

    pub fn signal(&self) {
        unsafe { SetEvent(self.0); }
    }

    pub fn handle(&self) -> HANDLE {
        self.0
    }
}

impl Drop for WakeEvent {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0); }
    }
}