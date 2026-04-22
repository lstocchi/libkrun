use std::os::windows::io::AsRawHandle;
use std::sync::Once;

use windows_sys::Win32::Foundation::HANDLE;

pub(crate) mod bindings;
pub mod epoll;
pub mod eventfd;
pub mod wake_event;

/// Cross-platform alias used by the rest of the codebase.  On Windows this
/// is just [`HANDLE`] — the two names are interchangeable.
pub type RawFd = HANDLE;

static WSA_INIT: Once = Once::new();

/// Ensure that `WSAStartup` has been called exactly once for this process.
/// Safe to call from any thread, any number of times.
pub fn ensure_wsa_init() {
    WSA_INIT.call_once(|| {
        use windows_sys::Win32::Networking::WinSock::{WSAStartup, WSADATA};
        let mut data: WSADATA = unsafe { std::mem::zeroed() };
        let ret = unsafe { WSAStartup(0x0202, &mut data) };
        assert!(ret == 0, "WSAStartup failed: {ret}");
    });
}

/// Windows equivalent of [`std::os::unix::io::AsRawFd`].
pub trait AsRawFd {
    fn as_raw_fd(&self) -> RawFd;
}

impl AsRawFd for std::fs::File {
    fn as_raw_fd(&self) -> RawFd {        
        self.as_raw_handle() as RawFd
    }
}

/// A thin wrapper around a raw `HANDLE` that implements [`Send`].
///
/// Raw pointers do not implement `Send`, but Windows kernel handles are safe
/// to use from any thread.  This wrapper lets closures capture a handle value
/// without needing an `unsafe impl Send` on the closure itself.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct SendHandle(pub HANDLE);

// SAFETY: Windows kernel object handles are process-wide and thread-safe.
unsafe impl Send for SendHandle {}

impl SendHandle {
    pub fn as_raw_handle(self) -> HANDLE {
        self.0
    }
}
