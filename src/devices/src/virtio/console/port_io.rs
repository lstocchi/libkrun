#[cfg(unix)]
use libc::{
    fcntl, F_GETFL, F_SETFL, O_NONBLOCK, STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO, TIOCGWINSZ,
};
use log::Level;
#[cfg(unix)]
use nix::errno::Errno;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, BorrowedHandle, OwnedHandle};
#[cfg(unix)]
use nix::ioctl_read_bad;
#[cfg(unix)]
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
#[cfg(unix)]
use nix::unistd::{dup, isatty};
#[cfg(unix)]
use std::fs::File;
use std::io::{self, ErrorKind};
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use utils::eventfd::EventFd;
use utils::eventfd::EFD_NONBLOCK;
use vm_memory::bitmap::Bitmap;
use vm_memory::{VolatileMemoryError, VolatileSlice, WriteVolatile};
#[cfg(windows)]
use std::collections::VecDeque;
#[cfg(windows)]
use std::sync::{Arc, Mutex};
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::FALSE,
    Storage::FileSystem::{ReadFile, WriteFile},
    System::{
        Console::{
            GetConsoleMode, GetConsoleScreenBufferInfo, ReadConsoleInputW, SetConsoleMode,
            CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, ENABLE_WINDOW_INPUT, INPUT_RECORD,
            KEY_EVENT, WINDOW_BUFFER_SIZE_EVENT,
        },
        Threading::{WaitForMultipleObjects, WaitForSingleObject, INFINITE},
    },
};

pub trait PortInput {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_readable(&self, stopfd: Option<&EventFd>);
}

pub trait PortOutput {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error>;

    fn wait_until_writable(&self);
}

/// Terminal properties associated with this port
pub trait PortTerminalProperties: Send + Sync {
    fn get_win_size(&self) -> (u16, u16);
}

#[cfg(unix)]
pub fn stdin() -> Result<Box<dyn PortInput + Send>, nix::Error> {
    let fd = dup_raw_fd_into_owned(STDIN_FILENO)?;
    make_non_blocking(&fd)?;
    Ok(Box::new(PortInputFd(fd)))
}

#[cfg(unix)]
pub fn input_to_raw_fd_dup(fd: RawFd) -> Result<Box<dyn PortInput + Send>, nix::Error> {
    let fd = dup_raw_fd_into_owned(fd)?;
    make_non_blocking(&fd)?;
    Ok(Box::new(PortInputFd(fd)))
}

#[cfg(windows)]
pub fn input_to_handle_dup(
    handle: *mut core::ffi::c_void,
) -> io::Result<Box<dyn PortInput + Send>> {
    Ok(Box::new(PortInputHandle(dup_handle(handle)?)))
}

#[cfg(unix)]
pub fn stdout() -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(STDOUT_FILENO)
}

#[cfg(unix)]
pub fn stderr() -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(STDERR_FILENO)
}

#[cfg(unix)]
pub fn term_fd(
    term_fd: RawFd,
) -> Result<Box<dyn PortTerminalProperties + Send + Sync>, nix::Error> {
    let fd = dup_raw_fd_into_owned(term_fd)?;
    assert!(
        isatty(&fd).is_ok_and(|v| v),
        "Expected fd {fd:?}, to be a tty, to query the window size!"
    );
    Ok(Box::new(PortTerminalPropertiesFd(fd)))
}

#[cfg(windows)]
pub fn term_handle(
    handle: *mut core::ffi::c_void,
) -> io::Result<Box<dyn PortTerminalProperties + Send + Sync>> {
    Ok(Box::new(PortTerminalPropertiesHandle(dup_handle(handle)?)))
}

pub fn term_fixed_size(width: u16, height: u16) -> Box<dyn PortTerminalProperties + Send + Sync> {
    Box::new(PortTerminalPropertiesFixed((width, height)))
}

pub fn input_empty() -> io::Result<Box<dyn PortInput + Send>> {
    Ok(Box::new(PortInputEmpty {}))
}

#[cfg(unix)]
pub fn output_file(file: File) -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    output_to_raw_fd_dup(file.as_raw_fd())
}

#[cfg(windows)]
pub fn output_file(file: std::fs::File) -> io::Result<Box<dyn PortOutput + Send>> {
    output_to_handle_dup(file.as_raw_handle())
}

#[cfg(unix)]
pub fn output_to_raw_fd_dup(fd: RawFd) -> Result<Box<dyn PortOutput + Send>, nix::Error> {
    let fd = dup_raw_fd_into_owned(fd)?;
    make_non_blocking(&fd)?;
    Ok(Box::new(PortOutputFd(fd)))
}

#[cfg(windows)]
pub fn output_to_handle_dup(
    handle: *mut core::ffi::c_void,
) -> io::Result<Box<dyn PortOutput + Send>> {
    Ok(Box::new(PortOutputHandle(dup_handle(handle)?)))
}

pub fn output_to_log_as_err() -> Box<dyn PortOutput + Send> {
    Box::new(PortOutputLog::new())
}

#[cfg(unix)]
struct PortInputFd(OwnedFd);

#[cfg(unix)]
impl AsRawFd for PortInputFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(unix)]
impl PortInput for PortInputFd {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> io::Result<usize> {
        // This source code is copied from vm-memory, except it fixes an issue, where
        // the original code would does not handle handle EWOULDBLOCK

        let fd = self.as_raw_fd();
        let guard = buf.ptr_guard_mut();

        let dst = guard.as_ptr().cast::<libc::c_void>();

        // SAFETY: We got a valid file descriptor from `AsRawFd`. The memory pointed to by `dst` is
        // valid for writes of length `buf.len() by the invariants upheld by the constructor
        // of `VolatileSlice`.
        let bytes_read = unsafe { libc::read(fd, dst, buf.len()) };

        if bytes_read < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::WouldBlock {
                // We don't know if a partial read might have happened, so mark everything as dirty
                buf.bitmap().mark_dirty(0, buf.len());
            }

            Err(err)
        } else {
            let bytes_read = bytes_read.try_into().unwrap();
            buf.bitmap().mark_dirty(0, bytes_read);
            Ok(bytes_read)
        }
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let mut poll_fds = Vec::new();
        poll_fds.push(PollFd::new(self.0.as_fd(), PollFlags::POLLIN));
        if let Some(stopfd) = stopfd {
            // SAFETY: we trust stopfd won't go away to avoid a dup call here.
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(stopfd.as_raw_fd()) };
            poll_fds.push(PollFd::new(borrowed_fd, PollFlags::POLLIN));
        }
        poll(&mut poll_fds, PollTimeout::NONE).expect("Failed to poll");
    }
}

#[cfg(unix)]
struct PortOutputFd(OwnedFd);

#[cfg(unix)]
impl AsRawFd for PortOutputFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(unix)]
impl PortOutput for PortOutputFd {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        self.0.write_volatile(buf).map_err(|e| match e {
            VolatileMemoryError::IOError(e) => e,
            e => {
                log::error!("Unsuported error from write_volatile: {e:?}");
                io::Error::other(e)
            }
        })
    }

    fn wait_until_writable(&self) {
        let mut poll_fds = [PollFd::new(self.0.as_fd(), PollFlags::POLLOUT)];
        poll(&mut poll_fds, PollTimeout::NONE).expect("Failed to poll");
    }
}

#[cfg(unix)]
fn dup_raw_fd_into_owned(raw_fd: RawFd) -> Result<OwnedFd, nix::Error> {
    // SAFETY: if raw_fd is invalid the `dup` call below will fail
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
    let fd = dup(borrowed_fd)?;
    Ok(fd)
}

#[cfg(unix)]
fn make_non_blocking(as_rw_fd: &impl AsRawFd) -> Result<(), nix::Error> {
    let fd = as_rw_fd.as_raw_fd();
    unsafe {
        let flags = fcntl(fd, F_GETFL, 0);
        if flags < 0 {
            return Err(Errno::last());
        }

        if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            return Err(Errno::last());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn dup_handle(raw: *mut core::ffi::c_void) -> io::Result<OwnedHandle> {
    let borrowed = unsafe { BorrowedHandle::borrow_raw(raw) };
    borrowed.try_clone_to_owned()
}

/// Block until at least one of the given Windows HANDLEs becomes signaled.
#[cfg(windows)]
fn wait_for_handles(handles: &[*mut core::ffi::c_void]) {
    match handles.len() {
        0 => std::thread::sleep(std::time::Duration::MAX),
        1 => unsafe { WaitForSingleObject(handles[0], INFINITE); },
        n => unsafe { WaitForMultipleObjects(n as u32, handles.as_ptr(), FALSE, INFINITE); },
    }
}

#[cfg(windows)]
struct PortInputHandle(OwnedHandle);

#[cfg(windows)]
impl PortInput for PortInputHandle {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> io::Result<usize> {
        let len = u32::try_from(buf.len())
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "buffer length exceeds u32::MAX"))?;
        let mut bytes_read: u32 = 0;
        let ret = unsafe {
            ReadFile(
                self.0.as_raw_handle(),
                buf.ptr_guard_mut().as_ptr(),
                len,
                &mut bytes_read,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            let err = io::Error::last_os_error();
            if err.kind() == ErrorKind::BrokenPipe {
                return Ok(0);
            }
            if err.kind() != ErrorKind::WouldBlock {
                // We don't know if a partial read might have happened, so mark everything as dirty
                buf.bitmap().mark_dirty(0, buf.len());
            }
            Err(err)
        } else {
            let n = bytes_read as usize;
            buf.bitmap().mark_dirty(0, n);
            Ok(n)
        }
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let mut handles = vec![self.0.as_raw_handle()];
        if let Some(s) = stopfd {
            handles.push(s.as_raw_fd());
        }
        wait_for_handles(&handles);
    }
}

/// Reads console input via `ReadConsoleInputW` on a background thread.
/// Key-down events are translated from UTF-16 to UTF-8 and buffered for
/// [`PortInputConsole`].  `WINDOW_BUFFER_SIZE_EVENT` events signal the
/// provided `sigwinch_evt` so the virtio console can update the guest.
#[cfg(windows)]
pub struct ConsoleInputReader {
    handle: OwnedHandle,
    buf: Arc<Mutex<VecDeque<u8>>>,
    data_evt: EventFd,
}

#[cfg(windows)]
impl ConsoleInputReader {
    pub fn new(console_handle: *mut core::ffi::c_void) -> io::Result<Self> {
        Ok(ConsoleInputReader {
            handle: dup_handle(console_handle)?,
            buf: Arc::new(Mutex::new(VecDeque::new())),
            data_evt: EventFd::new(EFD_NONBLOCK)?,
        })
    }

    pub fn create_port_input(&self) -> io::Result<Box<dyn PortInput + Send>> {
        Ok(Box::new(PortInputConsole {
            buf: self.buf.clone(),
            data_evt: self.data_evt.try_clone()?,
        }))
    }

    /// Enables `ENABLE_WINDOW_INPUT` on the console handle and spawns the
    /// background reader thread.  Resize events are forwarded via `sigwinch_evt`.
    pub fn start(self, sigwinch_evt: EventFd) -> io::Result<()> {
        unsafe {
            let raw = self.handle.as_raw_handle();
            let mut mode: CONSOLE_MODE = 0;
            if GetConsoleMode(raw, &mut mode) != 0 {
                let _ = SetConsoleMode(raw, mode | ENABLE_WINDOW_INPUT);
            }
        }

        let ConsoleInputReader {
            handle,
            buf,
            data_evt,
        } = self;
        std::thread::Builder::new()
            .name("console-input".into())
            .spawn(move || {
                console_input_reader_loop(handle, buf, data_evt, sigwinch_evt);
            })?;
        Ok(())
    }
}

#[cfg(windows)]
fn console_input_reader_loop(
    handle: OwnedHandle,
    buf: Arc<Mutex<VecDeque<u8>>>,
    data_evt: EventFd,
    sigwinch_evt: EventFd,
) {
    let raw = handle.as_raw_handle();
    let mut records: [INPUT_RECORD; 128] = unsafe { std::mem::zeroed() };
    // Windows natively uses UTF-16 for text. Most standard characters fit into a single 16-bit integer. 
    // However, things like Emojis require more space. 
    // UTF-16 handles this by splitting the character into two 16-bit chunks called a Surrogate Pair
    // a "High" surrogate followed immediately by a "Low" surrogate
    let mut high_surrogate: Option<u16> = None;

    loop {
        let mut count: u32 = 0;
        let ret = unsafe {
            ReadConsoleInputW(raw, records.as_mut_ptr(), records.len() as u32, &mut count)
        };
        if ret == 0 {
            log::error!("ReadConsoleInputW failed: {}", io::Error::last_os_error());
            return;
        }

        let mut utf8_bytes = Vec::new();

        for record in &records[..count as usize] {
            if record.EventType == KEY_EVENT as u16 {
                let key = unsafe { record.Event.KeyEvent };
                // Windows fires an event when a key is pressed and when it is released.
                // This drops the release events so we don't get double characters.
                if key.bKeyDown == 0 {
                    continue;
                }
                let ch = unsafe { key.uChar.UnicodeChar };
                if ch == 0 {
                    continue;
                }

                // UTF-16 surrogate pair handling for characters above U+FFFF
                // If it detects the first half of a pair, it stores it in high_surrogate
                if (0xD800..=0xDBFF).contains(&ch) {
                    high_surrogate = Some(ch);
                    continue;
                }

                // If it detects the second half of a pair, it combines it with the high surrogate
                // if it receives a normal character, it resets the high surrogate
                let codepoint = if (0xDC00..=0xDFFF).contains(&ch) {
                    if let Some(high) = high_surrogate.take() {
                        Some(
                            ((high as u32 - 0xD800) << 10) + (ch as u32 - 0xDC00) + 0x10000,
                        )
                    } else {
                        None
                    }
                } else {
                    high_surrogate = None;
                    Some(ch as u32)
                };

                // virtio console expects a stream of u8 bytes, so we need to convert the UTF-32 codepoint to UTF-8
                if let Some(c) = codepoint.and_then(char::from_u32) {
                    let mut enc = [0u8; 4];
                    let s = c.encode_utf8(&mut enc);
                    // Windows may fire multiple events for the same key press, so we need to repeat the bytes
                    // for the number of times the key was pressed
                    for _ in 0..key.wRepeatCount.max(1) {
                        utf8_bytes.extend_from_slice(s.as_bytes());
                    }
                }
            } else if record.EventType == WINDOW_BUFFER_SIZE_EVENT as u16 {
                let _ = sigwinch_evt.write(1);
            }
        }

        if !utf8_bytes.is_empty() {
            let mut lock = buf.lock().unwrap();
            lock.extend(&utf8_bytes);
            let _ = data_evt.write(1);
        }
    }
}

/// Reads from a shared buffer fed by [`ConsoleInputReader`].
/// The data event stays signaled as long as the buffer is non-empty (manual-
/// reset semantics), and is reset only when `read_volatile` fully drains it.
#[cfg(windows)]
struct PortInputConsole {
    buf: Arc<Mutex<VecDeque<u8>>>,
    data_evt: EventFd,
}

#[cfg(windows)]
impl PortInput for PortInputConsole {
    fn read_volatile(&mut self, slice: &mut VolatileSlice) -> io::Result<usize> {
        let mut lock = self.buf.lock().unwrap();
        if lock.is_empty() {
            let _ = self.data_evt.read();
            return Err(ErrorKind::WouldBlock.into());
        }

        let to_copy = lock.len().min(slice.len());
        let (front, _) = lock.make_contiguous().split_at(to_copy);
        slice.copy_from(front);
        drop(lock.drain(..to_copy));

        // The buffer may still have data, so we deliberately skip
        // the read to keep the data_evt signaled if not empty
        if lock.is_empty() {
            let _ = self.data_evt.read();
        }

        Ok(to_copy)
    }

    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let mut handles = vec![self.data_evt.as_raw_fd()];
        if let Some(s) = stopfd {
            handles.push(s.as_raw_fd());
        }
        wait_for_handles(&handles);
    }
}

#[cfg(windows)]
struct PortOutputHandle(OwnedHandle);

#[cfg(windows)]
impl PortOutput for PortOutputHandle {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> io::Result<usize> {
        let len = u32::try_from(buf.len())
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "buffer length exceeds u32::MAX"))?;
        let mut bytes_written: u32 = 0;
        let ret = unsafe {
            WriteFile(
                self.0.as_raw_handle(),
                buf.ptr_guard().as_ptr(),
                len,
                &mut bytes_written,
                std::ptr::null_mut(),
            )
        };
        if ret == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(bytes_written as usize)
        }
    }

    fn wait_until_writable(&self) {
        // Console/pipe output handles are always writable; nothing to wait for.
    }
}

#[cfg(windows)]
struct PortTerminalPropertiesHandle(OwnedHandle);

#[cfg(windows)]
impl PortTerminalProperties for PortTerminalPropertiesHandle {
    fn get_win_size(&self) -> (u16, u16) {
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        let ret = unsafe { GetConsoleScreenBufferInfo(self.0.as_raw_handle(), &mut info) };
        if ret == 0 {
            log::error!("GetConsoleScreenBufferInfo failed: {}", io::Error::last_os_error());
            return (0, 0);
        }
        let cols = (info.srWindow.Right - info.srWindow.Left + 1) as u16;
        let rows = (info.srWindow.Bottom - info.srWindow.Top + 1) as u16;
        (cols, rows)
    }
}

// Utility to relay log from the VM (the kernel boot log and messages from init)
// to the rust log
#[derive(Default)]
pub struct PortOutputLog {
    buf: Vec<u8>,
}

impl PortOutputLog {
    const FORCE_FLUSH_TRESHOLD: usize = 512;
    const LOG_TARGET: &'static str = "init_or_kernel";

    fn new() -> Self {
        Self::default()
    }

    fn force_flush(&mut self) {
        log::log!(target: PortOutputLog::LOG_TARGET, Level::Error, "[missing newline]{}", String::from_utf8_lossy(&self.buf));
        self.buf.clear();
    }
}

impl PortOutput for PortOutputLog {
    fn write_volatile(&mut self, buf: &VolatileSlice) -> Result<usize, io::Error> {
        self.buf.write_volatile(buf).map_err(io::Error::other)?;

        let mut start = 0;
        for (i, ch) in self.buf.iter().cloned().enumerate() {
            if ch == b'\n' {
                log::log!(target: PortOutputLog::LOG_TARGET, Level::Error, "{}", String::from_utf8_lossy(&self.buf[start..i]));
                start = i + 1;
            }
        }
        self.buf.drain(0..start);
        // Make sure to not grow the internal buffer forever!
        if self.buf.len() > PortOutputLog::FORCE_FLUSH_TRESHOLD {
            self.force_flush()
        }
        Ok(buf.len())
    }

    fn wait_until_writable(&self) {}
}

pub struct PortInputSigInt {
    sigint_evt: EventFd,
}

impl PortInputSigInt {
    pub fn new() -> Self {
        PortInputSigInt {
            sigint_evt: EventFd::new(EFD_NONBLOCK)
                .expect("Failed to create EventFd for SIGINT signaling"),
        }
    }

    pub fn sigint_evt(&self) -> &EventFd {
        &self.sigint_evt
    }
}

impl Default for PortInputSigInt {
    fn default() -> Self {
        Self::new()
    }
}

impl PortInput for PortInputSigInt {
    fn read_volatile(&mut self, buf: &mut VolatileSlice) -> Result<usize, io::Error> {
        self.sigint_evt.read()?;
        log::trace!("SIGINT received");
        buf.copy_from(&[3u8]); //ASCII 'ETX' -> generates SIGINIT in a terminal
        Ok(1)
    }

    #[cfg(unix)]
    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let mut poll_fds = Vec::with_capacity(2);
        // SAFETY: we trust sigint_evt won't go away to avoid a dup call here.
        let sigint_bfd = unsafe { BorrowedFd::borrow_raw(self.sigint_evt.as_raw_fd()) };
        poll_fds.push(PollFd::new(sigint_bfd, PollFlags::POLLIN));
        if let Some(stopfd) = stopfd {
            // SAFETY: we trust stopfd won't go away to avoid a dup call here.
            let stop_bfd = unsafe { BorrowedFd::borrow_raw(stopfd.as_raw_fd()) };
            poll_fds.push(PollFd::new(stop_bfd, PollFlags::POLLIN));
        }

        poll(&mut poll_fds, PollTimeout::NONE).expect("Failed to poll");
    }

    #[cfg(windows)]
    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let mut handles = vec![self.sigint_evt.as_raw_fd()];
        if let Some(s) = stopfd {
            handles.push(s.as_raw_fd());
        }
        wait_for_handles(&handles);
    }
}

pub struct PortInputEmpty {}

impl PortInputEmpty {
    pub fn new() -> Self {
        PortInputEmpty {}
    }
}

impl Default for PortInputEmpty {
    fn default() -> Self {
        Self::new()
    }
}

impl PortInput for PortInputEmpty {
    fn read_volatile(&mut self, _buf: &mut VolatileSlice) -> Result<usize, io::Error> {
        Ok(0)
    }

    #[cfg(unix)]
    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        if let Some(stopfd) = stopfd {
            // SAFETY: we trust stopfd won't go away to avoid a dup call here.
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(stopfd.as_raw_fd()) };
            let mut poll_fds = [PollFd::new(borrowed_fd, PollFlags::POLLIN)];
            poll(&mut poll_fds, PollTimeout::NONE).expect("Failed to poll");
        } else {
            std::thread::sleep(std::time::Duration::MAX);
        }
    }

    #[cfg(windows)]
    fn wait_until_readable(&self, stopfd: Option<&EventFd>) {
        let handles: Vec<_> = stopfd.iter().map(|s| s.as_raw_fd()).collect();
        wait_for_handles(&handles);
    }
}

struct PortTerminalPropertiesFixed((u16, u16));

impl PortTerminalProperties for PortTerminalPropertiesFixed {
    fn get_win_size(&self) -> (u16, u16) {
        self.0
    }
}

#[cfg(unix)]
struct PortTerminalPropertiesFd(OwnedFd);

#[cfg(unix)]
impl PortTerminalProperties for PortTerminalPropertiesFd {
    fn get_win_size(&self) -> (u16, u16) {
        let mut ws: WS = WS::default();

        if let Err(err) = unsafe { tiocgwinsz(self.0.as_raw_fd(), &mut ws) } {
            error!("Couldn't get terminal dimensions: {err}");
            return (0, 0);
        }
        (ws.cols, ws.rows)
    }
}

#[cfg(unix)]
#[repr(C)]
#[derive(Default)]
struct WS {
    rows: u16,
    cols: u16,
    xpixel: u16,
    ypixel: u16,
}
#[cfg(unix)]
ioctl_read_bad!(tiocgwinsz, TIOCGWINSZ, WS);
