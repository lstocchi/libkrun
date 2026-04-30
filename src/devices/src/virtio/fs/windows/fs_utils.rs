use std::io;

use super::super::super::linux_errno::{linux_error, linux_errno_raw};

pub fn ebadf() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::EBADF))
}

pub fn einval() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::EINVAL))
}

pub fn enoent() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::ENOENT))
}

pub fn enosys() -> io::Error {
    linux_error(io::Error::from_raw_os_error(libc::ENOSYS))
}

pub fn win_err_to_linux(e: io::Error) -> io::Error {
    // 1. Try to map highly specific Windows raw error codes first
    let linux_errno = if let Some(code) = e.raw_os_error() {
        match code as u32 {
            1 | 1314 => libc::EPERM,       // ERROR_INVALID_FUNCTION / ERROR_PRIVILEGE_NOT_HELD
            6 | 21 => libc::ENXIO,         // ERROR_INVALID_HANDLE / ERROR_NOT_READY
            1117 => libc::EIO,             // ERROR_IO_DEVICE
            4 => libc::EMFILE,             // ERROR_TOO_MANY_OPEN_FILES
            120 => libc::ENOSYS,           // ERROR_CALL_NOT_IMPLEMENTED
            4331 => libc::ENODATA,         // ERROR_NOT_FOUND (often used for missing xattrs)
            
            // If it's not a special case, fall through to checking the standard ErrorKind
            _ => map_kind_to_linux(e.kind()),
        }
    } else {
        // 2. If there's no raw OS error, rely purely on the ErrorKind
        map_kind_to_linux(e.kind())
    };

    // Safely wrap it in the virtio-fs linux_error format
    linux_error(io::Error::from_raw_os_error(linux_errno_raw(linux_errno)))
}

/// Helper function to cleanly map Rust's platform-agnostic ErrorKind to Linux errnos
fn map_kind_to_linux(kind: io::ErrorKind) -> i32 {
    match kind {
        io::ErrorKind::NotFound => libc::ENOENT,
        io::ErrorKind::PermissionDenied => libc::EACCES,
        io::ErrorKind::AlreadyExists => libc::EEXIST,
        io::ErrorKind::InvalidInput => libc::EINVAL,
        io::ErrorKind::DirectoryNotEmpty => libc::ENOTEMPTY,
        io::ErrorKind::OutOfMemory => libc::ENOMEM,
        io::ErrorKind::WriteZero => libc::ENOSPC,
        io::ErrorKind::Unsupported => libc::ENOSYS,            
        io::ErrorKind::InvalidData => libc::EILSEQ,
        io::ErrorKind::Interrupted => libc::EINTR,
        // Default fallback
        _ => libc::EIO, 
    }
}