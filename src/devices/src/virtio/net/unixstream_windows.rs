use std::io;
use std::os::windows::io::RawSocket;
use std::path::PathBuf;

use windows_sys::Win32::Networking::WinSock::{
    connect, ioctlsocket, recv, send, setsockopt, socket, WSAGetLastError, AF_UNIX, FIONBIO,
    INVALID_SOCKET, SOCKADDR_UN, SOCKET_ERROR, SOCK_STREAM, SOL_SOCKET, SO_RCVBUF, SO_SNDBUF,
    WSAECONNABORTED, WSAECONNRESET, WSAESHUTDOWN, WSAEWOULDBLOCK,
};

use super::backend::{ConnectError, NetBackend, ReadError, WriteError};
use super::PlatformSocket;
use super::write_virtio_net_hdr;

const FRAME_HEADER_LEN: usize = 4;

pub struct Unixstream {
    socket: RawSocket,
    expecting_frame_length: u32,
    last_partial_write_length: usize,
}

impl Unixstream {
    /// Wrap a pre-connected AF_UNIX stream socket.
    pub fn from_raw_socket(raw: RawSocket) -> Self {
        unsafe {
            let mut mode: u32 = 1;
            ioctlsocket(raw as usize, FIONBIO, &mut mode);

            let sndbuf: i32 = 16 * 1024 * 1024;
            setsockopt(
                raw as usize,
                SOL_SOCKET as i32,
                SO_SNDBUF as i32,
                &sndbuf as *const _ as *const _,
                std::mem::size_of::<i32>() as i32,
            );
        }

        Self {
            socket: raw,
            expecting_frame_length: 0,
            last_partial_write_length: 0,
        }
    }

    /// Connect to the gvproxy AF_UNIX stream socket at `path`.
    pub fn open(path: PathBuf) -> Result<Self, ConnectError> {
        utils::windows::ensure_wsa_init();

        unsafe {
            let sock = socket(AF_UNIX as i32, SOCK_STREAM, 0);
            if sock == INVALID_SOCKET {
                return Err(ConnectError::CreateSocket(io::Error::last_os_error()));
            }

            let mut addr: SOCKADDR_UN = std::mem::zeroed();
            addr.sun_family = AF_UNIX;

            let path_bytes = path.to_str().unwrap().as_bytes();
            for (i, &b) in path_bytes.iter().enumerate() {
                if i >= addr.sun_path.len() - 1 {
                    break;
                }
                addr.sun_path[i] = b as i8;
            }

            let res = connect(
                sock,
                &addr as *const _ as *const _,
                std::mem::size_of::<SOCKADDR_UN>() as i32,
            );

            if res == SOCKET_ERROR {
                return Err(ConnectError::Binding(io::Error::last_os_error()));
            }

            Ok(Self::from_raw_socket(sock as RawSocket))
        }
    }

    fn read_loop(&self, buf: &mut [u8], block_until_has_data: bool) -> Result<(), ReadError> {
        let mut bytes_read = 0;

        if !block_until_has_data {
            let res = unsafe {
                recv(
                    self.socket as _,
                    buf.as_mut_ptr() as *mut _,
                    buf.len() as i32,
                    0,
                )
            };
            if res > 0 {
                bytes_read += res as usize;
            } else if res == 0 {
                return Err(ReadError::NothingRead);
            } else {
                let err = unsafe { WSAGetLastError() };
                if err == WSAEWOULDBLOCK {
                    return Err(ReadError::NothingRead);
                }
                return Err(ReadError::Internal(io::Error::from_raw_os_error(err)));
            }
        }

        while bytes_read < buf.len() {
            let res = unsafe {
                recv(
                    self.socket as _,
                    buf[bytes_read..].as_mut_ptr() as *mut _,
                    (buf.len() - bytes_read) as i32,
                    0,
                )
            };

            if res > 0 {
                bytes_read += res as usize;
            } else if res == 0 {
                return Err(ReadError::NothingRead);
            } else {
                let err = unsafe { WSAGetLastError() };
                if err == WSAEWOULDBLOCK {
                    std::thread::yield_now();
                    continue;
                }
                return Err(ReadError::Internal(io::Error::from_raw_os_error(err)));
            }
        }
        Ok(())
    }

    fn write_loop(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let mut bytes_sent = 0;

        while bytes_sent < buf.len() {
            let res = unsafe {
                send(
                    self.socket as _,
                    buf[bytes_sent..].as_ptr() as *const _,
                    (buf.len() - bytes_sent) as i32,
                    0,
                )
            };

            if res > 0 {
                bytes_sent += res as usize;
            } else {
                let err = unsafe { WSAGetLastError() };
                if err == WSAEWOULDBLOCK {
                    if bytes_sent == 0 {
                        return Err(WriteError::NothingWritten);
                    } else {
                        self.last_partial_write_length += bytes_sent;
                        return Err(WriteError::PartialWrite);
                    }
                }
                if err == WSAECONNRESET || err == WSAECONNABORTED || err == WSAESHUTDOWN {
                    return Err(WriteError::ProcessNotRunning);
                }
                return Err(WriteError::Internal(io::Error::from_raw_os_error(err)));
            }
        }
        self.last_partial_write_length = 0;
        Ok(())
    }
}

impl NetBackend for Unixstream {
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        if self.expecting_frame_length == 0 {
            self.expecting_frame_length = {
                let mut frame_length_buf = [0u8; FRAME_HEADER_LEN];
                self.read_loop(&mut frame_length_buf, false)?;
                u32::from_be_bytes(frame_length_buf)
            };
        }

        let hdr_len = write_virtio_net_hdr(buf);
        let buf = &mut buf[hdr_len..];
        let frame_length = self.expecting_frame_length as usize;
        self.read_loop(&mut buf[..frame_length], false)?;
        self.expecting_frame_length = 0;

        Ok(hdr_len + frame_length)
    }

    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            panic!("Cannot write a frame while a partial write is not resolved.");
        }
        assert!(hdr_len >= FRAME_HEADER_LEN);

        let frame_length = buf.len() - hdr_len;
        buf[hdr_len - FRAME_HEADER_LEN..hdr_len]
            .copy_from_slice(&(frame_length as u32).to_be_bytes());

        self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN..])?;
        Ok(())
    }

    fn has_unfinished_write(&self) -> bool {
        self.last_partial_write_length != 0
    }

    fn try_finish_write(&mut self, hdr_len: usize, buf: &[u8]) -> Result<(), WriteError> {
        if self.last_partial_write_length != 0 {
            let already_written = self.last_partial_write_length;
            self.write_loop(&buf[hdr_len - FRAME_HEADER_LEN + already_written..])?;
        }
        Ok(())
    }

    fn raw_socket_fd(&self) -> PlatformSocket {
        self.socket
    }
}
