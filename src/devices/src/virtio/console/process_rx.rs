use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
#[cfg(not(windows))]
use std::io;
use std::thread;

use vm_memory::{GuestMemoryBackend, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion};
#[cfg(windows)]
use vm_memory::bitmap::Bitmap;

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::port_io::PortInput;
use crate::virtio::{DescriptorChain, InterruptTransport, Queue};

#[allow(clippy::too_many_arguments)]
pub(crate) fn process_rx(
    mem: GuestMemoryMmap,
    mut queue: Queue,
    interrupt: InterruptTransport,
    input: Arc<Mutex<Box<dyn PortInput + Send>>>,
    control: Arc<ConsoleControl>,
    port_id: u32,
    stopfd: utils::eventfd::EventFd,
    stop: Arc<AtomicBool>,
) {
    let mem = &mem;
    let mut eof = false;

    let mut input = input.lock().unwrap();
    loop {
        let Some(head) = pop_head_blocking(&mut queue, mem, &interrupt, &stop) else {
            return;
        };

        let head_index = head.index;
        let mut bytes_read = 0;
        for chain in head.into_iter().writable() {
            log::debug!(
                "console port {port_id}: reading descriptor {} ({} bytes)",
                chain.index,
                chain.len
            );
            match read_to_desc(chain, input.as_mut(), &mut eof) {
                Ok(0) => {
                    log::debug!("console port {port_id}: descriptor read returned zero bytes");
                    break;
                }
                Ok(len) => {
                    log::debug!("console port {port_id}: descriptor read returned {len} bytes");
                    bytes_read += len;
                }
                Err(e) => {
                    log::error!("Failed to read: {e:?}")
                }
            }
        }

        if bytes_read != 0 {
            log::debug!(
                "console port {port_id}: completing descriptor {head_index} with {bytes_read} bytes"
            );
            if let Err(e) = queue.add_used(mem, head_index, bytes_read as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            } else {
                log::debug!("console port {port_id}: RX descriptor completed");
            }
            #[cfg(target_os = "windows")]
            // Windows ReadFile blocks instead of returning WouldBlock, so the
            // guest has not received the wakeup sent by the polling path below.
            match interrupt.try_signal_used_queue() {
                Ok(()) => log::trace!("console port {port_id}: notified guest of {bytes_read} input bytes"),
                Err(e) => log::error!("console port {port_id}: failed to notify guest of input: {e:?}"),
            }
        }

        // We signal_used_queue only when we get WouldBlock or EOF
        if eof {
            interrupt.signal_used_queue();
            log::trace!("signaling EOF on port {port_id}");
            control.port_open(port_id, false);
            return;
        } else if bytes_read == 0 {
            queue.undo_pop();
            interrupt.signal_used_queue();
            input.wait_until_readable(Some(&stopfd));
        }

        if stop.load(Ordering::Acquire) {
            return;
        }
    }
}

fn pop_head_blocking<'mem>(
    queue: &mut Queue,
    mem: &'mem GuestMemoryMmap,
    interrupt: &InterruptTransport,
    stop: &AtomicBool,
) -> Option<DescriptorChain<'mem>> {
    loop {
        match queue.pop(mem) {
            Some(descriptor) => break Some(descriptor),
            None => {
                interrupt.signal_used_queue();
                if stop.load(Ordering::Acquire) {
                    break None;
                }
                thread::park();
                log::trace!("rx unparked, queue len {}", queue.len(mem))
            }
        }
    }
}

#[cfg(not(windows))]
fn read_to_desc(
    desc: DescriptorChain,
    input: &mut (dyn PortInput + Send),
    eof: &mut bool,
) -> Result<usize, GuestMemoryError> {
    // TODO: Switch to using `get_slices()` with the next vm-memory
    //       bump.
    #[allow(deprecated)]
    desc.mem
        .try_access(desc.len as usize, desc.addr, |_, len, addr, region| {
            let mut target = region.get_slice(addr, len).unwrap();
            match input.read_volatile(&mut target) {
                Ok(n) => {
                    if n == 0 {
                        *eof = true
                    }
                    Ok(n)
                }
                // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(0),
                Err(e) => Err(GuestMemoryError::IOError(e)),
            }
        })
}

#[cfg(windows)]
fn read_to_desc(
    desc: DescriptorChain,
    input: &mut (dyn PortInput + Send),
    eof: &mut bool,
) -> Result<usize, GuestMemoryError> {
    // Do not block in ReadFile while holding a guest-memory slice. WHP vCPUs
    // can need that same memory access to progress the console queue.
    let mut host_buf = vec![0; desc.len as usize];
    let bytes_read = input.read_bytes(&mut host_buf).map_err(GuestMemoryError::IOError)?;
    if bytes_read == 0 {
        *eof = true;
        return Ok(0);
    }

    let mut copied = 0;
    desc.mem
        .try_access(desc.len as usize, desc.addr, |_, len, addr, region| {
            let mut target = region.get_slice(addr, len).unwrap();
            let count = (bytes_read - copied).min(len);
            let guard = target.ptr_guard_mut();
            unsafe {
                std::ptr::copy_nonoverlapping(host_buf[copied..].as_ptr(), guard.as_ptr(), count);
            }
            target.bitmap().mark_dirty(0, count);
            copied += count;
            Ok(count)
        })
}
