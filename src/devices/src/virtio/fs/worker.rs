#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::thread;
#[cfg(windows)]
use utils::windows::AsRawFd;

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::{FsError, Queue};
use super::augment_fs::AugmentFs;
use super::descriptor_utils::{Reader, Writer};
use super::inode_alloc::InodeAllocator;
use super::null_fs::NullFs;
use super::passthrough::{self, PassthroughFs};
use super::read_only::PassthroughFsRo;
use super::server::Server;
use super::virtual_entry::VirtualDirEntry;
use crate::virtio::{InterruptTransport, VirtioShmRegion};

pub(super) enum FsServer {
    ReadWrite(Server<AugmentFs<PassthroughFs>>),
    ReadOnly(Server<AugmentFs<PassthroughFsRo>>),
    Null(Server<AugmentFs<NullFs>>),
}

impl FsServer {
    fn handle_message(
        &self,
        r: Reader,
        w: Writer,
        allow_idmap: bool,
        shm_region: &Option<VirtioShmRegion>,
        exit_code: &Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> super::Result<usize> {
        match self {
            FsServer::ReadWrite(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::ReadOnly(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::Null(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
        }
    }
}

/// Build the FUSE server shared by every queue worker of a device. Building
/// it once keeps the inode namespace (and the passthrough state behind it)
/// common to all request queues.
pub fn build_server(
    passthrough_cfg: Option<passthrough::Config>,
    read_only: bool,
    virtual_entries: Vec<VirtualDirEntry<'static>>,
) -> Result<Arc<FsServer>, io::Error> {
    let inode_alloc = Arc::new(InodeAllocator::new());
    let server = match passthrough_cfg {
        Some(cfg) if read_only => {
            let inner = PassthroughFsRo::new(cfg, inode_alloc.clone())?;
            FsServer::ReadOnly(Server::new(AugmentFs::new(
                inner,
                &inode_alloc,
                virtual_entries,
            )))
        }
        Some(cfg) => {
            let inner = PassthroughFs::new(cfg, inode_alloc.clone())?;
            FsServer::ReadWrite(Server::new(AugmentFs::new(
                inner,
                &inode_alloc,
                virtual_entries,
            )))
        }
        None => FsServer::Null(Server::new(AugmentFs::new(
            NullFs,
            &inode_alloc,
            virtual_entries,
        ))),
    };
    Ok(Arc::new(server))
}

/// A worker thread serving a single virtqueue of a virtio-fs device. Devices
/// advertise several request queues; the guest spreads requests across them
/// (by nodeid), and one worker per queue lets requests from different guest
/// tasks run concurrently instead of serializing behind a single thread.
pub struct FsWorker {
    server: Arc<FsServer>,
    queue: Queue,
    queue_evt: Arc<EventFd>,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    allow_idmap: bool,
    shm_region: Option<VirtioShmRegion>,
    stop_fd: EventFd,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
}

impl FsWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: Arc<FsServer>,
        queue: Queue,
        queue_evt: Arc<EventFd>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        allow_idmap: bool,
        shm_region: Option<VirtioShmRegion>,
        stop_fd: EventFd,
        exit_code: Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: Option<Sender<WorkerMessage>>,
    ) -> Self {
        Self {
            server,
            queue,
            queue_evt,
            interrupt,
            mem,
            allow_idmap,
            shm_region,
            stop_fd,
            exit_code,
            #[cfg(target_os = "macos")]
            map_sender,
        }
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("fs worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        utils::perf::init();

        let queue_ev_fd = self.queue_evt.as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();

        let mut epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            queue_ev_fd,
            &EpollEvent::new(EventSet::IN, queue_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == queue_ev_fd => {
                                self.handle_event();
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
                                return;
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    fn handle_event(&mut self) {
        debug!("Fs: queue event");
        if let Err(e) = self.queue_evt.read() {
            error!("Failed to get queue event: {e:?}");
        }

        loop {
            self.queue.disable_notification(&self.mem).unwrap();

            self.process_queue();

            if !self.queue.enable_notification(&self.mem).unwrap() {
                break;
            }
        }
    }

    fn process_queue(&mut self) {
        while let Some(head) = self.queue.pop(&self.mem) {
            let reader = Reader::new(&self.mem, head.clone())
                .map_err(FsError::QueueReader)
                .unwrap();
            let writer = Writer::new(&self.mem, head.clone())
                .map_err(FsError::QueueWriter)
                .unwrap();

            let handled_at = std::time::Instant::now();
            let len = match self.server.handle_message(
                reader,
                writer,
                self.allow_idmap,
                &self.shm_region,
                &self.exit_code,
                #[cfg(target_os = "macos")]
                &self.map_sender,
            ) {
                Ok(len) => len,
                Err(e) => {
                    error!("error handling message: {e:?}");
                    0
                }
            };
            utils::perf::inc(utils::perf::Counter::FsRequest);
            utils::perf::add(
                utils::perf::Counter::FsRequestNs,
                handled_at.elapsed().as_nanos() as u64,
            );

            if let Err(e) = self.queue.add_used(&self.mem, head.index, len as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }

            if self.queue.needs_notification(&self.mem).unwrap() {
                self.interrupt.signal_used_queue();
            }
        }
    }
}
