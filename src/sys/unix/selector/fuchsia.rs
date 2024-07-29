use std::{ffi::c_int, mem::MaybeUninit, os::fuchsia::zircon::RawHandle};
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use std::io;

use fuchsia_zircon_sys::{zx_deadline_after, zx_handle_close, zx_handle_duplicate, zx_handle_t, zx_object_wait_async, zx_port_cancel, zx_port_create, zx_port_packet_t, zx_port_wait, zx_status_t, ZX_OBJECT_READABLE, ZX_OBJECT_WRITABLE, ZX_OK, ZX_RIGHT_DUPLICATE, ZX_RIGHT_READ, ZX_RIGHT_SAME_RIGHTS, ZX_RIGHT_WRITE, ZX_TIME_INFINITE};

use crate::{Interest, Registry, Token};

pub type Event = zx_port_packet_t;
// TODO: Switch to an option or something
pub type Events = Vec<Event>;

trait ZxExt {
    fn zx_ok(self) -> Result<(), io::Error>;

    /// # Safety
    ///
    /// `ok` must be fully-initialized and contain a valid `T` if `self` is
    /// equal to `ZX_OK`.
    unsafe fn zx_unwrap<T>(self, ok: MaybeUninit<T>) -> Result<T, io::Error>;
}

impl ZxExt for zx_status_t {
    fn zx_ok(self) -> Result<(), io::Error> {
        if self == ZX_OK {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(self))
        }
    }

    unsafe fn zx_unwrap<T>(self, ok: MaybeUninit<T>) -> Result<T, io::Error> {
        self.zx_ok().map(|_| unsafe { ok.assume_init() })
    }
}

extern {
    fn fdio_get_service_handle(fd: c_int, out: *mut zx_handle_t) -> zx_status_t;
}

fn fd_to_raw_handle(fd: c_int) -> io::Result<zx_handle_t> {
    let mut handle = MaybeUninit::uninit();
    unsafe { fdio_get_service_handle(fd, handle.as_mut_ptr()).zx_unwrap(handle) }
}

/// Unique id for use as `SelectorId`.
#[cfg(debug_assertions)]
static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Debug)]
pub struct Selector {
    #[cfg(debug_assertions)]
    id: usize,
    pub(crate) port: zx_handle_t,
}

impl Selector {
    pub fn new() -> io::Result<Selector> {
        let mut port = MaybeUninit::uninit();
        Ok(Selector {
            #[cfg(debug_assertions)]
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            port: unsafe {
                zx_port_create(ZX_RIGHT_DUPLICATE | ZX_RIGHT_READ | ZX_RIGHT_WRITE, port.as_mut_ptr()).zx_unwrap(port)?
            },
        })
    }

    pub fn try_clone(&self) -> io::Result<Selector> {
        let mut port = MaybeUninit::uninit();
        let port = unsafe {
            zx_handle_duplicate(self.port, ZX_RIGHT_SAME_RIGHTS, port.as_mut_ptr()).zx_unwrap(port)?
        };
        Ok(Selector {
            // It's the same selector, so we use the same id.
            #[cfg(debug_assertions)]
            id: self.id,
            port,
        })
    }

    pub fn select(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        let deadline = timeout
            .map(|to| unsafe { zx_deadline_after(to.as_nanos() as i64) })
            .unwrap_or(ZX_TIME_INFINITE);

        events.clear();
        let mut packet = MaybeUninit::uninit();
        let packet = unsafe { zx_port_wait(self.port, deadline, packet.as_mut_ptr()).zx_unwrap(packet)? };
        events.push(packet);

        Ok(())
    }
}

cfg_io_source! {
    impl Selector {
        #[cfg(debug_assertions)]
        pub fn id(&self) -> usize {
            self.id
        }
    }
}

impl Drop for Selector {
    fn drop(&mut self) {
        unsafe {
            zx_handle_close(self.port).zx_ok().expect("error closing port")
        }
    }
}

pub mod event {
    use core::fmt;

    use fuchsia_zircon_sys::{zx_packet_signal_t, zx_signals_t};

    use crate::Token;

    use super::Event;

    fn signals(event: &Event) -> zx_signals_t {
        unsafe {
            event.union.as_ptr().cast::<zx_packet_signal_t>().read_unaligned().observed
        }
    }
    
    fn is_set(signals: &zx_signals_t, flag: &zx_signals_t) -> bool {
        *signals & *flag != 0
    }
    
    pub fn token(event: &Event) -> Token {
        Token(event.key as usize)
    }
    
    pub fn is_readable(event: &Event) -> bool {
        is_set(&signals(event), &fuchsia_zircon_sys::ZX_OBJECT_READABLE)
    }
    
    pub fn is_writable(event: &Event) -> bool {
        is_set(&signals(event), &fuchsia_zircon_sys::ZX_OBJECT_WRITABLE)
    }
    
    pub fn is_error(event: &Event) -> bool {
        event.status != fuchsia_zircon_sys::ZX_OK
    }
    
    pub fn is_read_closed(event: &Event) -> bool {
        is_set(&signals(event), &fuchsia_zircon_sys::ZX_OBJECT_PEER_CLOSED)
    }
    
    pub fn is_write_closed(event: &Event) -> bool {
        is_set(&signals(event), &fuchsia_zircon_sys::ZX_OBJECT_PEER_CLOSED)
    }
    
    pub fn is_priority(_: &Event) -> bool {
        false
    }

    pub fn is_aio(_: &Event) -> bool {
        false
    }

    pub fn is_lio(_: &Event) -> bool {
        false
    }

    pub fn debug_details(f: &mut fmt::Formatter<'_>, event: &Event) -> fmt::Result {
        debug_detail!(
            EventsDetails(zx_signals_t),
            is_set,
            fuchsia_zircon_sys::ZX_OBJECT_READABLE,
            fuchsia_zircon_sys::ZX_OBJECT_WRITABLE,
            fuchsia_zircon_sys::ZX_OBJECT_PEER_CLOSED,
        );
    
        f.debug_struct("epoll_event")
            .field("key", &event.key)
            .field("type", &event.packet_type)
            .field("signals", &EventsDetails(signals(event)))
            .field("union", &event.union)
            .finish()
    }
}

pub struct IoSourceState {
    key: u64,
}

impl IoSourceState {
    pub fn new() -> Self {
        Self {
            key: 0,
        }
    }

    pub fn do_io<T, F, R>(&self, f: F, io: &T) -> io::Result<R>
    where
        F: FnOnce(&T) -> io::Result<R>,
    {
        // We don't hold state, so we can just call the function and
        // return.
        f(io)
    }

    pub fn register(&mut self, registry: &Registry, token: Token, interests: Interest, handle: RawHandle) -> io::Result<()> {
        let mut signals = 0;
        if interests.is_readable() {
            signals |= ZX_OBJECT_READABLE;
        }
        if interests.is_writable() {
            signals |= ZX_OBJECT_WRITABLE;
        }

        self.key = token.0 as u64;

        unsafe {
            zx_object_wait_async(
                handle,
                registry.selector().port,
                token.0 as u64,
                signals,
                0,
            ).zx_ok()
        }
    }

    pub fn reregister(&mut self, registry: &Registry, token: Token, interests: Interest, handle: RawHandle) -> io::Result<()> {
        self.deregister(registry, handle)?;
        self.register(registry, token, interests, handle)
    }

    pub fn deregister(&mut self, registry: &Registry, handle: RawHandle) -> io::Result<()> {
        unsafe {
            zx_port_cancel(registry.selector().port, handle, self.key as u64).zx_ok()?;
        }
        self.key = 0;

        Ok(())
    }
}
