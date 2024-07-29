use std::{io, os::fuchsia::zircon::RawHandle};

use crate::{event, io_source::IoSource, Interest, Registry, Token};

/// TODO
#[derive(Debug)]
pub struct SourceHandle {
    inner: IoSource<RawHandle>,
}

impl SourceHandle {
    /// Create a new `SourceHandle`.
    ///
    /// # Safety
    ///
    /// `SourceHandle` does not take ownership of the handle. It will not manage
    /// any lifecycle related operations, such as closing the handle on drop.
    pub unsafe fn new(handle: RawHandle) -> SourceHandle {
        SourceHandle {
            inner: IoSource::new(handle),
        }
    }
}

impl event::Source for SourceHandle {
    fn register(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.inner.register(registry, token, interests)
    }

    fn reregister(
        &mut self,
        registry: &Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        self.inner.reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &Registry) -> io::Result<()> {
        self.inner.deregister(registry)
    }
}
