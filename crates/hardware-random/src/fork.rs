//! Process fork detection support.
//!
//! On Unix targets a `pthread_atfork` child handler bumps a process-global
//! generation counter, so checking for a fork is an atomic load instead of a
//! `getpid` syscall per generated key. The handler also survives process-id
//! reuse (for example double-fork patterns), which a raw pid comparison does
//! not. Targets without `fork`, or processes where the handler cannot be
//! installed, fall back to process-id comparison in [`crate::ForkGuard`].

#![allow(unsafe_code)]

#[cfg(unix)]
pub(crate) use unix::generation;

/// Targets without `fork` have no fork generation to track.
#[cfg(not(unix))]
pub(crate) fn generation() -> Option<u64> {
    None
}

#[cfg(unix)]
mod unix {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    static FORK_GENERATION: AtomicU64 = AtomicU64::new(0);

    extern "C" fn bump_generation_in_child() {
        // Async-signal-safe: a single atomic read-modify-write with no
        // allocation or locking.
        FORK_GENERATION.fetch_add(1, Ordering::SeqCst);
    }

    /// Returns the current fork generation, installing the `pthread_atfork`
    /// child handler on first use. Returns `None` if the handler could not be
    /// installed; callers must then fall back to process-id checks.
    pub(crate) fn generation() -> Option<u64> {
        static INSTALLED: OnceLock<bool> = OnceLock::new();
        let installed = *INSTALLED.get_or_init(|| {
            // SAFETY: the child handler is async-signal-safe and stays valid
            // for the process lifetime.
            unsafe { libc::pthread_atfork(None, None, Some(bump_generation_in_child)) == 0 }
        });
        installed.then(|| FORK_GENERATION.load(Ordering::Acquire))
    }
}
