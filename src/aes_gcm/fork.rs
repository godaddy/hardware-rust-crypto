//! Process fork detection for nonce-salt re-randomization.
//!
//! On Unix a `pthread_atfork` child handler bumps a process-global generation
//! counter, so detecting a fork is an atomic load rather than a `getpid`
//! syscall per nonce. The handler also survives process-id reuse. Targets
//! without `fork`, or processes where the handler cannot be installed, fall
//! back to process-id comparison.

#![allow(unsafe_code)]

/// Snapshot used to detect that generator state has crossed a process fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForkGuard {
    /// Fork-generation snapshot maintained by a `pthread_atfork` child handler.
    Generation(u64),
    /// Fallback: process-id snapshot compared via `getpid`.
    ProcessId(u32),
}

impl ForkGuard {
    pub(crate) fn capture() -> Self {
        generation().map_or_else(|| Self::ProcessId(current_process_id()), Self::Generation)
    }

    /// Returns true if no fork has been observed since `self` was captured.
    pub(crate) fn unchanged(self) -> bool {
        match self {
            Self::Generation(seen) => generation() == Some(seen),
            Self::ProcessId(seen) => current_process_id() == seen,
        }
    }
}

fn current_process_id() -> u32 {
    std::process::id()
}

#[cfg(all(unix, not(hax)))]
fn generation() -> Option<u64> {
    use core::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    static FORK_GENERATION: AtomicU64 = AtomicU64::new(0);

    extern "C" fn bump_generation_in_child() {
        // Async-signal-safe: a single atomic read-modify-write.
        FORK_GENERATION.fetch_add(1, Ordering::SeqCst);
    }

    static INSTALLED: OnceLock<bool> = OnceLock::new();
    let installed = *INSTALLED.get_or_init(|| {
        // SAFETY: the child handler is async-signal-safe and stays valid for
        // the process lifetime.
        unsafe { libc::pthread_atfork(None, None, Some(bump_generation_in_child)) == 0 }
    });
    installed.then(|| FORK_GENERATION.load(Ordering::Acquire))
}

// Under hax/F* extraction only: the `pthread_atfork` function pointer is outside
// hax's importable subset, and a runtime fork is not modeled by an extraction
// proof regardless. Fall back to the process-id path so the importer proceeds.
#[cfg(all(unix, hax))]
fn generation() -> Option<u64> {
    None
}

#[cfg(not(unix))]
fn generation() -> Option<u64> {
    None
}
