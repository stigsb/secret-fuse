//! Process hardening to protect secrets in memory.
//!
//! - mlockall: prevent memory from being swapped to disk
//! - Disable core dumps: prevent secrets from leaking via crash dumps
//! - Anti-ptrace: prevent same-user processes from reading our memory

use log::{info, warn};

/// Apply all available process hardening measures.
/// Failures are logged as warnings — hardening is best-effort.
pub fn harden_process() {
    lock_memory();
    disable_core_dumps();
    prevent_tracing();
}

/// Lock all current and future memory pages to prevent swapping.
fn lock_memory() {
    let result = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if result == 0 {
        info!("mlockall: memory locked (swap protection active)");
    } else {
        let err = std::io::Error::last_os_error();
        warn!("mlockall failed (secrets may be swapped to disk): {err}");
    }
}

/// Set RLIMIT_CORE to 0 to prevent core dump files.
fn disable_core_dumps() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let result = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) };
    if result == 0 {
        info!("core dumps disabled");
    } else {
        let err = std::io::Error::last_os_error();
        warn!("failed to disable core dumps: {err}");
    }
}

/// Prevent other processes from tracing/attaching to this process.
fn prevent_tracing() {
    #[cfg(target_os = "linux")]
    {
        // PR_SET_DUMPABLE=0 prevents ptrace attach from non-root
        let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if result == 0 {
            info!("ptrace protection active (PR_SET_DUMPABLE=0)");
        } else {
            let err = std::io::Error::last_os_error();
            warn!("failed to set PR_SET_DUMPABLE: {err}");
        }
    }

    #[cfg(target_os = "macos")]
    {
        // PT_DENY_ATTACH prevents debuggers from attaching
        let result = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if result == 0 {
            info!("ptrace protection active (PT_DENY_ATTACH)");
        } else {
            let err = std::io::Error::last_os_error();
            warn!("failed to set PT_DENY_ATTACH: {err}");
        }
    }
}
