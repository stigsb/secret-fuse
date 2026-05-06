//! Auto-lock watcher: wipes registered cache targets on screen lock / system sleep.
//!
//! macOS implementation lives in `mac.rs`; other platforms get a no-op stub.

use std::sync::Arc;

pub trait Lockable: Send + Sync {
    fn on_lock(&self);
}

#[derive(Debug, Clone, Copy)]
pub struct LockConfig {
    pub on_screen_lock: bool,
    pub on_sleep: bool,
}

#[cfg(target_os = "macos")]
mod mac;

pub struct LockWatcher {
    #[cfg(target_os = "macos")]
    inner: Option<mac::MacWatcher>,
    #[cfg(not(target_os = "macos"))]
    _phantom: (),
}

impl LockWatcher {
    #[allow(clippy::needless_return)]
    pub fn spawn(targets: Vec<Arc<dyn Lockable>>, cfg: LockConfig) -> Self {
        #[cfg(target_os = "macos")]
        {
            let inner = mac::MacWatcher::start(targets, cfg);
            return LockWatcher { inner };
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = (targets, cfg);
            log::warn!(
                "auto_lock: not supported on this platform yet (macOS-only); per-secret TTL still applies."
            );
            LockWatcher { _phantom: () }
        }
    }

    pub fn shutdown(self) {
        #[cfg(target_os = "macos")]
        if let Some(inner) = self.inner {
            inner.stop();
        }
    }
}
