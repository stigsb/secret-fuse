//! macOS lock watcher — stub. Full implementation lands in Task 8.

use super::{LockConfig, Lockable};
use std::sync::Arc;

pub(super) struct MacWatcher;

impl MacWatcher {
    pub(super) fn start(_targets: Vec<Arc<dyn Lockable>>, _cfg: LockConfig) -> Option<Self> {
        log::warn!("auto_lock: macOS implementation pending — caches will only expire on TTL.");
        None
    }

    pub(super) fn stop(self) {}
}
