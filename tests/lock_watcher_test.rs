use secret_fuse::lock_watcher::Lockable;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingTarget(AtomicUsize);

impl Lockable for CountingTarget {
    fn on_lock(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn test_on_lock_dispatches_to_target() {
    let t = Arc::new(CountingTarget(AtomicUsize::new(0)));
    let dyn_t: Arc<dyn Lockable> = t.clone();
    dyn_t.on_lock();
    assert_eq!(t.0.load(Ordering::SeqCst), 1);
}

#[test]
fn test_lock_watcher_spawn_and_shutdown_on_unsupported_platform_is_noop() {
    use secret_fuse::lock_watcher::{LockConfig, LockWatcher};
    let target: Arc<dyn Lockable> = Arc::new(CountingTarget(AtomicUsize::new(0)));
    let watcher = LockWatcher::spawn(
        vec![target.clone()],
        LockConfig {
            on_screen_lock: true,
            on_sleep: true,
        },
    );
    watcher.shutdown();
    // No assertion on count — on macOS this returns without firing events,
    // on Linux it's a no-op stub.
}
