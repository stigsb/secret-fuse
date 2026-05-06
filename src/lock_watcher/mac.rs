//! macOS lock watcher. Listens for screen lock and system sleep on a
//! dedicated `CFRunLoop` thread and dispatches `Lockable::on_lock()`.

use super::{LockConfig, Lockable};
use core_foundation::base::TCFType;
use core_foundation::runloop::{CFRunLoop, CFRunLoopSourceRef, kCFRunLoopDefaultMode};
use core_foundation::string::CFStringRef;
use log::{info, warn};
use std::ffi::c_void;
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

// ─── CFNotificationCenter FFI ─────────────────────────────────────────────────

type CFNotificationCenterRef = *mut c_void;
type CFNotificationCallback = unsafe extern "C" fn(
    center: CFNotificationCenterRef,
    observer: *mut c_void,
    name: CFStringRef,
    object: *const c_void,
    user_info: *const c_void,
);

const CF_NOTIFICATION_DELIVER_IMMEDIATELY: u32 = 4;

unsafe extern "C" {
    fn CFNotificationCenterGetDistributedCenter() -> CFNotificationCenterRef;
    fn CFNotificationCenterAddObserver(
        center: CFNotificationCenterRef,
        observer: *const c_void,
        callback: CFNotificationCallback,
        name: CFStringRef,
        object: *const c_void,
        suspension_behavior: u32,
    );
    fn CFNotificationCenterRemoveEveryObserver(
        center: CFNotificationCenterRef,
        observer: *const c_void,
    );
}

// ─── IOKit power-management FFI ───────────────────────────────────────────────

#[allow(non_camel_case_types)]
type io_object_t = u32;
#[allow(non_camel_case_types)]
type io_connect_t = u32;
#[allow(non_camel_case_types)]
type io_service_t = u32;
type IONotificationPortRef = *mut c_void;
type IOServiceInterestCallback = unsafe extern "C" fn(
    refcon: *mut c_void,
    service: io_service_t,
    message_type: u32,
    message_argument: *mut c_void,
);

const K_IO_MESSAGE_SYSTEM_WILL_SLEEP: u32 = 0xE0000280;

#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IORegisterForSystemPower(
        refcon: *mut c_void,
        the_port_ref: *mut IONotificationPortRef,
        callback: IOServiceInterestCallback,
        notifier: *mut io_object_t,
    ) -> io_connect_t;
    fn IODeregisterForSystemPower(notifier: *mut io_object_t) -> i32;
    fn IONotificationPortGetRunLoopSource(
        notify: IONotificationPortRef,
    ) -> CFRunLoopSourceRef;
    fn IONotificationPortDestroy(notify: IONotificationPortRef);
    fn IOAllowPowerChange(kernel_port: io_connect_t, notification_id: isize) -> i32;
}

// ─── RAII guard for IOKit power registration ─────────────────────────────────

/// Deregisters and destroys the IOKit notification port on drop, ensuring the
/// kernel resource is released even on panic.
struct IoPowerGuard {
    port: IONotificationPortRef,
    notifier: io_object_t,
}

impl Drop for IoPowerGuard {
    fn drop(&mut self) {
        if !self.port.is_null() {
            unsafe {
                IODeregisterForSystemPower(&mut self.notifier);
                IONotificationPortDestroy(self.port);
            }
        }
    }
}

// ─── Watcher ──────────────────────────────────────────────────────────────────

/// Heap-allocated context shared between observer callbacks and the runloop thread.
struct Context {
    targets: Vec<Arc<dyn Lockable>>,
    root_port: io_connect_t,
}

impl Context {
    fn dispatch(&self) {
        for t in &self.targets {
            t.on_lock();
        }
    }
}

pub(super) struct MacWatcher {
    runloop: CFRunLoop,
    thread: Option<thread::JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
}

impl Drop for MacWatcher {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.runloop.stop();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl MacWatcher {
    pub(super) fn start(
        targets: Vec<Arc<dyn Lockable>>,
        cfg: LockConfig,
    ) -> Option<Self> {
        if !cfg.on_screen_lock && !cfg.on_sleep {
            return None;
        }

        let (tx, rx) = std::sync::mpsc::channel::<CFRunLoop>();
        let stopping = Arc::new(AtomicBool::new(false));
        let stopping_thread = Arc::clone(&stopping);

        let thread = thread::Builder::new()
            .name("secret-fuse-lock-watcher".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Self::thread_main(targets, cfg, &stopping_thread, tx);
                }));
                if let Err(e) = result {
                    warn!("lock watcher thread panicked: {e:?}; falling back to TTL");
                }
            })
            .ok()?;

        let runloop = rx.recv_timeout(std::time::Duration::from_secs(2)).ok()?;

        info!("auto_lock: macOS lock watcher started");
        Some(MacWatcher {
            runloop,
            thread: Some(thread),
            stopping,
        })
    }

    fn thread_main(
        targets: Vec<Arc<dyn Lockable>>,
        cfg: LockConfig,
        stopping: &AtomicBool,
        runloop_tx: std::sync::mpsc::Sender<CFRunLoop>,
    ) {
        let context = Box::new(Context {
            targets,
            root_port: 0,
        });
        let context_ptr: *mut Context = Box::into_raw(context);

        // ─ Screen-lock observer ─
        if cfg.on_screen_lock {
            unsafe {
                let center = CFNotificationCenterGetDistributedCenter();
                if center.is_null() {
                    warn!("auto_lock: CFNotificationCenter unavailable; screen-lock disabled");
                } else {
                    // Build the CFStringRef for the notification name inline.
                    // We use the static C string to avoid lifetime issues.
                    use core_foundation::string::CFString;
                    let name = CFString::from_static_string("com.apple.screenIsLocked");
                    CFNotificationCenterAddObserver(
                        center,
                        context_ptr as *const c_void,
                        screen_locked_callback,
                        name.as_concrete_TypeRef(),
                        ptr::null(),
                        CF_NOTIFICATION_DELIVER_IMMEDIATELY,
                    );
                }
            }
        }

        // ─ Sleep observer ─
        let mut io_notify: IONotificationPortRef = ptr::null_mut();
        let mut io_notifier: io_object_t = 0;
        // RAII guard: deregisters/destroys IOKit port on drop (including panics).
        let _io_guard: Option<IoPowerGuard>;
        if cfg.on_sleep {
            unsafe {
                let root_port = IORegisterForSystemPower(
                    context_ptr as *mut c_void,
                    &mut io_notify,
                    sleep_callback,
                    &mut io_notifier,
                );
                if root_port == 0 {
                    warn!("auto_lock: IORegisterForSystemPower failed; sleep wipe disabled");
                    _io_guard = None;
                } else {
                    (*context_ptr).root_port = root_port;
                    // Bind the guard immediately after successful registration so
                    // the kernel resource is freed even if we panic before run_current.
                    _io_guard = Some(IoPowerGuard {
                        port: io_notify,
                        notifier: io_notifier,
                    });
                    let source = IONotificationPortGetRunLoopSource(io_notify);
                    if !source.is_null() {
                        // Use the safe wrapper: wrap source under get rule so
                        // core-foundation manages retain/release, then add via
                        // the high-level CFRunLoop::add_source method.
                        use core_foundation::runloop::CFRunLoopSource;
                        let cf_source: CFRunLoopSource =
                            TCFType::wrap_under_get_rule(source);
                        let rl = CFRunLoop::get_current();
                        rl.add_source(&cf_source, kCFRunLoopDefaultMode);
                        // cf_source drops here — that's OK; IOKit retains the source
                        // independently. We must NOT release it extra since we used
                        // wrap_under_get_rule (non-owning).
                    }
                }
            }
        } else {
            _io_guard = None;
        }

        // Send our runloop handle back to the parent.
        let runloop = CFRunLoop::get_current();
        let _ = runloop_tx.send(runloop);

        // Guard against the race where stop() is called before we reach
        // run_current(): CFRunLoopStop has no pending-stop flag, so calling it
        // on a not-yet-running runloop is a no-op and run_current() would block
        // forever. Check the flag here, after sending the handle, so stop() can
        // reliably set it and know we will see it.
        if !stopping.load(Ordering::SeqCst) {
            // Drive the runloop. Returns when CFRunLoopStop is called from
            // shutdown(), or when the runloop exhausts sources.
            CFRunLoop::run_current();
        }

        // ─ Tear down ─
        if cfg.on_screen_lock {
            unsafe {
                let center = CFNotificationCenterGetDistributedCenter();
                if !center.is_null() {
                    CFNotificationCenterRemoveEveryObserver(center, context_ptr as *const c_void);
                }
            }
        }
        // IOKit resources are cleaned up by _io_guard's Drop impl above.

        // Reclaim the context.
        let _ = unsafe { Box::from_raw(context_ptr) };
    }

    pub(super) fn stop(self) {
        info!("auto_lock: macOS lock watcher stopped");
        // Drop fires here, which sets stopping=true, calls runloop.stop(),
        // and joins the thread.
    }
}

unsafe extern "C" fn screen_locked_callback(
    _center: CFNotificationCenterRef,
    observer: *mut c_void,
    _name: CFStringRef,
    _object: *const c_void,
    _user_info: *const c_void,
) {
    if observer.is_null() {
        return;
    }
    let ctx = unsafe { &*(observer as *const Context) };
    log::info!("auto_lock: screen locked — wiping caches");
    ctx.dispatch();
}

unsafe extern "C" fn sleep_callback(
    refcon: *mut c_void,
    _service: io_service_t,
    message_type: u32,
    message_argument: *mut c_void,
) {
    if refcon.is_null() {
        return;
    }
    let ctx = unsafe { &*(refcon as *const Context) };
    if message_type == K_IO_MESSAGE_SYSTEM_WILL_SLEEP {
        log::info!("auto_lock: system will sleep — wiping caches");
        ctx.dispatch();
        unsafe {
            IOAllowPowerChange(ctx.root_port, message_argument as isize);
        }
    }
}
