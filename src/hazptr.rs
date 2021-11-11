use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

pub(crate) struct HazPtr {
    pub(crate) ptr: AtomicPtr<()>,
    pub(crate) next: AtomicPtr<HazPtr>,
    pub(crate) active: AtomicBool,
}

impl HazPtr {
    pub(crate) fn protect(&self, ptr: *mut ()) {
        self.ptr.store(ptr, Ordering::SeqCst);
    }

    pub(crate) fn maybe_activate(&self) -> bool {
        self.active
            .compare_exchange_weak(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
}
