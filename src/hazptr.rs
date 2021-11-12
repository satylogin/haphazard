use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

pub(crate) struct HazPtr {
    pub(crate) ptr: AtomicPtr<()>,
    pub(crate) next: *mut HazPtr,
    pub(crate) active: AtomicBool,
}

impl HazPtr {
    pub(crate) fn protect(&self, ptr: *mut ()) {
        self.ptr.store(ptr, Ordering::Release);
    }

    pub(crate) fn maybe_activate(&self) -> bool {
        !self.is_active()
            && self
                .active
                .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)
                .is_ok()
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
}
