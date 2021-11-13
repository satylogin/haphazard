use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

pub(crate) struct HazPtrRecord {
    pub(crate) ptr: AtomicPtr<()>,
    pub(crate) next: *mut HazPtrRecord,
    pub(crate) active: AtomicBool,
}

impl HazPtrRecord {
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

    pub(crate) fn reset(&self) {
        self.ptr.store(std::ptr::null_mut(), Ordering::Release);
    }

    pub(crate) fn release(&self) {
        self.active.store(false, Ordering::Release);
    }
}
