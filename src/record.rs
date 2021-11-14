use std::sync::atomic::{AtomicPtr, Ordering};

pub(crate) struct HazPtrRecord {
    pub(crate) ptr: AtomicPtr<()>,
    pub(crate) next: *mut HazPtrRecord,
    pub(crate) next_available: *mut HazPtrRecord,
}

impl HazPtrRecord {
    pub(crate) fn protect(&self, ptr: *mut ()) {
        self.ptr.store(ptr, Ordering::Release);
    }

    pub(crate) fn reset(&self) {
        self.ptr.store(std::ptr::null_mut(), Ordering::Release);
    }
}
