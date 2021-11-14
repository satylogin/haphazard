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

#[cfg(test)]
mod tests {
    use super::HazPtrRecord;
    use std::sync::atomic::{AtomicPtr, Ordering};

    fn new(ptr: *mut ()) -> HazPtrRecord {
        HazPtrRecord {
            ptr: AtomicPtr::new(ptr),
            next: std::ptr::null_mut(),
            next_available: std::ptr::null_mut(),
        }
    }

    #[test]
    fn test_protect() {
        let ptr = new(std::ptr::null_mut());
        let mut x: usize = 4;
        let y: *mut usize = &mut x;
        ptr.protect(y as *mut ());
        unsafe { assert_eq!(4, *(ptr.ptr.load(Ordering::Relaxed) as *mut usize)) };
    }

    #[test]
    fn test_reset() {
        let mut x: usize = 4;
        let y: *mut usize = &mut x;
        let ptr = new(y as *mut ());
        ptr.reset();
        assert!(ptr.ptr.load(Ordering::Relaxed).is_null());
    }
}
