pub trait Reclaim {}
impl<T> Reclaim for T {}

pub trait Deleter {
    /// # Safety
    ///
    /// The pointer must be valid, and post deletion should not be used.
    unsafe fn delete(&self, ptr: *mut dyn Reclaim);
}

impl Deleter for unsafe fn(*mut dyn Reclaim) {
    /// # Safety
    ///
    /// The pointer must be valid, and post deletion should not be used.
    unsafe fn delete(&self, ptr: *mut dyn Reclaim) {
        unsafe { (*self)(ptr) }
    }
}

/// # Safety
///
/// 1. The pointer must be valid, and post deletion should not be used.
/// 2. This should only be used for box types.
unsafe fn _drop_box(ptr: *mut dyn Reclaim) {
    // SAFETY: safe by function contract.
    unsafe { Box::from_raw(ptr) };
}

/// # Safety
///
/// 1. The pointer must be valid, and post deletion should not be used.
/// 2. This should only be used for box types.
#[allow(non_upper_case_globals)]
pub const drop_box: unsafe fn(*mut dyn Reclaim) = _drop_box;

/// # Safety
///
/// 1. The pointer must be valid, and post deletion should not be used.
unsafe fn _drop_in_place(ptr: *mut dyn Reclaim) {
    // SAFETY: safe by function contract.
    unsafe { std::ptr::drop_in_place(ptr) };
}

/// # Safety
///
/// 1. The pointer must be valid, and post deletion should not be used.
#[allow(non_upper_case_globals)]
pub const drop_in_place: unsafe fn(*mut dyn Reclaim) = _drop_in_place;
