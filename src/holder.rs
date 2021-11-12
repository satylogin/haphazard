use crate::hazptr::HazPtr;
use crate::{HazPtrDomain, HazPtrObject};
use std::sync::atomic::{AtomicPtr, Ordering};

pub struct HazPtrHolder<'domain, F> {
    hazard: &'domain HazPtr,
    domain: &'domain HazPtrDomain<F>,
}

impl HazPtrHolder<'static, crate::Global> {
    pub fn global() -> Self {
        HazPtrHolder::for_domain(HazPtrDomain::global())
    }
}

impl<'domain, F> HazPtrHolder<'domain, F> {
    pub fn for_domain(domain: &'domain HazPtrDomain<F>) -> Self {
        Self {
            hazard: domain.acquire(),
            domain,
        }
    }

    unsafe fn try_protect<'l, 'o, T>(
        &'l self,
        expected: *mut T,
        src: &'_ AtomicPtr<T>,
    ) -> Result<Option<&'l T>, *mut T>
    where
        T: HazPtrObject<'o, F>,
        'o: 'l,
        F: 'static,
    {
        self.hazard.protect(expected as *mut ());
        crate::asymmetric_light_barrier();
        let actual = src.load(Ordering::Acquire);
        if expected == actual {
            Ok(std::ptr::NonNull::new(actual).map(|nn| {
                let r = unsafe { nn.as_ref() };
                debug_assert_eq!(
                    self.domain as *const HazPtrDomain<F>,
                    r.domain() as *const HazPtrDomain<F>,
                    "object guarded by different domain than holder used to access it."
                );
                r
            }))
        } else {
            self.hazard.reset();
            Err(actual)
        }
    }

    pub unsafe fn protect<'l, 'o, T>(&'l self, ptr: &'_ AtomicPtr<T>) -> Option<&'l T>
    where
        T: HazPtrObject<'o, F>,
        'o: 'l,
        F: 'static,
    {
        let mut expected = ptr.load(Ordering::Relaxed);
        loop {
            match unsafe { self.try_protect(expected, ptr) } {
                Ok(r) => break r,
                Err(actual) => expected = actual,
            }
        }
    }

    pub fn reset_protection(&self) {
        self.hazard.reset()
    }

    pub fn release(&self) {
        self.hazard.release();
    }
}

impl<F> Drop for HazPtrHolder<'_, F> {
    fn drop(&mut self) {
        self.reset_protection();
        self.release();
    }
}
