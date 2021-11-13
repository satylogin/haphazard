use crate::record::HazPtrRecord;
use crate::{Domain, HazPtrObject};
use std::sync::atomic::{AtomicPtr, Ordering};

pub struct HazardPointer<'domain, F> {
    hazard: &'domain HazPtrRecord,
    domain: &'domain Domain<F>,
}

impl HazardPointer<'static, crate::Global> {
    pub fn make_global() -> Self {
        HazardPointer::make_in_domain(Domain::global())
    }
}

impl<'domain, F> HazardPointer<'domain, F> {
    pub fn make_in_domain(domain: &'domain Domain<F>) -> Self {
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
                    self.domain as *const Domain<F>,
                    r.domain() as *const Domain<F>,
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

impl<F> Drop for HazardPointer<'_, F> {
    fn drop(&mut self) {
        self.reset_protection();
        self.release();
    }
}
