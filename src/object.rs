use crate::deleter::{Deleter, Reclaim};
use crate::domain::Domain;
use std::ops::{Deref, DerefMut};

pub trait HazPtrObject<'domain, F>
where
    Self: Sized + 'domain,
    F: 'static,
{
    fn domain(&self) -> &'domain Domain<F>;

    unsafe fn retire(self: *mut Self, deleter: &'static dyn Deleter) -> isize {
        let ptr = self as *mut (dyn Reclaim + 'domain);
        unsafe { (&*self).domain().retire(ptr, deleter) }
    }
}

pub struct HazPtrObjectWrapper<'domain, T, F> {
    inner: T,
    domain: &'domain Domain<F>,
}

impl<T, F> Deref for HazPtrObjectWrapper<'_, T, F> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T, F> DerefMut for HazPtrObjectWrapper<'_, T, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'domain, T: 'domain, F: 'static> HazPtrObject<'domain, F>
    for HazPtrObjectWrapper<'domain, T, F>
{
    fn domain(&self) -> &'domain Domain<F> {
        self.domain
    }
}

impl<T> HazPtrObjectWrapper<'static, T, crate::Global> {
    pub fn with_global_domain(t: T) -> Self {
        HazPtrObjectWrapper::with_domain(Domain::global(), t)
    }
}

impl<'domain, T, F> HazPtrObjectWrapper<'domain, T, F> {
    pub fn with_domain(domain: &'domain Domain<F>, t: T) -> Self {
        Self { inner: t, domain }
    }
}
