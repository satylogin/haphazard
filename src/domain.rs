use crate::deleter::{Deleter, Reclaim};
use crate::hazptr::HazPtr;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

#[non_exhaustive]
pub struct Global;
impl Global {
    const fn new() -> Self {
        Global
    }
}
static SHARED_DOMAIN: HazPtrDomain<Global> = HazPtrDomain::new(&Global::new());

pub struct HazPtrDomain<F> {
    hazptrs: HazPtrs,
    retired: RetiredList,
    family: PhantomData<F>,
}

impl HazPtrDomain<Global> {
    pub fn global() -> &'static Self {
        &SHARED_DOMAIN
    }
}

#[macro_export]
macro_rules! unique_domain {
    () => {
        HazPtrDomain::new(&|| {})
    };
}

impl<F> HazPtrDomain<F> {
    pub const fn new(_: &F) -> Self {
        Self {
            hazptrs: HazPtrs {
                head: AtomicPtr::new(std::ptr::null_mut()),
            },
            retired: RetiredList {
                head: AtomicPtr::new(std::ptr::null_mut()),
                count: AtomicUsize::new(0),
            },
            family: PhantomData,
        }
    }

    pub(crate) fn acquire(&self) -> &HazPtr {
        let head_ptr = &self.hazptrs.head;
        let mut node = head_ptr.load(Ordering::SeqCst);
        loop {
            while !node.is_null() && unsafe { &*node }.is_active() {
                node = unsafe { &*node }.next.load(Ordering::SeqCst);
            }
            if node.is_null() {
                break self.hazptrs.allocate();
            } else {
                let node = unsafe { &*node };
                if node.maybe_activate() {
                    break node;
                }
            }
        }
    }

    pub(crate) unsafe fn retire<'domain>(
        &'domain self,
        ptr: *mut (dyn Reclaim + 'domain),
        deleter: &'static dyn Deleter,
    ) {
        let retired = Box::into_raw(Box::new(unsafe { Retired::new(self, ptr, deleter) }));
        self.retired.push(retired);

        // TODO: better heuristics
        if self.retired.count.load(Ordering::SeqCst) != 0 {
            self.bulk_reclaim(false);
        }
    }

    pub fn eager_reclaim(&self, block: bool) -> usize {
        self.bulk_reclaim(block)
    }

    fn bulk_reclaim(&self, block: bool) -> usize {
        // TODO: add barrier here to ensure execution ordering.
        let mut reclaimed = 0;
        loop {
            let mut node = self.retired.steal();
            let protected = self.hazptrs.protected();
            let mut beg = std::ptr::null_mut();
            let mut end: *mut Retired = std::ptr::null_mut();
            while !node.is_null() {
                let n = unsafe { &mut *node };
                let next_node = n.next.load(Ordering::Relaxed);
                if protected.contains(&(n.ptr as *mut ())) {
                    n.next.store(beg, Ordering::Relaxed);
                    beg = node;
                    if end.is_null() {
                        end = beg;
                    }
                } else {
                    let n = unsafe { Box::from_raw(node) };
                    unsafe { n.deleter.delete(n.ptr) };
                    reclaimed += 1;
                }
                node = next_node;
            }
            if !beg.is_null() {
                self.retired.append(beg, end);
            }
            if !block || self.retired.is_empty() {
                break;
            }
            std::thread::yield_now();
        }
        self.retired.count.fetch_sub(reclaimed, Ordering::SeqCst);
        reclaimed
    }
}

struct HazPtrs {
    head: AtomicPtr<HazPtr>,
}

impl HazPtrs {
    /// Allocate a new HazPtr.
    fn allocate(&self) -> &'static HazPtr {
        let hazptr = Box::into_raw(Box::new(HazPtr {
            ptr: AtomicPtr::new(std::ptr::null_mut()),
            next: AtomicPtr::new(std::ptr::null_mut()),
            active: AtomicBool::new(true),
        }));
        self.push(hazptr)
    }

    /// Push a node at list head.
    fn push(&self, hazptr: *mut HazPtr) -> &'static HazPtr {
        assert!(!hazptr.is_null());
        let mut head = self.head.load(Ordering::SeqCst);
        loop {
            *unsafe { &mut *hazptr }.next.get_mut() = head;
            match self
                .head
                .compare_exchange_weak(head, hazptr, Ordering::SeqCst, Ordering::Relaxed)
            {
                Ok(_) => break unsafe { &*hazptr },
                Err(new_head) => head = new_head,
            }
        }
    }

    /// Fetch all HazPtr which are active.
    fn protected(&self) -> HashSet<*mut ()> {
        let mut protected = HashSet::new();
        let mut node = self.head.load(Ordering::SeqCst);
        while !node.is_null() {
            let n = unsafe { &*node };
            if n.is_active() {
                protected.insert(n.ptr.load(Ordering::SeqCst));
            }
            node = n.next.load(Ordering::SeqCst);
        }
        protected
    }
}

impl Drop for HazPtrs {
    fn drop(&mut self) {
        let mut node = *self.head.get_mut();
        while !node.is_null() {
            let mut ptr = unsafe { Box::from_raw(node) };
            node = *ptr.next.get_mut();
        }
    }
}

impl<F> Drop for HazPtrDomain<F> {
    fn drop(&mut self) {
        let n_retired = *self.retired.count.get_mut();
        let n_reclaimed = self.eager_reclaim(false);
        debug_assert_eq!(n_retired, n_reclaimed);
        debug_assert!(self.retired.head.get_mut().is_null());
    }
}

struct Retired {
    // pointer to data that HazPtr protectes
    // This is 'domain which is enforced anything that constructs a Retired.
    ptr: *mut dyn Reclaim,
    deleter: &'static dyn Deleter,
    next: AtomicPtr<Retired>,
}

impl Retired {
    /// # Safety
    ///
    /// `ptr` will not be accessed after `'domain` ends.
    unsafe fn new<'domain, F>(
        _: &'domain HazPtrDomain<F>,
        ptr: *mut (dyn Reclaim + 'domain),
        deleter: &'static dyn Deleter,
    ) -> Self {
        Retired {
            ptr: unsafe { std::mem::transmute::<_, *mut (dyn Reclaim + 'static)>(ptr) },
            deleter,
            next: AtomicPtr::default(),
        }
    }
}

struct RetiredList {
    head: AtomicPtr<Retired>,
    count: AtomicUsize,
}

impl RetiredList {
    fn is_empty(&self) -> bool {
        self.head.load(Ordering::SeqCst).is_null()
    }

    fn push(&self, retired: *mut Retired) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.append(retired, retired);
    }

    // This does not alter count, and should be taken care by the caller.
    fn append(&self, beg: *mut Retired, end: *mut Retired) {
        assert!(!beg.is_null());
        assert!(!end.is_null());
        let mut head = self.head.load(Ordering::SeqCst);
        loop {
            *unsafe { &mut *end }.next.get_mut() = head;
            match self
                .head
                .compare_exchange_weak(head, beg, Ordering::SeqCst, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(new_head) => head = new_head,
            }
        }
    }

    // This does not decrease count due to race condition.
    fn steal(&self) -> *mut Retired {
        self.head.swap(std::ptr::null_mut(), Ordering::SeqCst)
    }
}

#[allow(dead_code)]
/// ```compile_fail
///  use std::sync::atomic::AtomicPtr;
///  use haphazard::*;
///
///  let dw = HazPtrDomain::global();
///  let dr = HazPtrDomain::new(&());
///
///  let x = AtomicPtr::new(Box::into_raw(Box::new(HazPtrObjectWrapper::with_domain(&dw, 42))));
///
///  let mut h = HazPtrHolder::for_domain(&dr);
///
///  let _ = unsafe { h.load(&x) }.unwrap();
/// ```
struct GlobalWriterLocalReaderShouldNotCompile;

#[allow(dead_code)]
/// ```compile_fail
///  use std::sync::atomic::AtomicPtr;
///  use haphazard::*;
///
///  let dw = HazPtrDomain::new(&());
///  let dr = HazPtrDomain::global();
///
///  let x = AtomicPtr::new(Box::into_raw(Box::new(HazPtrObjectWrapper::with_domain(&dw, 42))));
///
///  let mut h = HazPtrHolder::for_domain(&dr);
///
///  let _ = unsafe { h.load(&x) }.unwrap();
/// ```
struct GlobalReaderLocalWriterShouldNotCompile;

#[allow(dead_code)]
/// ```compile_fail
///  use std::sync::atomic::AtomicPtr;
///  use haphazard::*;
///
///  let dw = unique_domain!();
///  let dr = unique_domain!();
///
///  let x = AtomicPtr::new(Box::into_raw(Box::new(HazPtrObjectWrapper::with_domain(&dw, 42))));
///
///  let mut h = HazPtrHolder::for_domain(&dr);
///
///  let _ = unsafe { h.load(&x) }.unwrap();
/// ```
struct DomainWithDifferentFamilyShouldNotCompile;
