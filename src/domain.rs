use crate::deleter::{Deleter, Reclaim};
use crate::hazptr::HazPtr;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicPtr, AtomicU64, Ordering};
use std::time::Duration;

const RECLAIM_TIME_PERIOD: u64 = Duration::from_nanos(2000000000).as_nanos() as u64;
const RCOUNT_THRESHOLD: isize = 1000;
const HCOUNT_MULTIPLIER: isize = 2;

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
    next_reclaim_time: AtomicU64,
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
                count: AtomicIsize::new(0),
            },
            retired: RetiredList {
                head: AtomicPtr::new(std::ptr::null_mut()),
                count: AtomicIsize::new(0),
            },
            family: PhantomData,
            next_reclaim_time: AtomicU64::new(0),
        }
    }

    pub(crate) fn acquire(&self) -> &HazPtr {
        match self.hazptrs.acquire_existing() {
            Some(hazptr) => hazptr,
            None => self.hazptrs.allocate(), // No existing free pointer.
        }
    }

    pub(crate) unsafe fn retire<'domain>(
        &'domain self,
        ptr: *mut (dyn Reclaim + 'domain),
        deleter: &'static dyn Deleter,
    ) {
        let retired = Box::into_raw(Box::new(unsafe { Retired::new(self, ptr, deleter) }));
        self.retired.push(retired);
        if self.is_time_to_reclaim() || self.reached_threshold() {
            self.eager_reclaim(false);
        }
    }

    fn is_time_to_reclaim(&self) -> bool {
        use std::convert::TryFrom;

        let time = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time is set to before the epoc")
                .as_nanos(),
        )
        .expect("system time is too far in future");
        let next_reclaim_time = self.next_reclaim_time.load(Ordering::Relaxed);

        time > next_reclaim_time
            && self
                .next_reclaim_time
                .compare_exchange(
                    next_reclaim_time,
                    time + RECLAIM_TIME_PERIOD,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
    }

    fn reached_threshold(&self) -> bool {
        let rc = self.retired.count();
        rc >= RCOUNT_THRESHOLD || rc >= self.hazptrs.count() * HCOUNT_MULTIPLIER
    }

    pub fn eager_reclaim(&self, transitive: bool) -> isize {
        let mut reclaimed = 0;
        loop {
            let steal = self.retired.steal();
            if steal.is_null() {
                break;
            }
            crate::asymmetric_heavy_barrier(crate::HeavyBarrierKind::Expedited);
            let protected = self.hazptrs.protected();
            reclaimed += self.bulk_lookup_and_reclaim(steal, protected);
            if self.retired.is_empty() || !transitive {
                break;
            }
            std::thread::yield_now();
        }

        self.retired.count.fetch_sub(reclaimed, Ordering::Release);
        reclaimed
    }

    fn bulk_lookup_and_reclaim(
        &self,
        mut node: *mut Retired,
        protected: HashSet<*mut ()>,
    ) -> isize {
        let mut reclaimed = 0;
        let mut beg = std::ptr::null_mut();
        let mut end: *mut Retired = std::ptr::null_mut();
        while !node.is_null() {
            let n = unsafe { &mut *node };
            let next_node = n.next;
            debug_assert_ne!(node, next_node);
            if !protected.contains(&(n.ptr as *mut ())) {
                let n = unsafe { Box::from_raw(node) };
                unsafe { n.deleter.delete(n.ptr) };
                reclaimed += 1;
                // TODO: support linked nodes for efficient deallocation.
            } else {
                n.next = beg;
                beg = node;
                if end.is_null() {
                    end = beg;
                }
            }
            node = next_node;
        }
        if !beg.is_null() {
            self.retired.append(beg, end);
        }
        reclaimed
    }
}

struct HazPtrs {
    head: AtomicPtr<HazPtr>,
    count: AtomicIsize,
}

impl HazPtrs {
    fn count(&self) -> isize {
        self.count.load(Ordering::Acquire)
    }

    fn acquire_existing(&self) -> Option<&HazPtr> {
        let mut node = self.head.load(Ordering::Acquire);
        while !node.is_null() {
            // Try to acquire existing.
            let n = unsafe { &*node };
            if n.maybe_activate() {
                return Some(n);
            }
            node = n.next;
        }
        None
    }

    /// Allocate a new HazPtr.
    fn allocate(&self) -> &HazPtr {
        let hazptr = Box::into_raw(Box::new(HazPtr {
            ptr: AtomicPtr::new(std::ptr::null_mut()),
            next: std::ptr::null_mut(),
            active: AtomicBool::new(true),
        }));
        self.count.fetch_add(1, Ordering::Release);
        let mut head = self.head.load(Ordering::Acquire);
        loop {
            unsafe { &mut *hazptr }.next = head;
            match self
                .head
                .compare_exchange_weak(head, hazptr, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break unsafe { &*hazptr },
                Err(new_head) => head = new_head,
            }
        }
    }

    /// Fetch all HazPtr which are active.
    fn protected(&self) -> HashSet<*mut ()> {
        let mut protected = HashSet::new();
        let mut node = self.head.load(Ordering::Acquire);
        while !node.is_null() {
            let n = unsafe { &*node };
            if n.is_active() {
                protected.insert(n.ptr.load(Ordering::Acquire));
            }
            node = n.next;
        }
        protected
    }
}

impl Drop for HazPtrs {
    fn drop(&mut self) {
        let mut node = *self.head.get_mut();
        while !node.is_null() {
            node = unsafe { Box::from_raw(node) }.next;
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
    next: *mut Retired,
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
            next: std::ptr::null_mut(),
        }
    }
}

struct RetiredList {
    head: AtomicPtr<Retired>,
    count: AtomicIsize,
}

impl RetiredList {
    fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire).is_null()
    }

    fn count(&self) -> isize {
        self.count.load(Ordering::Acquire)
    }

    fn push(&self, retired: *mut Retired) {
        self.count.fetch_add(1, Ordering::Release);
        // We cannot mess with order here since if the addition is done after push, it could happen
        // that another thread reclaims the memory before addition happens, and usize can panic if
        // becomes negative as result off that.
        crate::asymmetric_light_barrier();
        self.append(retired, retired);
    }

    // This does not alter count, and should be taken care by the caller.
    fn append(&self, beg: *mut Retired, end: *mut Retired) {
        assert!(!beg.is_null());
        assert!(!end.is_null());
        let mut head = self.head.load(Ordering::Acquire);
        loop {
            unsafe { &mut *end }.next = head;
            match self
                .head
                .compare_exchange_weak(head, beg, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(new_head) => head = new_head,
            }
        }
    }

    // This does not decrease count due to race condition.
    fn steal(&self) -> *mut Retired {
        self.head.swap(std::ptr::null_mut(), Ordering::Acquire)
    }
}

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
#[cfg(doctest)]
struct GlobalWriterLocalReaderShouldNotCompile;

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
#[cfg(doctest)]
struct GlobalReaderLocalWriterShouldNotCompile;

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
#[cfg(doctest)]
struct DomainWithDifferentFamilyShouldNotCompile;
