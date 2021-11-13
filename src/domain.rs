use crate::deleter::{Deleter, Reclaim};
use crate::record::HazPtrRecord;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicPtr, AtomicU64, Ordering};
use std::time::Duration;

/// Returns system time in nano sec as u64
fn unix_epoc_nano() -> u64 {
    use std::convert::TryFrom;

    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is set to before the epoc")
            .as_nanos(),
    )
    .expect("system time is too far in future")
}

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

static SHARED_DOMAIN: Domain<Global> = Domain::new(&Global::new());

pub struct Domain<F> {
    hazptrs: HazPtrRecords,
    untagged: RetiredList,
    family: PhantomData<F>,
    due_time: AtomicU64,
    count: AtomicIsize,
    shutdown: bool,
}

impl Domain<Global> {
    pub fn global() -> &'static Self {
        &SHARED_DOMAIN
    }
}

#[macro_export]
macro_rules! unique_domain {
    () => {
        Domain::new(&|| {})
    };
}

impl<F> Domain<F> {
    pub const fn new(_: &F) -> Self {
        Self {
            hazptrs: HazPtrRecords {
                head: AtomicPtr::new(std::ptr::null_mut()),
                count: AtomicIsize::new(0),
            },
            untagged: RetiredList {
                head: AtomicPtr::new(std::ptr::null_mut()),
            },
            family: PhantomData,
            due_time: AtomicU64::new(0),
            count: AtomicIsize::new(0),
            shutdown: false,
        }
    }

    pub(crate) fn acquire(&self) -> &HazPtrRecord {
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
        self.count.fetch_add(1, Ordering::Release);
        self.untagged.push(retired);
        if self.is_time_to_reclaim() || self.reached_threshold() {
            self.eager_reclaim(false);
        }
    }

    fn is_time_to_reclaim(&self) -> bool {
        let time = unix_epoc_nano();
        let due_time = self.due_time.load(Ordering::Relaxed);

        time > due_time
            && self
                .due_time
                .compare_exchange(
                    due_time,
                    time + RECLAIM_TIME_PERIOD,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
    }

    fn reached_threshold(&self) -> bool {
        self.count() >= RCOUNT_THRESHOLD.max(HCOUNT_MULTIPLIER * self.hazptrs.count())
    }

    pub fn eager_reclaim(&self, transitive: bool) -> isize {
        let mut reclaimed = 0;
        loop {
            let steal = self.untagged.steal();
            if steal.is_null() {
                break;
            }
            crate::asymmetric_heavy_barrier(crate::HeavyBarrierKind::Expedited);
            let protected = self.hazptrs.protected();
            reclaimed += self.bulk_lookup_and_reclaim(steal, protected);
            if self.untagged.is_empty() || !transitive {
                break;
            } else {
                std::thread::yield_now();
            }
        }
        if reclaimed != 0 {
            self.count.fetch_sub(reclaimed, Ordering::Release);
        }

        reclaimed
    }

    fn bulk_lookup_and_reclaim(&self, steal: *mut Retired, protected: HashSet<*mut ()>) -> isize {
        let reclaimable = self.reclaimable(steal, protected);
        for node in &reclaimable {
            let node = unsafe { Box::from_raw(*node) };
            unsafe { node.deleter.delete(node.ptr) };
        }
        reclaimable.len() as isize
    }

    fn reclaimable(&self, steal: *mut Retired, protected: HashSet<*mut ()>) -> Vec<*mut Retired> {
        let mut remaining_head = std::ptr::null_mut();
        let mut remaining_tail: *mut Retired = std::ptr::null_mut();
        let mut reclaimable = vec![];
        let mut node = steal;
        while !node.is_null() {
            let n = unsafe { &mut *node };
            let next_node = n.next;
            debug_assert_ne!(node, next_node);
            if !protected.contains(&(n.ptr as *mut ())) {
                reclaimable.push(node);
            } else {
                n.next = remaining_head;
                remaining_head = node;
                if remaining_tail.is_null() {
                    remaining_tail = remaining_head;
                }
            }
            node = next_node;
        }
        unsafe { self.untagged.append(remaining_head, remaining_tail) };

        reclaimable
    }

    fn count(&self) -> isize {
        self.count.load(Ordering::Acquire)
    }
}

struct HazPtrRecords {
    head: AtomicPtr<HazPtrRecord>,
    count: AtomicIsize,
}

impl HazPtrRecords {
    fn count(&self) -> isize {
        self.count.load(Ordering::Acquire)
    }

    fn acquire_existing(&self) -> Option<&HazPtrRecord> {
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
    fn allocate(&self) -> &HazPtrRecord {
        let hazptr = Box::into_raw(Box::new(HazPtrRecord {
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

impl Drop for HazPtrRecords {
    fn drop(&mut self) {
        let mut node = *self.head.get_mut();
        while !node.is_null() {
            node = unsafe { Box::from_raw(node) }.next;
        }
    }
}

impl<F> Drop for Domain<F> {
    fn drop(&mut self) {
        self.shutdown = true;
        let n_retired = *self.count.get_mut();
        let n_reclaimed = self.eager_reclaim(true);
        debug_assert_eq!(n_retired, n_reclaimed);
        debug_assert!(self.untagged.head.get_mut().is_null());
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
        _: &'domain Domain<F>,
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
}

impl RetiredList {
    fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire).is_null()
    }

    fn push(&self, retired: *mut Retired) {
        // SAFETY: pointers are valid since we own them.
        unsafe { self.append(retired, retired) };
    }

    /// This does not alter count which should be taken care by the caller.
    ///
    /// Safety:
    /// 1. Caller sould ensure that `beg` and `end` corresponds to a valid linked list.
    unsafe fn append(&self, beg: *mut Retired, end: *mut Retired) {
        if beg.is_null() {
            return;
        }
        let mut head = self.head.load(Ordering::Acquire);
        loop {
            // SAFETY: by safety guarantee on function.
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

    // This does not decrease count. subtraction in only done for objects that are retired.
    fn steal(&self) -> *mut Retired {
        self.head.swap(std::ptr::null_mut(), Ordering::Acquire)
    }
}

/// ```compile_fail
///  use std::sync::atomic::AtomicPtr;
///  use haphazard::*;
///
///  let dw = Domain::global();
///  let dr = Domain::new(&());
///
///  let x = AtomicPtr::new(Box::into_raw(Box::new(HazPtrObjectWrapper::with_domain(&dw, 42))));
///
///  let mut h = HazardPointer::make_in_domain(&dr);
///
///  let _ = unsafe { h.protect(&x) }.unwrap();
/// ```
#[cfg(doctest)]
struct GlobalWriterLocalReaderShouldNotCompile;

/// ```compile_fail
///  use std::sync::atomic::AtomicPtr;
///  use haphazard::*;
///
///  let dw = Domain::new(&());
///  let dr = Domain::global();
///
///  let x = AtomicPtr::new(Box::into_raw(Box::new(HazPtrObjectWrapper::with_domain(&dw, 42))));
///
///  let mut h = HazardPointer::make_in_domain(&dr);
///
///  let _ = unsafe { h.protect(&x) }.unwrap();
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
///  let mut h = HazardPointer::make_in_domain(&dr);
///
///  let _ = unsafe { h.protect(&x) }.unwrap();
/// ```
#[cfg(doctest)]
struct DomainWithDifferentFamilyShouldNotCompile;
