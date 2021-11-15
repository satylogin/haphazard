use crate::deleter::{Deleter, Reclaim};
use crate::record::HazPtrRecord;
use crate::sync::atomic::{AtomicIsize, AtomicPtr, AtomicU64, AtomicUsize};
use std::collections::HashSet;
use std::marker::PhantomData;
use std::sync::atomic::Ordering;
use std::time::Duration;

const RECLAIM_TIME_PERIOD: u64 = Duration::from_nanos(2000000000).as_nanos() as u64;
const RCOUNT_THRESHOLD: isize = 1000;
const HCOUNT_MULTIPLIER: isize = 2;
const NUM_SHARDS: usize = 8;
const IGNORE_LOW_BITS: usize = 8;
const SHARD_MASK: usize = NUM_SHARDS - 1;
const LOCK_BIT: usize = 1;

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

fn calc_shard(input: *mut Retired) -> usize {
    (input as usize >> IGNORE_LOW_BITS) & SHARD_MASK
}

#[non_exhaustive]
pub struct Global;
impl Global {
    const fn new() -> Self {
        Global
    }
}

#[cfg(not(loom))]
static SHARED_DOMAIN: Domain<Global> = Domain::new(&Global::new());

#[cfg(loom)]
loom::lazy_static! {
    static ref SHARED_DOMAIN: Domain<Global> = Domain::new(&Global::new());
}

pub struct Domain<F> {
    hazptrs: HazPtrRecords,
    untagged: [RetiredList; NUM_SHARDS],
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

macro_rules! new {
    ($($decl:tt)*) => {
        pub $($decl)* new(_: &F) -> Self {

            #[cfg(not(loom))]
            let untagged = {
                const RETIRED_LIST: RetiredList = RetiredList::new();
                [RETIRED_LIST; NUM_SHARDS]
            };

            #[cfg(loom)]
            let untagged = {
                [(); NUM_SHARDS].map(|_| RetiredList::new())
            };

            Self {
                hazptrs: HazPtrRecords {
                    head: AtomicPtr::new(std::ptr::null_mut()),
                    available: AtomicUsize::new(0),
                    count: AtomicIsize::new(0),
                },
                untagged,
                family: PhantomData,
                due_time: AtomicU64::new(0),
                count: AtomicIsize::new(0),
                shutdown: false,
            }
        }
    };
}

impl<F> Domain<F> {
    #[cfg(loom)]
    new!(fn);

    #[cfg(not(loom))]
    new!(const fn);

    pub(crate) fn acquire(&self) -> &HazPtrRecord {
        self.acquire_many::<1>()[0]
    }

    pub(crate) fn acquire_many<const N: usize>(&self) -> [&HazPtrRecord; N] {
        let mut available = self.hazptrs.try_acquire_available::<N>();
        [(); N].map(|_| {
            if !available.is_null() {
                let rec = available;
                // SAFETY: `HazPtrRecord`s are never deallocated unless domain is dropped.
                available = unsafe { &*available }.next_available;
                // SAFETY: `HazPtrRecord`s are never deallocated unless domain is dropped.
                unsafe { &*rec }
            } else {
                self.hazptrs.allocate()
            }
        })
    }

    pub(crate) fn release(&self, rec: &HazPtrRecord) {
        self.release_many::<1>([rec])
    }

    pub(crate) fn release_many<const N: usize>(&self, recs: [&HazPtrRecord; N]) {
        self.hazptrs.push_available::<N>(recs);
    }

    /// # Safety
    /// 1. ptr should be a valid pointer.
    /// 2. ptr should not be accessed after calling retire on it. Readers who already have access
    ///    to it can keep on reading it.
    pub(crate) unsafe fn retire<'domain>(
        &'domain self,
        ptr: *mut (dyn Reclaim + 'domain),
        deleter: &'static dyn Deleter,
    ) {
        // SAFETY: By safety contract on function.
        let retired = Box::into_raw(Box::new(unsafe { Retired::new(self, ptr, deleter) }));
        self.count.fetch_add(1, Ordering::Release);
        // SAFETY: retired is valid pointers as it comes from box that we constructed.
        unsafe { self.untagged[calc_shard(retired)].push(retired, retired) };
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
        (0..NUM_SHARDS)
            .map(|shard| self.reclaim_shard(shard, transitive))
            .sum()
    }

    fn reclaim_shard(&self, shard: usize, transitive: bool) -> isize {
        let mut reclaimed = 0;
        loop {
            let steal = self.untagged[shard].steal();
            if steal.is_null() {
                break;
            }
            crate::asymmetric_heavy_barrier(crate::HeavyBarrierKind::Expedited);
            let protected = self.hazptrs.protected();
            reclaimed += self.bulk_lookup_and_reclaim(shard, steal, protected);
            if self.untagged[shard].is_empty() || !transitive {
                break;
            } else {
                crate::thread::yield_now();
            }
        }
        if reclaimed != 0 {
            self.count.fetch_sub(reclaimed, Ordering::Release);
        }

        reclaimed
    }

    fn bulk_lookup_and_reclaim(
        &self,
        shard: usize,
        steal: *mut Retired,
        protected: HashSet<*mut ()>,
    ) -> isize {
        let reclaimable = self.reclaimable(shard, steal, protected);
        for node in &reclaimable {
            let node = unsafe { Box::from_raw(*node) };
            unsafe { node.deleter.delete(node.ptr) };
        }
        reclaimable.len() as isize
    }

    fn reclaimable(
        &self,
        shard: usize,
        steal: *mut Retired,
        protected: HashSet<*mut ()>,
    ) -> Vec<*mut Retired> {
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
        unsafe { self.untagged[shard].push(remaining_head, remaining_tail) };

        reclaimable
    }

    fn count(&self) -> isize {
        self.count.load(Ordering::Acquire)
    }
}

struct HazPtrRecords {
    head: AtomicPtr<HazPtrRecord>,
    available: AtomicUsize, // *mut HazPtrRecord in reality.
    count: AtomicIsize,
}

impl HazPtrRecords {
    fn count(&self) -> isize {
        self.count.load(Ordering::Acquire)
    }

    fn cas_available(&self, current: usize, new: usize) -> bool {
        self.available
            .compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    fn try_acquire_available<const N: usize>(&self) -> *mut HazPtrRecord {
        loop {
            let available = self.available.load(Ordering::Acquire);
            if available == std::ptr::null::<HazPtrRecord>() as usize {
                return std::ptr::null_mut();
            }
            if (available as usize & LOCK_BIT) == 0 {
                // Not locked at the moment
                if self.cas_available(available, available as usize | LOCK_BIT) {
                    // SAFETY: We hold lock now.
                    break unsafe {
                        self.try_acquire_available_locked::<N>(available as *mut HazPtrRecord)
                    };
                } else {
                    crate::thread::yield_now();
                }
            }
        }
    }

    /// # Safety
    ///
    /// 1. Must already hold the lock for available HazPtrRecord.
    /// 2. head must point to a valid non null pointer.
    unsafe fn try_acquire_available_locked<const N: usize>(
        &self,
        head: *mut HazPtrRecord,
    ) -> *mut HazPtrRecord {
        let mut tail = head;
        let mut n = 1;
        // SAFETY: tail is head, which is valid via function contract.
        let mut next = unsafe { &*tail }.next_available;
        while !next.is_null() && n < N {
            debug_assert_eq!(next as usize & LOCK_BIT, 0);
            tail = next;
            // SAFETY: every non locked pointer is valid in available list.
            next = unsafe { &*tail }.next_available;
            n += 1;
        }

        let new_available_head = next as usize;
        debug_assert_eq!(new_available_head & LOCK_BIT, 0); // check valid pointer.
        self.available.store(new_available_head, Ordering::Release); // release lock.

        // SAFETY: every non locked pointer is valid in available list.
        unsafe { &mut *tail }.next_available = std::ptr::null_mut();

        head
    }

    fn link_and_clean<const N: usize>(
        recs: [&HazPtrRecord; N],
    ) -> Option<(&HazPtrRecord, &HazPtrRecord)> {
        if recs.is_empty() {
            return None;
        }
        recs.iter().for_each(|rec| rec.reset());
        recs.windows(2).for_each(|w| {
            let rec: *mut HazPtrRecord = w[0] as *const _ as *mut _;
            unsafe { &mut *rec }.next_available = w[1] as *const _ as *mut _;
        });
        if cfg!(debug_assertion) {
            (0..N).for_each(|i| debug_assert_eq!((recs[i] as *const _ as usize) & LOCK_BIT, 0));
        }
        Some((recs[0], *recs.last().unwrap()))
    }

    fn push_available<const N: usize>(&self, recs: [&HazPtrRecord; N]) {
        if let Some((head, tail)) = Self::link_and_clean(recs) {
            let tail: *mut HazPtrRecord = tail as *const _ as *mut _;
            debug_assert_eq!((head as *const _ as usize) & LOCK_BIT, 0);
            loop {
                let available = self.available.load(Ordering::Acquire);
                if (available & LOCK_BIT) == 0 {
                    unsafe { &mut *tail }.next_available = available as *mut HazPtrRecord;
                    if self.cas_available(available, head as *const _ as usize) {
                        break;
                    }
                } else {
                    crate::thread::yield_now();
                }
            }
        }
    }

    /// Allocate a new HazPtr.
    fn allocate(&self) -> &HazPtrRecord {
        let hazptr = Box::into_raw(Box::new(HazPtrRecord {
            ptr: AtomicPtr::new(std::ptr::null_mut()),
            next: std::ptr::null_mut(),
            next_available: std::ptr::null_mut(),
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
            protected.insert(n.ptr.load(Ordering::Acquire));
            node = n.next;
        }
        protected
    }
}

impl Drop for HazPtrRecords {
    fn drop(&mut self) {
        let mut node = self.head.load(Ordering::Acquire);
        while !node.is_null() {
            node = unsafe { Box::from_raw(node) }.next;
        }
    }
}

impl<F> Drop for Domain<F> {
    fn drop(&mut self) {
        self.shutdown = true;
        let n_retired = self.count.load(Ordering::Acquire);
        let n_reclaimed = self.eager_reclaim(true);
        debug_assert_eq!(n_retired, n_reclaimed);
    }
}

struct Retired {
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
    #[cfg(loom)]
    fn new() -> Self {
        Self {
            head: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    #[cfg(not(loom))]
    const fn new() -> Self {
        Self {
            head: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    fn is_empty(&self) -> bool {
        self.head.load(Ordering::Acquire).is_null()
    }

    /// This does not alter count which should be taken care by the caller.
    ///
    /// Safety:
    /// 1. Caller sould ensure that `beg` and `end` corresponds to a valid linked list.
    unsafe fn push(&self, beg: *mut Retired, end: *mut Retired) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire() {
        let domain = unique_domain!();
        let _: &HazPtrRecord = domain.acquire();
        assert_eq!(1, domain.hazptrs.count.load(Ordering::Relaxed));
    }

    #[test]
    fn acquire_reuses_released_pointers() {
        let domain = unique_domain!();
        let ptr = domain.acquire();
        domain.release(ptr);
        domain.acquire();

        assert_eq!(1, domain.hazptrs.count.load(Ordering::Relaxed));
    }

    #[test]
    fn acquire_many() {
        let domain = unique_domain!();
        let _: [&HazPtrRecord; 10] = domain.acquire_many::<10>();
        assert_eq!(10, domain.hazptrs.count.load(Ordering::Relaxed));
    }

    #[test]
    fn acquire_many_reuses_released_pointers() {
        let domain = unique_domain!();
        let ptrs: [&HazPtrRecord; 10] = domain.acquire_many::<10>();
        (0..5).for_each(|i| domain.release(ptrs[i]));
        let _: [&HazPtrRecord; 10] = domain.acquire_many::<10>();
        assert_eq!(15, domain.hazptrs.count.load(Ordering::Relaxed));
    }
}
