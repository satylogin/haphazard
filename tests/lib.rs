use haphazard::*;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::Arc;

struct CountDrops(Arc<AtomicUsize>);
impl Drop for CountDrops {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn test() {
    let drops_42 = Arc::new(AtomicUsize::new(0));
    let x = AtomicPtr::new(Box::into_raw(Box::new(
        HazPtrObjectWrapper::with_global_domain((42, CountDrops(Arc::clone(&drops_42)))),
    )));

    // As a reader:
    let h = HazPtrHolder::global();
    let my_x = unsafe { h.protect(&x) }.unwrap();
    assert_eq!(42, my_x.0);
    h.reset();
    // no longer protected via hazptr, but since it was not retired, valid to use
    assert_eq!(42, my_x.0);

    let my_x = unsafe { h.protect(&x) }.unwrap();
    assert_eq!(42, my_x.0);
    drop(h);
    // invalid:
    // let _ = **my_x;

    let h = HazPtrHolder::global();
    let my_x = unsafe { h.protect(&x) }.unwrap();

    let h_tmp = HazPtrHolder::global();
    let _ = unsafe { h_tmp.protect(&x) }.unwrap();
    drop(h_tmp);

    // As a writer:
    let drops_9001 = Arc::new(AtomicUsize::new(0));
    let old = x.swap(
        Box::into_raw(Box::new(HazPtrObjectWrapper::with_global_domain((
            9001,
            CountDrops(Arc::clone(&drops_9001)),
        )))),
        Ordering::SeqCst,
    );
    let h2 = HazPtrHolder::global();
    let my_x2 = unsafe { h2.protect(&x) }.unwrap();
    assert_eq!(42, my_x.0);
    assert_eq!(9001, my_x2.0);

    unsafe { old.retire(&deleter::drop_box) };
    assert_eq!(42, my_x.0);
    assert_eq!(0, drops_42.load(Ordering::SeqCst));

    assert_eq!(0, HazPtrDomain::global().eager_reclaim(false));
    assert_eq!(42, my_x.0);
    assert_eq!(0, drops_42.load(Ordering::SeqCst));

    drop(h);
    assert_eq!(0, drops_42.load(Ordering::SeqCst));
    assert_eq!(1, HazPtrDomain::global().eager_reclaim(false));
    assert_eq!(1, drops_42.load(Ordering::SeqCst));
    assert_eq!(0, drops_9001.load(Ordering::SeqCst));

    drop(h2);
    assert_eq!(0, HazPtrDomain::global().eager_reclaim(false));
    assert_eq!(0, drops_9001.load(Ordering::SeqCst));
}

#[test]
#[should_panic]
fn panics_when_domain_mismatch_between_reader_and_writer() {
    let dw = HazPtrDomain::new(&());
    let dr = HazPtrDomain::new(&());

    let drops_42 = Arc::new(AtomicUsize::new(0));
    let x = AtomicPtr::new(Box::into_raw(Box::new(HazPtrObjectWrapper::with_domain(
        &dw,
        (42, CountDrops(Arc::clone(&drops_42))),
    ))));

    let h = HazPtrHolder::for_domain(&dr);
    let _ = unsafe { h.protect(&x) }.unwrap();
}
