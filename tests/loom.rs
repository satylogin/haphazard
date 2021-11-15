#![cfg(loom)]

use haphazard::*;
use loom::sync::atomic::{AtomicPtr, Ordering};
use loom::thread::spawn;
use std::sync::Arc;

struct CountDrops(Arc<std::sync::atomic::AtomicUsize>);
impl CountDrops {
    pub fn new() -> Self {
        Self(Default::default())
    }

    pub fn counter(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::clone(&self.0)
    }
}
impl Drop for CountDrops {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn single_reader() {
    loom::model(move || {
        let drops_42 = CountDrops::new();
        let n_drops_42 = drops_42.counter();
        let x = Arc::new(AtomicPtr::new(Box::into_raw(Box::new(
            HazPtrObjectWrapper::with_global_domain((42, drops_42)),
        ))));

        let (tx, rx) = loom::sync::mpsc::channel();

        let x1 = Arc::clone(&x);
        let t1 = spawn(move || {
            let h = HazardPointer::make_global();
            let my_x = unsafe { h.protect(&*x1) }.unwrap();

            // Now  we can let writer change things.
            tx.send(()).unwrap();

            assert_eq!(n_drops_42.load(Ordering::SeqCst), 0);
            assert_eq!(42, my_x.0);
        });

        // Wait until t1 has protected the value.
        let _ = rx.recv();

        let drops_9001 = CountDrops::new();
        let n_drops_9001 = drops_9001.counter();
        let old = x.swap(
            Box::into_raw(Box::new(HazPtrObjectWrapper::with_global_domain((
                9001, drops_9001,
            )))),
            Ordering::SeqCst,
        );
        let n1 = unsafe { old.retire(&deleter::drop_box) };
        let n2 = Domain::global().eager_reclaim(false);

        t1.join().unwrap();
        let n3 = Domain::global().eager_reclaim(false);
        assert_eq!(1, n1 + n2 + n3);
        assert_eq!(0, n_drops_9001.load(Ordering::SeqCst));
    });
}

#[test]
fn multiple_readers() {
    loom::model(move || {
        let drops_42 = CountDrops::new();
        let n_drops_42_1 = drops_42.counter();
        let n_drops_42_2 = drops_42.counter();
        let n_drops_42_3 = drops_42.counter();
        let x = Arc::new(AtomicPtr::new(Box::into_raw(Box::new(
            HazPtrObjectWrapper::with_global_domain((42, drops_42)),
        ))));

        let (tx, rx) = loom::sync::mpsc::channel();

        let x1 = Arc::clone(&x);
        let tx1 = tx.clone();
        let t1 = spawn(move || {
            let h = HazardPointer::make_global();
            let my_x = unsafe { h.protect(&*x1) }.unwrap();

            // Now  we can let writer change things.
            tx1.send(()).unwrap();

            assert_eq!(n_drops_42_1.load(Ordering::SeqCst), 0);
            assert_eq!(42, my_x.0);
        });

        let x2 = Arc::clone(&x);
        let tx2 = tx.clone();
        let t2 = spawn(move || {
            let h = HazardPointer::make_global();
            let my_x = unsafe { h.protect(&*x2) }.unwrap();

            // Now  we can let writer change things.
            tx2.send(()).unwrap();

            assert_eq!(n_drops_42_2.load(Ordering::SeqCst), 0);
            assert_eq!(42, my_x.0);
        });

        // Wait until both threads has protected the value.
        let _ = rx.recv();
        let _ = rx.recv();

        let drops_9001 = CountDrops::new();
        let n_drops_9001 = drops_9001.counter();
        let old = x.swap(
            Box::into_raw(Box::new(HazPtrObjectWrapper::with_global_domain((
                9001, drops_9001,
            )))),
            Ordering::SeqCst,
        );
        let n1 = unsafe { old.retire(&deleter::drop_box) };
        let n2 = Domain::global().eager_reclaim(false);

        t1.join().unwrap();

        let n3 = Domain::global().eager_reclaim(false);

        t2.join().unwrap();

        let n4 = Domain::global().eager_reclaim(false);

        assert_eq!(1, n1 + n2 + n3 + n4);
        assert_eq!(1, n_drops_42_3.load(Ordering::SeqCst));
        assert_eq!(0, n_drops_9001.load(Ordering::SeqCst));
    });
}
