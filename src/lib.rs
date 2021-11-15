#![feature(arbitrary_self_types)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod deleter;
pub mod domain;
pub mod holder;
pub mod object;
mod record;
mod sync;
mod thread;

use std::sync::atomic::Ordering;

pub use domain::Global;

pub use deleter::{Deleter, Reclaim};
pub use domain::Domain;
pub use holder::HazardPointer;
pub use object::{HazPtrObject, HazPtrObjectWrapper};

pub(crate) fn asymmetric_light_barrier() {
    crate::sync::atomic::fence(Ordering::SeqCst);
}

pub(crate) enum HeavyBarrierKind {
    Expedited,
}

pub(crate) fn asymmetric_heavy_barrier(_: HeavyBarrierKind) {
    crate::sync::atomic::fence(Ordering::SeqCst);
}
