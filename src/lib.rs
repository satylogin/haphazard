#![feature(arbitrary_self_types)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod deleter;
pub mod domain;
mod hazptr;
pub mod holder;
pub mod object;

use std::sync::atomic::Ordering;

pub use domain::Global;

pub use deleter::{Deleter, Reclaim};
pub use domain::HazPtrDomain;
pub use holder::HazPtrHolder;
pub use object::{HazPtrObject, HazPtrObjectWrapper};

pub(crate) fn asymmetric_light_barrier() {
    std::sync::atomic::fence(Ordering::SeqCst);
}

pub(crate) enum HeavyBarrierKind {
    Normal,
    Expedited,
}

pub(crate) fn asymmetric_heavy_barrier(_: HeavyBarrierKind) {
    std::sync::atomic::fence(Ordering::SeqCst);
}
