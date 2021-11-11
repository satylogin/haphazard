#![feature(arbitrary_self_types)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod deleter;
pub mod domain;
mod hazptr;
pub mod holder;
pub mod object;

pub(crate) use domain::Global;

pub use deleter::{Deleter, Reclaim};
pub use domain::HazPtrDomain;
pub use holder::HazPtrHolder;
pub use object::{HazPtrObject, HazPtrObjectWrapper};
