//! Container and overlay projections.
//!
//! [`asar`] and [`nsis`] adapt `data-binary-container` facts; [`overlay`]
//! reports the trailing bytes and their embedded container signatures, and
//! [`entropy`] computes the whole-file and per-section entropy plus the `PE`
//! overlay range. They are facts: the product `unpack` workflow decides which
//! one to call and how to present the result.

pub mod asar;
pub mod entropy;
pub mod nsis;
pub mod overlay;
