//! Stable error surface of the product.
//!
//! The type itself is defined next to the format adapters and re-exported
//! here: the adapters are the lowest layer that reports a failure, and the
//! product must not depend on a crate that depends on it. Every operation
//! returns [`Result`], and every failure carries a code callers compare
//! instead of parsing prose. The code stays the same when the message is
//! reworded or translated.

pub use ida_format_adapters::error::{IdaError, Result};
