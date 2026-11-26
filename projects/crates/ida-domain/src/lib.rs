//! OpenIDA product domain.
//!
//! The domain owns the session, the product defaults, the stable error
//! surface, the capability matrix and the workflows that assemble reports. It
//! does not parse a format: every format fact is a projection in
//! `ida-format-adapters`, and every byte-observation algorithm that Boost owns
//! is a workflow here only until the wiring pass replaces it.
//!
//! The public surface is [`BinaryView`], [`OpenIda`], [`capabilities`],
//! [`IdaError`] and the [`report`] types.

#![recursion_limit = "256"]
#![warn(missing_docs)]

mod capabilities;
mod error;
mod report;
mod session;
mod workflow;

pub use capabilities::capabilities;
pub use error::{IdaError, Result};
pub use report::*;
pub use session::{BinaryView, OpenIda, OpenIdaOptions, parse_hex};
