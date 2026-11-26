//! Workflow orchestration.
//!
//! A workflow is a product use case over an open session: it picks the
//! defaults, bounds the work, calls one projection per fact and assembles the
//! report. Format parsing belongs to `ida-format-adapters`; byte observation
//! that Boost owns is delegated to `data-binary-inspect`, and only product
//! policy (defaults, paging, report shape) stays here.

pub(crate) mod compare;
pub(crate) mod disassemble;
pub(crate) mod extract;
pub(crate) mod inspect;
pub(crate) mod patch;
