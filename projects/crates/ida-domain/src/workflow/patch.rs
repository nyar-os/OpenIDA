//! Patch workflow.
//!
//! Patching is delegated to the upstream session, which writes atomically and
//! reports the whole-file hash before and after. The workflow keeps the
//! product rule: without an output path the source is patched in place, with
//! one the source is untouched.

use std::path::Path;

use data_binary_inspect::{BinarySession, PatchReport};

use crate::Result;

/// Applies one byte edit, in place or to `output`, through the upstream writer.
pub(crate) fn apply(session: &mut BinarySession, offset: u64, data: &[u8], output: Option<&Path>) -> Result<PatchReport> {
    session.patch(offset, data, output).map_err(Into::into)
}
