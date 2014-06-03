//! PE load configuration directory decoding.
//!
//! Data directory 10 carries the security cookie, the SEH handler table and the
//! control-flow guard metadata that the loader and `/GS` / `/guard` use. The
//! layout is little-endian and differs between PE32 and PE32+. This module reads
//! the documented prefix, decodes `GuardFlags` and reports the values; it never
//! treats them as a guarantee.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// Data directory index of the load configuration table.
const DIRECTORY_LOAD_CONFIG: usize = 10;

const IMAGE_GUARD_CF_INSTRUMENTED: u32 = 0x0000_0100;
const IMAGE_GUARD_CFW_INSTRUMENTED: u32 = 0x0000_0200;
const IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT: u32 = 0x0000_0400;
const IMAGE_GUARD_SECURITY_COOKIE_UNUSED: u32 = 0x0000_0800;
const IMAGE_GUARD_PROTECT_DELAYLOAD_IAT: u32 = 0x0000_1000;
const IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION: u32 = 0x0000_2000;
const IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT: u32 = 0x0000_4000;
const IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION: u32 = 0x0000_8000;
const IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT: u32 = 0x0001_0000;
const IMAGE_GUARD_RF_INSTRUMENTED: u32 = 0x0002_0000;
const IMAGE_GUARD_RF_ENABLE: u32 = 0x0004_0000;
const IMAGE_GUARD_RF_STRICT: u32 = 0x0008_0000;
const IMAGE_GUARD_RETPOLINE_PRESENT: u32 = 0x0010_0000;
const IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT: u32 = 0x0040_0000;
const IMAGE_GUARD_XFG_ENABLED: u32 = 0x0080_0000;
const IMAGE_GUARD_CASTGUARD_PRESENT: u32 = 0x0100_0000;
const IMAGE_GUARD_MEMCPY_PRESENT: u32 = 0x0200_0000;

/// `CodeIntegrity` block of the load configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeIntegrityInfo {
    /// Raw `Flags` field.
    pub flags: u16,
    /// Catalog file index.
    pub catalog: u16,
    /// Offset of the catalog file.
    pub catalog_offset: u32,
}

/// PE load configuration summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeLoadConfigReport {
    /// Whether the image has a non-empty load configuration directory.
    pub present: bool,
    /// Whether the table uses the 64-bit layout.
    pub is64: bool,
    /// Declared table size.
    pub size: u32,
    /// Build timestamp recorded by the linker.
    pub timestamp: u32,
    /// Major table version.
    pub major_version: u16,
    /// Minor table version.
    pub minor_version: u16,
    /// `GlobalFlagsClear`.
    pub global_flags_clear: u32,
    /// `GlobalFlagsSet`.
    pub global_flags_set: u32,
    /// Default critical-section spin timeout.
    pub critical_section_default_timeout: u32,
    /// `DeCommitFreeBlockThreshold`.
    pub de_commit_free_block_threshold: u64,
    /// `DeCommitTotalFreeThreshold`.
    pub de_commit_total_free_threshold: u64,
    /// Address of the lock-prefix table.
    pub lock_prefix_table: u64,
    /// `MaximumAllocationSize`.
    pub maximum_allocation_size: u64,
    /// `VirtualMemoryThreshold`.
    pub virtual_memory_threshold: u64,
    /// `ProcessAffinityMask`.
    pub process_affinity_mask: u64,
    /// `ProcessHeapFlags`.
    pub process_heap_flags: u32,
    /// `CSDVersion`.
    pub csd_version: u16,
    /// `DependentLoadFlags`.
    pub dependent_load_flags: u16,
    /// Address of the edit list.
    pub edit_list: u64,
    /// Address of the `/GS` security cookie.
    pub security_cookie: u64,
    /// Address of the SEH handler table.
    pub se_handler_table: u64,
    /// Number of entries in the SEH handler table.
    pub se_handler_count: u64,
    /// `GuardCFCheckFunctionPointer`.
    pub guard_cf_check_function_pointer: u64,
    /// `GuardCFDispatchFunctionPointer`.
    pub guard_cf_dispatch_function_pointer: u64,
    /// Address of the CFG function table.
    pub guard_cf_function_table: u64,
    /// Number of CFG function table entries.
    pub guard_cf_function_count: u64,
    /// Raw `GuardFlags`.
    pub guard_flags: u32,
    /// `GuardFlags` decoded into stable names.
    pub guard_flags_text: Vec<String>,
    /// `CodeIntegrity` block.
    pub code_integrity: CodeIntegrityInfo,
    /// Whether the declared size cut the documented prefix.
    pub truncated: bool,
}

impl PeLoadConfigReport {
    fn empty(is64: bool) -> Self {
        Self {
            present: false,
            is64,
            size: 0,
            timestamp: 0,
            major_version: 0,
            minor_version: 0,
            global_flags_clear: 0,
            global_flags_set: 0,
            critical_section_default_timeout: 0,
            de_commit_free_block_threshold: 0,
            de_commit_total_free_threshold: 0,
            lock_prefix_table: 0,
            maximum_allocation_size: 0,
            virtual_memory_threshold: 0,
            process_affinity_mask: 0,
            process_heap_flags: 0,
            csd_version: 0,
            dependent_load_flags: 0,
            edit_list: 0,
            security_cookie: 0,
            se_handler_table: 0,
            se_handler_count: 0,
            guard_cf_check_function_pointer: 0,
            guard_cf_dispatch_function_pointer: 0,
            guard_cf_function_table: 0,
            guard_cf_function_count: 0,
            guard_flags: 0,
            guard_flags_text: Vec::new(),
            code_integrity: CodeIntegrityInfo { flags: 0, catalog: 0, catalog_offset: 0 },
            truncated: false,
        }
    }
}

/// Decodes the PE load configuration directory of one session.
pub(crate) fn analyze(session: &BinarySession) -> Result<PeLoadConfigReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE load configuration requires a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let is64 = image.optional.magic == 0x20b;
    let directory = image.optional.data_directories[DIRECTORY_LOAD_CONFIG];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(PeLoadConfigReport::empty(is64));
    }
    let base = pe::rva_to_offset(&image.sections, directory.rva)
        .map_err(|error| IdaError::parse(format!("PE load configuration: {error}")))? as usize;

    let mut report = PeLoadConfigReport::empty(is64);
    report.present = true;
    report.size = read_u32(bytes, base).unwrap_or(0);
    report.timestamp = read_u32(bytes, base + 4).unwrap_or(0);
    report.major_version = read_u16(bytes, base + 8).unwrap_or(0);
    report.minor_version = read_u16(bytes, base + 10).unwrap_or(0);
    report.global_flags_clear = read_u32(bytes, base + 12).unwrap_or(0);
    report.global_flags_set = read_u32(bytes, base + 16).unwrap_or(0);
    report.critical_section_default_timeout = read_u32(bytes, base + 20).unwrap_or(0);

    let expected = if is64 { 0xa0 } else { 0x74 };
    report.truncated = (report.size as usize) < expected;

    if is64 {
        report.de_commit_free_block_threshold = read_u64(bytes, base + 0x18).unwrap_or(0);
        report.de_commit_total_free_threshold = read_u64(bytes, base + 0x20).unwrap_or(0);
        report.lock_prefix_table = read_u64(bytes, base + 0x28).unwrap_or(0);
        report.maximum_allocation_size = read_u64(bytes, base + 0x30).unwrap_or(0);
        report.virtual_memory_threshold = read_u64(bytes, base + 0x38).unwrap_or(0);
        report.process_affinity_mask = read_u64(bytes, base + 0x40).unwrap_or(0);
        report.process_heap_flags = read_u32(bytes, base + 0x48).unwrap_or(0);
        report.csd_version = read_u16(bytes, base + 0x4c).unwrap_or(0);
        report.dependent_load_flags = read_u16(bytes, base + 0x4e).unwrap_or(0);
        report.edit_list = read_u64(bytes, base + 0x50).unwrap_or(0);
        report.security_cookie = read_u64(bytes, base + 0x58).unwrap_or(0);
        report.se_handler_table = read_u64(bytes, base + 0x60).unwrap_or(0);
        report.se_handler_count = read_u64(bytes, base + 0x68).unwrap_or(0);
        report.guard_cf_check_function_pointer = read_u64(bytes, base + 0x70).unwrap_or(0);
        report.guard_cf_dispatch_function_pointer = read_u64(bytes, base + 0x78).unwrap_or(0);
        report.guard_cf_function_table = read_u64(bytes, base + 0x80).unwrap_or(0);
        report.guard_cf_function_count = read_u64(bytes, base + 0x88).unwrap_or(0);
        report.guard_flags = read_u32(bytes, base + 0x90).unwrap_or(0);
        report.code_integrity = CodeIntegrityInfo {
            flags: read_u16(bytes, base + 0x94).unwrap_or(0),
            catalog: read_u16(bytes, base + 0x96).unwrap_or(0),
            catalog_offset: read_u32(bytes, base + 0x98).unwrap_or(0),
        };
    }
    else {
        report.de_commit_free_block_threshold = u64::from(read_u32(bytes, base + 0x18).unwrap_or(0));
        report.de_commit_total_free_threshold = u64::from(read_u32(bytes, base + 0x1c).unwrap_or(0));
        report.lock_prefix_table = u64::from(read_u32(bytes, base + 0x20).unwrap_or(0));
        report.maximum_allocation_size = u64::from(read_u32(bytes, base + 0x24).unwrap_or(0));
        report.virtual_memory_threshold = u64::from(read_u32(bytes, base + 0x28).unwrap_or(0));
        report.process_heap_flags = read_u32(bytes, base + 0x2c).unwrap_or(0);
        report.process_affinity_mask = u64::from(read_u32(bytes, base + 0x30).unwrap_or(0));
        report.csd_version = read_u16(bytes, base + 0x34).unwrap_or(0);
        report.dependent_load_flags = read_u16(bytes, base + 0x36).unwrap_or(0);
        report.edit_list = u64::from(read_u32(bytes, base + 0x38).unwrap_or(0));
        report.security_cookie = u64::from(read_u32(bytes, base + 0x3c).unwrap_or(0));
        report.se_handler_table = u64::from(read_u32(bytes, base + 0x40).unwrap_or(0));
        report.se_handler_count = u64::from(read_u32(bytes, base + 0x44).unwrap_or(0));
        report.guard_cf_check_function_pointer = u64::from(read_u32(bytes, base + 0x48).unwrap_or(0));
        report.guard_cf_dispatch_function_pointer = u64::from(read_u32(bytes, base + 0x4c).unwrap_or(0));
        report.guard_cf_function_table = u64::from(read_u32(bytes, base + 0x50).unwrap_or(0));
        report.guard_cf_function_count = u64::from(read_u32(bytes, base + 0x54).unwrap_or(0));
        report.guard_flags = read_u32(bytes, base + 0x58).unwrap_or(0);
        report.code_integrity = CodeIntegrityInfo {
            flags: read_u16(bytes, base + 0x5c).unwrap_or(0),
            catalog: read_u16(bytes, base + 0x5e).unwrap_or(0),
            catalog_offset: read_u32(bytes, base + 0x60).unwrap_or(0),
        };
    }
    report.guard_flags_text = guard_flag_names(report.guard_flags);
    Ok(report)
}

fn guard_flag_names(flags: u32) -> Vec<String> {
    let known = [
        (IMAGE_GUARD_CF_INSTRUMENTED, "CF_INSTRUMENTED"),
        (IMAGE_GUARD_CFW_INSTRUMENTED, "CFW_INSTRUMENTED"),
        (IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, "CF_FUNCTION_TABLE_PRESENT"),
        (IMAGE_GUARD_SECURITY_COOKIE_UNUSED, "SECURITY_COOKIE_UNUSED"),
        (IMAGE_GUARD_PROTECT_DELAYLOAD_IAT, "PROTECT_DELAYLOAD_IAT"),
        (IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION, "DELAYLOAD_IAT_IN_ITS_OWN_SECTION"),
        (IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"),
        (IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION, "CF_ENABLE_EXPORT_SUPPRESSION"),
        (IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT, "CF_LONGJUMP_TABLE_PRESENT"),
        (IMAGE_GUARD_RF_INSTRUMENTED, "RF_INSTRUMENTED"),
        (IMAGE_GUARD_RF_ENABLE, "RF_ENABLE"),
        (IMAGE_GUARD_RF_STRICT, "RF_STRICT"),
        (IMAGE_GUARD_RETPOLINE_PRESENT, "RETPOLINE_PRESENT"),
        (IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT, "EH_CONTINUATION_TABLE_PRESENT"),
        (IMAGE_GUARD_XFG_ENABLED, "XFG_ENABLED"),
        (IMAGE_GUARD_CASTGUARD_PRESENT, "CASTGUARD_PRESENT"),
        (IMAGE_GUARD_MEMCPY_PRESENT, "MEMCPY_PRESENT"),
    ];
    known
        .into_iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect()
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?))
}
