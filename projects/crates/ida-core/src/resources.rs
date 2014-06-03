//! PE resource directory enumeration.
//!
//! Walks the three-level `IMAGE_RESOURCE_DIRECTORY` tree (type, name,
//! language) and reports the leaf data entries. The pinned PE reader exposes
//! the resource directory but not its contents, so the tree is decoded here.

use data_binary_inspect::{BinaryFormat, BinarySession};
use data_binary_pe::pe;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

const DIRECTORY_RESOURCE: usize = 2;
const MAX_RESOURCES: usize = 256;
const MAX_NODES: usize = 8192;

/// One leaf data entry of the resource tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeResource {
    /// Resource type: a standard name (`VERSION`, `MANIFEST`, ...), a custom
    /// type name, or `#<id>`.
    pub resource_type: String,
    /// Resource name: a custom name or `#<id>`.
    pub name: String,
    /// Language id; `0` when the language level used a string name.
    pub language: u32,
    /// `RVA` of the payload.
    pub data_rva: u32,
    /// Payload size in bytes.
    pub size: u32,
    /// Code page recorded in the data entry.
    pub code_page: u32,
}

/// Bounded resource directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesReport {
    /// Whether the image has a resource directory at all.
    pub present: bool,
    /// Leaf entries that survived the limit, in tree order.
    pub resources: Vec<PeResource>,
    /// Number of leaf entries declared by the tree.
    pub total: usize,
    /// Whether the listing was cut by the limit or a node budget.
    pub truncated: bool,
}

/// Decodes the PE resource directory of one session.
pub(crate) fn analyze(session: &BinarySession) -> Result<ResourcesReport> {
    if session.format() != BinaryFormat::Pe {
        return Err(IdaError::unsupported("PE resources require a PE container"));
    }
    let bytes = session.read(0, session.size())?;
    let image = pe::parse_pe(bytes).map_err(|error| IdaError::parse(format!("PE: {error}")))?;
    let directory = image.optional.data_directories[DIRECTORY_RESOURCE];
    if directory.rva == 0 || directory.size == 0 {
        return Ok(ResourcesReport { present: false, resources: Vec::new(), total: 0, truncated: false });
    }
    let base = pe::rva_to_offset(&image.sections, directory.rva)
        .map_err(|error| IdaError::parse(format!("PE resources: {error}")))? as usize;

    let mut walk = Walk { bytes, base, visited: 0, total: 0, resources: Vec::new(), truncated: false };
    let mut path = Vec::new();
    walk.directory(0, 0, &mut path)?;

    Ok(ResourcesReport {
        present: true,
        resources: walk.resources,
        total: walk.total,
        truncated: walk.truncated,
    })
}

enum Node {
    Id(u32),
    Name(String),
}

struct Walk<'a> {
    bytes: &'a [u8],
    base: usize,
    visited: usize,
    total: usize,
    resources: Vec<PeResource>,
    truncated: bool,
}

impl Walk<'_> {
    fn directory(&mut self, offset: u32, depth: usize, path: &mut Vec<Node>) -> Result<()> {
        self.visited += 1;
        if self.visited > MAX_NODES {
            self.truncated = true;
            return Ok(());
        }
        let at = self.base.saturating_add(offset as usize);
        let named = read_u16(self.bytes, at + 12)?;
        let ids = read_u16(self.bytes, at + 14)?;
        for index in 0..usize::from(named).saturating_add(usize::from(ids)) {
            let entry = at.saturating_add(16).saturating_add(index.saturating_mul(8));
            let name_field = read_u32(self.bytes, entry)?;
            let target = read_u32(self.bytes, entry + 4)?;
            let node = if name_field & 0x8000_0000 != 0 {
                Node::Name(self.string(name_field & 0x7fff_ffff)?)
            } else {
                Node::Id(name_field)
            };
            if target & 0x8000_0000 != 0 {
                path.push(node);
                self.directory(target & 0x7fff_ffff, depth + 1, path)?;
                path.pop();
            } else if depth >= 2 {
                self.leaf(target, path, node)?;
            }
        }
        Ok(())
    }

    fn leaf(&mut self, offset: u32, path: &[Node], language: Node) -> Result<()> {
        self.total += 1;
        if self.resources.len() >= MAX_RESOURCES {
            self.truncated = true;
            return Ok(());
        }
        let Some(resource_type) = path.first() else {
            return Ok(());
        };
        let Some(name) = path.get(1) else {
            return Ok(());
        };
        let at = self.base.saturating_add(offset as usize);
        let data_rva = read_u32(self.bytes, at)?;
        let size = read_u32(self.bytes, at + 4)?;
        let code_page = read_u32(self.bytes, at + 8)?;
        self.resources.push(PeResource {
            resource_type: render_type(resource_type),
            name: render_name(name),
            language: match language {
                Node::Id(id) => id,
                Node::Name(_) => 0,
            },
            data_rva,
            size,
            code_page,
        });
        Ok(())
    }

    fn string(&self, offset: u32) -> Result<String> {
        let at = self.base.saturating_add(offset as usize);
        let length = usize::from(read_u16(self.bytes, at)?);
        let start = at.saturating_add(2);
        let end = start.saturating_add(length.saturating_mul(2));
        let raw = self
            .bytes
            .get(start..end)
            .ok_or_else(|| IdaError::parse("a resource directory string lies outside the file"))?;
        let mut units = Vec::with_capacity(length);
        for index in 0..length {
            units.push(u16::from_le_bytes([raw[index * 2], raw[index * 2 + 1]]));
        }
        Ok(String::from_utf16_lossy(&units))
    }
}

fn render_type(node: &Node) -> String {
    match node {
        Node::Name(name) => name.clone(),
        Node::Id(id) => type_name(*id).map_or_else(|| format!("#{id}"), str::to_string),
    }
}

fn render_name(node: &Node) -> String {
    match node {
        Node::Name(name) => name.clone(),
        Node::Id(id) => format!("#{id}"),
    }
}

fn type_name(id: u32) -> Option<&'static str> {
    Some(match id {
        1 => "CURSOR",
        2 => "BITMAP",
        3 => "ICON",
        4 => "MENU",
        5 => "DIALOG",
        6 => "STRING",
        7 => "FONTDIR",
        8 => "FONT",
        9 => "ACCELERATOR",
        10 => "RCDATA",
        11 => "MESSAGETABLE",
        12 => "GROUP_CURSOR",
        14 => "GROUP_ICON",
        16 => "VERSION",
        17 => "DLGINCLUDE",
        19 => "PLUGPLAY",
        20 => "VXD",
        21 => "ANICURSOR",
        22 => "ANIICON",
        23 => "HTML",
        24 => "MANIFEST",
        _ => return None,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw: [u8; 2] = bytes
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| IdaError::parse("a resource directory entry lies outside the file"))?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| IdaError::parse("a resource directory entry lies outside the file"))?;
    Ok(u32::from_le_bytes(raw))
}
