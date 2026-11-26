//! x86 and x64 instruction decoding with Intel, MASM and NASM formatting.
//!
//! The decoder is a hand-written, table-driven implementation that covers the
//! encodings commonly found in PE and Mach-O code. Unknown or malformed
//! encodings fail safe to a single-byte `.byte` instruction.

#![warn(missing_docs)]

mod format;
mod modrm;
mod opcode;
mod operand;
mod prefix;
mod vex;

use format::render;
use opcode::Ctx;
use operand::Operand;
use prefix::Reader;

/// Assembly syntax used when rendering an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    /// Intel syntax.
    Intel,
    /// MASM syntax.
    Masm,
    /// NASM syntax.
    Nasm,
}

/// Result of decoding the opcode and its operands.
pub(crate) struct Decoded {
    /// Mnemonic, possibly decorated with a `lock` or `rep` prefix.
    pub(crate) mnemonic: String,
    /// Decoded operands in Intel operand order.
    pub(crate) operands: Vec<Operand>,
}

impl Decoded {
    /// Builds an instruction with no operands.
    pub(crate) fn bare(mnemonic: &'static str) -> Self {
        Self { mnemonic: mnemonic.to_string(), operands: Vec::new() }
    }

    /// Builds an instruction from a mnemonic and operands.
    pub(crate) fn new(mnemonic: &'static str, operands: Vec<Operand>) -> Self {
        Self { mnemonic: mnemonic.to_string(), operands }
    }
}

/// One decoded instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Address of the instruction.
    pub ip: u64,
    /// Encoded length in bytes.
    pub len: usize,
    /// Whether the bytes could not be decoded.
    invalid: bool,
    /// Rendered text in Intel syntax.
    intel: String,
    /// Rendered text in MASM syntax.
    masm: String,
    /// Rendered text in NASM syntax.
    nasm: String,
}

impl Instruction {
    /// Returns the rendered text in `syntax`.
    pub fn format(&self, syntax: Syntax) -> &str {
        match syntax {
            Syntax::Intel => &self.intel,
            Syntax::Masm => &self.masm,
            Syntax::Nasm => &self.nasm,
        }
    }

    /// Address of the instruction.
    pub fn ip(&self) -> u64 {
        self.ip
    }

    /// Encoded length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the bytes could not be decoded.
    pub fn is_invalid(&self) -> bool {
        self.invalid
    }
}

/// Streams instructions out of a byte slice.
pub struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
    ip: u64,
    bitness: u32,
}

impl<'a> Decoder<'a> {
    /// Creates a decoder over `bytes` with the given bitness and first address.
    pub fn new(bitness: u32, bytes: &'a [u8], ip: u64) -> Self {
        Self { bytes, position: 0, ip, bitness }
    }

    /// Current byte position.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Address of the next instruction.
    pub fn ip(&self) -> u64 {
        self.ip
    }

    /// Moves the cursor to `position`.
    pub fn set_position(&mut self, position: usize) {
        self.position = position.min(self.bytes.len());
    }

    /// Sets the address of the next instruction.
    pub fn set_ip(&mut self, ip: u64) {
        self.ip = ip;
    }

    /// Returns whether at least one byte remains.
    pub fn can_decode(&self) -> bool {
        self.position < self.bytes.len()
    }

    /// Decodes the next instruction.
    pub fn decode(&mut self) -> Instruction {
        let start = self.position;
        let ip = self.ip;
        if start >= self.bytes.len() {
            self.position = self.bytes.len();
            return Instruction { ip, len: 0, invalid: true, intel: String::new(), masm: String::new(), nasm: String::new() };
        }

        let mut reader = Reader::new(self.bytes, start);
        let prefixes = prefix::read_prefixes(&mut reader, self.bitness);
        let ctx = Ctx::new(self.bitness, prefixes, start, ip);
        let decoded = opcode::decode(&mut reader, ctx).ok();
        if decoded.is_none() {
            reader.pos = start + 1;
        }

        let len = reader.pos - start;
        let (mnemonic, operands, invalid) = match decoded {
            Some(decoded) => (decoded.mnemonic, decoded.operands, false),
            None => (String::new(), Vec::<Operand>::new(), true),
        };
        let intel =
            if invalid { format!(".byte 0x{:02x}", self.bytes[start]) } else { render(Syntax::Intel, &mnemonic, &operands) };
        let masm =
            if invalid { format!(".byte 0x{:02x}", self.bytes[start]) } else { render(Syntax::Masm, &mnemonic, &operands) };
        let nasm =
            if invalid { format!(".byte 0x{:02x}", self.bytes[start]) } else { render(Syntax::Nasm, &mnemonic, &operands) };

        self.position = reader.pos;
        self.ip = self.ip.wrapping_add(len as u64);
        Instruction { ip, len, invalid, intel, masm, nasm }
    }
}
