//! Legacy prefix, REX and byte cursor handling.

/// Cursor over the encoded instruction bytes.
pub(crate) struct Reader<'a> {
    /// Encoded bytes of the whole code block.
    pub bytes: &'a [u8],
    /// Offset of the next unread byte.
    pub pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader positioned at `pos`.
    pub(crate) fn new(bytes: &'a [u8], pos: usize) -> Self {
        Self { bytes, pos }
    }

    /// Returns the next byte without consuming it.
    pub(crate) fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Consumes and returns the next byte.
    pub(crate) fn byte(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    /// Consumes a little-endian `u16`.
    pub(crate) fn u16(&mut self) -> Option<u16> {
        let low = u16::from(self.byte()?);
        let high = u16::from(self.byte()?);
        Some(low | high << 8)
    }

    /// Consumes a little-endian `u32`.
    pub(crate) fn u32(&mut self) -> Option<u32> {
        let low = u32::from(self.u16()?);
        let high = u32::from(self.u16()?);
        Some(low | high << 16)
    }

    /// Consumes a little-endian `u64`.
    pub(crate) fn u64(&mut self) -> Option<u64> {
        let low = u64::from(self.u32()?);
        let high = u64::from(self.u32()?);
        Some(low | high << 32)
    }
}

/// Decoded legacy prefixes and REX state.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Prefixes {
    /// REX byte, or `0` when absent.
    pub(crate) rex: u8,
    /// Operand-size override (`0x66`).
    pub(crate) opsize: bool,
    /// Address-size override (`0x67`).
    pub(crate) addrsize: bool,
    /// Repeated string prefix (`0xF2` or `0xF3`).
    pub(crate) rep: Option<u8>,
    /// Lock prefix (`0xF0`).
    pub(crate) lock: bool,
    /// Segment override mnemonic.
    pub(crate) seg: Option<&'static str>,
}

impl Prefixes {
    /// Returns whether any REX prefix was present.
    pub(crate) fn has_rex(&self) -> bool {
        self.rex != 0
    }

    /// REX.W bit.
    pub(crate) fn w(&self) -> bool {
        self.rex & 0x08 != 0
    }

    /// REX.R bit.
    pub(crate) fn r(&self) -> bool {
        self.rex & 0x04 != 0
    }

    /// REX.X bit.
    pub(crate) fn x(&self) -> bool {
        self.rex & 0x02 != 0
    }

    /// REX.B bit.
    pub(crate) fn b(&self) -> bool {
        self.rex & 0x01 != 0
    }
}

/// Consumes all leading prefixes.
pub(crate) fn read_prefixes(r: &mut Reader<'_>, bitness: u32) -> Prefixes {
    let mut p = Prefixes::default();
    loop {
        let Some(byte) = r.peek()
        else {
            break;
        };
        match byte {
            0x66 => {
                p.opsize = true;
                p.rex = 0;
            }
            0x67 => {
                p.addrsize = true;
                p.rex = 0;
            }
            0xF0 => {
                p.lock = true;
                p.rex = 0;
            }
            0xF2 | 0xF3 => {
                p.rep = Some(byte);
                p.rex = 0;
            }
            0x2E => {
                p.seg = Some("cs");
                p.rex = 0;
            }
            0x36 => {
                p.seg = Some("ss");
                p.rex = 0;
            }
            0x3E => {
                p.seg = Some("ds");
                p.rex = 0;
            }
            0x26 => {
                p.seg = Some("es");
                p.rex = 0;
            }
            0x64 => {
                p.seg = Some("fs");
                p.rex = 0;
            }
            0x65 => {
                p.seg = Some("gs");
                p.rex = 0;
            }
            0x40..=0x4F if bitness == 64 => {
                p.rex = byte;
            }
            _ => break,
        }
        r.pos += 1;
    }
    p
}

/// Effective operand size of an instruction, ignoring per-opcode overrides.
pub(crate) fn operand_size(bitness: u32, p: &Prefixes) -> u32 {
    if bitness == 64 {
        if p.w() {
            64
        }
        else if p.opsize {
            16
        }
        else {
            32
        }
    }
    else if p.opsize {
        16
    }
    else {
        32
    }
}

/// Effective address size of an instruction.
pub(crate) fn address_size(bitness: u32, p: &Prefixes) -> u32 {
    if bitness == 64 {
        if p.addrsize { 32 } else { 64 }
    }
    else if p.addrsize {
        16
    }
    else {
        32
    }
}
