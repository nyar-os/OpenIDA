//! Operands, registers and memory references shared by decoder and formatters.

/// Register families produced by the decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegKind {
    /// General purpose register.
    Gpr,
    /// 64-bit MMX register.
    Mm,
    /// 128-bit SSE register.
    Xmm,
    /// 256-bit AVX register.
    Ymm,
    /// 512-bit AVX-512 register.
    Zmm,
    /// Segment register.
    Seg,
    /// Control register.
    Cr,
    /// Debug register.
    Dr,
}

/// One register operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Reg {
    /// Register family.
    pub kind: RegKind,
    /// Operand size in bits. Ignored for vector registers.
    pub size: u32,
    /// Register number, `0..31`.
    pub num: u8,
    /// Whether a REX prefix was used, which renames the low byte registers.
    pub rex: bool,
}

const GPR8: [&str; 16] =
    ["al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"];
const GPR8_LEGACY: [&str; 8] = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"];
const GPR16: [&str; 16] =
    ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"];
const GPR32: [&str; 16] =
    ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"];
const GPR64: [&str; 16] =
    ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];

impl Reg {
    /// Builds a general purpose register.
    pub(crate) fn gpr(size: u32, num: u8, rex: bool) -> Self {
        Self { kind: RegKind::Gpr, size, num, rex }
    }

    /// Builds a vector register of `kind`.
    pub(crate) fn vec(kind: RegKind, num: u8) -> Self {
        Self { kind, size: 0, num, rex: false }
    }

    /// Rendered register name.
    pub(crate) fn text(self) -> String {
        match self.kind {
            RegKind::Gpr => {
                let n = usize::from(self.num & 15);
                match self.size {
                    8 => {
                        if self.num >= 8 || self.rex {
                            GPR8[n].to_string()
                        }
                        else {
                            GPR8_LEGACY[n].to_string()
                        }
                    }
                    16 => GPR16[n].to_string(),
                    32 => GPR32[n].to_string(),
                    _ => GPR64[n].to_string(),
                }
            }
            RegKind::Mm => format!("mm{}", self.num & 7),
            RegKind::Xmm => format!("xmm{}", self.num),
            RegKind::Ymm => format!("ymm{}", self.num),
            RegKind::Zmm => format!("zmm{}", self.num),
            RegKind::Seg => {
                const SEG: [&str; 6] = ["es", "cs", "ss", "ds", "fs", "gs"];
                SEG[usize::from(self.num.min(5))].to_string()
            }
            RegKind::Cr => format!("cr{}", self.num),
            RegKind::Dr => format!("dr{}", self.num),
        }
    }
}

/// One memory reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mem {
    /// Access size in bits, or `0` when the instruction implies no size.
    pub size: u32,
    /// Segment override, if any.
    pub seg: Option<&'static str>,
    /// Base register name.
    pub base: Option<String>,
    /// Index register name.
    pub index: Option<String>,
    /// Index scale, always a power of two.
    pub scale: u8,
    /// Signed displacement.
    pub disp: i64,
    /// Whether the effective address is RIP-relative.
    pub rip: bool,
    /// Whether the effective address is an absolute displacement.
    pub absolute: bool,
}

impl Mem {
    /// Builds an empty 64-bit memory reference.
    pub(crate) fn new(size: u32) -> Self {
        Self { size, seg: None, base: None, index: None, scale: 1, disp: 0, rip: false, absolute: false }
    }
}

/// One decoded operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Operand {
    /// Register operand.
    Reg(Reg),
    /// Memory operand.
    Mem(Mem),
    /// Immediate operand, already sign-extended to `size` bits.
    Imm {
        /// Width of the immediate in bits.
        size: u32,
        /// Immediate value, zero-extended in the `u64`.
        value: u64,
    },
    /// Branch target as an absolute address.
    Rel(u64),
}
