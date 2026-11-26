//! One-byte opcode map and the helpers shared by every opcode map.
//!
//! The one-byte map lives here; the two-byte `0F` map is in [`map0f`], the SSE
//! and packed-integer helpers in [`sse`], and the three-byte `0F 38` / `0F 3A`
//! maps in [`map38`].

use crate::{
    Decoded,
    modrm::{self, ModRm},
    operand::{Mem, Operand, Reg, RegKind},
    prefix::{self, Prefixes, Reader},
};

mod map0f;
mod map38;
mod sse;

use self::map0f::decode_0f;

/// Decoding state shared by every opcode map.
#[derive(Clone, Copy)]
pub(crate) struct Ctx {
    /// Decoder bitness, either 32 or 64.
    pub(crate) bitness: u32,
    /// Legacy prefixes and REX bits.
    pub(crate) p: Prefixes,
    /// Effective operand size in bits.
    pub(crate) op_size: u32,
    /// Byte position where the instruction starts.
    pub(crate) start: usize,
    /// Address of the instruction.
    pub(crate) ip: u64,
}

impl Ctx {
    /// Builds a decoding context from the parsed prefixes.
    pub(crate) fn new(bitness: u32, p: Prefixes, start: usize, ip: u64) -> Self {
        let op_size = prefix::operand_size(bitness, &p);
        Self { bitness, p, op_size, start, ip }
    }

    /// General purpose register operand with the effective operand size.
    pub(crate) fn reg(&self, size: u32, num: u8) -> Operand {
        Operand::Reg(modrm::gpr(size, num, &self.p))
    }

    /// Register number of the ModRM reg field including REX.R.
    pub(crate) fn reg_num(&self, m: &ModRm) -> u8 {
        if self.p.r() { m.reg | 8 } else { m.reg }
    }

    /// Register number of the ModRM rm field including REX.B.
    pub(crate) fn rm_num(&self, m: &ModRm) -> u8 {
        if self.p.b() { m.rm | 8 } else { m.rm }
    }

    /// Computes the absolute target of a relative branch.
    pub(crate) fn rel(&self, r: &Reader<'_>, disp: i64) -> u64 {
        let after = self.ip.wrapping_add((r.pos - self.start) as u64);
        after.wrapping_add(disp as u64)
    }

    /// Operand size used by push, pop and near control transfers.
    pub(crate) fn stack_size(&self) -> u32 {
        if self.bitness == 64 { if self.p.opsize { 16 } else { 64 } } else { self.op_size }
    }
}

/// Decodes one instruction starting at the current reader position.
pub(crate) fn decode(r: &mut Reader<'_>, ctx: Ctx) -> Result<Decoded, ()> {
    let opcode = r.byte().ok_or(())?;
    if ctx.bitness == 64 {
        match opcode {
            0xC4 => return crate::vex::decode_vex(r, ctx, false),
            0xC5 => return crate::vex::decode_vex(r, ctx, true),
            0x62 => return crate::vex::decode_evex(r, ctx),
            _ => {}
        }
    }
    let mut decoded = match opcode {
        0x0F => decode_0f(r, ctx)?,
        _ => one_byte(r, ctx, opcode)?,
    };
    if ctx.p.lock {
        decoded.mnemonic.insert_str(0, "lock ");
    }
    Ok(decoded)
}

/// Decorates a string instruction with its repeat prefix.
fn with_rep(ctx: &Ctx, name: &'static str) -> String {
    match ctx.p.rep {
        Some(0xF3) => format!("rep {name}"),
        Some(0xF2) => format!("repne {name}"),
        _ => name.to_string(),
    }
}

/// Builds a string instruction with no explicit operands.
fn string_op(ctx: &Ctx, name: &'static str) -> Decoded {
    Decoded { mnemonic: with_rep(ctx, name), operands: Vec::new() }
}

/// Returns the width-suffixed name of a string instruction.
fn string_width_name(kind: usize, size: u32) -> &'static str {
    const WORD: [&str; 5] = ["movsw", "cmpsw", "stosw", "lodsw", "scasw"];
    const DWORD: [&str; 5] = ["movsd", "cmpsd", "stosd", "lodsd", "scasd"];
    const QWORD: [&str; 5] = ["movsq", "cmpsq", "stosq", "lodsq", "scasq"];
    match size {
        16 => WORD[kind],
        64 => QWORD[kind],
        _ => DWORD[kind],
    }
}

/// Reads an unsigned immediate of `bits` width.
fn imm(r: &mut Reader<'_>, bits: u32) -> Result<u64, ()> {
    match bits {
        8 => r.byte().map(u64::from),
        16 => r.u16().map(u64::from),
        32 => r.u32().map(u64::from),
        64 => r.u64(),
        _ => None,
    }
    .ok_or(())
}

/// Sign-extends `value` from `bits` to 64 bits.
fn sext(value: u64, bits: u32) -> u64 {
    if bits >= 64 {
        return value;
    }
    let shift = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

/// Reads an immediate operand, optionally sign-extending it to `result_bits`.
pub(crate) fn imm_operand(r: &mut Reader<'_>, read_bits: u32, result_bits: u32, signed: bool) -> Result<Operand, ()> {
    let raw = imm(r, read_bits)?;
    let mut value = if signed { sext(raw, read_bits) } else { raw };
    if result_bits < 64 {
        value &= (1u64 << result_bits) - 1;
    }
    Ok(Operand::Imm { size: result_bits, value })
}

/// Reads a ModRM byte plus its memory operand.
fn modrm(r: &mut Reader<'_>, ctx: &Ctx, size: u32) -> Result<(ModRm, Option<Mem>), ()> {
    modrm::read_modrm(r, size, ctx.bitness, &ctx.p)
}

/// Converts the rm half of a ModRM operand into a register or memory operand.
fn rm_operand(ctx: &Ctx, m: &ModRm, mem: Option<Mem>, size: u32) -> Operand {
    match mem {
        Some(mem) => Operand::Mem(mem),
        None => ctx.reg(size, ctx.rm_num(m)),
    }
}

/// Builds a ModRM register operand from the reg field.
fn reg_operand(ctx: &Ctx, m: &ModRm, size: u32) -> Operand {
    ctx.reg(size, ctx.reg_num(m))
}

/// Reads a ModRM operand in `reg, rm` order.
fn reg_rm(r: &mut Reader<'_>, ctx: &Ctx, size: u32) -> Result<(Operand, Operand), ()> {
    let (m, mem) = modrm(r, ctx, size)?;
    Ok((reg_operand(ctx, &m, size), rm_operand(ctx, &m, mem, size)))
}

/// Reads a ModRM operand in `rm, reg` order.
fn rm_reg(r: &mut Reader<'_>, ctx: &Ctx, size: u32) -> Result<(Operand, Operand), ()> {
    let (m, mem) = modrm(r, ctx, size)?;
    Ok((rm_operand(ctx, &m, mem, size), reg_operand(ctx, &m, size)))
}

/// Maps a ModRM reg field to an ALU mnemonic.
fn alu_name(reg: u8) -> &'static str {
    match reg & 7 {
        0 => "add",
        1 => "or",
        2 => "adc",
        3 => "sbb",
        4 => "and",
        5 => "sub",
        6 => "xor",
        _ => "cmp",
    }
}

/// Decodes one of the eight ALU groups at `0x00..=0x3F`.
fn alu(r: &mut Reader<'_>, ctx: &Ctx, opcode: u8) -> Result<Decoded, ()> {
    let name = alu_name(opcode >> 3);
    let form = opcode & 7;
    let size = ctx.op_size;
    let ops = match form {
        0 => {
            let (rm, reg) = rm_reg(r, ctx, 8)?;
            vec![rm, reg]
        }
        1 => {
            let (rm, reg) = rm_reg(r, ctx, size)?;
            vec![rm, reg]
        }
        2 => {
            let (reg, rm) = reg_rm(r, ctx, 8)?;
            vec![reg, rm]
        }
        3 => {
            let (reg, rm) = reg_rm(r, ctx, size)?;
            vec![reg, rm]
        }
        4 => vec![ctx.reg(8, 0), imm_operand(r, 8, 8, false)?],
        5 => {
            let imm_bits = if size == 16 { 16 } else { 32 };
            vec![ctx.reg(size, 0), imm_operand(r, imm_bits, size, size == 64)?]
        }
        _ => return Err(()),
    };
    Ok(Decoded::new(name, ops))
}

/// Decodes the group 1 arithmetic forms (`0x80`, `0x81`, `0x83`).
fn group1(r: &mut Reader<'_>, ctx: &Ctx, opcode: u8) -> Result<Decoded, ()> {
    let (m, mem) = modrm(r, ctx, if opcode == 0x80 { 8 } else { ctx.op_size })?;
    let name = alu_name(m.reg);
    let size = if opcode == 0x80 { 8 } else { ctx.op_size };
    let rm = rm_operand(ctx, &m, mem, size);
    let imm_bits = match opcode {
        0x80 => 8,
        0x81 => {
            if size == 16 {
                16
            }
            else {
                32
            }
        }
        _ => 8,
    };
    let signed = opcode == 0x83 || (opcode == 0x81 && size == 64);
    let imm = imm_operand(r, imm_bits, size, signed)?;
    Ok(Decoded::new(name, vec![rm, imm]))
}

/// Decodes the group 2 shift and rotate forms.
fn group2(r: &mut Reader<'_>, ctx: &Ctx, opcode: u8) -> Result<Decoded, ()> {
    let size = if opcode == 0xC0 || opcode == 0xD0 || opcode == 0xD2 { 8 } else { ctx.op_size };
    let (m, mem) = modrm(r, ctx, size)?;
    let name = match m.reg & 7 {
        0 => "rol",
        1 => "ror",
        2 => "rcl",
        3 => "rcr",
        4 => "shl",
        5 => "shr",
        6 => "sal",
        _ => "sar",
    };
    let rm = rm_operand(ctx, &m, mem, size);
    let count = match opcode {
        0xC0 | 0xC1 => imm_operand(r, 8, 8, false)?,
        0xD2 | 0xD3 => Operand::Reg(Reg::gpr(8, 1, ctx.p.has_rex())),
        _ => Operand::Imm { size: 8, value: 1 },
    };
    Ok(Decoded::new(name, vec![rm, count]))
}

/// Decodes the group 3 forms (`0xF6`, `0xF7`).
fn group3(r: &mut Reader<'_>, ctx: &Ctx, opcode: u8) -> Result<Decoded, ()> {
    let size = if opcode == 0xF6 { 8 } else { ctx.op_size };
    let (m, mem) = modrm(r, ctx, size)?;
    let rm = rm_operand(ctx, &m, mem, size);
    let name = match m.reg & 7 {
        0 | 1 => {
            let imm_bits = if size == 16 { 16 } else { 32 };
            let imm = imm_operand(r, if size == 8 { 8 } else { imm_bits }, size, size == 64)?;
            return Ok(Decoded::new("test", vec![rm, imm]));
        }
        2 => "not",
        3 => "neg",
        4 => "mul",
        5 => "imul",
        6 => "div",
        _ => "idiv",
    };
    Ok(Decoded::new(name, vec![rm]))
}

/// Decodes the group 4 forms (`0xFE`).
fn group4(r: &mut Reader<'_>, ctx: &Ctx) -> Result<Decoded, ()> {
    let (m, mem) = modrm(r, ctx, 8)?;
    let name = match m.reg & 7 {
        0 => "inc",
        1 => "dec",
        _ => return Err(()),
    };
    let rm = rm_operand(ctx, &m, mem, 8);
    Ok(Decoded::new(name, vec![rm]))
}

/// Decodes the group 5 forms (`0xFF`).
fn group5(r: &mut Reader<'_>, ctx: &Ctx) -> Result<Decoded, ()> {
    let stack = ctx.stack_size();
    let (m, mem) = modrm(r, ctx, stack)?;
    let name = match m.reg & 7 {
        0 => "inc",
        1 => "dec",
        2 => "call",
        4 => "jmp",
        6 => "push",
        _ => return Err(()),
    };
    let size = match m.reg & 7 {
        0 | 1 => ctx.op_size,
        _ => stack,
    };
    let rm = match mem {
        Some(mut mem) => {
            mem.size = size;
            Operand::Mem(mem)
        }
        None => ctx.reg(size, ctx.rm_num(&m)),
    };
    Ok(Decoded::new(name, vec![rm]))
}

/// Decodes an opcode from the one-byte map.
fn one_byte(r: &mut Reader<'_>, ctx: Ctx, opcode: u8) -> Result<Decoded, ()> {
    let size = ctx.op_size;
    match opcode {
        0x00..=0x3F => alu(r, &ctx, opcode),
        0x40..=0x4F => {
            if ctx.bitness == 64 {
                return Err(());
            }
            let name = if opcode < 0x48 { "inc" } else { "dec" };
            let num = (opcode & 7) + if ctx.p.b() { 8 } else { 0 };
            Ok(Decoded::new(name, vec![ctx.reg(size, num)]))
        }
        0x50..=0x57 => {
            let num = (opcode & 7) + if ctx.p.b() { 8 } else { 0 };
            let stack = ctx.stack_size();
            Ok(Decoded::new("push", vec![ctx.reg(stack, num)]))
        }
        0x58..=0x5F => {
            let num = (opcode & 7) + if ctx.p.b() { 8 } else { 0 };
            let stack = ctx.stack_size();
            Ok(Decoded::new("pop", vec![ctx.reg(stack, num)]))
        }
        0x60 | 0x61 => {
            if ctx.bitness == 64 {
                return Err(());
            }
            let name = if opcode == 0x60 { "pushad" } else { "popad" };
            Ok(Decoded::bare(if size == 16 { if opcode == 0x60 { "pushaw" } else { "popaw" } } else { name }))
        }
        0x63 => {
            if ctx.bitness == 64 {
                let (m, mem) = modrm(r, &ctx, 32)?;
                let reg = ctx.reg(ctx.op_size, ctx.reg_num(&m));
                let rm = rm_operand(&ctx, &m, mem, 32);
                Ok(Decoded::new("movsxd", vec![reg, rm]))
            }
            else {
                Ok(Decoded::bare("arpl"))
            }
        }
        0x68 => {
            let stack = ctx.stack_size();
            let imm_bits = if stack == 16 { 16 } else { 32 };
            let imm = imm_operand(r, imm_bits, stack, stack == 64)?;
            Ok(Decoded::new("push", vec![imm]))
        }
        0x69 | 0x6B => {
            let (reg, rm) = reg_rm(r, &ctx, size)?;
            let imm_bits = if opcode == 0x6B {
                8
            }
            else if size == 16 {
                16
            }
            else {
                32
            };
            let imm = imm_operand(r, imm_bits, size, opcode == 0x6B || size == 64)?;
            Ok(Decoded::new("imul", vec![reg, rm, imm]))
        }
        0x6A => {
            let stack = ctx.stack_size();
            let imm = imm_operand(r, 8, stack, true)?;
            Ok(Decoded::new("push", vec![imm]))
        }
        0x6C => Ok(string_op(&ctx, "insb")),
        0x6D => Ok(string_op(&ctx, if size == 16 { "insw" } else { "insd" })),
        0x6E => Ok(string_op(&ctx, "outsb")),
        0x6F => Ok(string_op(&ctx, if size == 16 { "outsw" } else { "outsd" })),
        0x70..=0x7F => {
            let name = jcc_name(opcode & 0xF);
            let disp = i64::from(r.byte().ok_or(())? as i8);
            let target = ctx.rel(r, disp);
            Ok(Decoded::new(name, vec![Operand::Rel(target)]))
        }
        0x80..=0x83 => group1(r, &ctx, opcode),
        0x84 | 0x85 => {
            let size = if opcode == 0x84 { 8 } else { size };
            let (rm, reg) = rm_reg(r, &ctx, size)?;
            Ok(Decoded::new("test", vec![rm, reg]))
        }
        0x86 | 0x87 => {
            let size = if opcode == 0x86 { 8 } else { size };
            let (rm, reg) = rm_reg(r, &ctx, size)?;
            Ok(Decoded::new("xchg", vec![rm, reg]))
        }
        0x88 | 0x89 => {
            let size = if opcode == 0x88 { 8 } else { size };
            let (rm, reg) = rm_reg(r, &ctx, size)?;
            Ok(Decoded::new("mov", vec![rm, reg]))
        }
        0x8A | 0x8B => {
            let size = if opcode == 0x8A { 8 } else { size };
            let (reg, rm) = reg_rm(r, &ctx, size)?;
            Ok(Decoded::new("mov", vec![reg, rm]))
        }
        0x8C => {
            let (m, mem) = modrm(r, &ctx, 16)?;
            let rm = rm_operand(&ctx, &m, mem, 16);
            let seg = Operand::Reg(Reg { kind: RegKind::Seg, size: 16, num: m.reg & 7, rex: false });
            Ok(Decoded::new("mov", vec![rm, seg]))
        }
        0x8D => {
            let (m, mem) = modrm(r, &ctx, 0)?;
            let Some(mem) = mem
            else {
                return Err(());
            };
            Ok(Decoded::new("lea", vec![ctx.reg(size, ctx.reg_num(&m)), Operand::Mem(mem)]))
        }
        0x8E => {
            let (m, mem) = modrm(r, &ctx, 16)?;
            let rm = rm_operand(&ctx, &m, mem, 16);
            let seg = Operand::Reg(Reg { kind: RegKind::Seg, size: 16, num: m.reg & 7, rex: false });
            Ok(Decoded::new("mov", vec![seg, rm]))
        }
        0x8F => {
            let (m, mem) = modrm(r, &ctx, ctx.stack_size())?;
            if m.reg & 7 != 0 {
                return Err(());
            }
            let rm = rm_operand(&ctx, &m, mem, ctx.stack_size());
            Ok(Decoded::new("pop", vec![rm]))
        }
        0x90 => {
            if ctx.p.b() {
                let stack = ctx.stack_size();
                Ok(Decoded::new("xchg", vec![ctx.reg(stack, 0), ctx.reg(stack, 8)]))
            }
            else if ctx.p.rep == Some(0xF3) {
                Ok(Decoded::bare("pause"))
            }
            else if ctx.p.opsize {
                Ok(Decoded::new("xchg", vec![ctx.reg(16, 0), ctx.reg(16, 0)]))
            }
            else {
                Ok(Decoded::bare("nop"))
            }
        }
        0x91..=0x97 => {
            let num = (opcode & 7) + if ctx.p.b() { 8 } else { 0 };
            Ok(Decoded::new("xchg", vec![ctx.reg(size, 0), ctx.reg(size, num)]))
        }
        0x98 => {
            let name = match size {
                16 => "cbw",
                64 => "cdqe",
                _ => "cwde",
            };
            Ok(Decoded::bare(name))
        }
        0x99 => {
            let name = match size {
                16 => "cwd",
                64 => "cqo",
                _ => "cdq",
            };
            Ok(Decoded::bare(name))
        }
        0x9B => Ok(Decoded::bare("wait")),
        0x9C => Ok(Decoded::bare(match ctx.stack_size() {
            16 => "pushf",
            64 => "pushfq",
            _ => "pushfd",
        })),
        0x9D => Ok(Decoded::bare(match ctx.stack_size() {
            16 => "popf",
            64 => "popfq",
            _ => "popfd",
        })),
        0x9E => Ok(Decoded::bare("sahf")),
        0x9F => Ok(Decoded::bare("lahf")),
        0xA0 | 0xA1 | 0xA2 | 0xA3 => moffs(r, &ctx, opcode),
        0xA4 => Ok(string_op(&ctx, "movsb")),
        0xA5 => Ok(string_op(&ctx, string_width_name(0, size))),
        0xA6 => Ok(string_op(&ctx, "cmpsb")),
        0xA7 => Ok(string_op(&ctx, string_width_name(1, size))),
        0xA8 => {
            let imm = imm_operand(r, 8, 8, false)?;
            Ok(Decoded::new("test", vec![ctx.reg(8, 0), imm]))
        }
        0xA9 => {
            let imm_bits = if size == 16 { 16 } else { 32 };
            let imm = imm_operand(r, imm_bits, size, size == 64)?;
            Ok(Decoded::new("test", vec![ctx.reg(size, 0), imm]))
        }
        0xAA => Ok(string_op(&ctx, "stosb")),
        0xAB => Ok(string_op(&ctx, string_width_name(2, size))),
        0xAC => Ok(string_op(&ctx, "lodsb")),
        0xAD => Ok(string_op(&ctx, string_width_name(3, size))),
        0xAE => Ok(string_op(&ctx, "scasb")),
        0xAF => Ok(string_op(&ctx, string_width_name(4, size))),
        0xB0..=0xB7 => {
            let num = (opcode & 7) + if ctx.p.b() { 8 } else { 0 };
            let imm = imm_operand(r, 8, 8, false)?;
            Ok(Decoded::new("mov", vec![ctx.reg(8, num), imm]))
        }
        0xB8..=0xBF => {
            let num = (opcode & 7) + if ctx.p.b() { 8 } else { 0 };
            let imm_bits = match size {
                16 => 16,
                64 => 64,
                _ => 32,
            };
            let imm = imm_operand(r, imm_bits, size, false)?;
            Ok(Decoded::new("mov", vec![ctx.reg(size, num), imm]))
        }
        0xC0 | 0xC1 | 0xD0..=0xD3 => group2(r, &ctx, opcode),
        0xC2 => {
            let imm = imm_operand(r, 16, 16, false)?;
            Ok(Decoded::new("ret", vec![imm]))
        }
        0xC3 => Ok(Decoded::bare("ret")),
        0xC6 | 0xC7 => {
            let size = if opcode == 0xC6 { 8 } else { size };
            let (m, mem) = modrm(r, &ctx, size)?;
            if m.reg & 7 != 0 {
                return Err(());
            }
            let rm = rm_operand(&ctx, &m, mem, size);
            let imm_bits = if size == 8 {
                8
            }
            else if size == 16 {
                16
            }
            else {
                32
            };
            let imm = imm_operand(r, imm_bits, size, size == 64)?;
            Ok(Decoded::new("mov", vec![rm, imm]))
        }
        0xC8 => {
            let imm = imm_operand(r, 16, 16, false)?;
            let level = imm_operand(r, 8, 8, false)?;
            Ok(Decoded::new("enter", vec![imm, level]))
        }
        0xC9 => Ok(Decoded::bare("leave")),
        0xCA => {
            let imm = imm_operand(r, 16, 16, false)?;
            Ok(Decoded::new("retf", vec![imm]))
        }
        0xCB => Ok(Decoded::bare("retf")),
        0xCC => Ok(Decoded::bare("int3")),
        0xCD => {
            let imm = imm_operand(r, 8, 8, false)?;
            Ok(Decoded::new("int", vec![imm]))
        }
        0xCF => Ok(Decoded::bare(match ctx.stack_size() {
            16 => "iret",
            64 => "iretq",
            _ => "iretd",
        })),
        0xD7 => Ok(Decoded::bare("xlatb")),
        0xE0..=0xE3 => {
            let name = match opcode {
                0xE0 => "loopne",
                0xE1 => "loope",
                0xE2 => "loop",
                _ => match prefix::address_size(ctx.bitness, &ctx.p) {
                    16 => "jcxz",
                    32 => "jecxz",
                    _ => "jrcxz",
                },
            };
            let disp = i64::from(r.byte().ok_or(())? as i8);
            let target = ctx.rel(r, disp);
            Ok(Decoded::new(name, vec![Operand::Rel(target)]))
        }
        0xE4 | 0xE5 => {
            let imm = imm_operand(r, 8, 8, false)?;
            let size = if opcode == 0xE4 { 8 } else { size };
            Ok(Decoded::new("in", vec![ctx.reg(size, 0), imm]))
        }
        0xE6 | 0xE7 => {
            let imm = imm_operand(r, 8, 8, false)?;
            let size = if opcode == 0xE6 { 8 } else { size };
            Ok(Decoded::new("out", vec![imm, ctx.reg(size, 0)]))
        }
        0xE8 | 0xE9 => {
            let disp = i64::from(r.u32().ok_or(())? as i32);
            let target = ctx.rel(r, disp);
            let name = if opcode == 0xE8 { "call" } else { "jmp" };
            Ok(Decoded::new(name, vec![Operand::Rel(target)]))
        }
        0xEB => {
            let disp = i64::from(r.byte().ok_or(())? as i8);
            let target = ctx.rel(r, disp);
            Ok(Decoded::new("jmp", vec![Operand::Rel(target)]))
        }
        0xEC | 0xED => {
            let size = if opcode == 0xEC { 8 } else { size };
            Ok(Decoded::new("in", vec![ctx.reg(size, 0), Operand::Reg(Reg::gpr(16, 2, false))]))
        }
        0xEE | 0xEF => {
            let size = if opcode == 0xEE { 8 } else { size };
            Ok(Decoded::new("out", vec![Operand::Reg(Reg::gpr(16, 2, false)), ctx.reg(size, 0)]))
        }
        0xF1 => Ok(Decoded::bare("int1")),
        0xF4 => Ok(Decoded::bare("hlt")),
        0xF5 => Ok(Decoded::bare("cmc")),
        0xF6 | 0xF7 => group3(r, &ctx, opcode),
        0xF8 => Ok(Decoded::bare("clc")),
        0xF9 => Ok(Decoded::bare("stc")),
        0xFA => Ok(Decoded::bare("cli")),
        0xFB => Ok(Decoded::bare("sti")),
        0xFC => Ok(Decoded::bare("cld")),
        0xFD => Ok(Decoded::bare("std")),
        0xFE => group4(r, &ctx),
        0xFF => group5(r, &ctx),
        _ => Err(()),
    }
}

/// Returns the mnemonic of a condition code.
fn jcc_name(condition: u8) -> &'static str {
    const JCC: [&str; 16] =
        ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"];
    JCC[usize::from(condition & 15)]
}

/// Decodes the `moffs` forms (`0xA0..=0xA3`).
fn moffs(r: &mut Reader<'_>, ctx: &Ctx, opcode: u8) -> Result<Decoded, ()> {
    let addr = prefix::address_size(ctx.bitness, &ctx.p);
    let address = match addr {
        16 => u64::from(r.u16().ok_or(())?),
        32 => u64::from(r.u32().ok_or(())?),
        _ => r.u64().ok_or(())?,
    };
    let size = if opcode & 1 == 0 { 8 } else { ctx.op_size };
    let mut mem = Mem::new(size);
    mem.seg = ctx.p.seg;
    mem.absolute = true;
    mem.disp = address as i64;
    if opcode < 0xA2 {
        Ok(Decoded::new("mov", vec![ctx.reg(size, 0), Operand::Mem(mem)]))
    }
    else {
        Ok(Decoded::new("mov", vec![Operand::Mem(mem), ctx.reg(size, 0)]))
    }
}
