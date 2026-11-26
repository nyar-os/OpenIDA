//! VEX and EVEX encoded vector instructions.

use crate::{
    Decoded,
    modrm::{self, ModRm},
    opcode::{Ctx, imm_operand},
    operand::{Mem, Operand, Reg, RegKind},
    prefix::Reader,
};

/// Decoded VEX or EVEX prefix fields.
#[derive(Clone, Copy)]
struct Vex {
    /// Opcode map: `1` is `0F`, `2` is `0F 38`, `3` is `0F 3A`.
    map: u8,
    /// Mandatory prefix: `0` none, `1` `0x66`, `2` `0xF3`, `3` `0xF2`.
    pp: u8,
    /// Vector length: `0` 128-bit, `1` 256-bit, `2` 512-bit.
    l: u8,
    /// W bit.
    w: bool,
    /// Non-destructive source register.
    vvvv: u8,
    /// Extension bit for the ModRM reg field (8).
    r: bool,
    /// Extension bit for the SIB index field.
    x: bool,
    /// Extension bit for the ModRM rm field.
    b: bool,
    /// EVEX extension bit for the ModRM reg field (16).
    r2: bool,
    /// Whether the instruction uses an EVEX prefix.
    evex: bool,
}

impl Vex {
    /// Vector register family selected by the length field.
    fn kind(&self) -> RegKind {
        match self.l {
            0 => RegKind::Xmm,
            1 => RegKind::Ymm,
            _ => RegKind::Zmm,
        }
    }

    /// Vector width in bits.
    fn bits(&self) -> u32 {
        128 << self.l
    }
}

/// Builds a vector register operand.
fn vreg(kind: RegKind, num: u8) -> Operand {
    Operand::Reg(Reg::vec(kind, num))
}

/// Builds the ModRM reg operand.
fn reg_operand(v: &Vex, m: &ModRm) -> Operand {
    let num = m.reg + if v.r { 8 } else { 0 } + if v.evex && v.r2 { 16 } else { 0 };
    vreg(v.kind(), num)
}

/// Builds the ModRM rm operand when it selects a register.
fn rm_operand(v: &Vex, m: &ModRm) -> Operand {
    let num = m.rm + if v.b { 8 } else { 0 } + if v.evex && v.x { 16 } else { 0 };
    vreg(v.kind(), num)
}

/// Builds the non-destructive source operand.
fn vvvv_operand(v: &Vex) -> Operand {
    vreg(v.kind(), v.vvvv)
}

/// Rewrites the prefix context so shared ModRM helpers see the VEX bits.
fn vex_ctx(ctx: &Ctx, v: &Vex) -> Ctx {
    let mut p = ctx.p;
    p.rex = (if v.w { 8 } else { 0 }) | (if v.r { 4 } else { 0 }) | (if v.x { 2 } else { 0 }) | (if v.b { 1 } else { 0 });
    p.opsize = v.pp == 1;
    p.rep = match v.pp {
        2 => Some(0xF3),
        3 => Some(0xF2),
        _ => None,
    };
    Ctx::new(ctx.bitness, p, ctx.start, ctx.ip)
}

/// Reads a ModRM byte for a vector instruction.
fn read_rm(r: &mut Reader<'_>, ctx: &Ctx, bits: u32) -> Result<(ModRm, Option<Mem>), ()> {
    modrm::read_modrm(r, bits, ctx.bitness, &ctx.p)
}

/// Decodes a two-operand `reg, rm` vector instruction.
fn v2(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, name: &'static str, bits: u32) -> Result<Decoded, ()> {
    let (m, mem) = read_rm(r, ctx, bits)?;
    let dst = reg_operand(v, &m);
    let src = match mem {
        Some(mem) => Operand::Mem(mem),
        None => rm_operand(v, &m),
    };
    Ok(Decoded::new(name, vec![dst, src]))
}

/// Decodes a two-operand `rm, reg` vector instruction.
fn v2_store(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, name: &'static str, bits: u32) -> Result<Decoded, ()> {
    let (m, mem) = read_rm(r, ctx, bits)?;
    let src = reg_operand(v, &m);
    let dst = match mem {
        Some(mem) => Operand::Mem(mem),
        None => rm_operand(v, &m),
    };
    Ok(Decoded::new(name, vec![dst, src]))
}

/// Decodes a three-operand `reg, vvvv, rm` vector instruction.
fn v3(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, name: &'static str, bits: u32) -> Result<Decoded, ()> {
    let (m, mem) = read_rm(r, ctx, bits)?;
    let dst = reg_operand(v, &m);
    let src2 = vvvv_operand(v);
    let src1 = match mem {
        Some(mem) => Operand::Mem(mem),
        None => rm_operand(v, &m),
    };
    Ok(Decoded::new(name, vec![dst, src2, src1]))
}

/// Decodes a `reg, rm, imm8` vector instruction.
fn v2_imm(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, name: &'static str, bits: u32) -> Result<Decoded, ()> {
    let (m, mem) = read_rm(r, ctx, bits)?;
    let dst = reg_operand(v, &m);
    let src = match mem {
        Some(mem) => Operand::Mem(mem),
        None => rm_operand(v, &m),
    };
    let imm = imm_operand(r, 8, 8, false)?;
    Ok(Decoded::new(name, vec![dst, src, imm]))
}

/// Decodes a `reg, vvvv, rm, imm8` vector instruction.
fn v3_imm(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, name: &'static str, bits: u32) -> Result<Decoded, ()> {
    let (m, mem) = read_rm(r, ctx, bits)?;
    let dst = reg_operand(v, &m);
    let src2 = vvvv_operand(v);
    let src1 = match mem {
        Some(mem) => Operand::Mem(mem),
        None => rm_operand(v, &m),
    };
    let imm = imm_operand(r, 8, 8, false)?;
    Ok(Decoded::new(name, vec![dst, src2, src1, imm]))
}

/// Decodes a two-byte or three-byte VEX prefix and its instruction.
pub(crate) fn decode_vex(r: &mut Reader<'_>, ctx: Ctx, two_byte: bool) -> Result<Decoded, ()> {
    let mut v = Vex { map: 1, pp: 0, l: 0, w: false, vvvv: 0, r: false, x: false, b: false, r2: false, evex: false };
    if two_byte {
        let byte = r.byte().ok_or(())?;
        v.r = byte & 0x80 == 0;
        v.vvvv = (!(byte >> 3)) & 0xF;
        v.l = (byte >> 2) & 1;
        v.pp = byte & 3;
    }
    else {
        let b2 = r.byte().ok_or(())?;
        let b3 = r.byte().ok_or(())?;
        v.r = b2 & 0x80 == 0;
        v.x = b2 & 0x40 == 0;
        v.b = b2 & 0x20 == 0;
        v.map = b2 & 0x1F;
        v.w = b3 & 0x80 != 0;
        v.vvvv = (!(b3 >> 3)) & 0xF;
        v.l = (b3 >> 2) & 1;
        v.pp = b3 & 3;
        if v.map < 1 || v.map > 3 {
            return Err(());
        }
    }
    let inner = vex_ctx(&ctx, &v);
    let op = r.byte().ok_or(())?;
    match v.map {
        1 => map1(r, &inner, &v, op),
        2 => map2(r, &inner, &v, op),
        _ => map3(r, &inner, &v, op),
    }
}

/// Decodes an EVEX prefix and its instruction.
pub(crate) fn decode_evex(r: &mut Reader<'_>, ctx: Ctx) -> Result<Decoded, ()> {
    let p0 = r.byte().ok_or(())?;
    let p1 = r.byte().ok_or(())?;
    let p2 = r.byte().ok_or(())?;
    if p0 & 0x0C != 0 {
        return Err(());
    }
    let map = p0 & 3;
    if map == 0 {
        return Err(());
    }
    if p1 & 0x04 == 0 {
        return Err(());
    }
    let ll = (p2 >> 5) & 3;
    if ll == 3 {
        return Err(());
    }
    let v = Vex {
        map,
        pp: p1 & 3,
        l: ll,
        w: p1 & 0x80 != 0,
        vvvv: ((!(p1 >> 3)) & 0xF) + if p2 & 0x08 == 0 { 16 } else { 0 },
        r: p0 & 0x10 == 0,
        x: p0 & 0x40 == 0,
        b: p0 & 0x20 == 0,
        r2: p0 & 0x80 == 0,
        evex: true,
    };
    let inner = vex_ctx(&ctx, &v);
    let op = r.byte().ok_or(())?;
    if map != 1 {
        return Err(());
    }
    evex_map1(r, &inner, &v, op)
}

/// Returns the scalar name for a mandatory prefix, or `None`.
fn scalar_name(op: u8, pp: u8) -> Option<(&'static str, u32)> {
    let table: &[(&'static str, &'static str, &'static str, &'static str)] = match op {
        0x58 => &[("vaddps", "vaddpd", "vaddss", "vaddsd")],
        0x59 => &[("vmulps", "vmulpd", "vmulss", "vmulsd")],
        0x5C => &[("vsubps", "vsubpd", "vsubss", "vsubsd")],
        0x5D => &[("vminps", "vminpd", "vminss", "vminsd")],
        0x5E => &[("vdivps", "vdivpd", "vdivss", "vdivsd")],
        0x5F => &[("vmaxps", "vmaxpd", "vmaxss", "vmaxsd")],
        _ => return None,
    };
    let entry = table[0];
    let (name, bits) = match pp {
        0 => (entry.0, 128),
        1 => (entry.1, 128),
        2 => (entry.2, 32),
        _ => (entry.3, 64),
    };
    Some((name, bits))
}

/// Decodes the VEX `0F` map.
fn map1(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    let bits = v.bits();
    match op {
        0x10 | 0x11 => vex_move(r, ctx, v, op),
        0x28 | 0x29 => {
            let name = match v.pp {
                0 => "vmovaps",
                1 => "vmovapd",
                _ => return Err(()),
            };
            if op == 0x28 { v2(r, ctx, v, name, bits) } else { v2_store(r, ctx, v, name, bits) }
        }
        0x2A => vex_cvtsi2f(r, ctx, v),
        0x2B => {
            let name = match v.pp {
                0 => "vmovntps",
                1 => "vmovntpd",
                _ => return Err(()),
            };
            v2_store(r, ctx, v, name, bits)
        }
        0x2C | 0x2D => vex_cvtf2si(r, ctx, v, op),
        0x2E | 0x2F => {
            let name = match (op, v.pp) {
                (0x2E, 0) => "vucomiss",
                (0x2E, 1) => "vucomisd",
                (0x2F, 0) => "vcomiss",
                (0x2F, 1) => "vcomisd",
                _ => return Err(()),
            };
            let bits = if v.pp == 0 { 32 } else { 64 };
            v2(r, ctx, v, name, bits)
        }
        0x50 => {
            let name = if v.pp == 1 { "vmovmskpd" } else { "vmovmskps" };
            let (m, mem) = read_rm(r, ctx, bits)?;
            if mem.is_some() {
                return Err(());
            }
            let dst_bits = if v.w { 64 } else { 32 };
            let dst = Operand::Reg(Reg::gpr(dst_bits, m.reg + if v.r { 8 } else { 0 }, false));
            Ok(Decoded::new(name, vec![dst, rm_operand(v, &m)]))
        }
        0x51 => vex_sqrt(r, ctx, v, op),
        0x52 | 0x53 => vex_rsqrt(r, ctx, v, op),
        0x54..=0x5F => vex_arith(r, ctx, v, op),
        0x60..=0x6F => vex_packed(r, ctx, v, op),
        0x70 => {
            let name = match v.pp {
                1 => "vpshufd",
                2 => "vpshufhw",
                3 => "vpshuflw",
                _ => return Err(()),
            };
            v2_imm(r, ctx, v, name, bits)
        }
        0x71..=0x73 => vex_shift_group(r, ctx, v, op),
        0x74..=0x76 => {
            let name = match op {
                0x74 => "vpcmpeqb",
                0x75 => "vpcmpeqw",
                _ => "vpcmpeqd",
            };
            v3(r, ctx, v, name, bits)
        }
        0x77 => match (v.pp, v.l, v.vvvv) {
            (0, 0, 0) => Ok(Decoded::bare("vzeroupper")),
            (0, 1, 0) => Ok(Decoded::bare("vzeroall")),
            _ => Err(()),
        },
        0x7E | 0x7F => vex_move_special(r, ctx, v, op),
        0xC2 => {
            let name = match v.pp {
                0 => "vcmpps",
                1 => "vcmppd",
                2 => "vcmpss",
                _ => "vcmpsd",
            };
            let bits = match v.pp {
                2 => 32,
                3 => 64,
                _ => bits,
            };
            v3_imm(r, ctx, v, name, bits)
        }
        0xC6 => {
            let name = if v.pp == 1 { "vshufpd" } else { "vshufps" };
            v3_imm(r, ctx, v, name, bits)
        }
        0xD4 => v3(r, ctx, v, "vpaddq", bits),
        0xD7 => {
            let (m, mem) = read_rm(r, ctx, bits)?;
            if mem.is_some() {
                return Err(());
            }
            let dst_bits = if v.w { 64 } else { 32 };
            let dst = Operand::Reg(Reg::gpr(dst_bits, m.reg + if v.r { 8 } else { 0 }, false));
            Ok(Decoded::new("vpmovmskb", vec![dst, rm_operand(v, &m)]))
        }
        0xDB => v3(r, ctx, v, "vpand", bits),
        0xDF => v3(r, ctx, v, "vpandn", bits),
        0xEB => v3(r, ctx, v, "vpor", bits),
        0xEF => v3(r, ctx, v, "vpxor", bits),
        0xE7 => v2_store(r, ctx, v, "vmovntdq", bits),
        0xF8 => v3(r, ctx, v, "vpsubb", bits),
        0xF9 => v3(r, ctx, v, "vpsubw", bits),
        0xFA => v3(r, ctx, v, "vpsubd", bits),
        0xFB => v3(r, ctx, v, "vpsubq", bits),
        0xFC => v3(r, ctx, v, "vpaddb", bits),
        0xFD => v3(r, ctx, v, "vpaddw", bits),
        0xFE => v3(r, ctx, v, "vpaddd", bits),
        _ => Err(()),
    }
}

/// Decodes the VEX `vmov*` families.
fn vex_move(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    let (name, bits, scalar) = match (op, v.pp) {
        (0x10, 0) => ("vmovups", v.bits(), false),
        (0x10, 1) => ("vmovupd", v.bits(), false),
        (0x10, 2) => ("vmovss", 32, true),
        (0x10, 3) => ("vmovsd", 64, true),
        (0x11, 0) => ("vmovups", v.bits(), false),
        (0x11, 1) => ("vmovupd", v.bits(), false),
        (0x11, 2) => ("vmovss", 32, true),
        (0x11, 3) => ("vmovsd", 64, true),
        _ => return Err(()),
    };
    if op == 0x11 {
        return v2_store(r, ctx, v, name, bits);
    }
    if scalar {
        let (m, mem) = read_rm(r, ctx, bits)?;
        let dst = vreg(RegKind::Xmm, m.reg + if v.r { 8 } else { 0 });
        let src2 = vreg(RegKind::Xmm, v.vvvv);
        let src1 = match mem {
            Some(mem) => Operand::Mem(mem),
            None => vreg(RegKind::Xmm, m.rm + if v.b { 8 } else { 0 }),
        };
        return Ok(Decoded::new(name, vec![dst, src2, src1]));
    }
    v2(r, ctx, v, name, bits)
}

/// Decodes VEX integer to scalar-float conversions.
fn vex_cvtsi2f(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex) -> Result<Decoded, ()> {
    let name = match v.pp {
        2 => "vcvtsi2ss",
        3 => "vcvtsi2sd",
        _ => return Err(()),
    };
    let src_bits = if v.w { 64 } else { 32 };
    let (m, mem) = read_rm(r, ctx, src_bits)?;
    let dst = vreg(RegKind::Xmm, m.reg + if v.r { 8 } else { 0 });
    let src2 = vreg(RegKind::Xmm, v.vvvv);
    let src1 = match mem {
        Some(mem) => Operand::Mem(mem),
        None => Operand::Reg(Reg::gpr(src_bits, m.rm + if v.b { 8 } else { 0 }, false)),
    };
    Ok(Decoded::new(name, vec![dst, src2, src1]))
}

/// Decodes VEX scalar-float to integer conversions.
fn vex_cvtf2si(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    let (name, src_bits) = match (op, v.pp) {
        (0x2C, 2) => ("vcvttss2si", 32),
        (0x2C, 3) => ("vcvttsd2si", 64),
        (0x2D, 2) => ("vcvtss2si", 32),
        (0x2D, 3) => ("vcvtsd2si", 64),
        _ => return Err(()),
    };
    let dst_bits = if v.w { 64 } else { 32 };
    let (m, mem) = read_rm(r, ctx, src_bits)?;
    let dst = Operand::Reg(Reg::gpr(dst_bits, m.reg + if v.r { 8 } else { 0 }, false));
    let src = match mem {
        Some(mem) => Operand::Mem(mem),
        None => vreg(RegKind::Xmm, m.rm + if v.b { 8 } else { 0 }),
    };
    Ok(Decoded::new(name, vec![dst, src]))
}

/// Decodes VEX square root instructions.
fn vex_sqrt(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    let _ = op;
    match v.pp {
        0 => v2(r, ctx, v, "vsqrtps", v.bits()),
        1 => v2(r, ctx, v, "vsqrtpd", v.bits()),
        2 => {
            let (m, mem) = read_rm(r, ctx, 32)?;
            let dst = vreg(RegKind::Xmm, m.reg + if v.r { 8 } else { 0 });
            let src2 = vreg(RegKind::Xmm, v.vvvv);
            let src1 = match mem {
                Some(mem) => Operand::Mem(mem),
                None => vreg(RegKind::Xmm, m.rm + if v.b { 8 } else { 0 }),
            };
            Ok(Decoded::new("vsqrtss", vec![dst, src2, src1]))
        }
        _ => {
            let (m, mem) = read_rm(r, ctx, 64)?;
            let dst = vreg(RegKind::Xmm, m.reg + if v.r { 8 } else { 0 });
            let src2 = vreg(RegKind::Xmm, v.vvvv);
            let src1 = match mem {
                Some(mem) => Operand::Mem(mem),
                None => vreg(RegKind::Xmm, m.rm + if v.b { 8 } else { 0 }),
            };
            Ok(Decoded::new("vsqrtsd", vec![dst, src2, src1]))
        }
    }
}

/// Decodes VEX reciprocal instructions.
fn vex_rsqrt(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    let packed = if op == 0x52 { "vrsqrtps" } else { "vrcpps" };
    let scalar = if op == 0x52 { "vrsqrtss" } else { "vrcpss" };
    match v.pp {
        0 => v2(r, ctx, v, packed, v.bits()),
        2 => {
            let (m, mem) = read_rm(r, ctx, 32)?;
            let dst = vreg(RegKind::Xmm, m.reg + if v.r { 8 } else { 0 });
            let src2 = vreg(RegKind::Xmm, v.vvvv);
            let src1 = match mem {
                Some(mem) => Operand::Mem(mem),
                None => vreg(RegKind::Xmm, m.rm + if v.b { 8 } else { 0 }),
            };
            Ok(Decoded::new(scalar, vec![dst, src2, src1]))
        }
        _ => Err(()),
    }
}

/// Decodes VEX packed and scalar arithmetic.
fn vex_arith(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    if let Some((name, bits)) = scalar_name(op, v.pp) {
        return v3(r, ctx, v, name, bits);
    }
    let bits = v.bits();
    let (name, scalar_bits) = match (op, v.pp) {
        (0x54, 0) => ("vandps", 0),
        (0x54, 1) => ("vandpd", 0),
        (0x55, 0) => ("vandnps", 0),
        (0x55, 1) => ("vandnpd", 0),
        (0x56, 0) => ("vorps", 0),
        (0x56, 1) => ("vorpd", 0),
        (0x57, 0) => ("vxorps", 0),
        (0x57, 1) => ("vxorpd", 0),
        (0x5A, 0) => ("vcvtps2pd", 0),
        (0x5A, 1) => ("vcvtpd2ps", 0),
        (0x5A, 2) => ("vcvtss2sd", 32),
        (0x5A, 3) => ("vcvtsd2ss", 64),
        (0x5B, 0) => ("vcvtdq2ps", 0),
        (0x5B, 1) => ("vcvtps2dq", 0),
        (0x5B, 2) => ("vcvttps2dq", 0),
        _ => return Err(()),
    };
    if scalar_bits == 0 { v3(r, ctx, v, name, bits) } else { v3(r, ctx, v, name, scalar_bits) }
}

/// Decodes VEX packed-integer instructions.
fn vex_packed(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    let bits = v.bits();
    match op {
        0x60..=0x6D => {
            if v.pp != 1 {
                return Err(());
            }
            let name = match op {
                0x60 => "vpunpcklbw",
                0x61 => "vpunpcklwd",
                0x62 => "vpunpckldq",
                0x63 => "vpacksswb",
                0x64 => "vpcmpgtb",
                0x65 => "vpcmpgtw",
                0x66 => "vpcmpgtd",
                0x67 => "vpackuswb",
                0x68 => "vpunpckhbw",
                0x69 => "vpunpckhwd",
                0x6A => "vpunpckhdq",
                0x6B => "vpackssdw",
                0x6C => "vpunpcklqdq",
                _ => "vpunpckhqdq",
            };
            v3(r, ctx, v, name, bits)
        }
        0x6E => {
            if v.pp != 1 {
                return Err(());
            }
            let src_bits = if v.w { 64 } else { 32 };
            let (m, mem) = read_rm(r, ctx, src_bits)?;
            let dst = vreg(RegKind::Xmm, m.reg + if v.r { 8 } else { 0 });
            let src = match mem {
                Some(mem) => Operand::Mem(mem),
                None => Operand::Reg(Reg::gpr(src_bits, m.rm + if v.b { 8 } else { 0 }, false)),
            };
            Ok(Decoded::new(if src_bits == 64 { "vmovq" } else { "vmovd" }, vec![dst, src]))
        }
        0x6F => match v.pp {
            1 => v2(r, ctx, v, "vmovdqa", bits),
            2 => v2(r, ctx, v, "vmovdqu", bits),
            0 => v2(r, ctx, v, "vmovq", 64),
            _ => Err(()),
        },
        _ => Err(()),
    }
}

/// Decodes VEX packed shift groups.
fn vex_shift_group(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    if v.pp != 1 {
        return Err(());
    }
    let bits = v.bits();
    let (m, mem) = read_rm(r, ctx, bits)?;
    let name = match (op, m.reg & 7) {
        (0x71, 2) => "vpsrlw",
        (0x71, 4) => "vpsraw",
        (0x71, 6) => "vpsllw",
        (0x72, 2) => "vpsrld",
        (0x72, 4) => "vpsrad",
        (0x72, 6) => "vpslld",
        (0x73, 2) => "vpsrlq",
        (0x73, 6) => "vpsllq",
        _ => return Err(()),
    };
    let dst = vvvv_operand(v);
    let src = match mem {
        Some(mem) => Operand::Mem(mem),
        None => rm_operand(v, &m),
    };
    let imm = imm_operand(r, 8, 8, false)?;
    Ok(Decoded::new(name, vec![dst, src, imm]))
}

/// Decodes VEX `0F 7E` and `0F 7F`.
fn vex_move_special(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    if op == 0x7F {
        return match v.pp {
            1 => v2_store(r, ctx, v, "vmovdqa", v.bits()),
            2 => v2_store(r, ctx, v, "vmovdqu", v.bits()),
            _ => Err(()),
        };
    }
    match v.pp {
        1 => {
            let bits = if v.w { 64 } else { 32 };
            let (m, mem) = read_rm(r, ctx, bits)?;
            let dst = match mem {
                Some(mem) => Operand::Mem(mem),
                None => Operand::Reg(Reg::gpr(bits, m.rm + if v.b { 8 } else { 0 }, false)),
            };
            let src = vreg(RegKind::Xmm, m.reg + if v.r { 8 } else { 0 });
            Ok(Decoded::new(if bits == 64 { "vmovq" } else { "vmovd" }, vec![dst, src]))
        }
        2 => v2(r, ctx, v, "vmovq", 64),
        _ => Err(()),
    }
}

/// Decodes the VEX `0F 38` map.
fn map2(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    let bits = v.bits();
    match op {
        0x00..=0x0B => {
            if v.pp != 1 {
                return Err(());
            }
            let name = match op {
                0x00 => "vpshufb",
                0x01 => "vphaddw",
                0x02 => "vphaddd",
                0x03 => "vphaddsw",
                0x04 => "vpmaddubsw",
                0x05 => "vphsubw",
                0x06 => "vphsubd",
                0x07 => "vphsubsw",
                0x08 => "vpsignb",
                0x09 => "vpsignw",
                0x0A => "vpsignd",
                _ => "vpmulhrsw",
            };
            v3(r, ctx, v, name, bits)
        }
        0x0C => v3(r, ctx, v, "vpermilps", bits),
        0x0D => v3(r, ctx, v, "vpermilpd", bits),
        0x17 => v2(r, ctx, v, "vptest", bits),
        0x18 => v2(r, ctx, v, "vbroadcastss", 32),
        0x19 => v2(r, ctx, v, "vbroadcastsd", 64),
        0x1A => v2(r, ctx, v, "vbroadcastf128", 128),
        0x1C..=0x1E => {
            let name = match op {
                0x1C => "vpabsb",
                0x1D => "vpabsw",
                _ => "vpabsd",
            };
            v2(r, ctx, v, name, bits)
        }
        0x20..=0x25 => vpmovx_vex(r, ctx, v, op, true),
        0x28 => v3(r, ctx, v, "vpmuldq", bits),
        0x29 => v3(r, ctx, v, "vpcmpeqq", bits),
        0x2A => v2(r, ctx, v, "vmovntdqa", bits),
        0x2B => v3(r, ctx, v, "vpackusdw", bits),
        0x30..=0x35 => vpmovx_vex(r, ctx, v, op, false),
        0x37 => v3(r, ctx, v, "vpcmpgtq", bits),
        0x38..=0x3F => {
            let name = match op {
                0x38 => "vpminsb",
                0x39 => "vpminsd",
                0x3A => "vpminuw",
                0x3B => "vpminud",
                0x3C => "vpmaxsb",
                0x3D => "vpmaxsd",
                0x3E => "vpmaxuw",
                _ => "vpmaxud",
            };
            v3(r, ctx, v, name, bits)
        }
        0x40 => v3(r, ctx, v, "vpmulld", bits),
        0x41 => v2(r, ctx, v, "vphminposuw", bits),
        0xDB..=0xDF => {
            let name = match op {
                0xDB => "vaesimc",
                0xDC => "vaesenc",
                0xDD => "vaesenclast",
                0xDE => "vaesdec",
                _ => "vaesdeclast",
            };
            if op == 0xDB { v2(r, ctx, v, name, 128) } else { v3(r, ctx, v, name, 128) }
        }
        _ => Err(()),
    }
}

/// Decodes a VEX widening move (`vpmovsx*` or `vpmovzx*`).
fn vpmovx_vex(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8, signed: bool) -> Result<Decoded, ()> {
    if v.pp != 1 {
        return Err(());
    }
    let name = match (op & 7, signed) {
        (0, true) => "vpmovsxbw",
        (1, true) => "vpmovsxbd",
        (2, true) => "vpmovsxbq",
        (3, true) => "vpmovsxwd",
        (4, true) => "vpmovsxwq",
        (5, true) => "vpmovsxdq",
        (0, false) => "vpmovzxbw",
        (1, false) => "vpmovzxbd",
        (2, false) => "vpmovzxbq",
        (3, false) => "vpmovzxwd",
        (4, false) => "vpmovzxwq",
        _ => "vpmovzxdq",
    };
    let bits = match op & 7 {
        2 => 16,
        1 | 4 => 32,
        _ => 64,
    };
    v2(r, ctx, v, name, bits)
}

/// Decodes the VEX `0F 3A` map.
fn map3(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    let bits = v.bits();
    match op {
        0x08 => v2_imm(r, ctx, v, "vroundps", bits),
        0x09 => v2_imm(r, ctx, v, "vroundpd", bits),
        0x0A => v3_imm(r, ctx, v, "vroundss", 32),
        0x0B => v3_imm(r, ctx, v, "vroundsd", 64),
        0x0C => v3_imm(r, ctx, v, "vblendps", bits),
        0x0D => v3_imm(r, ctx, v, "vblendpd", bits),
        0x0E => v3_imm(r, ctx, v, "vpblendw", bits),
        0x0F => v3_imm(r, ctx, v, "vpalignr", bits),
        0x14..=0x17 => vex_extract(r, ctx, v, op),
        0x20..=0x22 => vex_insert(r, ctx, v, op),
        0x38 => v3_imm(r, ctx, v, "vinserti128", bits),
        0x39 => {
            let (m, mem) = read_rm(r, ctx, bits)?;
            let src = match mem {
                Some(mem) => Operand::Mem(mem),
                None => rm_operand(v, &m),
            };
            let dst = reg_operand(v, &m);
            let imm = imm_operand(r, 8, 8, false)?;
            Ok(Decoded::new("vextracti128", vec![src, dst, imm]))
        }
        0x40 => v3_imm(r, ctx, v, "vdpps", bits),
        0x41 => v3_imm(r, ctx, v, "vdppd", bits),
        0x42 => v3_imm(r, ctx, v, "vmpsadbw", bits),
        0x44 => v3_imm(r, ctx, v, "vpclmulqdq", bits),
        0xDF => v2_imm(r, ctx, v, "vaeskeygenassist", 128),
        _ => Err(()),
    }
}

/// Decodes VEX extract instructions.
fn vex_extract(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    let bits = match op {
        0x14 => 8,
        0x15 => 16,
        0x16 => {
            if v.w {
                64
            }
            else {
                32
            }
        }
        _ => 32,
    };
    let name = match op {
        0x14 => "vpextrb",
        0x15 => "vpextrw",
        0x16 => {
            if bits == 64 {
                "vpextrq"
            }
            else {
                "vpextrd"
            }
        }
        _ => "vextractps",
    };
    let (m, mem) = read_rm(r, ctx, bits)?;
    let dst = match mem {
        Some(mem) => Operand::Mem(mem),
        None => Operand::Reg(Reg::gpr(bits.max(32), m.rm + if v.b { 8 } else { 0 }, false)),
    };
    let src = vreg(RegKind::Xmm, m.reg + if v.r { 8 } else { 0 });
    let imm = imm_operand(r, 8, 8, false)?;
    Ok(Decoded::new(name, vec![dst, src, imm]))
}

/// Decodes VEX insert instructions.
fn vex_insert(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    let bits = match op {
        0x20 => 8,
        0x21 => 32,
        _ => {
            if v.w {
                64
            }
            else {
                32
            }
        }
    };
    let name = match op {
        0x20 => "vpinsrb",
        0x21 => "vinsertps",
        _ => {
            if bits == 64 {
                "vpinsrq"
            }
            else {
                "vpinsrd"
            }
        }
    };
    let (m, mem) = read_rm(r, ctx, bits)?;
    let dst = reg_operand(v, &m);
    let src2 = vreg(RegKind::Xmm, v.vvvv);
    let src3 = match mem {
        Some(mem) => Operand::Mem(mem),
        None if op == 0x21 => vreg(RegKind::Xmm, m.rm + if v.b { 8 } else { 0 }),
        None => Operand::Reg(Reg::gpr(bits.max(32), m.rm + if v.b { 8 } else { 0 }, false)),
    };
    let imm = imm_operand(r, 8, 8, false)?;
    Ok(Decoded::new(name, vec![dst, src2, src3, imm]))
}

/// Decodes the EVEX `0F` map subset.
fn evex_map1(r: &mut Reader<'_>, ctx: &Ctx, v: &Vex, op: u8) -> Result<Decoded, ()> {
    let bits = v.bits();
    match op {
        0x10 | 0x11 => {
            let name = match v.pp {
                0 => "vmovups",
                1 => "vmovupd",
                _ => return Err(()),
            };
            if op == 0x10 { v2(r, ctx, v, name, bits) } else { v2_store(r, ctx, v, name, bits) }
        }
        0x28 | 0x29 => {
            let name = match v.pp {
                0 => "vmovaps",
                1 => "vmovapd",
                _ => return Err(()),
            };
            if op == 0x28 { v2(r, ctx, v, name, bits) } else { v2_store(r, ctx, v, name, bits) }
        }
        0x51 => {
            let name = match v.pp {
                0 => "vsqrtps",
                1 => "vsqrtpd",
                _ => return Err(()),
            };
            v2(r, ctx, v, name, bits)
        }
        0x54..=0x57 => {
            let name = match (op, v.pp) {
                (0x54, 0) => "vandps",
                (0x54, 1) => "vandpd",
                (0x55, 0) => "vandnps",
                (0x55, 1) => "vandnpd",
                (0x56, 0) => "vorps",
                (0x56, 1) => "vorpd",
                (0x57, 0) => "vxorps",
                (0x57, 1) => "vxorpd",
                _ => return Err(()),
            };
            v3(r, ctx, v, name, bits)
        }
        0x58 | 0x59 | 0x5C..=0x5F => {
            let Some((name, scalar_bits)) = scalar_name(op, v.pp)
            else {
                return Err(());
            };
            v3(r, ctx, v, name, if scalar_bits == 32 || scalar_bits == 64 { scalar_bits } else { bits })
        }
        0x60..=0x6D => {
            if v.pp != 1 {
                return Err(());
            }
            let name = match op {
                0x60 => "vpunpcklbw",
                0x61 => "vpunpcklwd",
                0x62 => "vpunpckldq",
                0x63 => "vpacksswb",
                0x64 => "vpcmpgtb",
                0x65 => "vpcmpgtw",
                0x66 => "vpcmpgtd",
                0x67 => "vpackuswb",
                0x68 => "vpunpckhbw",
                0x69 => "vpunpckhwd",
                0x6A => "vpunpckhdq",
                0x6B => "vpackssdw",
                0x6C => "vpunpcklqdq",
                _ => "vpunpckhqdq",
            };
            v3(r, ctx, v, name, bits)
        }
        0x6F | 0x7F => {
            let name = match (v.pp, v.w) {
                (1, false) => "vmovdqa32",
                (1, true) => "vmovdqa64",
                (2, false) => "vmovdqu32",
                (2, true) => "vmovdqu64",
                _ => return Err(()),
            };
            if op == 0x6F { v2(r, ctx, v, name, bits) } else { v2_store(r, ctx, v, name, bits) }
        }
        0x70 => v2_imm(r, ctx, v, "vpshufd", bits),
        0x74..=0x76 => {
            let name = match op {
                0x74 => "vpcmpeqb",
                0x75 => "vpcmpeqw",
                _ => "vpcmpeqd",
            };
            v3(r, ctx, v, name, bits)
        }
        0xDB => v3(r, ctx, v, if v.w { "vpandq" } else { "vpandd" }, bits),
        0xDF => v3(r, ctx, v, if v.w { "vpandnq" } else { "vpandnd" }, bits),
        0xEB => v3(r, ctx, v, if v.w { "vporq" } else { "vpord" }, bits),
        0xEF => v3(r, ctx, v, if v.w { "vpxorq" } else { "vpxord" }, bits),
        0xF8 => v3(r, ctx, v, "vpsubb", bits),
        0xF9 => v3(r, ctx, v, "vpsubw", bits),
        0xFA => v3(r, ctx, v, if v.w { "vpsubq" } else { "vpsubd" }, bits),
        0xFB => v3(r, ctx, v, "vpsubq", bits),
        0xFC => v3(r, ctx, v, "vpaddb", bits),
        0xFD => v3(r, ctx, v, "vpaddw", bits),
        0xFE => v3(r, ctx, v, if v.w { "vpaddq" } else { "vpaddd" }, bits),
        _ => Err(()),
    }
}
