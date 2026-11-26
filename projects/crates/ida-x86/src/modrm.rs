//! ModRM, SIB and effective address decoding.

use crate::{
    operand::{Mem, Reg},
    prefix::{Prefixes, Reader, address_size},
};

/// Decoded ModRM byte.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ModRm {
    /// Mod field.
    pub(crate) mod_: u8,
    /// Reg field.
    pub(crate) reg: u8,
    /// Rm field.
    pub(crate) rm: u8,
}

impl ModRm {
    /// Returns whether the rm field selects a register.
    pub(crate) fn is_reg(&self) -> bool {
        self.mod_ == 3
    }
}

/// Builds a general purpose register operand.
pub(crate) fn gpr(size: u32, num: u8, p: &Prefixes) -> Reg {
    Reg::gpr(size, num, p.has_rex())
}

/// Builds a general purpose register name.
fn gpr_name(size: u32, num: u8, p: &Prefixes) -> String {
    gpr(size, num, p).text()
}

/// Reads a ModRM byte and, when it selects memory, its effective address.
pub(crate) fn read_modrm(r: &mut Reader<'_>, size: u32, bitness: u32, p: &Prefixes) -> Result<(ModRm, Option<Mem>), ()> {
    let byte = r.byte().ok_or(())?;
    let m = ModRm { mod_: byte >> 6, reg: (byte >> 3) & 7, rm: byte & 7 };
    if m.is_reg() {
        return Ok((m, None));
    }
    let mut mem = Mem::new(size);
    mem.seg = p.seg;
    let addr = address_size(bitness, p);
    if addr == 16 {
        decode16(r, &m, &mut mem)?;
    }
    else {
        decode32(r, &m, addr, p, &mut mem)?;
    }
    Ok((m, Some(mem)))
}

/// Reads a displacement of `mod_`-implied width into `mem`.
fn read_disp(r: &mut Reader<'_>, mod_: u8, mem: &mut Mem) -> Result<(), ()> {
    match mod_ {
        0 => {}
        1 => mem.disp = i64::from(r.byte().ok_or(())? as i8),
        2 => mem.disp = i64::from(r.u32().ok_or(())? as i32),
        _ => return Err(()),
    }
    Ok(())
}

/// Decodes 32-bit and 64-bit addressing forms (including SIB).
fn decode32(r: &mut Reader<'_>, m: &ModRm, addr: u32, p: &Prefixes, mem: &mut Mem) -> Result<(), ()> {
    if m.rm == 4 {
        let sib = r.byte().ok_or(())?;
        let scale = sib >> 6;
        let index = (sib >> 3) & 7;
        let base = sib & 7;
        if index != 4 || p.x() {
            mem.index = Some(gpr_name(addr, index + if p.x() { 8 } else { 0 }, p));
            mem.scale = 1 << scale;
        }
        if base == 5 && m.mod_ == 0 {
            let disp = r.u32().ok_or(())?;
            if mem.index.is_some() {
                mem.disp = i64::from(disp as i32);
            }
            else {
                mem.disp = i64::from(disp);
                mem.absolute = true;
            }
        }
        else {
            mem.base = Some(gpr_name(addr, base + if p.b() { 8 } else { 0 }, p));
            read_disp(r, m.mod_, mem)?;
        }
        Ok(())
    }
    else if m.rm == 5 && m.mod_ == 0 {
        let disp = r.u32().ok_or(())?;
        if addr == 64 {
            mem.rip = true;
            mem.disp = i64::from(disp as i32);
        }
        else {
            mem.absolute = true;
            mem.disp = i64::from(disp);
        }
        Ok(())
    }
    else {
        mem.base = Some(gpr_name(addr, m.rm + if p.b() { 8 } else { 0 }, p));
        read_disp(r, m.mod_, mem)
    }
}

/// Decodes 16-bit addressing forms.
fn decode16(r: &mut Reader<'_>, m: &ModRm, mem: &mut Mem) -> Result<(), ()> {
    const BASES: [(&str, Option<&str>); 8] = [
        ("bx", Some("si")),
        ("bx", Some("di")),
        ("bp", Some("si")),
        ("bp", Some("di")),
        ("si", None),
        ("di", None),
        ("bp", None),
        ("bx", None),
    ];
    if m.mod_ == 0 && m.rm == 6 {
        mem.absolute = true;
        mem.disp = i64::from(r.u16().ok_or(())?);
        return Ok(());
    }
    let (base, index) = BASES[usize::from(m.rm)];
    mem.base = Some(base.to_string());
    mem.index = index.map(str::to_string);
    match m.mod_ {
        0 => {}
        1 => mem.disp = i64::from(r.byte().ok_or(())? as i8),
        2 => mem.disp = i64::from(r.u16().ok_or(())? as i16),
        _ => return Err(()),
    }
    Ok(())
}
