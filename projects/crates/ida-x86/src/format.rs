//! Syntax-specific operand rendering.

use crate::{
    Syntax,
    operand::{Mem, Operand},
};

/// Formats a value as a lower-case hexadecimal literal.
pub(crate) fn hex(value: u64) -> String {
    format!("0x{value:x}")
}

/// Renders `mnemonic` and `operands` in `syntax`.
pub(crate) fn render(syntax: Syntax, mnemonic: &str, operands: &[Operand]) -> String {
    let mut text = String::from(mnemonic);
    for (index, operand) in operands.iter().enumerate() {
        text.push(if index == 0 { ' ' } else { ',' });
        format_operand(syntax, operand, &mut text);
    }
    text
}

/// Appends one operand to `out`.
fn format_operand(syntax: Syntax, operand: &Operand, out: &mut String) {
    match operand {
        Operand::Reg(reg) => out.push_str(&reg.text()),
        Operand::Imm { size, value } => {
            let mask = if *size >= 64 {
                u64::MAX
            }
            else if *size == 0 {
                u64::MAX
            }
            else {
                (1u64 << size) - 1
            };
            out.push_str(&hex(*value & mask));
        }
        Operand::Rel(target) => out.push_str(&hex(*target)),
        Operand::Mem(mem) => format_mem(syntax, mem, out),
    }
}

/// Returns the size keyword iced uses for `bits`.
fn size_keyword(bits: u32) -> Option<&'static str> {
    match bits {
        8 => Some("byte"),
        16 => Some("word"),
        32 => Some("dword"),
        48 => Some("fword"),
        64 => Some("qword"),
        80 => Some("tbyte"),
        128 => Some("xmmword"),
        256 => Some("ymmword"),
        512 => Some("zmmword"),
        _ => None,
    }
}

/// Appends a memory operand, including its size and segment decoration.
fn format_mem(syntax: Syntax, mem: &Mem, out: &mut String) {
    if let Some(keyword) = size_keyword(mem.size) {
        out.push_str(keyword);
        if syntax != Syntax::Nasm {
            out.push_str(" ptr");
        }
        out.push(' ');
    }
    if syntax != Syntax::Nasm {
        if let Some(seg) = mem.seg {
            out.push_str(seg);
            out.push(':');
        }
    }
    out.push('[');
    if syntax == Syntax::Nasm {
        if let Some(seg) = mem.seg {
            out.push_str(seg);
            out.push(':');
        }
    }
    format_address(mem, out);
    out.push(']');
}

/// Appends the base/index/displacement part of an effective address.
fn format_address(mem: &Mem, out: &mut String) {
    if mem.rip {
        out.push_str("rip");
        append_disp(mem.disp, false, out);
        return;
    }
    if mem.absolute {
        out.push_str(&hex(mem.disp as u64));
        return;
    }
    let mut wrote = false;
    if let Some(base) = &mem.base {
        out.push_str(base);
        wrote = true;
    }
    if let Some(index) = &mem.index {
        if wrote {
            out.push('+');
        }
        out.push_str(index);
        if mem.scale > 1 {
            out.push('*');
            out.push_str(&mem.scale.to_string());
        }
        wrote = true;
    }
    if !wrote {
        out.push('0');
        return;
    }
    append_disp(mem.disp, true, out);
}

/// Appends a displacement, omitting zero displacements when `omit_zero` is set.
fn append_disp(disp: i64, omit_zero: bool, out: &mut String) {
    if disp == 0 {
        if !omit_zero {
            out.push_str("+0x0");
        }
        return;
    }
    if disp < 0 {
        out.push('-');
        out.push_str(&hex(disp.unsigned_abs()));
    }
    else {
        out.push('+');
        out.push_str(&hex(disp as u64));
    }
}
