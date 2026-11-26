# ida-x86

x86 and x64 instruction decoding with Intel, MASM and NASM formatting. The
decoder is hand-written and table-driven, and is meant for walking code found
in PE and Mach-O binaries.

## Usage

```rust
use ida_x86::{Decoder, Syntax};

let mut decoder = Decoder::new(64, &bytes, 0x1000);
let instruction = decoder.decode();
println!("{:016x}  {}", instruction.ip(), instruction.format(Syntax::Intel));
```

## API

- `Decoder::new(bitness: u32, bytes: &'a [u8], ip: u64) -> Decoder<'a>` with bitness 32 or 64.
- `Decoder::decode(&mut self) -> Instruction`, with `position`, `ip`, `set_position`, `set_ip` and `can_decode` for cursor control.
- `Instruction::format(&self, syntax: Syntax) -> &str`, `ip()`, `len()` and `is_invalid()`.
- `Syntax` selects `Intel`, `Masm` or `Nasm` rendering.

## Coverage

Legacy prefixes, REX, ModRM/SIB and displacement decoding, the one-byte, `0F`,
`0F 38` and `0F 3A` maps, and a subset of VEX and EVEX encodings. This is not
the full x86 instruction set: an unknown encoding advances exactly one byte and
renders as `.byte 0xNN`, which `Instruction::is_invalid` reports.

## License

This crate is licensed under `Apache-2.0`, matching the OpenIDA workspace.
