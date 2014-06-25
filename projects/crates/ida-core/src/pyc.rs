//! Static decoding of CPython `marshal` streams and 3.11 bytecode.
//!
//! The input is either a raw `marshal` dump (the object graph, optionally
//! prefixed by the version byte `2` through `6` that `PyMarshal_Write`
//! writes) or a `.pyc` file whose first sixteen bytes are the container
//! header (magic,
//! flags, timestamp or hash, source size). The code-object field order
//! decoded here is the 3.11 one: `argcount`, `posonlyargcount`,
//! `kwonlyargcount`, `stacksize`, `flags`, `code`, `consts`, `names`,
//! `localsplusnames`, `localspluskinds`, `filename`, `name`, `qualname`,
//! `firstlineno`, `linetable`, `exceptiontable`. The `localsplus` pair
//! (CPython 3.11 through 3.13) replaced the older `varnames`, `freevars`
//! and `cellvars` tuples: the kind byte marks each name `0x20` local,
//! `0x40` cell or `0x80` free, and the report splits it back into the
//! three familiar lists.
//!
//! Every `code` object in the graph is flattened into the report in parse
//! order. Its bytecode is walked as word-code pairs: the opcode byte names
//! the instruction, the argument byte resolves against the names, constants
//! and locals tables, and inline cache slots (opcode byte `0`, the only
//! place that value appears in non-adaptive code) are counted against the
//! preceding instruction instead of being emitted. Nothing is executed.

use data_binary_inspect::BinarySession;
use serde::{Deserialize, Serialize};

use crate::{IdaError, Result};

/// `co_localspluskinds` bit: the name is a fast local.
const LOCAL_KIND_LOCAL: u8 = 0x20;

/// `co_localspluskinds` bit: the name is a cell.
const LOCAL_KIND_CELL: u8 = 0x40;

/// `co_localspluskinds` bit: the name is a free variable.
const LOCAL_KIND_FREE: u8 = 0x80;

/// Size of the `.pyc` container header that precedes the stream.
const PYC_HEADER_SIZE: usize = 16;

/// Default cap on decoded code objects.
const DEFAULT_CODE_LIMIT: usize = 1024;

/// Default cap on emitted instructions across the whole graph.
const DEFAULT_INSTRUCTION_LIMIT: usize = 65_536;

/// Cap on rendered names, locals and consts per code object.
const RENDER_LIST_LIMIT: usize = 4096;

/// Hard cap on one decoded string, bytes object or the whole stream.
const MAX_BLOB_SIZE: usize = 64 * 1024 * 1024;

/// First opcode that carries an argument byte.
const HAVE_ARGUMENT: u8 = 90;

/// Opcode that prefixes a larger argument.
const EXTENDED_ARG: u8 = 144;

/// Inputs of one [`crate::OpenIda::pyc`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PycOptions {
    /// Absolute offset of the stream start; defaults to the file start.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Stream framing; `auto` picks `marshal` on the version byte, else `pyc`.
    #[serde(default)]
    pub format: PycFormat,
    /// Keep only code objects whose `qualname` or `name` contains this text.
    #[serde(default)]
    pub code: Option<String>,
    /// Cap on decoded code objects; clamped to 16384.
    #[serde(default = "default_code_limit")]
    pub code_limit: usize,
    /// Cap on emitted instructions; clamped to 1048576.
    #[serde(default = "default_instruction_limit")]
    pub instruction_limit: usize,
}

impl Default for PycOptions {
    fn default() -> Self {
        Self {
            offset: None,
            format: PycFormat::default(),
            code: None,
            code_limit: default_code_limit(),
            instruction_limit: default_instruction_limit(),
        }
    }
}

/// Framing of the input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PycFormat {
    /// `marshal` when the first byte is a code type byte or the version
    /// four byte, else `pyc`.
    #[default]
    Auto,
    /// Raw `marshal.dumps` output starting at the offset.
    Marshal,
    /// `.pyc` container: skip the sixteen-byte header at the offset.
    Pyc,
}

/// One decoded constant, rendered for the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PycConst {
    /// Discriminator name: `int`, `str`, `bytes`, `tuple`, `code`, ...
    pub kind: String,
    /// Compact Python-style rendering, truncated when long.
    pub repr: String,
    /// Index into [`PycReport::codes`] when this constant is a code object.
    pub code_index: Option<usize>,
}

/// One decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PycInstruction {
    /// Byte offset of the instruction inside `co_code`.
    pub offset: u32,
    /// Raw opcode byte.
    pub opcode: u8,
    /// Opcode name, or `<opcode N>` when unknown.
    pub name: String,
    /// Combined argument, `None` for opcodes below `HAVE_ARGUMENT`.
    pub arg: Option<u32>,
    /// Resolved argument text: name, constant repr, local, jump target, ...
    pub resolved: Option<String>,
    /// Inline cache slots that follow this instruction.
    pub caches: u32,
}

/// One decoded code object with its disassembly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PycCodeObject {
    /// Position in the flattened report list.
    pub index: usize,
    /// Dotted qualified name.
    pub qualname: String,
    /// Simple name.
    pub name: String,
    /// Source file recorded in the code object.
    pub filename: String,
    /// `co_argcount`.
    pub argcount: i32,
    /// `co_posonlyargcount`.
    pub posonlyargcount: i32,
    /// `co_kwonlyargcount`.
    pub kwonlyargcount: i32,
    /// `co_stacksize`.
    pub stacksize: i32,
    /// `co_flags` as a raw word.
    pub flags: u32,
    /// `co_flags` rendered as `OPTIMIZED, NEWLOCALS, ...`.
    pub flags_text: String,
    /// `co_firstlineno`.
    pub firstlineno: i32,
    /// Byte length of `co_code`.
    pub code_len: u32,
    /// Byte length of `co_linetable`.
    pub linetable_len: u32,
    /// Byte length of `co_exceptiontable`.
    pub exceptiontable_len: u32,
    /// `co_names`, cut at the render limit.
    pub names: Vec<String>,
    /// `co_varnames`, cut at the render limit.
    pub varnames: Vec<String>,
    /// `co_freevars`, cut at the render limit.
    pub freevars: Vec<String>,
    /// `co_cellvars`, cut at the render limit.
    pub cellvars: Vec<String>,
    /// `co_consts` summaries, cut at the render limit.
    pub consts: Vec<PycConst>,
    /// Disassembly, cut when the instruction budget ran out.
    pub instructions: Vec<PycInstruction>,
    /// Whether any list of this code object was cut.
    pub truncated: bool,
}

/// Full decode of one `marshal` stream or `.pyc` container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PycReport {
    /// Absolute offset of the stream start.
    pub start_offset: u64,
    /// Framing actually used: `marshal` or `pyc`.
    pub source_format: String,
    /// `marshal` version byte when the stream carried one.
    pub marshal_version: Option<u8>,
    /// `.pyc` magic word when the framing was `pyc`.
    pub pyc_magic: Option<u32>,
    /// `.pyc` flags word when the framing was `pyc`.
    pub pyc_flags: Option<u32>,
    /// Interpreter named by the magic, e.g. `CPython 3.11`.
    pub python: Option<String>,
    /// Code objects decoded before the limit and the filter.
    pub code_count: usize,
    /// Instructions emitted across every decoded code object.
    pub instruction_count: usize,
    /// Code objects in parse order, after the `--code` filter.
    pub codes: Vec<PycCodeObject>,
    /// Whether the graph or an instruction budget was cut.
    pub truncated: bool,
}

fn default_code_limit() -> usize {
    DEFAULT_CODE_LIMIT
}

fn default_instruction_limit() -> usize {
    DEFAULT_INSTRUCTION_LIMIT
}

/// Whether a window of bytes looks like bytecode rather than machine code.
///
/// The unified disassembly route uses this to pick the bytecode path when
/// `--format auto` meets a `marshal` stream (a version prefix byte, the
/// referenced code type `0xE3` or the bare code type `c`) or a `.pyc`
/// container (a two-byte magic in the assigned range followed by `CR LF`).
/// Classified containers stay on the machine path; an explicit `--format`
/// always overrides this guess.
pub fn sniff(bytes: &[u8]) -> bool {
    if matches!(bytes.first(), Some(2..=6) | Some(&0xE3) | Some(&b'c')) {
        return true;
    }
    if bytes.len() >= 4 && bytes[2] == 0x0D && bytes[3] == 0x0A {
        let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
        return (2000..=4000).contains(&magic) && magic % 2 == 0;
    }
    false
}

/// Decodes the `marshal` stream of one open session.
pub fn analyze(session: &BinarySession, options: &PycOptions) -> Result<PycReport> {
    let start = options.offset.unwrap_or(0);
    let remaining = session
        .size()
        .checked_sub(start)
        .ok_or_else(|| IdaError::parse(format!("offset {start} is past the end of the file")))?;
    if remaining > MAX_BLOB_SIZE as u64 {
        return Err(IdaError::parse(format!("the marshal stream at {start} is {remaining} bytes, over the {MAX_BLOB_SIZE} byte cap")));
    }
    let data = session.read(start, remaining)?;

    let mut stream = 0usize;
    let mut pyc_magic = None;
    let mut pyc_flags = None;
    let format = match options.format {
        PycFormat::Auto
            if matches!(data.first(), Some(2..=6) | Some(&0xE3) | Some(&b'c')) =>
        {
            PycFormat::Marshal
        }
        PycFormat::Auto => PycFormat::Pyc,
        explicit => explicit,
    };
    if format == PycFormat::Pyc {
        if data.len() < PYC_HEADER_SIZE {
            return Err(IdaError::parse("the pyc container header is truncated"));
        }
        pyc_magic = Some(u32::from_le_bytes(data[0..4].try_into().expect("four-byte window")));
        pyc_flags = Some(u32::from_le_bytes(data[4..8].try_into().expect("four-byte window")));
        stream = PYC_HEADER_SIZE;
    }

    let code_limit = options.code_limit.clamp(1, 16_384);
    let instruction_limit = options.instruction_limit.clamp(1, 1_048_576);
    let mut parser = Parser::new(&data[stream..], code_limit, instruction_limit);
    if !matches!(parser.stream()?, Value::Code(_)) {
        return Err(IdaError::parse("the marshal stream does not start with a code object"));
    }

    let instruction_count = parser.codes.iter().map(|code| code.instructions.len()).sum();
    let truncated = parser.truncated || parser.codes.iter().any(|code| code.truncated);
    let python = pyc_magic.and_then(python_name);
    let mut codes = parser.codes;
    if let Some(needle) = &options.code {
        codes.retain(|code| code.qualname.contains(needle) || code.name.contains(needle));
        if codes.is_empty() {
            return Err(IdaError::parse(format!("no code object matches {needle}")));
        }
    }

    Ok(PycReport {
        start_offset: start,
        source_format: match format {
            PycFormat::Marshal => "marshal".to_string(),
            _ => "pyc".to_string(),
        },
        marshal_version: parser.version,
        pyc_magic,
        pyc_flags,
        python,
        code_count: parser.decoded_codes,
        instruction_count,
        codes,
        truncated,
    })
}

/// Names the interpreter from a `.pyc` magic number.
fn python_name(magic: u32) -> Option<String> {
    let version = match magic & 0xffff {
        3413 => "3.8",
        3425 => "3.9",
        3439 => "3.10",
        3495 => "3.11",
        3531 => "3.12",
        3571 => "3.13",
        _ => return None,
    };
    Some(format!("CPython {version}"))
}

/// A decoded `marshal` value, kept in memory only.
#[derive(Debug, Clone)]
enum Value {
    None,
    Bool(bool),
    Int(i64),
    Long(String),
    Float(f64),
    Complex(String),
    Str(String),
    Bytes(Vec<u8>),
    Tuple(Vec<Value>),
    List(Vec<Value>),
    Set(Vec<Value>),
    Dict(Vec<(Value, Value)>),
    Code(usize),
    Ellipsis,
    StopIter,
    Unknown(String),
}

impl Value {
    /// Discriminator name used in [`PycConst::kind`].
    fn kind(&self) -> &'static str {
        match self {
            Value::None => "none",
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Long(_) => "long",
            Value::Float(_) => "float",
            Value::Complex(_) => "complex",
            Value::Str(_) => "str",
            Value::Bytes(_) => "bytes",
            Value::Tuple(_) => "tuple",
            Value::List(_) => "list",
            Value::Set(_) => "set",
            Value::Dict(_) => "dict",
            Value::Code(_) => "code",
            Value::Ellipsis => "ellipsis",
            Value::StopIter => "stopiter",
            Value::Unknown(_) => "unknown",
        }
    }
}

/// Parses one `marshal` v4 stream into flattened code objects.
struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
    version: Option<u8>,
    refs: Vec<Value>,
    codes: Vec<PycCodeObject>,
    decoded_codes: usize,
    budget: usize,
    truncated: bool,
    code_limit: usize,
}

impl<'a> Parser<'a> {
    /// Creates a parser over one stream body.
    fn new(data: &'a [u8], code_limit: usize, instruction_limit: usize) -> Self {
        Self {
            data,
            pos: 0,
            version: None,
            refs: Vec::new(),
            codes: Vec::new(),
            decoded_codes: 0,
            budget: instruction_limit,
            truncated: false,
            code_limit,
        }
    }

    /// Reads the optional version byte and the single top-level object.
    fn stream(&mut self) -> Result<Value> {
        if let Some(&version @ 2..=6) = self.data.get(self.pos) {
            self.version = Some(version);
            self.pos += 1;
        }
        self.object()
    }

    /// Reads one raw byte.
    fn byte(&mut self) -> Result<u8> {
        let value = *self.data.get(self.pos).ok_or_else(|| self.truncated_error())?;
        self.pos += 1;
        Ok(value)
    }

    /// Reads a little-endian word.
    fn i32(&mut self) -> Result<i32> {
        let end = self.pos.checked_add(4).ok_or_else(|| self.truncated_error())?;
        let window: [u8; 4] = self.data.get(self.pos..end).ok_or_else(|| self.truncated_error())?.try_into().expect("four-byte window");
        self.pos = end;
        Ok(i32::from_le_bytes(window))
    }

    /// Reads a little-endian double word.
    fn i64(&mut self) -> Result<i64> {
        let end = self.pos.checked_add(8).ok_or_else(|| self.truncated_error())?;
        let window: [u8; 8] = self.data.get(self.pos..end).ok_or_else(|| self.truncated_error())?.try_into().expect("eight-byte window");
        self.pos = end;
        Ok(i64::from_le_bytes(window))
    }

    /// Reads a little-endian half word.
    fn u16(&mut self) -> Result<u16> {
        let end = self.pos.checked_add(2).ok_or_else(|| self.truncated_error())?;
        let window: [u8; 2] = self.data.get(self.pos..end).ok_or_else(|| self.truncated_error())?.try_into().expect("two-byte window");
        self.pos = end;
        Ok(u16::from_le_bytes(window))
    }

    /// Error for a stream that ends mid-object.
    fn truncated_error(&self) -> IdaError {
        IdaError::parse(format!("the marshal stream ends at offset {}", self.pos))
    }

    /// Reads one object, honouring the reference flag and interning.
    fn object(&mut self) -> Result<Value> {
        let byte = self.byte()?;
        let flagged = byte & 0x80 != 0;
        let kind = byte & 0x7f;
        // `marshal` reserves the reference slot when the type byte is seen,
        // before the object body is written, so nested references number the
        // parent first (pre-order). Interned string kinds join the table even
        // without the flag bit. An empty `Unknown` marks a slot whose object
        // is still being parsed.
        let slot = if flagged || matches!(kind, b't' | b'A' | b'Z') {
            let index = self.refs.len();
            self.refs.push(Value::Unknown(String::new()));
            Some(index)
        } else {
            None
        };
        let value = match kind {
            b'0' | b'N' => Value::None,
            b'F' => Value::Bool(false),
            b'T' => Value::Bool(true),
            b'S' => Value::StopIter,
            b'.' => Value::Ellipsis,
            b'i' => Value::Int(i64::from(self.i32()?)),
            b'I' => Value::Int(self.i64()?),
            b'b' => Value::Int(i64::from(self.byte()? as i8)),
            b'l' => self.long()?,
            b'g' => Value::Float(f64::from_bits(self.i64()? as u64)),
            b'f' => Value::Float(f64::from(f32::from_bits(self.i32()? as u32))),
            b'x' => {
                let real = f64::from_bits(self.i64()? as u64);
                let imag = f64::from_bits(self.i64()? as u64);
                Value::Complex(format!("({real}+{imag}j)"))
            }
            b's' => Value::Bytes(self.blob()?),
            b'a' | b'A' | b't'..=b'u' => Value::Str(self.text()?),
            b'z' | b'Z' => {
                let len = usize::from(self.byte()?);
                let end = self.pos.checked_add(len).ok_or_else(|| self.truncated_error())?;
                let bytes = self.data.get(self.pos..end).ok_or_else(|| self.truncated_error())?.to_vec();
                self.pos = end;
                Value::Str(String::from_utf8_lossy(&bytes).into_owned())
            }
            b'r' => {
                let index = self.i32()?;
                match usize::try_from(index).ok().and_then(|i| self.refs.get(i)).cloned() {
                    Some(Value::Unknown(text)) if text.is_empty() => {
                        return Err(IdaError::parse(format!(
                            "marshal reference {index} points at an object that is not complete"
                        )));
                    }
                    Some(value) => value,
                    None => Value::Unknown(format!("ref {index}")),
                }
            }
            b'(' => Value::Tuple(self.seq_of()?),
            b'[' => Value::List(self.seq_of()?),
            b'<' => Value::Set(self.seq_of()?),
            b'>' => Value::Set(self.seq_of()?),
            b')' => {
                let count = i32::from(self.byte()?);
                Value::Tuple(self.seq(count)?)
            }
            b'{' => self.dict()?,
            b'c' => self.code()?,
            other => {
                return Err(IdaError::parse(format!(
                    "unsupported marshal type '{}' at stream offset {}",
                    other as char,
                    self.pos - 1
                )));
            }
        };
        if let Some(index) = slot {
            self.refs[index] = value.clone();
        }
        Ok(value)
    }

    /// Reads a length word and the sequence it counts.
    fn seq_of(&mut self) -> Result<Vec<Value>> {
        let count = self.i32()?;
        self.seq(count)
    }

    /// Reads a sequence of `count` objects, guarding the count.
    fn seq(&mut self, count: i32) -> Result<Vec<Value>> {
        let count = usize::try_from(count).map_err(|_| self.count_error())?;
        if count > 1 << 22 {
            return Err(self.count_error());
        }
        let mut items = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            items.push(self.object()?);
        }
        Ok(items)
    }

    /// Error for an implausible element count.
    fn count_error(&self) -> IdaError {
        IdaError::parse(format!("implausible marshal element count at offset {}", self.pos))
    }

    /// Reads key/value pairs until the `null` terminator.
    fn dict(&mut self) -> Result<Value> {
        let mut pairs = Vec::new();
        loop {
            let peek = *self.data.get(self.pos).ok_or_else(|| self.truncated_error())?;
            if peek & 0x7f == b'0' {
                self.pos += 1;
                break;
            }
            let key = self.object()?;
            let value = self.object()?;
            pairs.push((key, value));
            if pairs.len() > 1 << 22 {
                return Err(self.count_error());
            }
        }
        Ok(Value::Dict(pairs))
    }

    /// Reads a `TYPE_LONG`: digit count, sign, base-2^15 digits.
    fn long(&mut self) -> Result<Value> {
        let raw = self.i32()?;
        let negative = raw < 0;
        let digits = raw.unsigned_abs() as usize;
        if digits > 65_536 {
            return Err(self.count_error());
        }
        let mut acc: u128 = 0;
        let mut overflow = false;
        for index in 0..digits {
            let digit = u128::from(self.u16()?);
            if !overflow {
                if index >= 8 {
                    overflow = true;
                } else {
                    acc += digit << (15 * index);
                }
            }
        }
        if overflow {
            return Ok(Value::Long(format!("<long {digits} digits>")));
        }
        Ok(Value::Long(if negative { format!("-{acc}") } else { acc.to_string() }))
    }

    /// Reads a length-prefixed byte blob.
    fn blob(&mut self) -> Result<Vec<u8>> {
        let len = self.i32()?;
        let len = usize::try_from(len).map_err(|_| IdaError::parse("negative marshal blob length"))?;
        if len > MAX_BLOB_SIZE {
            return Err(IdaError::parse(format!("marshal blob of {len} bytes is over the cap")));
        }
        let end = self.pos.checked_add(len).ok_or_else(|| self.truncated_error())?;
        let bytes = self.data.get(self.pos..end).ok_or_else(|| self.truncated_error())?.to_vec();
        self.pos = end;
        Ok(bytes)
    }

    /// Reads a length-prefixed UTF-8 string.
    fn text(&mut self) -> Result<String> {
        let bytes = self.blob()?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Reads one `code` object and disassembles it immediately.
    fn code(&mut self) -> Result<Value> {
        if self.codes.len() >= self.code_limit {
            self.truncated = true;
            return Err(IdaError::parse(format!(
                "the marshal stream holds more than {} code objects",
                self.code_limit
            )));
        }
        // The scalar code fields are raw little-endian words, not objects.
        let argcount = self.i32()?;
        let posonlyargcount = self.i32()?;
        let kwonlyargcount = self.i32()?;
        let stacksize = self.i32()?;
        let flags = self.i32()? as u32;
        let code = match self.object()? {
            Value::Bytes(bytes) => bytes,
            other => return Err(IdaError::parse(format!("code field is a marshal {}, not bytes", other.kind()))),
        };
        let consts = match self.object()? {
            Value::Tuple(items) => items,
            other => return Err(IdaError::parse(format!("consts field is a marshal {}, not a tuple", other.kind()))),
        };
        let names = self.string_tuple("names")?;
        let localsplus = self.string_tuple("localsplusnames")?;
        let kinds = match self.object()? {
            Value::Bytes(bytes) => bytes,
            other => return Err(IdaError::parse(format!("localspluskinds field is a marshal {}, not bytes", other.kind()))),
        };
        let (varnames, freevars, cellvars) = split_localsplus(&localsplus, &kinds);
        let filename = self.expect_str("filename")?;
        let name = self.expect_str("name")?;
        let qualname = self.expect_str("qualname")?;
        let firstlineno = self.i32()?;
        let linetable = match self.object()? {
            Value::Bytes(bytes) => bytes,
            other => return Err(IdaError::parse(format!("linetable field is a marshal {}, not bytes", other.kind()))),
        };
        let exceptiontable = match self.object()? {
            Value::Bytes(bytes) => bytes,
            other => return Err(IdaError::parse(format!("exceptiontable field is a marshal {}, not bytes", other.kind()))),
        };

        let mut truncated = false;
        let mut rendered_consts = Vec::new();
        for item in consts.iter().take(RENDER_LIST_LIMIT) {
            let code_index = match item {
                Value::Code(index) => Some(*index),
                _ => None,
            };
            rendered_consts.push(PycConst {
                kind: item.kind().to_string(),
                repr: repr_value(item, &self.codes),
                code_index,
            });
        }
        if consts.len() > RENDER_LIST_LIMIT {
            truncated = true;
        }

        let mut cells = cellvars.clone();
        cells.extend(freevars.iter().cloned());
        let (instructions, cut) = self.disassemble(&code, &names, &consts, &varnames, &cells);
        if cut {
            truncated = true;
        }

        let index = self.codes.len();
        self.decoded_codes += 1;
        self.codes.push(PycCodeObject {
            index,
            qualname,
            name,
            filename,
            argcount,
            posonlyargcount,
            kwonlyargcount,
            stacksize,
            flags,
            flags_text: flags_text(flags),
            firstlineno,
            code_len: code.len() as u32,
            linetable_len: linetable.len() as u32,
            exceptiontable_len: exceptiontable.len() as u32,
            names: render_list(names, &mut truncated),
            varnames: render_list(varnames, &mut truncated),
            freevars: render_list(freevars, &mut truncated),
            cellvars: render_list(cellvars, &mut truncated),
            consts: rendered_consts,
            instructions,
            truncated,
        });
        Ok(Value::Code(index))
    }

    /// Reads a tuple-of-strings field such as `co_names`.
    fn string_tuple(&mut self, field: &str) -> Result<Vec<String>> {
        let items = match self.object()? {
            Value::Tuple(items) => items,
            other => return Err(IdaError::parse(format!("{field} field is a marshal {}, not a tuple", other.kind()))),
        };
        items
            .iter()
            .map(|item| match item {
                Value::Str(text) => Ok(text.clone()),
                other => Err(IdaError::parse(format!("{field} holds a marshal {}, not a string", other.kind()))),
            })
            .collect()
    }

    /// Reads a string field of a code object.
    fn expect_str(&mut self, field: &str) -> Result<String> {
        match self.object()? {
            Value::Str(text) => Ok(text),
            other => Err(IdaError::parse(format!("{field} field is a marshal {}, not a string", other.kind()))),
        }
    }

    /// Walks `co_code` as word-code pairs and resolves arguments.
    fn disassemble(
        &mut self,
        code: &[u8],
        names: &[String],
        consts: &[Value],
        varnames: &[String],
        cells: &[String],
    ) -> (Vec<PycInstruction>, bool) {
        let tables = Tables { names, consts, varnames, cells, codes: &self.codes };
        let mut out: Vec<PycInstruction> = Vec::new();
        let mut cut = false;
        let mut extended: u32 = 0;
        let mut offset = 0usize;
        while offset + 1 < code.len() {
            let op = code[offset];
            let byte = code[offset + 1];
            if op == 0 {
                if let Some(last) = out.last_mut() {
                    last.caches += 1;
                }
                offset += 2;
                continue;
            }
            let arg = if op >= HAVE_ARGUMENT { Some(u32::from(byte) | extended) } else { None };
            extended = if op == EXTENDED_ARG { (u32::from(byte) | extended) << 8 } else { 0 };
            if self.budget == 0 {
                cut = true;
                offset += 2;
                continue;
            }
            self.budget -= 1;
            let resolved = arg.and_then(|arg| resolve(op, arg, offset as u32, &tables));
            out.push(PycInstruction {
                offset: offset as u32,
                opcode: op,
                name: opcode_name(op).to_string(),
                arg,
                resolved,
                caches: 0,
            });
            offset += 2;
        }
        (out, cut)
    }
}

/// The lookup tables one code object resolves its arguments against.
struct Tables<'a> {
    names: &'a [String],
    consts: &'a [Value],
    varnames: &'a [String],
    cells: &'a [String],
    codes: &'a [PycCodeObject],
}

/// Keeps the first `RENDER_LIST_LIMIT` items and flags the cut.
fn render_list(items: Vec<String>, truncated: &mut bool) -> Vec<String> {
    if items.len() > RENDER_LIST_LIMIT {
        *truncated = true;
        items.into_iter().take(RENDER_LIST_LIMIT).collect()
    } else {
        items
    }
}

/// Splits the 3.11+ `localsplus` pair into the three classic name lists.
/// A name can carry both the local and the cell bit, so it appears in
/// both lists, exactly like the `co_*` accessors expose it.
fn split_localsplus(names: &[String], kinds: &[u8]) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut varnames = Vec::new();
    let mut freevars = Vec::new();
    let mut cellvars = Vec::new();
    for (index, text) in names.iter().enumerate() {
        let kind = kinds.get(index).copied().unwrap_or(LOCAL_KIND_LOCAL);
        if kind & LOCAL_KIND_LOCAL != 0 {
            varnames.push(text.clone());
        }
        if kind & LOCAL_KIND_CELL != 0 {
            cellvars.push(text.clone());
        }
        if kind & LOCAL_KIND_FREE != 0 {
            freevars.push(text.clone());
        }
    }
    (varnames, freevars, cellvars)
}

/// Renders `co_flags` as comma-separated `CO_*` names.
fn flags_text(flags: u32) -> String {
    const NAMES: [(u32, &str); 10] = [
        (1, "OPTIMIZED"),
        (2, "NEWLOCALS"),
        (4, "VARARGS"),
        (8, "VARKEYWORDS"),
        (16, "NESTED"),
        (32, "GENERATOR"),
        (64, "NOFREE"),
        (128, "COROUTINE"),
        (256, "ITERABLE_COROUTINE"),
        (512, "ASYNC_GENERATOR"),
    ];
    let mut parts: Vec<String> = Vec::new();
    let mut rest = flags;
    for (bit, name) in NAMES {
        if rest & bit != 0 {
            parts.push((*name).to_string());
            rest &= !bit;
        }
    }
    if rest != 0 {
        parts.push(format!("<{rest:#x}>"));
    }
    parts.join(", ")
}

/// Resolves one instruction argument into display text.
fn resolve(op: u8, arg: u32, offset: u32, tables: &Tables) -> Option<String> {
    let Tables { names, consts, varnames, cells, codes } = *tables;
    let index = arg as usize;
    match op {
        100 | 172 => consts.get(index).map(|value| repr_value(value, codes)),
        90..=91 | 95..=98 | 101 | 106 | 108..=109 | 160 => names.get(index).cloned(),
        116 => names.get(index / 2).map(|base| if arg & 1 == 1 { format!("NULL + {base}") } else { base.clone() }),
        124..=126 => varnames.get(index).cloned(),
        135..=139 | 148 => cells.get(index).cloned(),
        111..=112 => Some(format!("to {}", arg * 2)),
        93 | 110 | 114..=115 | 128..=129 => Some(format!("to {}", offset + 2 + arg * 2)),
        123 | 134 | 140 | 173..=176 => Some(format!("to {}", offset + 2 - arg * 2.min((offset + 2) / 2))),
        117 => Some(if arg == 0 { "is".to_string() } else { "is not".to_string() }),
        118 => Some(if arg == 0 { "in".to_string() } else { "not in".to_string() }),
        107 => CMP_OPS.get(index).map(|text| (*text).to_string()),
        122 => NB_OPS.get(index).map(|text| (*text).to_string()),
        132 => {
            let mut parts = Vec::new();
            for (bit, name) in [(1, "defaults"), (2, "kwdefaults"), (4, "annotations"), (8, "closure")] {
                if arg & bit != 0 {
                    parts.push(name);
                }
            }
            Some(parts.join(", "))
        }
        155 => {
            let converter = ["", "str", "repr", "ascii"][usize::try_from(arg & 3).unwrap_or(0)];
            let format = if arg & 4 != 0 { ", with format" } else { "" };
            Some(format!("{}{format}", if converter.is_empty() { "none" } else { converter }))
        }
        _ => None,
    }
}

/// Comparison operators indexed by the `COMPARE_OP` argument.
const CMP_OPS: [&str; 10] = ["<", "<=", "==", "!=", ">", ">=", "is", "is not", "in", "not in"];

/// Arithmetic operators indexed by the `BINARY_OP` argument.
const NB_OPS: [&str; 26] = [
    "add", "and", "floor_divide", "lshift", "matrix_multiply", "multiply", "remainder", "or", "power", "rshift",
    "subtract", "true_divide", "xor", "inplace_add", "inplace_and", "inplace_floor_divide", "inplace_lshift",
    "inplace_matrix_multiply", "inplace_multiply", "inplace_remainder", "inplace_or", "inplace_power",
    "inplace_rshift", "inplace_subtract", "inplace_true_divide", "inplace_xor",
];

/// Names the 3.11 base opcodes; specialized forms never appear in `co_code`.
fn opcode_name(op: u8) -> &'static str {
    match op {
        0 => "CACHE",
        1 => "POP_TOP",
        2 => "PUSH_NULL",
        9 => "NOP",
        10 => "UNARY_POSITIVE",
        11 => "UNARY_NEGATIVE",
        12 => "UNARY_NOT",
        15 => "UNARY_INVERT",
        25 => "BINARY_SUBSCR",
        30 => "GET_LEN",
        31 => "MATCH_MAPPING",
        32 => "MATCH_SEQUENCE",
        33 => "MATCH_KEYS",
        35 => "PUSH_EXC_INFO",
        36 => "CHECK_EXC_MATCH",
        37 => "CHECK_EG_MATCH",
        49 => "WITH_EXCEPT_START",
        50 => "GET_AITER",
        51 => "GET_ANEXT",
        52 => "BEFORE_ASYNC_WITH",
        53 => "BEFORE_WITH",
        54 => "END_ASYNC_FOR",
        60 => "STORE_SUBSCR",
        61 => "DELETE_SUBSCR",
        68 => "GET_ITER",
        69 => "GET_YIELD_FROM_ITER",
        70 => "PRINT_EXPR",
        71 => "LOAD_BUILD_CLASS",
        74 => "LOAD_ASSERTION_ERROR",
        75 => "RETURN_GENERATOR",
        82 => "LIST_TO_TUPLE",
        83 => "RETURN_VALUE",
        84 => "IMPORT_STAR",
        85 => "SETUP_ANNOTATIONS",
        86 => "YIELD_VALUE",
        87 => "ASYNC_GEN_WRAP",
        88 => "PREP_RERAISE_STAR",
        89 => "POP_EXCEPT",
        90 => "STORE_NAME",
        91 => "DELETE_NAME",
        92 => "UNPACK_SEQUENCE",
        93 => "FOR_ITER",
        94 => "UNPACK_EX",
        95 => "STORE_ATTR",
        96 => "DELETE_ATTR",
        97 => "STORE_GLOBAL",
        98 => "DELETE_GLOBAL",
        99 => "SWAP",
        100 => "LOAD_CONST",
        101 => "LOAD_NAME",
        102 => "BUILD_TUPLE",
        103 => "BUILD_LIST",
        104 => "BUILD_SET",
        105 => "BUILD_MAP",
        106 => "LOAD_ATTR",
        107 => "COMPARE_OP",
        108 => "IMPORT_NAME",
        109 => "IMPORT_FROM",
        110 => "JUMP_FORWARD",
        111 => "JUMP_IF_FALSE_OR_POP",
        112 => "JUMP_IF_TRUE_OR_POP",
        114 => "POP_JUMP_FORWARD_IF_FALSE",
        115 => "POP_JUMP_FORWARD_IF_TRUE",
        116 => "LOAD_GLOBAL",
        117 => "IS_OP",
        118 => "CONTAINS_OP",
        119 => "RERAISE",
        120 => "COPY",
        122 => "BINARY_OP",
        123 => "SEND",
        124 => "LOAD_FAST",
        125 => "STORE_FAST",
        126 => "DELETE_FAST",
        128 => "POP_JUMP_FORWARD_IF_NOT_NONE",
        129 => "POP_JUMP_FORWARD_IF_NONE",
        130 => "RAISE_VARARGS",
        131 => "GET_AWAITABLE",
        132 => "MAKE_FUNCTION",
        133 => "BUILD_SLICE",
        134 => "JUMP_BACKWARD_NO_INTERRUPT",
        135 => "MAKE_CELL",
        136 => "LOAD_CLOSURE",
        137 => "LOAD_DEREF",
        138 => "STORE_DEREF",
        139 => "DELETE_DEREF",
        140 => "JUMP_BACKWARD",
        142 => "CALL_FUNCTION_EX",
        144 => "EXTENDED_ARG",
        145 => "LIST_APPEND",
        146 => "SET_ADD",
        147 => "MAP_ADD",
        148 => "LOAD_CLASSDEREF",
        149 => "COPY_FREE_VARS",
        151 => "RESUME",
        152 => "MATCH_CLASS",
        155 => "FORMAT_VALUE",
        156 => "BUILD_CONST_KEY_MAP",
        157 => "BUILD_STRING",
        160 => "LOAD_METHOD",
        162 => "LIST_EXTEND",
        163 => "SET_UPDATE",
        164 => "DICT_MERGE",
        165 => "DICT_UPDATE",
        166 => "PRECALL",
        171 => "CALL",
        172 => "KW_NAMES",
        173 => "POP_JUMP_BACKWARD_IF_NOT_NONE",
        174 => "POP_JUMP_BACKWARD_IF_NONE",
        175 => "POP_JUMP_BACKWARD_IF_FALSE",
        176 => "POP_JUMP_BACKWARD_IF_TRUE",
        _ => "UNKNOWN",
    }
}

/// Renders one constant in a Python-like, length-capped form.
fn repr_value(value: &Value, codes: &[PycCodeObject]) -> String {
    match value {
        Value::None => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::Int(number) => number.to_string(),
        Value::Long(text) => text.clone(),
        Value::Float(number) => number.to_string(),
        Value::Complex(text) => text.clone(),
        Value::Str(text) => quoted(text),
        Value::Bytes(bytes) => {
            let preview: String = bytes
                .iter()
                .take(48)
                .map(|byte| if byte.is_ascii_graphic() || *byte == b' ' { *byte as char } else { '.' })
                .collect();
            format!("b({} B) \"{preview}\"", bytes.len())
        }
        Value::Tuple(items) | Value::List(items) | Value::Set(items) => {
            let open = match value {
                Value::Tuple(_) => "(",
                Value::List(_) => "[",
                _ => "{",
            };
            let close = match value {
                Value::Tuple(_) => ")",
                Value::List(_) => "]",
                _ => "}",
            };
            let parts: Vec<String> = items.iter().take(8).map(|item| repr_value(item, codes)).collect();
            let tail = if items.len() > 8 { ", ..." } else { "" };
            format!("{open}{}{tail}{close}", parts.join(", "))
        }
        Value::Dict(pairs) => {
            let parts: Vec<String> = pairs
                .iter()
                .take(8)
                .map(|(key, value)| format!("{}: {}", repr_value(key, codes), repr_value(value, codes)))
                .collect();
            let tail = if pairs.len() > 8 { ", ..." } else { "" };
            format!("{{{}}}{}", parts.join(", "), tail)
        }
        Value::Code(index) => match codes.get(*index) {
            Some(code) => format!("<code {code}>", code = code.qualname),
            None => format!("<code #{index}>"),
        },
        Value::Ellipsis => "...".to_string(),
        Value::StopIter => "<stopiter>".to_string(),
        Value::Unknown(text) => format!("<{text}>"),
    }
}

/// Quotes and truncates a string constant.
fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars().take(96) {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if ch.is_control() => out.push_str(&format!("\\x{:02x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}
