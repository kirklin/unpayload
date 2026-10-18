//! DEX bytecode files.
//!
//! References lead from the tables of strings, types, prototypes, fields,
//! methods and classes to the items they index or point at, from data items
//! to the items they point at, and from instructions to the indices they
//! use and the code their branches reach.

use std::collections::BTreeMap;
use std::mem::offset_of;
use std::ops::{Range, RangeInclusive};

use zerocopy::byteorder::little_endian::U32;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use super::disasm::{Group, put, u16_at, u32_at};
use super::{INVALID_OFFSET, OFFSET_BOUND, Offset, Reference, corrupt};
use crate::error::Result;
use layout::*;

/// Offsets point past the header, so zero marks an absent item.
const NO_OFFSET: Offset = 0;
/// An absent index.
const NO_INDEX: Offset = u32::MAX;
const MAX_MAP_ITEMS: u32 = 21;
const METHOD_HANDLE_TYPES: u16 = 9;

// Map list type codes of the variable-length items.
const TYPE_LIST: u16 = 0x1001;
const ANNOTATION_SET_REF_LIST: u16 = 0x1002;
const ANNOTATION_SET_ITEM: u16 = 0x1003;
const CODE_ITEM: u16 = 0x2001;
const ANNOTATIONS_DIRECTORY_ITEM: u16 = 0x2006;

/// Records of the format. The derives check that each is packed without
/// padding; several fields are never read.
#[allow(dead_code)]
mod layout {
    use zerocopy::byteorder::little_endian::{U16, U32};
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct HeaderItem {
        pub magic: [u8; 8],
        pub checksum: U32,
        pub signature: [u8; 20],
        pub file_size: U32,
        pub header_size: U32,
        pub endian_tag: U32,
        pub link_size: U32,
        pub link_off: U32,
        pub map_off: U32,
        pub string_ids_size: U32,
        pub string_ids_off: U32,
        pub type_ids_size: U32,
        pub type_ids_off: U32,
        pub proto_ids_size: U32,
        pub proto_ids_off: U32,
        pub field_ids_size: U32,
        pub field_ids_off: U32,
        pub method_ids_size: U32,
        pub method_ids_off: U32,
        pub class_defs_size: U32,
        pub class_defs_off: U32,
        pub data_size: U32,
        pub data_off: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct MapItem {
        pub kind: U16,
        pub unused: U16,
        pub size: U32,
        pub offset: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct StringIdItem {
        pub string_data_off: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct TypeIdItem {
        pub descriptor_idx: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct ProtoIdItem {
        pub shorty_idx: U32,
        pub return_type_idx: U32,
        pub parameters_off: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct FieldIdItem {
        pub class_idx: U16,
        pub type_idx: U16,
        pub name_idx: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct MethodIdItem {
        pub class_idx: U16,
        pub proto_idx: U16,
        pub name_idx: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct ClassDefItem {
        pub class_idx: U32,
        pub access_flags: U32,
        pub superclass_idx: U32,
        pub interfaces_off: U32,
        pub source_file_idx: U32,
        pub annotations_off: U32,
        pub class_data_off: U32,
        pub static_values_off: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct CallSiteIdItem {
        pub call_site_off: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct MethodHandleItem {
        pub method_handle_type: U16,
        pub unused_1: U16,
        pub field_or_method_id: U16,
        pub unused_2: U16,
    }

    /// Header of a code item; instructions and try blocks follow.
    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct CodeItem {
        pub registers_size: U16,
        pub ins_size: U16,
        pub outs_size: U16,
        pub tries_size: U16,
        pub debug_info_off: U32,
        pub insns_size: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct TryItem {
        pub start_addr: U32,
        pub insn_count: U16,
        pub handler_off: U16,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct TypeItem {
        pub type_idx: U16,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct AnnotationSetRefItem {
        pub annotations_off: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct AnnotationOffItem {
        pub annotation_off: U32,
    }

    /// Header of an annotations directory; the field, method and parameter
    /// annotations follow.
    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct AnnotationsDirectoryItem {
        pub class_annotations_off: U32,
        pub fields_size: U32,
        pub annotated_methods_size: U32,
        pub annotated_parameters_size: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct FieldAnnotation {
        pub field_idx: U32,
        pub annotations_off: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct MethodAnnotation {
        pub method_idx: U32,
        pub annotations_off: U32,
    }

    #[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
    #[repr(C)]
    pub struct ParameterAnnotation {
        pub method_idx: U32,
        pub annotations_off: U32,
    }
}

/// Tables of fixed-size items that indices name.
#[derive(Clone, Copy)]
enum Table {
    StringId,
    TypeId,
    ProtoId,
    FieldId,
    MethodId,
    ClassDef,
    CallSiteId,
    MethodHandle,
}

impl Table {
    const ALL: [Self; 8] = [
        Self::StringId,
        Self::TypeId,
        Self::ProtoId,
        Self::FieldId,
        Self::MethodId,
        Self::ClassDef,
        Self::CallSiteId,
        Self::MethodHandle,
    ];

    /// Type code in the map list.
    fn code(self) -> u16 {
        match self {
            Self::StringId => 0x0001,
            Self::TypeId => 0x0002,
            Self::ProtoId => 0x0003,
            Self::FieldId => 0x0004,
            Self::MethodId => 0x0005,
            Self::ClassDef => 0x0006,
            Self::CallSiteId => 0x0007,
            Self::MethodHandle => 0x0008,
        }
    }

    fn item_size(self) -> u32 {
        (match self {
            Self::StringId => size_of::<StringIdItem>(),
            Self::TypeId => size_of::<TypeIdItem>(),
            Self::ProtoId => size_of::<ProtoIdItem>(),
            Self::FieldId => size_of::<FieldIdItem>(),
            Self::MethodId => size_of::<MethodIdItem>(),
            Self::ClassDef => size_of::<ClassDefItem>(),
            Self::CallSiteId => size_of::<CallSiteIdItem>(),
            Self::MethodHandle => size_of::<MethodHandleItem>(),
        }) as u32
    }
}

/// Elements found by walking variable-length items.
#[derive(Clone, Copy)]
enum List {
    TypeItems,
    AnnotationSetRefItems,
    AnnotationOffItems,
    AnnotationsDirectories,
    FieldAnnotations,
    MethodAnnotations,
    ParameterAnnotations,
}

impl List {
    const COUNT: usize = 7;
}

/// How a stored value names its target.
#[derive(Clone, Copy)]
enum Target {
    Index16(Table),
    Index32(Table),
    Offset32,
    /// Displacements in 16-bit code units.
    Branch8,
    Branch16,
    Branch32,
}

/// Where references of one type are stored.
#[derive(Clone, Copy)]
enum Reader {
    /// A field of every item of a table.
    Items(Table, u32, Target),
    /// The field or method id of method handles of the kinds in the range,
    /// indexing the table.
    MethodHandles(Table, u16, u16),
    /// A field of every element of a list.
    Elements(List, u32, Target),
    /// An operand of instructions with the format, at the offset listed for
    /// their opcode.
    Code(Format, &'static [(u8, u32)], Target),
}

impl Reader {
    /// How targets are stored, which also decides how they are written.
    fn target(self) -> Target {
        match self {
            Self::Items(_, _, target) | Self::Elements(_, _, target) | Self::Code(_, _, target) => target,
            Self::MethodHandles(table, ..) => Target::Index16(table),
        }
    }
}

/// A reference type: the pool its targets belong to, and where it is stored.
struct Kind(u8, Reader);

macro_rules! field {
    ($record:ident, $field:ident) => {
        offset_of!($record, $field) as u32
    };
}

/// Reference types in tag order, which groups them by pool.
#[rustfmt::skip]
const KINDS: [Kind; 42] = {
    use Format::{C, T};
    use List::*;
    use Table::*;
    use Target::*;
    [
        // Pool 0: string ids.
        Kind(0, Reader::Items(TypeId, field!(TypeIdItem, descriptor_idx), Index32(StringId))),
        Kind(0, Reader::Items(ProtoId, field!(ProtoIdItem, shorty_idx), Index32(StringId))),
        Kind(0, Reader::Items(FieldId, field!(FieldIdItem, name_idx), Index32(StringId))),
        Kind(0, Reader::Items(MethodId, field!(MethodIdItem, name_idx), Index32(StringId))),
        Kind(0, Reader::Items(ClassDef, field!(ClassDefItem, source_file_idx), Index32(StringId))),
        Kind(0, Reader::Code(C, &[(0x1A, 2)], Index16(StringId))),
        Kind(0, Reader::Code(C, &[(0x1B, 2)], Index32(StringId))),
        // Pool 1: type ids.
        Kind(1, Reader::Items(ProtoId, field!(ProtoIdItem, return_type_idx), Index32(TypeId))),
        Kind(1, Reader::Items(FieldId, field!(FieldIdItem, class_idx), Index16(TypeId))),
        Kind(1, Reader::Items(FieldId, field!(FieldIdItem, type_idx), Index16(TypeId))),
        Kind(1, Reader::Items(MethodId, field!(MethodIdItem, class_idx), Index16(TypeId))),
        Kind(1, Reader::Items(ClassDef, field!(ClassDefItem, class_idx), Index32(TypeId))),
        Kind(1, Reader::Items(ClassDef, field!(ClassDefItem, superclass_idx), Index32(TypeId))),
        Kind(1, Reader::Elements(TypeItems, field!(TypeItem, type_idx), Index16(TypeId))),
        Kind(
            1,
            Reader::Code(
                C,
                &[(0x1C, 2), (0x1F, 2), (0x20, 2), (0x22, 2), (0x23, 2), (0x24, 2), (0x25, 2)],
                Index16(TypeId),
            ),
        ),
        // Pool 2: prototype ids.
        Kind(2, Reader::Code(C, &[(0xFA, 6), (0xFB, 6), (0xFF, 2)], Index16(ProtoId))),
        Kind(2, Reader::Items(MethodId, field!(MethodIdItem, proto_idx), Index16(ProtoId))),
        // Pool 3: field ids.
        Kind(3, Reader::Code(C, &[(0x52, 2), (0x60, 2)], Index16(FieldId))),
        Kind(3, Reader::MethodHandles(FieldId, 0, 3)),
        Kind(3, Reader::Elements(FieldAnnotations, field!(FieldAnnotation, field_idx), Index32(FieldId))),
        // Pool 4: method ids.
        Kind(4, Reader::Code(C, &[(0x6E, 2), (0x74, 2), (0xFA, 2), (0xFB, 2)], Index16(MethodId))),
        Kind(4, Reader::MethodHandles(MethodId, 4, 8)),
        Kind(4, Reader::Elements(MethodAnnotations, field!(MethodAnnotation, method_idx), Index32(MethodId))),
        Kind(4, Reader::Elements(ParameterAnnotations, field!(ParameterAnnotation, method_idx), Index32(MethodId))),
        // Pool 5: call site ids.
        Kind(5, Reader::Code(C, &[(0xFC, 2), (0xFD, 2)], Index16(CallSiteId))),
        // Pool 6: method handles.
        Kind(6, Reader::Code(C, &[(0xFE, 2)], Index16(MethodHandle))),
        // Pool 7: type lists.
        Kind(7, Reader::Items(ProtoId, field!(ProtoIdItem, parameters_off), Offset32)),
        Kind(7, Reader::Items(ClassDef, field!(ClassDefItem, interfaces_off), Offset32)),
        // Pool 8: annotation set ref lists.
        Kind(8, Reader::Elements(ParameterAnnotations, field!(ParameterAnnotation, annotations_off), Offset32)),
        // Pool 9: annotation sets.
        Kind(9, Reader::Elements(AnnotationSetRefItems, field!(AnnotationSetRefItem, annotations_off), Offset32)),
        Kind(9, Reader::Elements(AnnotationsDirectories, field!(AnnotationsDirectoryItem, class_annotations_off), Offset32)),
        Kind(9, Reader::Elements(FieldAnnotations, field!(FieldAnnotation, annotations_off), Offset32)),
        Kind(9, Reader::Elements(MethodAnnotations, field!(MethodAnnotation, annotations_off), Offset32)),
        // Pool 10: class data.
        Kind(10, Reader::Items(ClassDef, field!(ClassDefItem, class_data_off), Offset32)),
        // Pool 11: code, through branch displacements.
        Kind(11, Reader::Code(T, &[(0x28, 1)], Branch8)),
        Kind(11, Reader::Code(T, &[(0x29, 2), (0x32, 2), (0x38, 2)], Branch16)),
        Kind(11, Reader::Code(T, &[(0x26, 2), (0x2A, 2), (0x2B, 2), (0x2C, 2)], Branch32)),
        // Pool 12: string data.
        Kind(12, Reader::Items(StringId, field!(StringIdItem, string_data_off), Offset32)),
        // Pool 13: annotations.
        Kind(13, Reader::Elements(AnnotationOffItems, field!(AnnotationOffItem, annotation_off), Offset32)),
        // Pool 14: encoded arrays.
        Kind(14, Reader::Items(ClassDef, field!(ClassDefItem, static_values_off), Offset32)),
        // Pool 15: annotations directories.
        Kind(15, Reader::Items(ClassDef, field!(ClassDefItem, annotations_off), Offset32)),
        // Pool 16: call sites.
        Kind(16, Reader::Items(CallSiteId, field!(CallSiteIdItem, call_site_off), Offset32)),
    ]
};

/// Instruction formats, as far as references need to tell them apart.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Format {
    B,
    C,
    H,
    I,
    L,
    N,
    S,
    T,
    X,
}

struct Instruction {
    opcode: u8,
    /// Length in 16-bit code units.
    units: u8,
    format: Format,
    /// Number of consecutive opcodes sharing the entry.
    variants: u8,
}

const fn op(opcode: u8, units: u8, format: Format) -> Instruction {
    ops(opcode, units, format, 1)
}

const fn ops(opcode: u8, units: u8, format: Format, variants: u8) -> Instruction {
    Instruction {
        opcode,
        units,
        format,
        variants,
    }
}

const BYTECODE: &[Instruction] = {
    use Format::*;
    &[
        op(0x00, 1, X),
        op(0x01, 1, X),
        op(0x02, 2, X),
        op(0x03, 3, X),
        op(0x04, 1, X),
        op(0x05, 2, X),
        op(0x06, 3, X),
        op(0x07, 1, X),
        op(0x08, 2, X),
        op(0x09, 3, X),
        op(0x0A, 1, X),
        op(0x0B, 1, X),
        op(0x0C, 1, X),
        op(0x0D, 1, X),
        op(0x0E, 1, X),
        op(0x0F, 1, X),
        op(0x10, 1, X),
        op(0x11, 1, X),
        op(0x12, 1, N),
        op(0x13, 2, S),
        op(0x14, 3, I),
        op(0x15, 2, H),
        op(0x16, 2, S),
        op(0x17, 3, I),
        op(0x18, 5, L),
        op(0x19, 2, H),
        op(0x1A, 2, C),
        op(0x1B, 3, C),
        op(0x1C, 2, C),
        op(0x1D, 1, X),
        op(0x1E, 1, X),
        op(0x1F, 2, C),
        op(0x20, 2, C),
        op(0x21, 1, X),
        op(0x22, 2, C),
        op(0x23, 2, C),
        op(0x24, 3, C),
        op(0x25, 3, C),
        op(0x26, 3, T),
        op(0x27, 1, X),
        op(0x28, 1, T),
        op(0x29, 2, T),
        op(0x2A, 3, T),
        op(0x2B, 3, T),
        op(0x2C, 3, T),
        ops(0x2D, 2, X, 5),
        ops(0x32, 2, T, 6),
        ops(0x38, 2, T, 6),
        ops(0x44, 2, X, 14),
        ops(0x52, 2, C, 14),
        ops(0x60, 2, C, 14),
        ops(0x6E, 3, C, 5),
        ops(0x74, 3, C, 5),
        ops(0x7B, 1, X, 21),
        ops(0x90, 2, X, 32),
        ops(0xB0, 1, X, 32),
        ops(0xD0, 2, S, 8),
        ops(0xD8, 2, B, 11),
        op(0xFA, 4, C),
        op(0xFB, 4, C),
        op(0xFC, 3, C),
        op(0xFD, 3, C),
        op(0xFE, 2, C),
        op(0xFF, 2, C),
    ]
};

/// Index into `BYTECODE` of the entry for each opcode, `u8::MAX` for unused
/// opcodes.
const OPCODES: [u8; 256] = {
    let mut table = [u8::MAX; 256];
    let mut index = 0;
    while index < BYTECODE.len() {
        let entry = &BYTECODE[index];
        let mut opcode = entry.opcode as usize;
        while opcode < entry.opcode as usize + entry.variants as usize {
            table[opcode] = index as u8;
            opcode += 1;
        }
        index += 1;
    }
    table
};

fn instruction(opcode: u8) -> Option<&'static Instruction> {
    BYTECODE.get(usize::from(OPCODES[usize::from(opcode)]))
}

/// Location and number of the items of one map list entry.
#[derive(Clone, Copy, Default)]
struct Items {
    offset: Offset,
    count: u32,
}

pub(super) struct Dex {
    size: usize,
    /// Indexed by `Table`.
    tables: [Items; Table::ALL.len()],
    /// Sorted offsets of code items.
    code_items: Vec<Offset>,
    /// Sorted element offsets, indexed by `List`.
    lists: [Vec<Offset>; List::COUNT],
}

impl Dex {
    pub fn parse(image: &[u8]) -> Result<Self> {
        Self::parse_image(image).ok_or_else(|| corrupt("element is not a valid DEX file"))
    }

    fn parse_image(image: &[u8]) -> Option<Self> {
        let header_size = size_of::<HeaderItem>();
        let (header, _) = HeaderItem::ref_from_prefix(image).ok()?;
        let magic = &header.magic;
        if magic[..4] != *b"dex\n" || magic[7] != 0 || !matches!(&magic[4..7], b"035" | b"037" | b"038" | b"039") {
            return None;
        }
        let size = header.file_size.get() as usize;
        if size > image.len() || size < header_size || (header.map_off.get() as usize) < header_size {
            return None;
        }
        let image = &image[..size];

        let mut map = Cursor::at(image, header.map_off.get());
        let count = map.read::<U32>()?.get();
        if count > MAX_MAP_ITEMS {
            return None;
        }
        let mut entries = BTreeMap::new();
        for entry in map.records::<MapItem>(count as usize)? {
            let kind = entry.kind.get();
            let items = Items {
                offset: entry.offset.get(),
                count: entry.size.get(),
            };
            if !covers(image, items, item_base_size(kind)) || entries.insert(kind, items).is_some() {
                return None;
            }
        }
        let items = |code: u16| entries.get(&code).copied().unwrap_or_default();

        let mut lists: [Vec<Offset>; List::COUNT] = Default::default();
        lists[List::TypeItems as usize] = elements(image, items(TYPE_LIST), size_of::<TypeItem>())?;
        lists[List::AnnotationSetRefItems as usize] =
            elements(image, items(ANNOTATION_SET_REF_LIST), size_of::<AnnotationSetRefItem>())?;
        lists[List::AnnotationOffItems as usize] =
            elements(image, items(ANNOTATION_SET_ITEM), size_of::<AnnotationOffItem>())?;
        directories(image, items(ANNOTATIONS_DIRECTORY_ITEM), &mut lists)?;
        Some(Self {
            size,
            tables: Table::ALL.map(|table| items(table.code())),
            code_items: code_items(image, items(CODE_ITEM))?,
            lists,
        })
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn groups(&self) -> Vec<Group> {
        KINDS
            .iter()
            .enumerate()
            .map(|(tag, &Kind(pool, _))| Group { tag: tag as u8, pool })
            .collect()
    }

    /// Appends the references of type `tag` located in `[lo, hi)`.
    pub fn read(&self, image: &[u8], tag: u8, lo: Offset, hi: Offset, out: &mut Vec<Reference>) {
        let image = &image[..self.size];
        let range = lo..hi;
        match KINDS[usize::from(tag)].1 {
            Reader::Items(table, field, target) => {
                self.read_items(table, field, range, out, |item| {
                    self.target(image, target, item + field)
                });
            }
            Reader::MethodHandles(table, first, last) => {
                let field = field!(MethodHandleItem, field_or_method_id);
                self.read_items(Table::MethodHandle, field, range, out, |item| {
                    self.method_handle(image, table, first..=last, item)
                });
            }
            Reader::Elements(list, field, target) => {
                read_elements(&self.lists[list as usize], field, range, out, |at| {
                    self.target(image, target, at)
                });
            }
            Reader::Code(format, operands, target) => {
                self.read_code(image, format, operands, range, out, |at| self.target(image, target, at));
            }
        }
    }

    /// The field at `field` of each item of `table` within the range, whose
    /// target `target` finds from the item.
    fn read_items(
        &self,
        table: Table,
        field: u32,
        Range { start: lo, end: hi }: Range<Offset>,
        out: &mut Vec<Reference>,
        target: impl Fn(Offset) -> Offset,
    ) {
        let Items { offset: base, count } = self.tables[table as usize];
        let size = table.item_size();
        let item = |index: u32| base + index * size;
        let mut index = if base == NO_OFFSET {
            count
        } else if lo < base {
            0
        } else if lo < item(count) {
            // Skip the item whose field lies before `lo`.
            let index = (lo - base) / size;
            if lo > item(index) + field { index + 1 } else { index }
        } else {
            count
        };
        while index < count {
            let at = item(index);
            let location = at + field;
            if location >= hi {
                break;
            }
            let target = target(at);
            if target == INVALID_OFFSET {
                break;
            }
            index += 1;
            if target != NO_OFFSET && target != NO_INDEX {
                out.push(Reference { location, target });
            }
        }
    }

    /// Operands within the range of instructions with `format`, at the offset
    /// `operands` lists for their opcode.
    fn read_code(
        &self,
        image: &[u8],
        format: Format,
        operands: &[(u8, u32)],
        Range { start: lo, end: hi }: Range<Offset>,
        out: &mut Vec<Reference>,
        target: impl Fn(Offset) -> Offset,
    ) {
        let first = self
            .code_items
            .partition_point(|&offset| offset <= lo)
            .saturating_sub(1);
        for &code_item in &self.code_items[first..] {
            for (at, instruction) in Instructions::new(image, code_item) {
                if at >= hi {
                    return;
                }
                let operand = operands
                    .iter()
                    .find(|&&(opcode, _)| instruction.format == format && instruction.opcode == opcode);
                let Some(&(_, operand)) = operand else {
                    continue;
                };
                let location = at + operand;
                if location < lo {
                    continue;
                }
                if location >= hi {
                    return;
                }
                let target = target(location);
                if target != INVALID_OFFSET {
                    out.push(Reference { location, target });
                }
            }
        }
    }

    /// The target named by the value stored at `at`.
    fn target(&self, image: &[u8], target: Target, at: Offset) -> Offset {
        let index = at as usize;
        match target {
            Target::Index16(table) => self.index_target(table, u16_at(image, index).into()),
            Target::Index32(table) => self.index_target(table, u32_at(image, index)),
            Target::Offset32 => match u32_at(image, index) {
                NO_OFFSET => NO_OFFSET,
                offset if offset as usize >= image.len() => INVALID_OFFSET,
                offset => offset,
            },
            // Branches count code units from the instruction, which starts one
            // unit before the operand.
            Target::Branch8 => at.wrapping_add(((i32::from(image[index] as i8) - 1) * 2) as u32),
            Target::Branch16 => at.wrapping_add(((i32::from(u16_at(image, index) as i16) - 1) * 2) as u32),
            Target::Branch32 => {
                let target = i64::from(at) + (i64::from(u32_at(image, index) as i32) - 1) * 2;
                u32::try_from(target)
                    .ok()
                    .filter(|&target| target < OFFSET_BOUND)
                    .unwrap_or(INVALID_OFFSET)
            }
        }
    }

    /// The item an index into `table` names.
    fn index_target(&self, table: Table, index: u32) -> Offset {
        let items = self.tables[table as usize];
        if index == NO_INDEX {
            NO_INDEX
        } else if index >= items.count {
            INVALID_OFFSET
        } else {
            items.offset + index * table.item_size()
        }
    }

    /// The field or method of the method handle at `at`, if its kind is one
    /// of `kinds`.
    fn method_handle(&self, image: &[u8], table: Table, kinds: RangeInclusive<u16>, at: Offset) -> Offset {
        let (handle, _) = MethodHandleItem::ref_from_prefix(&image[at as usize..]).unwrap();
        match handle.method_handle_type.get() {
            kind if kind >= METHOD_HANDLE_TYPES => INVALID_OFFSET,
            kind if !kinds.contains(&kind) => NO_INDEX,
            _ => self.index_target(table, handle.field_or_method_id.get().into()),
        }
    }

    /// Stores `reference` of type `tag`. Targets that do not fit the stored
    /// form are skipped.
    pub fn write(&self, image: &mut [u8], tag: u8, reference: Reference) -> Result<()> {
        let Reference { location, target } = reference;
        let at = location as usize;
        // Branches count code units from the instruction, one unit before the
        // operand.
        let units = (i64::from(target) - i64::from(location)) / 2 + 1;
        match KINDS[usize::from(tag)].1.target() {
            Target::Index16(table) => {
                if let Some(index) = self.index_of(table, target) {
                    let index = u16::try_from(index).map_err(|_| corrupt("index does not fit 16 bits"))?;
                    put(image, at, &index.to_le_bytes())?;
                }
            }
            Target::Index32(table) => {
                if let Some(index) = self.index_of(table, target) {
                    put(image, at, &(index as u32).to_le_bytes())?;
                }
            }
            Target::Offset32 => put(image, at, &target.to_le_bytes())?,
            Target::Branch8 => {
                if let Ok(units) = i8::try_from(units) {
                    put(image, at, &units.to_le_bytes())?;
                }
            }
            Target::Branch16 => {
                if let Ok(units) = i16::try_from(units) {
                    put(image, at, &units.to_le_bytes())?;
                }
            }
            Target::Branch32 => {
                if let Ok(units) = i32::try_from(units) {
                    put(image, at, &units.to_le_bytes())?;
                }
            }
        }
        Ok(())
    }

    /// Index of the item of `table` at `target`, if it lies in the table.
    fn index_of(&self, table: Table, target: Offset) -> Option<u64> {
        let items = self.tables[table as usize];
        let index = u64::from(target.wrapping_sub(items.offset)) / u64::from(table.item_size());
        (index < u64::from(items.count)).then_some(index)
    }
}

/// The field at `field` of each element at `offsets` within the range.
fn read_elements(
    offsets: &[Offset],
    field: u32,
    Range { start: lo, end: hi }: Range<Offset>,
    out: &mut Vec<Reference>,
    target: impl Fn(Offset) -> Offset,
) {
    let mut first = offsets.partition_point(|&offset| offset <= lo);
    if first > 0 && offsets[first - 1] + field >= lo {
        first -= 1;
    }
    for &offset in &offsets[first..] {
        let location = offset + field;
        if location >= hi {
            break;
        }
        match target(location) {
            INVALID_OFFSET => break,
            NO_OFFSET => {}
            target => out.push(Reference { location, target }),
        }
    }
}

/// A lower bound on the size of an item of map type `code`.
fn item_base_size(code: u16) -> usize {
    match code {
        TYPE_LIST | ANNOTATION_SET_REF_LIST | ANNOTATION_SET_ITEM => size_of::<u32>(),
        CODE_ITEM => size_of::<CodeItem>(),
        ANNOTATIONS_DIRECTORY_ITEM => size_of::<AnnotationsDirectoryItem>(),
        _ => Table::ALL
            .into_iter()
            .find(|table| table.code() == code)
            .map_or(1, |table| table.item_size() as usize),
    }
}

/// Whether `items` of at least `width` bytes each fit before the image end.
fn covers(image: &[u8], items: Items, width: usize) -> bool {
    let offset = items.offset as usize;
    offset <= image.len() && (image.len() - offset) / width >= items.count as usize
}

/// Element offsets of lists that each hold a 32-bit count and that many
/// elements of `width` bytes.
fn elements(image: &[u8], items: Items, width: usize) -> Option<Vec<Offset>> {
    if !covers(image, items, size_of::<u32>()) {
        return None;
    }
    let mut cursor = Cursor::at(image, items.offset);
    let mut offsets = Vec::new();
    for _ in 0..items.count {
        cursor.align()?;
        let count = cursor.read::<U32>()?.get() as usize;
        offsets.extend(cursor.skip(count, width)?.step_by(width).map(|at| at as Offset));
    }
    Some(offsets)
}

/// Offsets of annotations directories and of their field, method and
/// parameter annotations.
fn directories(image: &[u8], items: Items, lists: &mut [Vec<Offset>; List::COUNT]) -> Option<()> {
    if !covers(image, items, size_of::<AnnotationsDirectoryItem>()) {
        return None;
    }
    let mut cursor = Cursor::at(image, items.offset);
    for _ in 0..items.count {
        cursor.align()?;
        lists[List::AnnotationsDirectories as usize].push(cursor.at as Offset);
        let directory = cursor.read::<AnnotationsDirectoryItem>()?;
        for (list, count, width) in [
            (
                List::FieldAnnotations,
                directory.fields_size,
                size_of::<FieldAnnotation>(),
            ),
            (
                List::MethodAnnotations,
                directory.annotated_methods_size,
                size_of::<MethodAnnotation>(),
            ),
            (
                List::ParameterAnnotations,
                directory.annotated_parameters_size,
                size_of::<ParameterAnnotation>(),
            ),
        ] {
            let span = cursor.skip(count.get() as usize, width)?;
            lists[list as usize].extend(span.step_by(width).map(|at| at as Offset));
        }
    }
    Some(())
}

/// Offsets of code items, walking past their instructions, try blocks and
/// exception handlers. A DEX file without code is rejected.
fn code_items(image: &[u8], items: Items) -> Option<Vec<Offset>> {
    if !covers(image, items, size_of::<CodeItem>()) {
        return None;
    }
    let mut cursor = Cursor::at(image, items.offset);
    let mut offsets = Vec::with_capacity(items.count as usize);
    for _ in 0..items.count {
        cursor.align()?;
        offsets.push(cursor.at as Offset);
        let code = cursor.read::<CodeItem>()?;
        cursor.skip(code.insns_size.get() as usize, size_of::<u16>())?;
        let tries = usize::from(code.tries_size.get());
        if tries == 0 {
            continue;
        }
        cursor.align()?;
        cursor.skip(tries, size_of::<TryItem>())?;
        let handlers = cursor.uleb128()? as usize;
        if cursor.remaining() < handlers {
            return None;
        }
        for _ in 0..handlers {
            // Type and address pairs, then a catch-all address unless the
            // count is positive.
            let size = cursor.sleb128()?;
            let pairs = size.unsigned_abs() as usize;
            if cursor.remaining() < pairs {
                return None;
            }
            for _ in 0..pairs {
                cursor.skip_leb128()?;
                cursor.skip_leb128()?;
            }
            if size <= 0 {
                cursor.skip_leb128()?;
            }
        }
    }
    (!offsets.is_empty()).then_some(offsets)
}

/// A read position that clamps to the image end when placed past it, and
/// fails reads that run past it.
struct Cursor<'a> {
    image: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn at(image: &'a [u8], offset: Offset) -> Self {
        Self {
            image,
            at: (offset as usize).min(image.len()),
        }
    }

    fn remaining(&self) -> usize {
        self.image.len() - self.at
    }

    /// Moves up to a multiple of four, unless that passes the end.
    fn align(&mut self) -> Option<()> {
        let aligned = self.at.next_multiple_of(4);
        (aligned <= self.image.len()).then(|| self.at = aligned)
    }

    fn read<T: FromBytes + KnownLayout + Immutable + Unaligned>(&mut self) -> Option<&'a T> {
        let (value, _) = T::ref_from_prefix(&self.image[self.at..]).ok()?;
        self.at += size_of::<T>();
        Some(value)
    }

    fn records<T: FromBytes + KnownLayout + Immutable + Unaligned>(&mut self, count: usize) -> Option<&'a [T]> {
        let (records, _) = <[T]>::ref_from_prefix_with_elems(&self.image[self.at..], count).ok()?;
        self.at += size_of_val(records);
        Some(records)
    }

    /// Moves past `count` elements of `width` bytes, returning the span.
    fn skip(&mut self, count: usize, width: usize) -> Option<Range<usize>> {
        if self.remaining() / width < count {
            return None;
        }
        let start = self.at;
        self.at += count * width;
        Some(start..self.at)
    }

    /// An unsigned LEB128 value of at most five bytes; bits past the 32nd
    /// are dropped.
    fn uleb128(&mut self) -> Option<u32> {
        let mut value = 0u32;
        for (index, &byte) in self.image[self.at..].iter().take(5).enumerate() {
            value |= u32::from(byte & 0x7F) << (7 * index);
            if byte & 0x80 == 0 {
                self.at += index + 1;
                return Some(value);
            }
        }
        None
    }

    /// A signed LEB128 value of at most five bytes.
    fn sleb128(&mut self) -> Option<i32> {
        let mut value = 0i32;
        for (index, &byte) in self.image[self.at..].iter().take(5).enumerate() {
            let shift = 7 * index as u32;
            value |= (u32::from(byte & 0x7F) << shift) as i32;
            if byte & 0x80 == 0 {
                self.at += index + 1;
                if shift == 28 {
                    return Some(value);
                }
                // Extend the sign bit of the last group.
                let unused = 25 - shift;
                return Some((value << unused) >> unused);
            }
        }
        None
    }

    fn skip_leb128(&mut self) -> Option<()> {
        let length = self.image[self.at..]
            .iter()
            .take(5)
            .position(|&byte| byte & 0x80 == 0)?;
        self.at += length + 1;
        Some(())
    }
}

/// Successive instructions of a code item. Iteration stops at an unknown
/// opcode, and at the payloads that switch and array instructions point to.
struct Instructions<'a> {
    image: &'a [u8],
    at: usize,
    end: usize,
    payload: usize,
}

impl<'a> Instructions<'a> {
    fn new(image: &'a [u8], code_item: Offset) -> Self {
        let (code, _) = CodeItem::ref_from_prefix(&image[code_item as usize..]).unwrap();
        let at = code_item as usize + size_of::<CodeItem>();
        let end = at + code.insns_size.get() as usize * size_of::<u16>();
        Self {
            image,
            at,
            end,
            payload: end,
        }
    }
}

impl Iterator for Instructions<'_> {
    type Item = (Offset, &'static Instruction);

    fn next(&mut self) -> Option<Self::Item> {
        if self.at >= self.payload {
            return None;
        }
        let instruction = instruction(self.image[self.at])?;
        let length = usize::from(instruction.units) * 2;
        if self.end - self.at < length {
            return None;
        }
        // fill-array-data, packed-switch and sparse-switch point to their
        // payload, which must follow them within the code item.
        if matches!(instruction.opcode, 0x26 | 0x2B | 0x2C) {
            let units = u32_at(self.image, self.at + 2) as i32;
            if units < i32::from(instruction.units) || units as usize >= (self.end - self.at) / 2 {
                return None;
            }
            self.payload = self.payload.min(self.at + units as usize * 2);
        }
        let at = self.at as Offset;
        self.at += length;
        Some((at, instruction))
    }
}
