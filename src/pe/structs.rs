use crate::errors::{PeSignError, PeSignResult};

pub trait Castable {}

/// Represents the architecture of the PE image.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Arch {
    X86,
    X64,
}

pub const HDR32_MAGIC: u16 = 0x010B;
pub const HDR64_MAGIC: u16 = 0x020B;

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ImageDOSHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}
impl Castable for ImageDOSHeader {}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ImageNtHeaders {
    ImageNTHeaders32(ImageNTHeaders32),
    ImageNTHeaders64(ImageNTHeaders64),
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ImageNTHeaders32 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader32,
}
impl Castable for ImageNTHeaders32 {}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ImageNTHeaders64 {
    pub signature: u32,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}
impl Castable for ImageNTHeaders64 {}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}
impl Castable for ImageFileHeader {}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}
impl Castable for ImageOptionalHeader32 {}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}
impl Castable for ImageOptionalHeader64 {}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ImageDirectoryEntry {
    Export = 0,
    Import = 1,
    Resource = 2,
    Exception = 3,
    Security = 4,
    BaseReloc = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPTR = 8,
    TLS = 9,
    LoadConfig = 10,
    BoundImport = 11,
    IAT = 12,
    DelayImport = 13,
    COMDescriptor = 14,
    Reserved = 15,
}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Default, Debug)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}
impl Castable for ImageDataDirectory {}

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}
impl Castable for ImageSectionHeader {}
impl ImageSectionHeader {
    pub fn name(self: &Self) -> Result<String, PeSignError> {
        Ok(String::from_utf8(self.name.to_vec())
            .map_unknown_err()?
            .trim_end_matches('\0')
            .to_owned())
    }
}
