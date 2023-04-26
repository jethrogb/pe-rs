/*
 * Zero-copy Portable Executable parser
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#![allow(non_camel_case_types)]

use super::utility::{FP,RVA,CChar,RefSafe,Size4Bytes};

pub const DOS_SIGNATURE: u16 = 0x5a4d;
pub const PE_SIGNATURE: u32 = 0x00004550;
pub const OH_SIGNATURE_PE32: u16 = 0x10b;
pub const OH_SIGNATURE_PE32P: u16 = 0x20b;

#[repr(u16)]
#[derive(Copy,Clone,Debug,PartialEq,Eq)]
pub enum Machine {
    UNKNOWN   = 0x0000,
    AM33      = 0x01d3,
    AMD64     = 0x8664,
    ARM       = 0x01c0,
    ARMNT     = 0x01c4,
    ARM64     = 0xaa64,
    EBC       = 0x0ebc,
    I386      = 0x014c,
    IA64      = 0x0200,
    M32R      = 0x9041,
    MIPS16    = 0x0266,
    MIPSFPU   = 0x0366,
    MIPSFPU16 = 0x0466,
    POWERPC   = 0x01f0,
    POWERPCFP = 0x01f1,
    R4000     = 0x0166,
    SH3       = 0x01a2,
    SH3DSP    = 0x01a3,
    SH4       = 0x01a6,
    SH5       = 0x01a8,
    THUMB     = 0x01c2,
    WCEMIPSV2 = 0x0169,
}

#[repr(u16)]
#[derive(Copy,Clone,Debug,PartialEq,Eq)]
pub enum Subsystem {
    UNKNOWN                 =  0,
    NATIVE                  =  1,
    WINDOWS_GUI             =  2,
    WINDOWS_CUI             =  3,
    POSIX_CUI               =  7,
    WINDOWS_CE_GUI          =  9,
    EFI_APPLICATION         = 10,
    EFI_BOOT_SERVICE_DRIVER = 11,
    EFI_RUNTIME_DRIVER      = 12,
    EFI_ROM                 = 13,
    XBOX                    = 14,
}

#[repr(u16)]
#[derive(Copy,Clone,Debug,PartialEq,Eq)]
pub enum RelocationType {
	ABSOLUTE        = 0,
	HIGH            = 1,
	LOW             = 2,
	HIGHLOW         = 3,
	HIGHADJ         = 4,
	ARM_MOV32A      = 5, // also MIPS_JMPADDR
	RESERVED1       = 6,
	ARM_MOV32T      = 7,
	RESERVED2       = 8,
	MIPS_JMPADDR16  = 9,
	DIR64           = 10,
	RESERVED3       = 11,
	RESERVED4       = 12,
	RESERVED5       = 13,
	RESERVED6       = 14,
	RESERVED7       = 15,
}

pub mod image_characteristics {
    // https://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx
    bitflags! {
        #[repr(packed)]
        flags Characteristics: u16 {
            const RELOCS_STRIPPED         = 0x0001,
            const EXECUTABLE_IMAGE        = 0x0002,
            const LINE_NUMS_STRIPPED      = 0x0004,
            const LOCAL_SYMS_STRIPPED     = 0x0008,
            const AGGRESSIVE_WS_TRIM      = 0x0010,
            const LARGE_ADDRESS_AWARE     = 0x0020,
            const RESERVED1               = 0x0040,
            const BYTES_REVERSED_LO       = 0x0080,
            const MACHINE_32BIT           = 0x0100,
            const DEBUG_STRIPPED          = 0x0200,
            const REMOVABLE_RUN_FROM_SWAP = 0x0400,
            const NET_RUN_FROM_SWAP       = 0x0800,
            const SYSTEM                  = 0x1000,
            const DLL                     = 0x2000,
            const UP_SYSTEM_ONLY          = 0x4000,
            const BYTES_REVERSED_HI       = 0x8000,
        }
    }
}

pub mod dll_characteristics {
    bitflags! {
        #[repr(packed)]
        flags Characteristics: u16 {
            const RESERVED1             = 0x0001,
            const RESERVED2             = 0x0002,
            const RESERVED3             = 0x0004,
            const RESERVED4             = 0x0008,
            const RESERVED5             = 0x0010,
            const RESERVED6             = 0x0020,
            const DYNAMIC_BASE          = 0x0040,
            const FORCE_INTEGRITY       = 0x0080,
            const NX_COMPAT             = 0x0100,
            const NO_ISOLATION          = 0x0200,
            const NO_SEH                = 0x0400,
            const NO_BIND               = 0x0800,
            const RESERVED7             = 0x1000,
            const WDM_DRIVER            = 0x2000,
            const RESERVED8             = 0x4000,
            const TERMINAL_SERVER_AWARE = 0x8000,
        }
    }
}

pub mod section_characteristics {
    bitflags! {
        #[repr(packed)]
        flags Characteristics: u32 {
            const RESERVED2                        = 0x00000001,
            const RESERVED3                        = 0x00000002,
            const RESERVED4                        = 0x00000004,
            const IMAGE_SCN_TYPE_NO_PAD            = 0x00000008,
            const RESERVED5                        = 0x00000010,
            const IMAGE_SCN_CNT_CODE               = 0x00000020,
            const IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040,
            const IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
            const IMAGE_SCN_LNK_OTHER              = 0x00000100,
            const IMAGE_SCN_LNK_INFO               = 0x00000200,
            const RESERVED6                        = 0x00000400,
            const IMAGE_SCN_LNK_REMOVE             = 0x00000800,
            const IMAGE_SCN_LNK_COMDAT             = 0x00001000,
            const RESERVED7                        = 0x00002000,
            const RESERVED8                        = 0x00004000,
            const IMAGE_SCN_GPREL                  = 0x00008000,
            const RESERVED9                        = 0x00010000,
            const IMAGE_SCN_MEM_16BIT              = 0x00020000,
            const IMAGE_SCN_MEM_LOCKED             = 0x00040000,
            const IMAGE_SCN_MEM_PRELOAD            = 0x00080000,
            const IMAGE_SCN_ALIGN_BIT0             = 0x00100000,
            const IMAGE_SCN_ALIGN_BIT1             = 0x00200000,
            const IMAGE_SCN_ALIGN_BIT2             = 0x00400000,
            const IMAGE_SCN_ALIGN_BIT3             = 0x00800000,
            const IMAGE_SCN_LNK_NRELOC_OVFL        = 0x01000000,
            const IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000,
            const IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000,
            const IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000,
            const IMAGE_SCN_MEM_SHARED             = 0x10000000,
            const IMAGE_SCN_MEM_EXECUTE            = 0x20000000,
            const IMAGE_SCN_MEM_READ               = 0x40000000,
            const IMAGE_SCN_MEM_WRITE              = 0x80000000,
        }
    }
}

#[repr(usize)]
#[derive(Copy,Clone,Debug,PartialEq,Eq)]
pub enum DirectoryEntry {
    ExportTable = 0,
    ImportTable,
    ResourceTable,
    ExceptionTable,
    CertificateTable,
    BaseRelocationTable,
    Debug,
    Architecture,
    GlobalPtr,
    ThreadLocalStorageTable,
    LoadConfigTable,
    BoundImport,
    ImportAddressTable,
    DelayImportDescriptor,
    CommonLanguageRuntimeHeader,
    Reserved,
}

#[repr(packed)]
#[derive(Clone, Debug, Default)]
pub struct DosHeader {
    pub signature: u16,
    _unused: [u16; 29],
    pub new: FP<PeHeader>,
}
unsafe impl RefSafe for DosHeader {}

#[repr(packed)]
#[derive(Clone, Debug)]
pub struct PeHeader {
    pub signature: u32,
    pub machine: Machine,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: FP<[()]>,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: image_characteristics::Characteristics,
}
unsafe impl RefSafe for PeHeader {}

#[repr(packed)]
#[derive(Clone, Debug)]
pub struct PeOptionalHeader32 {
    pub signature: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: RVA<dyn Fn()>,
    pub base_of_code: RVA<()>,
    pub base_of_data: RVA<()>,
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
    pub check_sum: u32,
    pub subsystem: Subsystem,
    pub characteristics: dll_characteristics::Characteristics,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}
unsafe impl RefSafe for PeOptionalHeader32 {}

#[repr(packed)]
#[derive(Clone, Debug)]
pub struct PeOptionalHeader64 {
    pub signature: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: RVA<dyn Fn()>,
    pub base_of_code: RVA<()>,
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
    pub check_sum: u32,
    pub subsystem: Subsystem,
    pub characteristics: dll_characteristics::Characteristics,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}
unsafe impl RefSafe for PeOptionalHeader64 {}

#[repr(packed)]
#[derive(Clone, Debug)]
pub struct DataDirectory<T: Size4Bytes> {
    pub virtual_address: T, //Normally RVA, but FP for offset 4 (Certificate table)
    pub size: u32,
}
unsafe impl<T: RefSafe> RefSafe for DataDirectory<T> where T: Size4Bytes {}

#[repr(packed)]
#[derive(Clone, Debug)]
pub struct SectionHeader {
    pub name: [CChar;8],
    pub virtual_size: u32,
    pub virtual_address: RVA<[u8]>,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: FP<[u8]>,
    pub pointer_to_relocations: FP<[()]>,
    pub pointer_to_linenumbers: FP<[()]>,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: section_characteristics::Characteristics,
}
unsafe impl RefSafe for SectionHeader {}

#[repr(packed)]
#[derive(Clone, Debug)]
pub struct ExportDirectory {
    pub export_flags: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: RVA<[CChar]>,
    pub ordinal_base: u32,
    pub address_table_entries: u32,
    pub number_of_name_pointers: u32,
    pub export_address_table: RVA<[RawExportAddress]>,
    pub name_pointer: RVA<[RVA<[CChar]>]>,
    pub ordinal_table: RVA<[u16]>,
}
unsafe impl RefSafe for ExportDirectory {}

#[repr(packed)]
#[derive(Clone, Debug)]
pub struct RawExportAddress(pub RVA<()>);
unsafe impl RefSafe for RawExportAddress {}

#[repr(packed)]
#[derive(Clone, Debug)]
pub struct RelocationBlock {
    pub page_rva: RVA<()>, // Could be RVA<u16>, RVA<u32> or RVA<u64>
    pub block_size: u32,
}
unsafe impl RefSafe for RelocationBlock {}

#[repr(packed)]
#[derive(Copy,Clone,Debug,PartialEq,Eq,Default)]
pub struct Relocation(pub u16);
unsafe impl RefSafe for Relocation {}

impl Relocation {
	pub fn encode(rtype: RelocationType, offset: u16) -> Relocation {
		if offset>0xfff {
			panic!("Invalid relocation offset");
		}
		Relocation(offset&0xfff | ((rtype as u16)<<12))
	}
	pub fn decode(self) -> (RelocationType,u16) {
		(unsafe{::std::mem::transmute(self.0>>12)},self.0&0xfff)
	}
}
