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

#[cfg_attr(test,macro_use)]
#[cfg(test)]
extern crate lazy_static;

#[macro_use]
extern crate bitflags;

pub mod types;
mod utility;

use std::mem::{transmute,size_of};

use types::*;
use utility::{RefSafe,URP,URPConvert,FPRef};
pub use utility::{FP,RVA,CChar,Error,Result,AsOsStr};

#[cfg(target_endian="big")] const E:ENDIANNESS_NOT_SUPPORTED=();

pub struct Pe<'data> {
	data: &'data [u8],
	h: &'data PeHeader,
	oh: PeOptionalHeader<'data>,
	directories: &'data [DataDirectory<u32>],
	sections: &'data [SectionHeader],
}

#[derive(Copy,Clone)]
pub enum PeOptionalHeader<'data> {
	Pe32(&'data PeOptionalHeader32),
	Pe32Plus(&'data PeOptionalHeader64),
}

impl<'data> PeOptionalHeader<'data> {
	pub fn get_number_of_rva_and_sizes(&self) -> u32 {
		match self {
			&PeOptionalHeader::Pe32(h) => h.number_of_rva_and_sizes,
			&PeOptionalHeader::Pe32Plus(h) => h.number_of_rva_and_sizes,
		}
	}

	pub fn get_size_of_headers(&self) -> u32 {
		match self {
			&PeOptionalHeader::Pe32(h) => h.size_of_headers,
			&PeOptionalHeader::Pe32Plus(h) => h.size_of_headers,
		}
	}

	pub fn get_check_sum(&self) -> u32 {
		match self {
			&PeOptionalHeader::Pe32(h) => h.check_sum,
			&PeOptionalHeader::Pe32Plus(h) => h.check_sum,
		}
	}
}

pub trait Directory: RefSafe {
	type Type: utility::Size4Bytes + URP<Self>;

	// TODO: replace by const fn or associated constant when stable
	fn entry() -> DirectoryEntry;
}

macro_rules! directory_entry(
	($n:ident = $urp:ident<$t:ty>) => (
		impl Directory for $t {
			type Type = $urp<$t>;

			fn entry() -> DirectoryEntry {
				DirectoryEntry::$n
			}
		}
	);
);

directory_entry!(ExportTable         = RVA<ExportDirectory>);
directory_entry!(BaseRelocationTable = RVA<RelocationBlock>);

pub struct Exports<'pe,'data: 'pe> {
	pe: &'pe Pe<'data>,
	ddir: &'data DataDirectory<RVA<ExportDirectory>>,
	edir: &'data ExportDirectory,
}

#[derive(Debug)]
pub enum ExportAddress<'data> {
	Export(&'data RVA<dyn Fn()>),
	Forwarder(&'data RVA<[CChar]>),
}

pub struct RelocationIter<'pe,'data: 'pe> {
	pe: &'pe Pe<'data>,
	next_rblock: RVA<RelocationBlock>,
	end: RVA<()>,
}

impl<'data> Pe<'data> {
// PRIVATE
	fn resolve_rva_raw<'a>(&self, rva: RVA<()>, length: u32, max_length: Option<&'a mut u32>) -> Result<FP<()>> {
		for section in self.sections {
			if section.virtual_address<=rva && rva<section.virtual_address+section.virtual_size {
				if rva+length>section.virtual_address+section.size_of_raw_data {
					return Err(Error::ResolveMapError);
				}
				if let Some(max)=max_length {
					*max=(section.virtual_address+section.size_of_raw_data).get()-rva.get();
				}
				return Ok(section.pointer_to_raw_data.offset(rva.get()-section.virtual_address.get()));
			}
		}
		Err(Error::ResolveMapError)
	}

	fn resolve_rva<T>(&self, rva: RVA<T>) -> Result<FP<T>> {
		let length=size_of::<T>() as u32;
		Ok(self.resolve_rva_raw(rva+0u32,length,None)?.offset(0))
	}

	fn resolve_rva_slice<T>(&self, rva: RVA<[T]>, count: u32) -> Result<FP<[T]>> {
		let length=size_of::<T>() as u32*count;
		Ok(self.resolve_rva_raw(rva+0u32,length,None)?.offset(0))
	}

// PUBLIC
	pub fn new(data: &'data [u8]) -> Result<Pe<'data>> {
		let sig=*data.ref_at(FP::<u16>::new(0))?;
		let pe_header_fp=if sig==DOS_SIGNATURE {
			data.ref_at(FP::<DosHeader>::new(0))?.new
		} else if sig as u32==PE_SIGNATURE {
			FP::new(0)
		} else {
			return Err(Error::NotPe)
		};
		let pe_header=data.ref_at(pe_header_fp)?;

		if pe_header.size_of_optional_header<2 {
			return Err(Error::NotPe);
		}
		let pe_oh_fp=pe_header_fp+(size_of::<PeHeader>() as u32);
		let sig: u16=*data.ref_at(pe_oh_fp.offset(0))?;

		let pe_dd_fp;
		let dd_size;
		let pe_oh=match sig {
			OH_SIGNATURE_PE32 => {
				let s=size_of::<PeOptionalHeader32>() as u16;
				if pe_header.size_of_optional_header<s { return Err(Error::NotPe) }
				dd_size=pe_header.size_of_optional_header-s;
				pe_dd_fp=pe_oh_fp.offset(s as u32);
				PeOptionalHeader::Pe32(data.ref_at(pe_oh_fp.offset(0))?)
			},
			OH_SIGNATURE_PE32P => {
				let s=size_of::<PeOptionalHeader64>() as u16;
				if pe_header.size_of_optional_header<s { return Err(Error::NotPe) }
				dd_size=pe_header.size_of_optional_header-s;
				pe_dd_fp=pe_oh_fp.offset(s as u32);
				PeOptionalHeader::Pe32Plus(data.ref_at(pe_oh_fp.offset(0))?)
			},
			_ => return Err(Error::NotPe),
		};

		let n=pe_oh.get_number_of_rva_and_sizes();
		if ((n*size_of::<DataDirectory<u32>>() as u32) as u16)>dd_size {
			return Err(Error::InvalidSize);
		}
		let pe_dd=data.ref_slice_at(pe_dd_fp,n)?;

		let pe_sec_fp=pe_dd_fp.offset(n*(size_of::<DataDirectory<u32>>() as u32));
		let pe_sec=data.ref_slice_at(pe_sec_fp,pe_header.number_of_sections as u32)?;

		Ok(Pe{data:data,h:pe_header,oh:pe_oh,directories:pe_dd,sections:pe_sec})
	}

	pub fn ref_at<T: RefSafe>(&self, rva: RVA<T>) -> Result<&'data T> {
		let fp=self.resolve_rva(rva)?;
		self.data.ref_at(fp)
	}

	pub fn ref_slice_at<T: RefSafe>(&self, rva: RVA<[T]>, count: u32) -> Result<&'data [T]> {
		let fp=self.resolve_rva_slice(rva,count)?;
		self.data.ref_slice_at(fp,count)
	}

	pub fn ref_cstr_at(&self, rva: RVA<[CChar]>) -> Result<&'data [CChar]> {
		let mut max_len=0;
		let fp=self.resolve_rva_raw(rva+0u32,0,Some(&mut max_len))?;
		self.data.ref_cstr_at(fp.offset(0),Some(max_len))
	}

	pub fn ref_at_fp<T: RefSafe>(&self, fp: FP<T>) -> Result<&'data T> {
		self.data.ref_at(fp)
	}

	pub fn ref_slice_at_fp<T: RefSafe>(&self, fp: FP<[T]>, count: u32) -> Result<&'data [T]> {
		self.data.ref_slice_at(fp,count)
	}

	pub fn ref_cstr_at_fp(&self, fp: FP<[CChar]>) -> Result<&'data [CChar]> {
		self.data.ref_cstr_at(fp,None)
	}

	pub fn ref_pe_header(&self) -> Result<&'data [u8]> {
		if self.oh.get_size_of_headers() as usize>self.data.len() {
			return Err(Error::InvalidSize);
		}
		Ok(&self.data[..self.oh.get_size_of_headers() as usize])
	}

	pub fn get_header(&self) -> &'data PeHeader {
		self.h
	}

	pub fn get_optional_header(&self) -> PeOptionalHeader<'data> {
		self.oh
	}

	pub fn get_sections(&self) -> &'data [SectionHeader] {
		self.sections
	}

	pub fn get_directory<D: Directory>(&self) -> Result<&'data DataDirectory<D::Type>> {
		self.directories.get(D::entry() as usize)
			.ok_or(Error::DirectoryMissing)
			.map(|ddir|unsafe{transmute::<&'data DataDirectory<_>,&'data DataDirectory<_>>(ddir)})
	}

	pub fn get_directory_raw(&self, entry: DirectoryEntry) -> Result<&'data DataDirectory<RVA<[u8]>>> {
		if self.directories.len()<=(entry as usize) {
			return Err(Error::DirectoryMissing);
		}
		Ok(unsafe{transmute::<&'data DataDirectory<_>,&'data DataDirectory<_>>(&self.directories[entry as usize])})
	}

	pub fn get_exports(&self) -> Result<Exports> {
		let ddir=self.get_directory::<ExportDirectory>()?;
		if (ddir.size as usize)<size_of::<ExportDirectory>() {
			return Err(Error::InvalidSize);
		}
		Ok(Exports{pe:self,ddir:ddir,edir:self.ref_at(ddir.virtual_address)?})
	}

	pub fn get_relocations<'pe>(&'pe self) -> Result<RelocationIter<'pe,'data>> {
		let ddir=self.get_directory::<RelocationBlock>()?;
		Ok(RelocationIter{pe:self,next_rblock:ddir.virtual_address,end:ddir.virtual_address+ddir.size})
	}
}

impl<'pe,'data: 'pe> Exports<'pe, 'data> {
	pub fn get_export_directory(&self) -> &'data ExportDirectory {
		self.edir
	}

	pub fn concretize_export_address<'a>(&self, addr: &'a RawExportAddress) -> ExportAddress<'a> {
		if addr.0>=self.ddir.virtual_address && addr.0<(self.ddir.virtual_address+self.ddir.size) {
			ExportAddress::Forwarder(unsafe{transmute(addr)})
		} else {
			ExportAddress::Export(unsafe{transmute(addr)})
		}
	}

	/// The outputs of this function and `get_ordinal_offsets` represent pairs.
	pub fn get_names(&self) -> Result<&'data [RVA<[CChar]>]> {
		self.pe.ref_slice_at(self.edir.name_pointer,self.edir.number_of_name_pointers)
	}

	/// The outputs of this function and `get_names` represent pairs. This
	/// function returns ordinal offsets. To get the ordinal number, add
	/// ordinal_base
	pub fn get_ordinal_offsets(&self) -> Result<&'data [u16]> {
		self.pe.ref_slice_at(self.edir.ordinal_table,self.edir.number_of_name_pointers)
	}

	/// The outputs of this function is indexed by ordinal offset.
	pub fn get_export_addresses(&self) -> Result<&'data [RawExportAddress]> {
		self.pe.ref_slice_at(self.edir.export_address_table,self.edir.address_table_entries)
	}

	pub fn lookup_symbol(&self, symbol: &str) -> Result<ExportAddress<'data>> {
		let pos=self.get_names()?.iter().position(|&name_rva|{
			self.pe.ref_cstr_at(name_rva).ok().map_or(false,|cstr|cstr.as_os_str()==symbol)
		}).ok_or(Error::SymbolNotFound)?;
		let ordinal_offset=self.get_ordinal_offsets()?[pos];
		let export=self.get_export_addresses()?.get(ordinal_offset as usize).ok_or(Error::ExportNotFound)?;
		Ok(self.concretize_export_address(export))
	}
}

impl<'pe,'data: 'pe> RelocationIter<'pe,'data> {
	fn advance(&mut self) -> Result<(RVA<()>,&'data [Relocation])> {
		let rblock=self.pe.ref_at(self.next_rblock)?;
		let relocs: &[Relocation]=self.pe.ref_slice_at(self.next_rblock.offset(size_of::<RelocationBlock>() as u32),rblock.block_size/2)?;
		self.next_rblock=self.next_rblock.offset(rblock.block_size);
		Ok((rblock.page_rva,relocs))
	}
}

impl<'pe,'data: 'pe> Iterator for RelocationIter<'pe,'data> {
	type Item=Result<(RVA<()>,&'data [Relocation])>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.next_rblock.offset(size_of::<RelocationBlock>() as u32) as RVA<()><=self.end {
			Some(self.advance())
		} else if self.next_rblock.get()==self.end.get() {
			None
		} else {
			Some(Err(Error::InvalidSize))
		}
	}
}

#[cfg(test)]
mod tests;
