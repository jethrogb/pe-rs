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

use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::ffi::OsStr;
use std::ops::Add;
use std::mem::{transmute,size_of};
use std::slice::from_raw_parts;
use std::marker::PhantomData;

/// Unsafe relative pointer type
pub trait URP<T: ?Sized> : Copy {
	fn new(addr: u32) -> Self;
}

pub trait URPConvert<T: ?Sized, U: ?Sized> {
	type Out;
	fn offset(self, by: u32) -> Self::Out;
}

macro_rules! define_urp {
	{ pub struct $URP:ident<T>; } => {

		#[repr(packed)]
		pub struct $URP<T: ?Sized>(u32,PhantomData<T>);

		impl<T: ?Sized> $URP<T> {
			#[inline]
			pub fn get(self) -> u32 {
				self.0
			}
		}

		impl<T: ?Sized, U: ?Sized> ::std::cmp::PartialEq<$URP<U>> for $URP<T> {
			#[inline]
			fn eq(&self, other: &$URP<U>) -> bool {
				self.0.eq(&other.0)
			}
		}
		impl<T: ?Sized, U: ?Sized> ::std::cmp::PartialOrd<$URP<U>> for $URP<T> {
			#[inline]
			fn partial_cmp(&self, other: &$URP<U>) -> ::std::option::Option<::std::cmp::Ordering> {
				self.0.partial_cmp(&other.0)
			}
		}
		impl<T: ?Sized> ::std::cmp::Eq for $URP<T> {}
		impl<T: ?Sized> ::std::cmp::Ord for $URP<T> {
			#[inline]
			fn cmp(&self, other: &$URP<T>) -> ::std::cmp::Ordering {
				self.0.cmp(&other.0)
			}
		}
		impl<T: ?Sized> ::std::fmt::Debug for $URP<T> {
			#[inline]
			fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
				let mut builder = f.debug_tuple(concat!(stringify!($URP),"<T>"));
				builder.field(&self.0);
				builder.finish()
			}
		}
		impl<T: ?Sized> ::std::default::Default for $URP<T> {
			#[inline]
			fn default() -> $URP<T> { $URP(::std::default::Default::default(),PhantomData) }
		}
		impl<T: ?Sized> ::std::clone::Clone for $URP<T> {
			#[inline]
			fn clone(&self) -> $URP<T> {
				$URP(self.0,PhantomData)
			}
		}
		impl<T: ?Sized> ::std::marker::Copy for $URP<T> { }
		unsafe impl<T: ?Sized> ::std::marker::Sync for $URP<T> { }
		unsafe impl<T: ?Sized> ::std::marker::Send for $URP<T> { }

		impl<T: ?Sized, U: ?Sized> URPConvert<T,U> for $URP<T> {
			type Out=$URP<U>;

			#[inline]
			fn offset(self, by: u32) -> $URP<U> {
				$URP(self.0+by,PhantomData)
			}
		}

		impl<T: ?Sized> URP<T> for $URP<T> {
			#[inline]
			fn new(addr: u32) -> $URP<T> {
				$URP(addr,PhantomData)
			}
		}

		impl<T: ?Sized> Add<u32> for $URP<T> {
			type Output=$URP<()>;

			#[inline]
			fn add(self, rhs: u32) -> $URP<()> {
				$URP(self.0+rhs,PhantomData)
			}
		}

		impl<T: ?Sized> Add<usize> for $URP<T> {
			type Output=usize;

			#[inline]
			fn add(self, rhs: usize) -> usize {
				self.0 as usize+rhs
			}
		}

		unsafe impl<T: ?Sized> Size4Bytes for $URP<T> {
			unsafe fn _check_size(a: Self) { transmute::<_,u32>(a); }
		}
	}
}

define_urp!{pub struct FP<T>;}
define_urp!{pub struct RVA<T>;}

#[repr(packed)]
pub struct CChar(u8);

trait NullTerminatedStr {
	fn null_terminated(&self) -> Option<&Self>;
}

impl NullTerminatedStr for [CChar] {
	fn null_terminated(&self) -> Option<&Self> {
		self.iter().position(|&CChar(v)|v==0).map(|pos|&self[..pos])
	}
}

pub trait AsOsStr {
	fn as_os_str(&self) -> &OsStr;
}

impl AsOsStr for [CChar] {
	fn as_os_str(&self) -> &OsStr {
		let cstr=self.null_terminated().unwrap_or(&self);
		unsafe{transmute::<&[CChar],&str>(cstr).as_ref()}
	}
}

// This trait must only be implemented by types that are 4 bytes
pub unsafe trait Size4Bytes: Sized {
	#[doc(hidden)]
	unsafe fn _check_size(_: Self) {/* you can implement a size check here */}
}
unsafe impl Size4Bytes for u32 {}
unsafe impl Size4Bytes for i32 {}

// This trait must only be implemented by types without pointers/references!
pub unsafe trait RefSafe {}

unsafe impl RefSafe for u8 {}
unsafe impl RefSafe for u16 {}
unsafe impl RefSafe for u32 {}
unsafe impl RefSafe for u64 {}
unsafe impl RefSafe for usize {}
unsafe impl RefSafe for i8 {}
unsafe impl RefSafe for i16 {}
unsafe impl RefSafe for i32 {}
unsafe impl RefSafe for i64 {}
unsafe impl RefSafe for isize {}

unsafe impl<T: RefSafe> RefSafe for RVA<T> {}
unsafe impl<T: RefSafe> RefSafe for RVA<[T]> {}
unsafe impl RefSafe for RVA<[CChar]> {}

#[derive(Debug)]
pub enum Error {
	/// Not a PE file
	NotPe,
	/// A size specified was not enough to contain the data specified
	InvalidSize,
	/// The requested mapping does not exist in the file or is not contiguous in the file
	ResolveMapError,
	/// The requested directory does not exist in the file
	DirectoryMissing,
	/// The requested symbol does not exist in the symbol table
	SymbolNotFound,
	/// The requested ordinal does not exist in the export table, this probably indicates a malformed file
	ExportNotFound,
	Io(IoError),
}

pub type Result<T>=::std::result::Result<T,Error>;

impl From<IoError> for Error {
	fn from(err: IoError) -> Error {
		Error::Io(err)
	}
}

pub trait FPRef<'data> {
	fn ref_at<T: RefSafe>(&'data self, fp: FP<T>) -> Result<&'data T>;
	fn ref_slice_at<T: RefSafe>(&'data self, fp: FP<[T]>, count: u32) -> Result<&'data [T]>;
	fn ref_cstr_at(&'data self, fp: FP<[CChar]>, maxlen: u32) -> Result<&'data [CChar]>;
}

impl<'data> FPRef<'data> for [u8] {
	fn ref_at<T: RefSafe>(&'data self, fp: FP<T>) -> Result<&'data T> {
		if fp+size_of::<T>()>self.len() {
			return Err(IoError::new(IoErrorKind::UnexpectedEof,"input buffer not long enough").into())
		}
		unsafe{
			let ptr=self.as_ptr().offset(fp.get() as isize) as *const T;
			Ok(&*ptr)
		}
	}

	fn ref_slice_at<T: RefSafe>(&'data self, fp: FP<[T]>, count: u32) -> Result<&'data [T]> {
		if (fp+(count as usize*size_of::<T>()))>self.len() {
			return Err(IoError::new(IoErrorKind::UnexpectedEof,"input buffer not long enough").into())
		}
		unsafe{
			let ptr=self.as_ptr().offset(fp.get() as isize) as *const T;
			Ok(from_raw_parts(ptr,count as usize))
		}
	}

	fn ref_cstr_at(&'data self, fp: FP<[CChar]>, maxlen: u32) -> Result<&'data [CChar]> {
		let mut data=&self[fp.get() as usize..];
		if (maxlen as usize)<data.len() {
			data=&data[..maxlen as usize];
		}
		let cstr=unsafe{transmute::<&[u8],&[CChar]>(data)};
		match cstr.null_terminated() {
			None => Err(IoError::new(IoErrorKind::UnexpectedEof,"could not find NULL terminator").into()),
			Some(strz) => Ok(&cstr[..strz.len()+1]),
		}
	}
}
