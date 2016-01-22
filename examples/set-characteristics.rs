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

extern crate pe;

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read,Write,Seek,SeekFrom};

const USAGE: &'static str = "Usage: set-characteristics <file> <hex-new-characteristics>\n";

fn hex_arg(opt: Option<OsString>) -> u16 {
	u16::from_str_radix(
		&opt.expect(&format!("{}\nMust supply {} on command line!",USAGE,"new-characteristics"))
		.into_string().expect(&format!("{}\nMust supply valid numeric {}!",USAGE,"new-characteristics")),
	16).expect(&format!("{}\nMust supply valid hexadecimal {} (no prefix)!",USAGE,"new-characteristics"))
}

fn main() {
	let mut args=std::env::args_os();
	let _name=args.next();
	let file=args.next().expect(USAGE);
	let new_characteristics=hex_arg(args.next());

	let mut file=OpenOptions::new().read(true).write(true).truncate(false).append(false).open(file).unwrap();
	let mut buf=vec![];
	file.read_to_end(&mut buf).unwrap();
	let pos=(&pe::Pe::new(&buf).unwrap().get_header().characteristics as *const _ as usize)-(buf.as_ptr() as usize);
	file.seek(SeekFrom::Start(pos as u64)).unwrap();
	file.write(&unsafe{::std::mem::transmute::<_,[u8;2]>(new_characteristics)}).unwrap();
}
