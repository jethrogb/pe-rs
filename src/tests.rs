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

extern crate itertools;

use super::*;
use std::io::Read;
use std::fs::File;

// Testing on SQLite binaries since those are in the public domain
lazy_static! {
	static ref SQLITE_X64_BUF: Vec<u8> = {
		let mut file=File::open("test/sqlite3_x64.dll").unwrap();
		let mut buf=vec![];
		file.read_to_end(&mut buf).unwrap();
		buf
	};
	static ref SQLITE_X64_PE: Pe<'static> = Pe::new(&SQLITE_X64_BUF).unwrap();
	static ref SQLITE_X86_BUF: Vec<u8> = {
		let mut file=File::open("test/sqlite3_x86.dll").unwrap();
		let mut buf=vec![];
		file.read_to_end(&mut buf).unwrap();
		buf
	};
	static ref SQLITE_X86_PE: Pe<'static> = Pe::new(&SQLITE_X86_BUF).unwrap();
}

#[test]
fn list_sections() {
	let sqlite_x64_sections=[".text",".rdata",".data",".pdata",".idata",".gfids",".00cfg",".rsrc",".reloc"];
	let sqlite_x86_sections=[".text",".rdata",".data",".idata",".gfids",".00cfg",".rsrc",".reloc"];

	itertools::assert_equal(SQLITE_X64_PE.get_sections().iter().map(|section|section.name.as_os_str()),sqlite_x64_sections.iter().cloned());
	itertools::assert_equal(SQLITE_X86_PE.get_sections().iter().map(|section|section.name.as_os_str()),sqlite_x86_sections.iter().cloned());
}

#[test]
fn rsds_debug_directory() {
	let debug_dir = SQLITE_X86_PE.get_directory::<DebugDirectory>().unwrap();

	let start_address: utility::RVA<types::DebugDirectory> = debug_dir.virtual_address;
	let size = debug_dir.size;

	let num_debug_directories = size / 28;
	assert_eq!(num_debug_directories, 2);

	let rsds_offset: RVA<DebugDirectory> = start_address;
	let rsds_debug_entry: &DebugDirectory = SQLITE_X86_PE.ref_at(rsds_offset).unwrap();
	assert_eq!(rsds_debug_entry.debug_type, 2);

	let signature_rva: RVA<u32> = RVA::new(rsds_debug_entry.address_of_raw_data.get());
	let signature: &u32 = SQLITE_X86_PE.ref_at(signature_rva).unwrap();
	assert_eq!(signature, &0x53445352); // "RSDS"

	let path_rva: RVA<[CChar]> = signature_rva.offset(24);
	let path: &[CChar] = SQLITE_X86_PE.ref_cstr_at(path_rva).unwrap();
	assert_eq!(path.as_os_str(), "C:\\dev\\sqlite\\core\\sqlite3.pdb");

	let guid_bytes: RVA<[u8]> = signature_rva.offset(4);
	let guid_bytes: &[u8] = SQLITE_X86_PE.ref_slice_at(guid_bytes, 16).unwrap();

	// {39152019-C388-4D2A-AA1D-E640BF5EE86A}
	assert_eq!(guid_bytes, &[25, 32, 21, 57, 136, 195, 42, 77, 170, 29, 230, 64, 191, 94, 232, 106]);
}

#[test]
fn export_name() {
	let name="sqlite3.dll";
	let edir=SQLITE_X64_PE.get_exports().unwrap();
	assert_eq!(SQLITE_X64_PE.ref_cstr_at(edir.get_export_directory().name).unwrap().as_os_str(),name);
	let edir=SQLITE_X86_PE.get_exports().unwrap();
	assert_eq!(SQLITE_X86_PE.ref_cstr_at(edir.get_export_directory().name).unwrap().as_os_str(),name);
}

fn check_export_table(file: &Pe, data: &[(u16,&str)]) {
	let edir=file.get_exports().unwrap();
	let names=edir.get_names().unwrap().iter().map(|&name|file.ref_cstr_at(name).unwrap().as_os_str());
	itertools::assert_equal(names,data.iter().map(|&(_,name)|name));
	let offsets=edir.get_ordinal_offsets().unwrap().iter().cloned();
	itertools::assert_equal(offsets,data.iter().map(|&(offset,_)|offset));
}

#[test]
fn list_export_table() {
	let sqlite_export_table: Vec<(u16,&str)>=vec![
(  0,"sqlite3_aggregate_context"),      (  1,"sqlite3_aggregate_count"),        (  2,"sqlite3_auto_extension"),
(  3,"sqlite3_backup_finish"),          (  4,"sqlite3_backup_init"),            (  5,"sqlite3_backup_pagecount"),
(  6,"sqlite3_backup_remaining"),       (  7,"sqlite3_backup_step"),            (  8,"sqlite3_bind_blob"),
(  9,"sqlite3_bind_blob64"),            ( 10,"sqlite3_bind_double"),            ( 11,"sqlite3_bind_int"),
( 12,"sqlite3_bind_int64"),             ( 13,"sqlite3_bind_null"),              ( 14,"sqlite3_bind_parameter_count"),
( 15,"sqlite3_bind_parameter_index"),   ( 16,"sqlite3_bind_parameter_name"),    ( 17,"sqlite3_bind_text"),
( 18,"sqlite3_bind_text16"),            ( 19,"sqlite3_bind_text64"),            ( 20,"sqlite3_bind_value"),
( 21,"sqlite3_bind_zeroblob"),          ( 22,"sqlite3_bind_zeroblob64"),        ( 23,"sqlite3_blob_bytes"),
( 24,"sqlite3_blob_close"),             ( 25,"sqlite3_blob_open"),              ( 26,"sqlite3_blob_read"),
( 27,"sqlite3_blob_reopen"),            ( 28,"sqlite3_blob_write"),             ( 29,"sqlite3_busy_handler"),
( 30,"sqlite3_busy_timeout"),           ( 31,"sqlite3_cancel_auto_extension"),  ( 32,"sqlite3_changes"),
( 33,"sqlite3_clear_bindings"),         ( 34,"sqlite3_close"),                  ( 35,"sqlite3_close_v2"),
( 36,"sqlite3_collation_needed"),       ( 37,"sqlite3_collation_needed16"),     ( 38,"sqlite3_column_blob"),
( 39,"sqlite3_column_bytes"),           ( 40,"sqlite3_column_bytes16"),         ( 41,"sqlite3_column_count"),
( 42,"sqlite3_column_database_name"),   ( 43,"sqlite3_column_database_name16"), ( 44,"sqlite3_column_decltype"),
( 45,"sqlite3_column_decltype16"),      ( 46,"sqlite3_column_double"),          ( 47,"sqlite3_column_int"),
( 48,"sqlite3_column_int64"),           ( 49,"sqlite3_column_name"),            ( 50,"sqlite3_column_name16"),
( 51,"sqlite3_column_origin_name"),     ( 52,"sqlite3_column_origin_name16"),   ( 53,"sqlite3_column_table_name"),
( 54,"sqlite3_column_table_name16"),    ( 55,"sqlite3_column_text"),            ( 56,"sqlite3_column_text16"),
( 57,"sqlite3_column_type"),            ( 58,"sqlite3_column_value"),           ( 59,"sqlite3_commit_hook"),
( 60,"sqlite3_compileoption_get"),      ( 61,"sqlite3_compileoption_used"),     ( 62,"sqlite3_complete"),
( 63,"sqlite3_complete16"),             ( 64,"sqlite3_config"),                 ( 65,"sqlite3_context_db_handle"),
( 66,"sqlite3_create_collation"),       ( 67,"sqlite3_create_collation16"),     ( 68,"sqlite3_create_collation_v2"),
( 69,"sqlite3_create_function"),        ( 70,"sqlite3_create_function16"),      ( 71,"sqlite3_create_function_v2"),
( 72,"sqlite3_create_module"),          ( 73,"sqlite3_create_module_v2"),       ( 74,"sqlite3_data_count"),
( 75,"sqlite3_data_directory"),         ( 76,"sqlite3_db_cacheflush"),          ( 77,"sqlite3_db_config"),
( 78,"sqlite3_db_filename"),            ( 79,"sqlite3_db_handle"),              ( 80,"sqlite3_db_mutex"),
( 81,"sqlite3_db_readonly"),            ( 82,"sqlite3_db_release_memory"),      ( 83,"sqlite3_db_status"),
( 84,"sqlite3_declare_vtab"),           ( 85,"sqlite3_enable_load_extension"),  ( 86,"sqlite3_enable_shared_cache"),
( 87,"sqlite3_errcode"),                ( 88,"sqlite3_errmsg"),                 ( 89,"sqlite3_errmsg16"),
( 90,"sqlite3_errstr"),                 ( 91,"sqlite3_exec"),                   ( 92,"sqlite3_expired"),
( 93,"sqlite3_extended_errcode"),       ( 94,"sqlite3_extended_result_codes"),  ( 95,"sqlite3_file_control"),
( 96,"sqlite3_finalize"),               ( 97,"sqlite3_free"),                   ( 98,"sqlite3_free_table"),
( 99,"sqlite3_fts5_may_be_corrupt"),    (100,"sqlite3_get_autocommit"),         (101,"sqlite3_get_auxdata"),
(102,"sqlite3_get_table"),              (103,"sqlite3_global_recover"),         (104,"sqlite3_initialize"),
(105,"sqlite3_interrupt"),              (106,"sqlite3_last_insert_rowid"),      (107,"sqlite3_libversion"),
(108,"sqlite3_libversion_number"),      (109,"sqlite3_limit"),                  (110,"sqlite3_load_extension"),
(111,"sqlite3_log"),                    (112,"sqlite3_malloc"),                 (113,"sqlite3_malloc64"),
(114,"sqlite3_memory_alarm"),           (115,"sqlite3_memory_highwater"),       (116,"sqlite3_memory_used"),
(117,"sqlite3_mprintf"),                (118,"sqlite3_msize"),                  (119,"sqlite3_mutex_alloc"),
(120,"sqlite3_mutex_enter"),            (121,"sqlite3_mutex_free"),             (122,"sqlite3_mutex_leave"),
(123,"sqlite3_mutex_try"),              (124,"sqlite3_next_stmt"),              (125,"sqlite3_open"),
(126,"sqlite3_open16"),                 (127,"sqlite3_open_v2"),                (128,"sqlite3_os_end"),
(129,"sqlite3_os_init"),                (130,"sqlite3_overload_function"),      (131,"sqlite3_prepare"),
(132,"sqlite3_prepare16"),              (133,"sqlite3_prepare16_v2"),           (134,"sqlite3_prepare_v2"),
(135,"sqlite3_profile"),                (136,"sqlite3_progress_handler"),       (137,"sqlite3_randomness"),
(138,"sqlite3_realloc"),                (139,"sqlite3_realloc64"),              (140,"sqlite3_release_memory"),
(141,"sqlite3_reset"),                  (142,"sqlite3_reset_auto_extension"),   (143,"sqlite3_result_blob"),
(144,"sqlite3_result_blob64"),          (145,"sqlite3_result_double"),          (146,"sqlite3_result_error"),
(147,"sqlite3_result_error16"),         (148,"sqlite3_result_error_code"),      (149,"sqlite3_result_error_nomem"),
(150,"sqlite3_result_error_toobig"),    (151,"sqlite3_result_int"),             (152,"sqlite3_result_int64"),
(153,"sqlite3_result_null"),            (154,"sqlite3_result_subtype"),         (155,"sqlite3_result_text"),
(156,"sqlite3_result_text16"),          (157,"sqlite3_result_text16be"),        (158,"sqlite3_result_text16le"),
(159,"sqlite3_result_text64"),          (160,"sqlite3_result_value"),           (161,"sqlite3_result_zeroblob"),
(162,"sqlite3_result_zeroblob64"),      (163,"sqlite3_rollback_hook"),          (164,"sqlite3_rtree_geometry_callback"),
(165,"sqlite3_rtree_query_callback"),   (166,"sqlite3_set_authorizer"),         (167,"sqlite3_set_auxdata"),
(168,"sqlite3_shutdown"),               (169,"sqlite3_sleep"),                  (170,"sqlite3_snprintf"),
(171,"sqlite3_soft_heap_limit"),        (172,"sqlite3_soft_heap_limit64"),      (173,"sqlite3_sourceid"),
(174,"sqlite3_sql"),                    (175,"sqlite3_status"),                 (176,"sqlite3_status64"),
(177,"sqlite3_step"),                   (178,"sqlite3_stmt_busy"),              (179,"sqlite3_stmt_readonly"),
(180,"sqlite3_stmt_status"),            (181,"sqlite3_strglob"),                (182,"sqlite3_stricmp"),
(183,"sqlite3_strlike"),                (184,"sqlite3_strnicmp"),               (185,"sqlite3_table_column_metadata"),
(186,"sqlite3_temp_directory"),         (187,"sqlite3_test_control"),           (188,"sqlite3_thread_cleanup"),
(189,"sqlite3_threadsafe"),             (190,"sqlite3_total_changes"),          (191,"sqlite3_trace"),
(192,"sqlite3_transfer_bindings"),      (193,"sqlite3_update_hook"),            (194,"sqlite3_uri_boolean"),
(195,"sqlite3_uri_int64"),              (196,"sqlite3_uri_parameter"),          (197,"sqlite3_user_data"),
(198,"sqlite3_value_blob"),             (199,"sqlite3_value_bytes"),            (200,"sqlite3_value_bytes16"),
(201,"sqlite3_value_double"),           (202,"sqlite3_value_dup"),              (203,"sqlite3_value_free"),
(204,"sqlite3_value_int"),              (205,"sqlite3_value_int64"),            (206,"sqlite3_value_numeric_type"),
(207,"sqlite3_value_subtype"),          (208,"sqlite3_value_text"),             (209,"sqlite3_value_text16"),
(210,"sqlite3_value_text16be"),         (211,"sqlite3_value_text16le"),         (212,"sqlite3_value_type"),
(213,"sqlite3_version"),                (214,"sqlite3_vfs_find"),               (215,"sqlite3_vfs_register"),
(216,"sqlite3_vfs_unregister"),         (217,"sqlite3_vmprintf"),               (218,"sqlite3_vsnprintf"),
(219,"sqlite3_vtab_config"),            (220,"sqlite3_vtab_on_conflict"),       (221,"sqlite3_wal_autocheckpoint"),
(222,"sqlite3_wal_checkpoint"),         (223,"sqlite3_wal_checkpoint_v2"),      (224,"sqlite3_wal_hook"),
(225,"sqlite3_win32_is_nt"),            (226,"sqlite3_win32_mbcs_to_utf8"),     (227,"sqlite3_win32_set_directory"),
(228,"sqlite3_win32_sleep"),            (229,"sqlite3_win32_utf8_to_mbcs"),     (230,"sqlite3_win32_write_debug"),
	];

	check_export_table(&SQLITE_X64_PE,&sqlite_export_table);
	check_export_table(&SQLITE_X86_PE,&sqlite_export_table);
}

#[derive(Debug)]
#[allow(dead_code)]
enum ExportAddressTestValue {
	Export(u32),
	Forwarder(u32),
}

impl<'a,'b> ::std::cmp::PartialEq<ExportAddress<'a>> for &'b ExportAddressTestValue {
	fn eq(&self, other: &ExportAddress) -> bool {
		use self::ExportAddressTestValue as EAT;
		use ExportAddress as EA;
		match (self,other) {
			(&&EAT::Export(a),&EA::Export(rva)) if a==rva.get() => true,
			(&&EAT::Forwarder(a),&EA::Forwarder(rva)) if a==rva.get() => true,
			_ => false,
		}
	}
}

#[test]
fn list_exports() {
	let sqlite_x86_exports: Vec<_>=[
		0x1014, 0x1131, 0x11b3, 0x11ae,  0x1569, 0x1541,   0x11ea,   0x156e, 0x15af, 0x109b,
		0x10c3, 0x1145, 0x1631, 0x1596,  0x112c, 0x1136,   0x11a4,   0x15aa, 0x1055, 0x1096,
		0x100f, 0x146f, 0x128a, 0x122b,  0x1258, 0x10f0,   0x10fa,   0x150a, 0x121c, 0x14ec,
		0x14d3, 0x103c, 0x1064, 0x13de,  0x1604, 0x1140,   0x100a,   0x11bd, 0x11cc, 0x151e,
		0x154b, 0x152d, 0x123f, 0x160e,  0x150f, 0x12e9,   0x1348,   0x11db, 0x1492, 0x118b,
		0x1483, 0x12f8, 0x116d, 0x1019,  0x10b4, 0x11e0,   0x131b,   0x11d6, 0x13c5, 0x15f0,
		0x1190, 0x11c2, 0x1163, 0x1479,  0x1311, 0x1582,   0x126c,   0x1230, 0x1181, 0x106e,
		0x155a, 0x1636, 0x13d4, 0x155f,  0x1500, 0x10fe3c, 0x1456,   0x1587, 0x12ee, 0x1578,
		0x115e, 0x1406, 0x1519, 0x15a0,  0x14b0, 0x13d9,   0x10d7,   0x1050, 0x1460, 0x1208,
		0x1537, 0x140b, 0x1618, 0x1087,  0x11b8, 0x127b,   0x147e,   0x137a, 0x1159, 0x10e1a8,
		0x117c, 0x143d, 0x1546, 0x11f4,  0x1573, 0x15d7,   0x114f,   0x1221, 0x157d, 0x110e,
		0x1352, 0x105f, 0x15d2, 0x10b9,  0x1505, 0x1253,   0x11c7,   0x10aa, 0x10e6, 0x13ed,
		0x13a2, 0x1447, 0x13e3, 0x1073,  0x12df, 0x1410,   0x1433,   0x1069, 0x1532, 0x108c,
		0x145b, 0x1212, 0x13b6, 0x15eb,  0x13f2, 0x1046,   0x13e8,   0x1627, 0x1217, 0x13cf,
		0x129e, 0x15fa, 0x13ac, 0x10cd,  0x1361, 0x134d,   0x1555,   0x15cd, 0x1339, 0x12b2,
		0x14c9, 0x1401, 0x142e, 0x10c8,  0x1118, 0x10dc,   0x1334,   0x1082, 0x1091, 0x133e,
		0x1316, 0x1424, 0x1357, 0x158c,  0x14e7, 0x1609,   0x11f9,   0x15be, 0x1109, 0x15ff,
		0x1271, 0x1622, 0x1037, 0x1262,  0x105a, 0x153c,   0x10ff,   0x13fc, 0x123a, 0x1186,
		0x1280, 0x10a5, 0x10a0, 0x1078,  0x1168, 0x15b9,   0x10fe38, 0x148d, 0x10eb, 0x13f7,
		0x14ce, 0x10d2, 0x1203, 0x10be,  0x119a, 0x15a5,   0x107d,   0x1226, 0x1299, 0x14c4,
		0x14fb, 0x12da, 0x1370, 0x12a3,  0x136b, 0x14f1,   0x1375,   0x14d8, 0x12ad, 0x1244,
		0x12c1, 0x12d5, 0x12a8, 0xe8488, 0x1384, 0x1474,   0x130c,   0x1488, 0x1294, 0x1177,
		0x12d0, 0x14f6, 0x146a, 0x162c,  0x1154, 0x15c8,   0x14bf,   0x111d, 0x15e6, 0x1285,
		0x1122,
	].into_iter().map(|&i|ExportAddressTestValue::Export(i)).collect();
	let sqlite_x64_exports: Vec<_>=[
		0x124e, 0x143d, 0x1032, 0x119f,   0x130c, 0x1208,   0x1267,   0x12e9, 0x1276, 0x12cb,
		0x1339, 0x10eb, 0x14ec, 0x1249,   0x1433, 0x1573,   0x1159,   0x12b2, 0x1361, 0x1366,
		0x1488, 0x1343, 0x1190, 0x15be,   0x100a, 0x154b,   0x1532,   0x101e, 0x1005, 0x1104,
		0x10ff, 0x1541, 0x1587, 0x1203,   0x150f, 0x13a2,   0x107d,   0x1398, 0x14ce, 0x12da,
		0x1113, 0x12d5, 0x14d3, 0x11c2,   0x15af, 0x12fd,   0x11cc,   0x12a8, 0x1352, 0x1474,
		0x10a0, 0x116d, 0x12b7, 0x12df,   0x1140, 0x147e,   0x1195,   0x14c4, 0x12d0, 0x1082,
		0x1316, 0x14d8, 0x1384, 0x13f7,   0x1073, 0x10d7,   0x11b3,   0x13c5, 0x1118, 0x110e,
		0x14a6, 0x105f, 0x11ae, 0x13ca,   0x12ee, 0x1654c0, 0x1460,   0x1235, 0x1555, 0x12ad,
		0x10fa, 0x155f, 0x1591, 0x1285,   0x120d, 0x1258,   0x114f,   0x1401, 0x1096, 0x13cf,
		0x109b, 0x10c8, 0x1465, 0x13a7,   0x13f2, 0x11e5,   0x10f5,   0x10cd, 0x105a, 0x161468,
		0x1177, 0x1217, 0x115e, 0x1429,   0x1230, 0x112c,   0x1109,   0x14e7, 0x1497, 0x150a,
		0x155a, 0x1050, 0x1122, 0x1311,   0x14b5, 0x140b,   0x13de,   0x145b, 0x1523, 0x128a,
		0x117c, 0x10c3, 0x121c, 0x13e3,   0x128f, 0x10d2,   0x106e,   0x1410, 0x1127, 0x1582,
		0x11fe, 0x1456, 0x1221, 0x1438,   0x1451, 0x142e,   0x10aa,   0x146a, 0x156e, 0x10b9,
		0x1514, 0x1505, 0x1064, 0x125d,   0x1370, 0x1294,   0x1145,   0x14ba, 0x1325, 0x159b,
		0x1041, 0x1186, 0x118b, 0x13bb,   0x134d, 0x1262,   0x1244,   0x137f, 0x1389, 0x123f,
		0x11a4, 0x114a, 0x1055, 0x153c,   0x14e2, 0x1528,   0x11ef,   0x108c, 0x138e, 0x14fb,
		0x137a, 0x1019, 0x1136, 0x13ac,   0x104b, 0x1087,   0x139d,   0x10dc, 0x1375, 0x1447,
		0x152d, 0x1406, 0x144c, 0x1415,   0x13b1, 0x1014,   0x1654b8, 0x12bc, 0x127b, 0x11f9,
		0x1271, 0x1424, 0x1307, 0x1091,   0x1492, 0x11a9,   0x11e0,   0x11d6, 0x132f, 0x15b4,
		0x11d1, 0x12f3, 0x1037, 0x132a,   0x1046, 0x1596,   0x1168,   0x10f0, 0x135c, 0x141f,
		0x157d, 0x1578, 0x1348, 0x1228ac, 0x10e1, 0x1550,   0x1564,   0x1131, 0x1280, 0x14b0,
		0x1069, 0x102d, 0x14f6, 0x149c,   0x131b, 0x1154,   0x1302,   0x1442, 0x10e6, 0x103c,
		0x123a,
	].into_iter().map(|&i|ExportAddressTestValue::Export(i)).collect();

	let edir=SQLITE_X86_PE.get_exports().unwrap();
	let exports=edir.get_export_addresses().unwrap().iter().map(|rawea|edir.concretize_export_address(rawea));
	itertools::assert_equal(&sqlite_x86_exports,exports);

	assert_eq!(&sqlite_x86_exports[0],edir.lookup_symbol("sqlite3_aggregate_context").unwrap());

	let edir=SQLITE_X64_PE.get_exports().unwrap();
	let exports=edir.get_export_addresses().unwrap().iter().map(|rawea|edir.concretize_export_address(rawea));
	itertools::assert_equal(&sqlite_x64_exports,exports);

	assert_eq!(&sqlite_x64_exports[0],edir.lookup_symbol("sqlite3_aggregate_context").unwrap());
}
