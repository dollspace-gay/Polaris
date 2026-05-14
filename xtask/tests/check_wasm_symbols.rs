//! Integration tests for `xtask check-wasm-symbols`.
//!
//! Drives [`check_wasm_symbols::scan_wasm_bytes`] against two synthetic
//! wasm modules: one with no lexicon-related symbols (must fire the
//! missing-symbols branch when run through [`check_wasm_symbols::run`])
//! and one with a function whose name contains `lexicon` (must report
//! a non-zero match count).
//!
//! We build the synthetic modules at the byte level rather than calling
//! `wat::parse_str` because the xtask crate already depends on
//! `wasmparser` (the read side) and we don't want to take a build-time
//! dep on `wat` just for two test fixtures.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]

use xtask::check_wasm_symbols::scan_wasm_bytes;

/// Wasm magic bytes + version (`\0asm` + version 1).
const WASM_HEADER: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

/// Build a minimal valid wasm module that carries a custom `name`
/// section whose Function subsection names a single function. The
/// function index does not need to refer to a real function entry for
/// the scanner's purposes — `scan_wasm_bytes` reads the name section
/// alone — but we make the module valid enough that `wasmparser`'s
/// `parse_all` accepts it.
fn module_with_function_name(name: &str) -> Vec<u8> {
    let mut bytes = WASM_HEADER.to_vec();

    // Build the Function subsection body of the name custom section:
    //
    //   name-section          := 0x00 (section-len:u32) (payload)
    //   payload               := "name" (subsections)
    //   function-subsection   := 0x01 (subsection-len:u32) (count:u32) (entry*)
    //   entry                 := (index:u32) (name-len:u32) (name-bytes)
    //
    // We encode every length as a single-byte LEB128 — every value we
    // emit fits in 7 bits, which is the LEB128 single-byte range.

    // Inner function entry: index=0, name=<name>
    let mut function_entries = Vec::new();
    function_entries.push(0x00_u8); // index = 0
    function_entries.push(u8::try_from(name.len()).expect("test name fits in one byte"));
    function_entries.extend_from_slice(name.as_bytes());

    // Function subsection body: count=1 then the entry above.
    let mut function_subsection = Vec::new();
    function_subsection.push(0x01_u8); // count = 1
    function_subsection.extend_from_slice(&function_entries);

    // Subsection envelope: tag = 0x01 (Function), len, body.
    let mut subsection = Vec::new();
    subsection.push(0x01_u8); // subsection tag = 1 = Function
    subsection.push(u8::try_from(function_subsection.len()).expect("subsection fits in one byte"));
    subsection.extend_from_slice(&function_subsection);

    // Custom section payload: "name" string + subsection bytes.
    //
    //   custom-section header  := 0x00 (section-len:u32) (payload)
    //   payload                := (name-len:u32) (name-bytes) (data)
    let name_string = b"name";
    let mut custom_payload = Vec::new();
    custom_payload.push(u8::try_from(name_string.len()).expect("\"name\" length fits in one byte"));
    custom_payload.extend_from_slice(name_string);
    custom_payload.extend_from_slice(&subsection);

    // Section envelope: id = 0x00 (Custom), len, payload.
    bytes.push(0x00_u8);
    bytes.push(u8::try_from(custom_payload.len()).expect("custom payload fits in one byte"));
    bytes.extend_from_slice(&custom_payload);

    bytes
}

#[test]
fn header_only_module_reports_no_lexicon_symbols() {
    let report = scan_wasm_bytes(WASM_HEADER).expect("header-only module parses");
    assert_eq!(report.total_symbols, 0);
    assert_eq!(report.lexicon_symbol_count, 0);
}

#[test]
fn module_with_non_lexicon_symbol_reports_zero_matches() {
    let bytes = module_with_function_name("polaris_frontend_App");
    let report = scan_wasm_bytes(&bytes).expect("synthetic module parses");
    assert_eq!(report.total_symbols, 1);
    assert_eq!(
        report.lexicon_symbol_count, 0,
        "polaris_frontend_App must not match any lexicon needle",
    );
}

#[test]
fn module_with_lexicon_function_reports_one_match() {
    let bytes = module_with_function_name("proto_blue_lexicon_validate_record");
    let report = scan_wasm_bytes(&bytes).expect("synthetic module parses");
    assert_eq!(report.total_symbols, 1);
    assert_eq!(
        report.lexicon_symbol_count, 1,
        "function name must match a lexicon needle",
    );
}

#[test]
fn module_with_validate_symbol_reports_one_match() {
    // `validate` on its own is a lexicon needle — covers the case where
    // the engine ships under a different mangling but the entry-point
    // symbol still carries `validate` in its name.
    let bytes = module_with_function_name("validate_object");
    let report = scan_wasm_bytes(&bytes).expect("synthetic module parses");
    assert_eq!(report.total_symbols, 1);
    assert_eq!(report.lexicon_symbol_count, 1);
}
