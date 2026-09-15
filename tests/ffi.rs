use std::ffi::{CStr, CString};

use authbox::ffi::*;

unsafe fn c_string_owned(ptr: *mut std::ffi::c_char) -> String {
    assert!(!ptr.is_null());
    let out = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_owned();
    authbox_string_free(ptr);
    out
}

#[test]
fn c_abi_did_key_roundtrip_works() {
    let version = unsafe { CStr::from_ptr(authbox_version()) }
        .to_str()
        .unwrap();
    assert_eq!(version, env!("CARGO_PKG_VERSION"));

    let key = [7u8; 32];
    let did = unsafe { c_string_owned(authbox_did_key_encode_ed25519(key.as_ptr(), key.len())) };
    assert!(did.starts_with("did:key:z"));

    let did_c = CString::new(did.clone()).unwrap();
    assert!(authbox_did_is_uri(did_c.as_ptr()));
    let document = unsafe { c_string_owned(authbox_did_key_resolve_document_json(did_c.as_ptr())) };
    assert!(document.contains(&did));
    assert!(document.contains("JsonWebKey2020"));
}

#[test]
fn c_abi_did_web_url_and_hash_work() {
    let did = CString::new("did:web:example.com:robots:tractor").unwrap();
    let url = unsafe { c_string_owned(authbox_did_web_document_url(did.as_ptr())) };
    assert_eq!(url, "https://example.com/robots/tractor/did.json");

    let mut out = [0u8; 32];
    assert!(authbox_sha256(
        b"abc".as_ptr(),
        3,
        out.as_mut_ptr(),
        out.len()
    ));
    assert_eq!(
        hex_lower(&out),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn c_abi_reports_bad_key_length() {
    let key = [1u8; 31];
    let did = authbox_did_key_encode_ed25519(key.as_ptr(), key.len());
    assert!(did.is_null());
    let error = unsafe { CStr::from_ptr(authbox_last_error_message()) }
        .to_str()
        .unwrap();
    assert!(error.contains("32 bytes"));
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
