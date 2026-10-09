//! C ABI for authbox.
//!
//! Conventions: opaque Box-backed handles (free with the matching
//! *_free); fallible calls return bool/int with the reason in the
//! thread-local authbox_last_error_message(); owned strings returned to C
//! must be released with authbox_string_free().
//!
//! `include/authbox.h` is generated from this file by cbindgen.

// extern "C" fns take raw pointers from C and deref them by design.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::ptr;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

fn set_last_error(message: impl Into<String>) {
    let message = message.into().replace('\0', " ");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = Some(
            CString::new(message).unwrap_or_else(|_| CString::new("authbox ffi error").unwrap()),
        );
    });
}

unsafe fn cstr<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        set_last_error("null string pointer");
        return None;
    }
    match unsafe { CStr::from_ptr(ptr) }.to_str() {
        Ok(value) => Some(value),
        Err(_) => {
            set_last_error("string must be valid UTF-8");
            None
        }
    }
}

unsafe fn bytes_in<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        set_last_error("null input pointer with nonzero length");
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

unsafe fn bytes_out<'a>(ptr: *mut u8, len: usize, expected: usize) -> Option<&'a mut [u8]> {
    if ptr.is_null() {
        set_last_error("null output pointer");
        return None;
    }
    if len < expected {
        set_last_error(format!("output buffer too small: need {expected} bytes"));
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts_mut(ptr, expected) })
}

fn string_out(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(value) => value.into_raw(),
        Err(_) => {
            set_last_error("output string contains nul byte");
            ptr::null_mut()
        }
    }
}

/// Borrowed byte view used by the C ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuthboxBytes {
    pub ptr: *const u8,
    pub len: usize,
}

/// Returns a pointer to the last error message, or NULL if there is none.
/// The pointer is valid until the next FFI call on this thread.
#[unsafe(no_mangle)]
pub extern "C" fn authbox_last_error_message() -> *const c_char {
    LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map_or(ptr::null(), |message| message.as_ptr())
    })
}

/// Free an owned C string returned by authbox.
#[unsafe(no_mangle)]
pub extern "C" fn authbox_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(value));
    }
}

/// Crate version, as a static NUL-terminated string.
#[unsafe(no_mangle)]
pub extern "C" fn authbox_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr().cast()
}

/// Return whether `did_uri` is syntactically a DID URI.
#[unsafe(no_mangle)]
pub extern "C" fn authbox_did_is_uri(did_uri: *const c_char) -> bool {
    clear_last_error();
    let Some(did_uri) = (unsafe { cstr(did_uri) }) else {
        return false;
    };
    crate::did::is_did_uri(did_uri)
}

/// Convert a did:web URI to its HTTPS document URL. Caller frees with authbox_string_free.
#[unsafe(no_mangle)]
pub extern "C" fn authbox_did_web_document_url(did_uri: *const c_char) -> *mut c_char {
    clear_last_error();
    let Some(did_uri) = (unsafe { cstr(did_uri) }) else {
        return ptr::null_mut();
    };
    match crate::did::did_web_document_url(did_uri) {
        Ok(value) => string_out(value),
        Err(error) => {
            set_last_error(error.to_string());
            ptr::null_mut()
        }
    }
}

/// Encode a 32-byte Ed25519 public key as did:key. Caller frees with authbox_string_free.
#[unsafe(no_mangle)]
pub extern "C" fn authbox_did_key_encode_ed25519(
    public_key: *const u8,
    public_key_len: usize,
) -> *mut c_char {
    clear_last_error();
    let Some(public_key) = (unsafe { bytes_in(public_key, public_key_len) }) else {
        return ptr::null_mut();
    };
    if public_key.len() != 32 {
        set_last_error("Ed25519 public key must be 32 bytes");
        return ptr::null_mut();
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(public_key);
    match crate::did::encode_ed25519_did_key(key) {
        Ok(value) => string_out(value),
        Err(error) => {
            set_last_error(error.to_string());
            ptr::null_mut()
        }
    }
}

/// Resolve a did:key DID document as JSON. Caller frees with authbox_string_free.
#[unsafe(no_mangle)]
pub extern "C" fn authbox_did_key_resolve_document_json(did_uri: *const c_char) -> *mut c_char {
    clear_last_error();
    let Some(did_uri) = (unsafe { cstr(did_uri) }) else {
        return ptr::null_mut();
    };
    match crate::did::resolve_did_key_document_json(did_uri) {
        Ok(value) => string_out(value),
        Err(error) => {
            set_last_error(error.to_string());
            ptr::null_mut()
        }
    }
}

/// Compute SHA-256 into a caller-owned 32-byte output buffer.
#[unsafe(no_mangle)]
pub extern "C" fn authbox_sha256(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> bool {
    clear_last_error();
    let Some(input) = (unsafe { bytes_in(input, input_len) }) else {
        return false;
    };
    let Some(out) = (unsafe { bytes_out(out, out_len, 32) }) else {
        return false;
    };
    out.copy_from_slice(&crate::pki::sha256(input));
    true
}

/// Compute Keccak-256 into a caller-owned 32-byte output buffer.
#[unsafe(no_mangle)]
pub extern "C" fn authbox_keccak256(
    input: *const u8,
    input_len: usize,
    out: *mut u8,
    out_len: usize,
) -> bool {
    clear_last_error();
    let Some(input) = (unsafe { bytes_in(input, input_len) }) else {
        return false;
    };
    let Some(out) = (unsafe { bytes_out(out, out_len, 32) }) else {
        return false;
    };
    out.copy_from_slice(&crate::pki::keccak256(input));
    true
}
