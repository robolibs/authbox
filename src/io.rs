//! Top-level I/O compatibility namespace for `xtra/authbox/include/pki/files.hpp`.
//!
//! The C++ header lives under `include/pki/files.hpp`, but the helpers are
//! exported in `authbox::io`.  Keep the real implementation in
//! `src/pki/files.rs` and expose this small namespace shim instead of folding
//! the file helper surface into an unrelated module.

pub use crate::pki::{
    BinaryReadResult, read_binary, read_binary_bytes, read_binary_result, write_binary,
    write_binary_bool, write_binary_result,
};
