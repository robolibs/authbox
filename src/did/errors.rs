//! C++ `include/did/errors.hpp` compatibility module.
//!
//! The Rust implementation lives in `src/did/error.rs`, but the public module
//! name stays plural here to mirror the C++ header hierarchy without copying
//! the implementation into a second file.

pub use super::error::*;
