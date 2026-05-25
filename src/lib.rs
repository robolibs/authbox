//! Pure Rust translation of the C++ `authbox` library staged in `xtra/authbox`.

/// Compatibility alias mirroring the C++ top-level `namespace ab = authbox`.
pub extern crate self as ab;

pub const VERSION: &str = "0.0.1";

pub mod json;

pub mod io;

pub mod did;
pub mod pki;

/// Compatibility namespace mirroring the C++ primary `authbox::pik` namespace.
pub mod pik {
    pub use crate::pki::*;
}

pub fn log_startup() {
    eprintln!("authbox initialized, version={VERSION}");
}

#[cfg(test)]
mod tests;
