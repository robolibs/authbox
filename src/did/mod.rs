pub mod error;
pub use error::{DidError, DidErrorCode, DidResult, is_supported_method, to_dp_string};
pub mod errors;

#[allow(clippy::module_inception)]
pub mod did;
pub use did::*;

pub mod document;
pub use document::*;

pub mod options;
pub use options::*;

pub mod key;
pub use key::*;

pub mod jwk;
pub use jwk::*;

pub mod dns;
pub use dns::*;

pub mod peer;
pub use peer::*;

pub mod pkh;
pub use pkh::*;

pub mod method_registry;
pub use method_registry::*;

pub mod resolver;
pub use resolver::*;

pub mod dereference;
pub use dereference::*;

pub mod privacy;
pub mod security;

pub mod rpc;
pub mod web_fetch;
pub use web_fetch::*;
pub mod x509;
pub use x509::*;
pub mod detail;

#[cfg(test)]
mod tests;
