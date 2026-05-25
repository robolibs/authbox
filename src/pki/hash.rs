//! Hash helpers used by PKI utilities.
//!
//! Keep the authbox-facing functions in the mirrored PKI hierarchy, but let the
//! RustCrypto ecosystem own the SHA-2 implementations instead of carrying local
//! compression functions.

use sha2::{Digest as _, Sha256, Sha384, Sha512};
use sha3::Keccak256;

use super::{HashAlgorithm, PkiResult};

pub fn digest(algorithm: HashAlgorithm, input: &[u8]) -> PkiResult<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Sha256 => Ok(sha256(input).to_vec()),
        HashAlgorithm::Sha384 => Ok(sha384(input).to_vec()),
        HashAlgorithm::Sha512 => Ok(sha512(input).to_vec()),
        HashAlgorithm::Blake2b => Ok(super::key_exchange::blake2b_256(input).to_vec()),
        HashAlgorithm::Keccak256 => Ok(keccak256(input).to_vec()),
    }
}

pub fn sha256(input: &[u8]) -> [u8; 32] {
    let hash = Sha256::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

pub fn sha384(input: &[u8]) -> [u8; 48] {
    let hash = Sha384::digest(input);
    let mut out = [0u8; 48];
    out.copy_from_slice(&hash);
    out
}

pub fn sha512(input: &[u8]) -> [u8; 64] {
    let hash = Sha512::digest(input);
    let mut out = [0u8; 64];
    out.copy_from_slice(&hash);
    out
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let hash = Keccak256::digest(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}
