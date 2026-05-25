//! Hash helpers — thin delegations into the sibling `keylock` crate.

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
    let hash = keylock::hash::sha256::hash(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

pub fn sha384(input: &[u8]) -> [u8; 48] {
    let mut hasher = keylock::hash::sha384::init();
    keylock::hash::sha384::update(&mut hasher, input);
    let digest = keylock::hash::sha384::final_bytes(hasher);
    let mut out = [0u8; 48];
    out.copy_from_slice(&digest);
    out
}

pub fn sha512(input: &[u8]) -> [u8; 64] {
    let hash = keylock::hash::sha512::hash(input);
    let mut out = [0u8; 64];
    out.copy_from_slice(&hash);
    out
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    keylock::keccak256(input)
}
