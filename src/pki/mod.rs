//! Pure Rust PKI implementation translated from `xtra/authbox/include/pki`.

pub mod error;
pub use error::{PkiError, PkiResult};

pub mod asn1_common;
pub use asn1_common::*;

pub mod asn1_utils;
pub use asn1_utils::*;

pub mod asn1_writer;
pub use asn1_writer::der;

pub mod pem;
pub use pem::*;
pub mod detail;
pub(crate) mod random;

pub mod oid_registry;
pub use oid_registry::*;

pub mod distinguished_name;
pub use distinguished_name::*;

pub mod parser;
pub use parser::*;

pub mod parser_utils;

pub mod certificate;
pub use certificate::*;

pub mod builder;
pub use builder::*;

pub mod files;
pub use files::*;

pub mod csr;
pub use csr::*;

pub mod csr_builder;
pub use csr_builder::*;

pub mod crl;
pub use crl::*;

pub mod crl_builder;
pub use crl_builder::*;

pub mod verify;
pub use verify::*;

pub mod trust_store;
pub use trust_store::*;

pub mod key_utils;
pub use key_utils::{
    KeyPair, decrypt_pkcs8_private_key_der, decrypt_pkcs8_private_key_pem,
    ecdsa_p256_subject_public_key_info, ecdsa_p384_subject_public_key_info,
    ecdsa_p521_subject_public_key_info, ed448_subject_public_key_info,
    ed25519_subject_public_key_info, encode_private_key_octets, encrypt_pkcs8_private_key_der,
    encrypt_pkcs8_private_key_pem, generate_ecdsa_p256_keypair, generate_ecdsa_p384_keypair,
    generate_ecdsa_p521_keypair, generate_ed448_keypair, generate_ed25519_keypair,
    generate_rsa_2048_keypair, generate_rsa_keypair, raw_ecdsa_p256_private_key_from_sec1,
    raw_ecdsa_p256_public_key_from_spki, raw_ecdsa_p384_private_key_from_sec1,
    raw_ecdsa_p384_public_key_from_spki, raw_ecdsa_p521_private_key_from_sec1,
    raw_ecdsa_p521_public_key_from_spki, raw_ed448_public_key_from_spki,
    raw_ed25519_public_key_from_spki, raw_rsa_public_key_from_spki, rsa_subject_public_key_info,
    rsa_subject_public_key_info_with_options, sec1_from_ecdsa_p256_private,
    sec1_from_ecdsa_p384_private, sec1_from_ecdsa_p521_private, spki_from_ecdsa_p256_public,
    spki_from_ecdsa_p384_public, spki_from_ecdsa_p521_public, spki_from_ed448_public,
    spki_from_ed25519_public, spki_from_rsa_public, spki_from_rsa_public_with_options,
};

pub mod key_exchange;

pub mod hash;
pub use hash::{digest, keccak256, sha256, sha384, sha512};

pub mod ed25519;
pub use ed25519::{ed25519_public_key_from_seed, sign_ed25519_detached, verify_ed25519_signature};

pub mod ed448;
pub use ed448::{ed448_public_key_from_seed, sign_ed448_detached, verify_ed448_signature};

pub mod ecdsa;
pub use ecdsa::{
    encode_ecdsa_p256_signature_der, encode_ecdsa_p384_signature_der,
    encode_ecdsa_p521_signature_der, p256_public_key_from_private, p384_public_key_from_private,
    p521_public_key_from_private, sign_ecdsa_p256_sha256, sign_ecdsa_p256_sha256_with_nonce,
    sign_ecdsa_p384_sha384, sign_ecdsa_p521_sha512, verify_ecdsa_p256_sha256,
    verify_ecdsa_p384_sha384, verify_ecdsa_p521_sha512,
};

pub mod signature;
pub use signature::{
    RsaPublicKey, parse_rsa_public_key, parse_rsa_public_key_blob, parse_rsa_public_key_der,
    rsa_public_key_blob, verify_certificate_signature, verify_signature_bytes,
};

pub mod rsa;
pub use rsa::{
    RsaPrivateKey, parse_rsa_private_key, parse_rsa_private_key_blob, parse_rsa_private_key_der,
    rsa_private_key_blob, rsa_private_key_blob_with_primes, rsa_private_key_from_pkcs1_der,
    rsa_private_key_from_pkcs8_der, rsa_private_key_pkcs1_der, rsa_private_key_pkcs8_der,
    rsa_public_key_from_spki_der, rsa_public_key_spki_der, sign_rsa_pkcs1v15,
    sign_rsa_pkcs1v15_keypair, sign_rsa_pss, sign_rsa_pss_keypair,
};

#[allow(clippy::module_inception)]
pub mod pki;
pub use pki::{
    CertificateRecord, PkiFacadeResult, collect_did_uris, has_did_binding, parse_pem_certificate,
    parse_pem_certificate_result, parse_pem_certificate_result_with_relaxed,
    parse_pem_certificate_with_relaxed, to_dp_string, validate_with_system_trust,
    validate_with_system_trust_result, validate_with_trust, validate_with_trust_result,
};

#[cfg(test)]
mod tests;
