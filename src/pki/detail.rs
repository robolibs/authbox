//! Compatibility helpers for the C++ `authbox::pik::detail` namespace.
//!
//! The C++ headers reopen `authbox::pik::detail` from several PKI headers.
//! This module starts that shared namespace with the PEM/base64 helpers from
//! `xtra/authbox/include/pki/pem.hpp`, `pki/asn1_utils.hpp`,
//! `pki/oid_registry.hpp`, and `pki/distinguished_name.hpp` while keeping the
//! real surfaces in their mirrored Rust modules.

use super::certificate::{Certificate, CertificateResult};
pub use super::crl::{
    CrlDerCursor, crl_copy_span, crl_parse_algorithm_identifier, crl_parse_name, crl_parse_time,
    identify_crl_entry_extension, identify_crl_extension, parse_crl_entry_extensions,
    parse_crl_extensions, parse_reason_code,
};
pub use super::distinguished_name::{
    ParsedDn, attribute_from_oid, attribute_from_string, dn_trim, encode_directory_string,
    encode_name, is_printable_string, oid_from_attribute, parse_dn_string,
};
pub use super::parser::{
    ParseResult, ValidityRange, copy_bytes, make_error, parse_algorithm_identifier_full,
    parse_certificate, parse_extension_sequence, parse_extensions_full, parse_name_full,
    parse_subject_public_key_info_full, parse_time_choice as parse_time_choice_full,
    parse_validity, parse_version,
};
use super::{
    CertificateContext, CurveId, DerTime, ExtensionId, HashAlgorithm, Oid, PkiError, PkiResult,
    RawExtension, SignatureAlgorithmId, SubjectPublicKeyInfo, encode_ecdsa_p256_signature_der,
    encode_ecdsa_p384_signature_der, encode_ecdsa_p521_signature_der, parse_integer, parse_oid,
    parse_sequence,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const K_MAX_LENGTH_OCTETS: usize = std::mem::size_of::<usize>();

pub type OidArray<const N: usize> = [u32; N];

pub const K_OID_SHA256_WITH_RSA: &[u32] = &[1, 2, 840, 113549, 1, 1, 11];
pub const K_OID_SHA384_WITH_RSA: &[u32] = &[1, 2, 840, 113549, 1, 1, 12];
pub const K_OID_SHA512_WITH_RSA: &[u32] = &[1, 2, 840, 113549, 1, 1, 13];
pub const K_OID_RSA_PSS: &[u32] = &[1, 2, 840, 113549, 1, 1, 10];
pub const K_OID_ECDSA_SHA256: &[u32] = &[1, 2, 840, 10045, 4, 3, 2];
pub const K_OID_ECDSA_SHA384: &[u32] = &[1, 2, 840, 10045, 4, 3, 3];
pub const K_OID_ECDSA_SHA512: &[u32] = &[1, 2, 840, 10045, 4, 3, 4];
pub const K_OID_ED25519: &[u32] = &[1, 3, 101, 112];
pub const K_OID_ED448: &[u32] = &[1, 3, 101, 113];

pub const K_SIGNATURE_ALGORITHMS: &[(SignatureAlgorithmId, &[u32])] = &[
    (SignatureAlgorithmId::RsaPkcs1Sha256, K_OID_SHA256_WITH_RSA),
    (SignatureAlgorithmId::RsaPkcs1Sha384, K_OID_SHA384_WITH_RSA),
    (SignatureAlgorithmId::RsaPkcs1Sha512, K_OID_SHA512_WITH_RSA),
    (SignatureAlgorithmId::RsaPssSha256, K_OID_RSA_PSS),
    (SignatureAlgorithmId::EcdsaSha256, K_OID_ECDSA_SHA256),
    (SignatureAlgorithmId::EcdsaSha384, K_OID_ECDSA_SHA384),
    (SignatureAlgorithmId::EcdsaSha512, K_OID_ECDSA_SHA512),
    (SignatureAlgorithmId::Ed25519, K_OID_ED25519),
    (SignatureAlgorithmId::Ed448, K_OID_ED448),
];

pub const K_OID_SHA256: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
pub const K_OID_SHA512: &[u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];
pub const K_OID_BLAKE2B: &[u32] = &[1, 3, 6, 1, 4, 1, 1722, 12, 2, 1, 8];

pub const K_HASH_ALGORITHMS: &[(HashAlgorithm, &[u32])] = &[
    (HashAlgorithm::Sha256, K_OID_SHA256),
    (HashAlgorithm::Sha512, K_OID_SHA512),
    (HashAlgorithm::Blake2b, K_OID_BLAKE2B),
];

pub const K_OID_SECP256R1: &[u32] = &[1, 2, 840, 10045, 3, 1, 7];
pub const K_OID_SECP384R1: &[u32] = &[1, 3, 132, 0, 34];
pub const K_OID_SECP521R1: &[u32] = &[1, 3, 132, 0, 35];
pub const K_OID_SECP256K1: &[u32] = &[1, 3, 132, 0, 10];
pub const K_OID_X25519: &[u32] = &[1, 3, 101, 110];
pub const K_OID_X448: &[u32] = &[1, 3, 101, 111];

pub const K_CURVE_OIDS: &[(CurveId, &[u32])] = &[
    (CurveId::Secp256r1, K_OID_SECP256R1),
    (CurveId::Secp384r1, K_OID_SECP384R1),
    (CurveId::Secp521r1, K_OID_SECP521R1),
    (CurveId::Secp256k1, K_OID_SECP256K1),
    (CurveId::Ed25519, K_OID_ED25519),
    (CurveId::Ed448, K_OID_ED448),
    (CurveId::X25519, K_OID_X25519),
    (CurveId::X448, K_OID_X448),
];

pub const K_OID_BASIC_CONSTRAINTS: &[u32] = &[2, 5, 29, 19];
pub const K_OID_KEY_USAGE: &[u32] = &[2, 5, 29, 15];
pub const K_OID_EXTENDED_KEY_USAGE: &[u32] = &[2, 5, 29, 37];
pub const K_OID_SUBJECT_ALT_NAME: &[u32] = &[2, 5, 29, 17];
pub const K_OID_AUTHORITY_KEY_ID: &[u32] = &[2, 5, 29, 35];
pub const K_OID_SUBJECT_KEY_ID: &[u32] = &[2, 5, 29, 14];
pub const K_OID_CERTIFICATE_POLICIES: &[u32] = &[2, 5, 29, 32];
pub const K_OID_CRL_DISTRIBUTION_POINTS: &[u32] = &[2, 5, 29, 31];
pub const K_OID_AUTHORITY_INFO_ACCESS: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 1, 1];
pub const K_OID_NAME_CONSTRAINTS: &[u32] = &[2, 5, 29, 30];
pub const K_OID_ISSUER_ALT_NAME: &[u32] = &[2, 5, 29, 18];
pub const K_OID_POLICY_MAPPINGS: &[u32] = &[2, 5, 29, 33];
pub const K_OID_POLICY_CONSTRAINTS: &[u32] = &[2, 5, 29, 36];
pub const K_OID_INHIBIT_ANY_POLICY: &[u32] = &[2, 5, 29, 54];

pub const K_EXTENSION_OIDS: &[(ExtensionId, &[u32])] = &[
    (ExtensionId::BasicConstraints, K_OID_BASIC_CONSTRAINTS),
    (ExtensionId::KeyUsage, K_OID_KEY_USAGE),
    (ExtensionId::ExtendedKeyUsage, K_OID_EXTENDED_KEY_USAGE),
    (ExtensionId::SubjectAltName, K_OID_SUBJECT_ALT_NAME),
    (ExtensionId::AuthorityKeyIdentifier, K_OID_AUTHORITY_KEY_ID),
    (ExtensionId::SubjectKeyIdentifier, K_OID_SUBJECT_KEY_ID),
    (ExtensionId::CertificatePolicies, K_OID_CERTIFICATE_POLICIES),
    (
        ExtensionId::CrlDistributionPoints,
        K_OID_CRL_DISTRIBUTION_POINTS,
    ),
    (
        ExtensionId::AuthorityInfoAccess,
        K_OID_AUTHORITY_INFO_ACCESS,
    ),
    (ExtensionId::NameConstraints, K_OID_NAME_CONSTRAINTS),
    (ExtensionId::IssuerAltName, K_OID_ISSUER_ALT_NAME),
    (ExtensionId::PolicyMappings, K_OID_POLICY_MAPPINGS),
    (ExtensionId::PolicyConstraints, K_OID_POLICY_CONSTRAINTS),
    (ExtensionId::InhibitAnyPolicy, K_OID_INHIBIT_ANY_POLICY),
];

pub const K_BEGIN_MARKER: &str = "-----BEGIN ";
pub const K_END_MARKER: &str = "-----END ";
pub const K_TRAILER: &str = "-----";
pub const K_BASE64_ALPHABET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DnSpanCursor<'a> {
    pub data: &'a [u8],
    pub offset: usize,
}

impl<'a> DnSpanCursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }

    pub fn empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    pub fn advance(&mut self, count: usize) -> bool {
        if self.offset + count > self.data.len() {
            return false;
        }
        self.offset += count;
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeylockSignatureAlgorithm {
    Ed25519,
    RsaPkcs1v15Sha256,
    RsaPkcs1v15Sha384,
    RsaPkcs1v15Sha512,
    RsaPssSha256,
    RsaPssSha384,
    RsaPssSha512,
    EcdsaP256Sha256,
}

#[allow(non_upper_case_globals)]
pub const kMaxLengthOctets: usize = K_MAX_LENGTH_OCTETS;
#[allow(non_upper_case_globals)]
pub const kOidSha256WithRsa: &[u32] = K_OID_SHA256_WITH_RSA;
#[allow(non_upper_case_globals)]
pub const kOidSha384WithRsa: &[u32] = K_OID_SHA384_WITH_RSA;
#[allow(non_upper_case_globals)]
pub const kOidSha512WithRsa: &[u32] = K_OID_SHA512_WITH_RSA;
#[allow(non_upper_case_globals)]
pub const kOidRsaPss: &[u32] = K_OID_RSA_PSS;
#[allow(non_upper_case_globals)]
pub const kOidEcdsaSha256: &[u32] = K_OID_ECDSA_SHA256;
#[allow(non_upper_case_globals)]
pub const kOidEcdsaSha384: &[u32] = K_OID_ECDSA_SHA384;
#[allow(non_upper_case_globals)]
pub const kOidEcdsaSha512: &[u32] = K_OID_ECDSA_SHA512;
#[allow(non_upper_case_globals)]
pub const kOidEd25519: &[u32] = K_OID_ED25519;
#[allow(non_upper_case_globals)]
pub const kOidEd448: &[u32] = K_OID_ED448;
#[allow(non_upper_case_globals)]
pub const kSignatureAlgorithms: &[(SignatureAlgorithmId, &[u32])] = K_SIGNATURE_ALGORITHMS;
#[allow(non_upper_case_globals)]
pub const kOidSha256: &[u32] = K_OID_SHA256;
#[allow(non_upper_case_globals)]
pub const kOidSha512: &[u32] = K_OID_SHA512;
#[allow(non_upper_case_globals)]
pub const kOidBlake2b: &[u32] = K_OID_BLAKE2B;
#[allow(non_upper_case_globals)]
pub const kHashAlgorithms: &[(HashAlgorithm, &[u32])] = K_HASH_ALGORITHMS;
#[allow(non_upper_case_globals)]
pub const kOidSecp256r1: &[u32] = K_OID_SECP256R1;
#[allow(non_upper_case_globals)]
pub const kOidSecp384r1: &[u32] = K_OID_SECP384R1;
#[allow(non_upper_case_globals)]
pub const kOidSecp521r1: &[u32] = K_OID_SECP521R1;
#[allow(non_upper_case_globals)]
pub const kOidSecp256k1: &[u32] = K_OID_SECP256K1;
#[allow(non_upper_case_globals)]
pub const kOidX25519: &[u32] = K_OID_X25519;
#[allow(non_upper_case_globals)]
pub const kOidX448: &[u32] = K_OID_X448;
#[allow(non_upper_case_globals)]
pub const kCurveOids: &[(CurveId, &[u32])] = K_CURVE_OIDS;
#[allow(non_upper_case_globals)]
pub const kOidBasicConstraints: &[u32] = K_OID_BASIC_CONSTRAINTS;
#[allow(non_upper_case_globals)]
pub const kOidKeyUsage: &[u32] = K_OID_KEY_USAGE;
#[allow(non_upper_case_globals)]
pub const kOidExtendedKeyUsage: &[u32] = K_OID_EXTENDED_KEY_USAGE;
#[allow(non_upper_case_globals)]
pub const kOidSubjectAltName: &[u32] = K_OID_SUBJECT_ALT_NAME;
#[allow(non_upper_case_globals)]
pub const kOidAuthorityKeyId: &[u32] = K_OID_AUTHORITY_KEY_ID;
#[allow(non_upper_case_globals)]
pub const kOidSubjectKeyId: &[u32] = K_OID_SUBJECT_KEY_ID;
#[allow(non_upper_case_globals)]
pub const kOidCertificatePolicies: &[u32] = K_OID_CERTIFICATE_POLICIES;
#[allow(non_upper_case_globals)]
pub const kOidCrlDistributionPoints: &[u32] = K_OID_CRL_DISTRIBUTION_POINTS;
#[allow(non_upper_case_globals)]
pub const kOidAuthorityInfoAccess: &[u32] = K_OID_AUTHORITY_INFO_ACCESS;
#[allow(non_upper_case_globals)]
pub const kOidNameConstraints: &[u32] = K_OID_NAME_CONSTRAINTS;
#[allow(non_upper_case_globals)]
pub const kOidIssuerAltName: &[u32] = K_OID_ISSUER_ALT_NAME;
#[allow(non_upper_case_globals)]
pub const kOidPolicyMappings: &[u32] = K_OID_POLICY_MAPPINGS;
#[allow(non_upper_case_globals)]
pub const kOidPolicyConstraints: &[u32] = K_OID_POLICY_CONSTRAINTS;
#[allow(non_upper_case_globals)]
pub const kOidInhibitAnyPolicy: &[u32] = K_OID_INHIBIT_ANY_POLICY;
#[allow(non_upper_case_globals)]
pub const kExtensionOids: &[(ExtensionId, &[u32])] = K_EXTENSION_OIDS;
#[allow(non_upper_case_globals)]
pub const kBeginMarker: &str = K_BEGIN_MARKER;
#[allow(non_upper_case_globals)]
pub const kEndMarker: &str = K_END_MARKER;
#[allow(non_upper_case_globals)]
pub const kTrailer: &str = K_TRAILER;
#[allow(non_upper_case_globals)]
pub const kBase64Alphabet: &str = K_BASE64_ALPHABET;

pub fn lookup_enum<T: Copy + Eq>(oid: &Oid, table: &[(T, &[u32])], unknown: T) -> T {
    table
        .iter()
        .find(|(_, pattern)| oid.nodes == *pattern)
        .map(|(value, _)| *value)
        .unwrap_or(unknown)
}

pub fn make_random_serial() -> PkiResult<Vec<u8>> {
    let mut serial = vec![0u8; 16];
    fill_random_bytes(&mut serial)?;
    serial[0] &= 0x7f;
    Ok(serial)
}

pub fn get_extension_oid(id: ExtensionId) -> Oid {
    K_EXTENSION_OIDS
        .iter()
        .find(|(value, _)| *value == id)
        .map(|(_, pattern)| Oid::new(*pattern))
        .unwrap_or_default()
}

pub fn get_signature_oid(id: SignatureAlgorithmId) -> PkiResult<Oid> {
    if matches!(
        id,
        SignatureAlgorithmId::RsaPssSha384 | SignatureAlgorithmId::RsaPssSha512
    ) {
        return Ok(Oid::new(K_OID_RSA_PSS));
    }
    K_SIGNATURE_ALGORITHMS
        .iter()
        .find(|(value, _)| *value == id)
        .map(|(_, pattern)| Oid::new(*pattern))
        .ok_or_else(|| PkiError::new("Failed to get OID for signature algorithm ID"))
}

pub fn make_certificate_from_context(ctx: CertificateContext) -> Certificate {
    Certificate::from_context(ctx)
}

pub fn contains_pem_marker(data: impl AsRef<[u8]>) -> bool {
    data.as_ref()
        .windows(b"-----BEGIN".len())
        .any(|window| window == b"-----BEGIN")
}

pub fn equals_case_insensitive(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.eq_ignore_ascii_case(b)
}

pub fn parse_extended_key_usage(ext: &RawExtension) -> Vec<Oid> {
    let Ok(seq) = parse_sequence(&ext.value) else {
        return Vec::new();
    };
    let mut cursor = DnSpanCursor::new(&seq.value);
    let mut oids = Vec::new();
    while !cursor.empty() {
        let Ok(oid) = parse_oid(cursor.remaining()) else {
            break;
        };
        oids.push(oid.value);
        if !cursor.advance(oid.bytes_consumed) {
            break;
        }
    }
    oids
}

pub fn label_count(name: &str) -> usize {
    if name.is_empty() {
        0
    } else {
        name.bytes().filter(|byte| *byte == b'.').count() + 1
    }
}

pub fn parse_ipv4(input: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut count = 0usize;
    for part in input.split('.') {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let value = part.parse::<u16>().ok()?;
        if value > 255 || count >= 4 {
            return None;
        }
        out[count] = value as u8;
        count += 1;
    }
    (count == 4).then_some(out)
}

pub fn is_ipv4_literal(input: &str) -> bool {
    parse_ipv4(input).is_some()
}

pub fn ipv4_equal_bytes(bytes: &[u8], ip: &[u8; 4]) -> bool {
    bytes == ip
}

pub fn wildcard_match(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let hostname = hostname.to_ascii_lowercase();
    let Some(star) = pattern.find('*') else {
        return pattern == hostname;
    };
    if star != 0 || pattern.len() < 3 || !pattern.starts_with("*.") || pattern[1..].contains('*') {
        return false;
    }
    let suffix = &pattern[2..];
    if suffix.is_empty() || label_count(&hostname) != label_count(&pattern) {
        return false;
    }
    if hostname.len() < suffix.len() + 1 {
        return false;
    }
    let host_suffix = &hostname[hostname.len() - suffix.len()..];
    if host_suffix != suffix {
        return false;
    }
    let prefix_len = hostname.len() - suffix.len();
    if prefix_len == 0 || hostname.as_bytes()[prefix_len - 1] != b'.' {
        return false;
    }
    let left = &hostname[..prefix_len - 1];
    !left.is_empty() && !left.contains('.')
}

pub fn strip_integer_padding(mut value: Vec<u8>) -> Vec<u8> {
    while value.len() > 1 && value.first() == Some(&0) {
        value.remove(0);
    }
    value
}

pub fn parse_rsa_public_key_der(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let key = super::signature::parse_rsa_public_key_der(der).ok()?;
    Some((key.modulus, key.exponent))
}

pub fn keylock_signature_algorithm(
    signature_algorithm: SignatureAlgorithmId,
) -> Option<KeylockSignatureAlgorithm> {
    match signature_algorithm {
        SignatureAlgorithmId::Ed25519 => Some(KeylockSignatureAlgorithm::Ed25519),
        SignatureAlgorithmId::RsaPkcs1Sha256 => Some(KeylockSignatureAlgorithm::RsaPkcs1v15Sha256),
        SignatureAlgorithmId::RsaPkcs1Sha384 => Some(KeylockSignatureAlgorithm::RsaPkcs1v15Sha384),
        SignatureAlgorithmId::RsaPkcs1Sha512 => Some(KeylockSignatureAlgorithm::RsaPkcs1v15Sha512),
        SignatureAlgorithmId::RsaPssSha256 => Some(KeylockSignatureAlgorithm::RsaPssSha256),
        SignatureAlgorithmId::RsaPssSha384 => Some(KeylockSignatureAlgorithm::RsaPssSha384),
        SignatureAlgorithmId::RsaPssSha512 => Some(KeylockSignatureAlgorithm::RsaPssSha512),
        SignatureAlgorithmId::EcdsaSha256 => Some(KeylockSignatureAlgorithm::EcdsaP256Sha256),
        _ => None,
    }
}

pub fn normalize_public_key_for_verify(
    spki: &SubjectPublicKeyInfo,
    signature_algorithm: SignatureAlgorithmId,
) -> CertificateResult<Vec<u8>> {
    match signature_algorithm {
        SignatureAlgorithmId::Ed25519 => {
            if spki.public_key.len() != 32 {
                CertificateResult::failure("Invalid Ed25519 issuer public key size")
            } else {
                CertificateResult::ok(spki.public_key.clone())
            }
        }
        SignatureAlgorithmId::EcdsaSha256 => {
            if spki.public_key.len() == 65 && spki.public_key.first() == Some(&0x04) {
                CertificateResult::ok(spki.public_key[1..].to_vec())
            } else if spki.public_key.len() == 64 {
                CertificateResult::ok(spki.public_key.clone())
            } else {
                CertificateResult::failure("Invalid ECDSA P-256 issuer public key format")
            }
        }
        SignatureAlgorithmId::RsaPkcs1Sha256
        | SignatureAlgorithmId::RsaPkcs1Sha384
        | SignatureAlgorithmId::RsaPkcs1Sha512
        | SignatureAlgorithmId::RsaPssSha256
        | SignatureAlgorithmId::RsaPssSha384
        | SignatureAlgorithmId::RsaPssSha512 => {
            if let Some((modulus, exponent)) = parse_rsa_public_key_der(&spki.public_key) {
                CertificateResult::ok(encode_rsa_public_key_blob(&modulus, &exponent))
            } else {
                CertificateResult::ok(spki.public_key.clone())
            }
        }
        _ => CertificateResult::failure("Unsupported signature algorithm for key conversion"),
    }
}

pub fn normalize_signature_for_verify(
    signature: &[u8],
    signature_algorithm: SignatureAlgorithmId,
) -> CertificateResult<Vec<u8>> {
    if signature_algorithm != SignatureAlgorithmId::EcdsaSha256 {
        return CertificateResult::ok(signature.to_vec());
    }
    if signature.len() == 64 {
        return CertificateResult::ok(signature.to_vec());
    }
    match decode_ecdsa_p256_signature_der(signature) {
        Ok(decoded) => CertificateResult::ok(decoded),
        Err(error) => CertificateResult::failure(error.message),
    }
}

pub fn normalize_signature_for_emit(
    signature: &[u8],
    signature_algorithm: SignatureAlgorithmId,
) -> CertificateResult<Vec<u8>> {
    let normalized = match signature_algorithm {
        SignatureAlgorithmId::EcdsaSha256 if signature.len() == 64 => {
            encode_ecdsa_p256_signature_der(signature)
        }
        SignatureAlgorithmId::EcdsaSha384 if signature.len() == 96 => {
            encode_ecdsa_p384_signature_der(signature)
        }
        SignatureAlgorithmId::EcdsaSha512 if signature.len() == 132 => {
            encode_ecdsa_p521_signature_der(signature)
        }
        SignatureAlgorithmId::EcdsaSha256
        | SignatureAlgorithmId::EcdsaSha384
        | SignatureAlgorithmId::EcdsaSha512
            if signature.first() != Some(&0x30) =>
        {
            Err(PkiError::new("Unexpected ECDSA raw signature size"))
        }
        _ => return CertificateResult::ok(signature.to_vec()),
    };
    match normalized {
        Ok(der) => CertificateResult::ok(der),
        Err(error) => CertificateResult::failure(error.message),
    }
}

pub fn is_utctime(time: &DerTime) -> bool {
    (1950..=2049).contains(&time.year)
}

pub fn to_gmtime(tp: SystemTime) -> DerTime {
    let seconds = seconds_since_unix_epoch(tp);
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    DerTime {
        year,
        month,
        day,
        hour: (seconds_of_day / 3_600) as u8,
        minute: ((seconds_of_day % 3_600) / 60) as u8,
        second: (seconds_of_day % 60) as u8,
    }
}

pub fn decode_base64_char(ch: char) -> i32 {
    match ch {
        'A'..='Z' => ch as i32 - 'A' as i32,
        'a'..='z' => ch as i32 - 'a' as i32 + 26,
        '0'..='9' => ch as i32 - '0' as i32 + 52,
        '+' => 62,
        '/' => 63,
        '=' => -2,
        _ => -1,
    }
}

pub fn is_digit(ch: char) -> bool {
    ch.is_ascii_digit()
}

pub fn parse_decimal(view: &str, value: &mut i32) -> bool {
    *value = 0;
    if view.is_empty() {
        return false;
    }
    for ch in view.chars() {
        if !is_digit(ch) {
            return false;
        }
        *value = (*value * 10) + (ch as i32 - '0' as i32);
    }
    true
}

pub fn make_time_point(
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    second: i32,
) -> super::ASN1Result<SystemTime> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return time_point_failure("invalid time component");
    }

    let max_day = days_in_month(year, month as u8);
    if day as u8 > max_day {
        return time_point_failure("invalid calendar date");
    }

    let days = days_from_civil(year, month, day);
    let seconds = i128::from(days) * 86_400
        + i128::from(hour) * 3_600
        + i128::from(minute) * 60
        + i128::from(second);
    let Some(time_point) = system_time_from_unix_seconds(seconds) else {
        return time_point_failure("time point out of range");
    };
    super::ASN1Result::ok(time_point, 0)
}

pub fn encode_base64(data: &[u8]) -> String {
    super::pem::encode_base64(data)
}

pub fn decode_base64(input: &str, output: &mut Vec<u8>) -> bool {
    match super::pem::decode_base64(input) {
        Ok(decoded) => {
            output.clear();
            output.extend(decoded);
            true
        }
        Err(_) => false,
    }
}

pub fn strip_whitespace(view: &str, start: usize, end: usize) -> String {
    let Some(slice) = view.get(start..end) else {
        return String::new();
    };
    slice
        .chars()
        .filter(|ch| !matches!(ch, '\r' | '\n' | ' ' | '\t'))
        .collect()
}

pub fn error_result(message: impl Into<String>) -> super::PemResult {
    super::PemResult::err(message)
}

pub fn build_block(label: &str, body: &str, line_length: usize) -> String {
    let mut out = format!("{K_BEGIN_MARKER}{label}{K_TRAILER}\n");
    if line_length == 0 {
        out.push_str(body);
        out.push('\n');
    } else {
        for chunk in body.as_bytes().chunks(line_length) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 body is ASCII"));
            out.push('\n');
        }
    }
    out.push_str(&format!("{K_END_MARKER}{label}{K_TRAILER}\n"));
    out
}

fn encode_rsa_public_key_blob(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + modulus.len() + exponent.len());
    out.extend((modulus.len() as u32).to_be_bytes());
    out.extend(modulus);
    out.extend((exponent.len() as u32).to_be_bytes());
    out.extend(exponent);
    out
}

fn decode_ecdsa_p256_signature_der(signature: &[u8]) -> PkiResult<Vec<u8>> {
    let seq = parse_sequence(signature)?;
    let r = parse_integer(&seq.value)?;
    let s = parse_integer(&seq.value[r.bytes_consumed..])?;
    if r.bytes_consumed + s.bytes_consumed != seq.value.len() {
        return Err(PkiError::new("trailing data in ECDSA signature"));
    }
    let mut out = Vec::with_capacity(64);
    out.extend(integer_to_p256_scalar(&r.value)?);
    out.extend(integer_to_p256_scalar(&s.value)?);
    Ok(out)
}

fn integer_to_p256_scalar(input: &[u8]) -> PkiResult<[u8; 32]> {
    let value = strip_integer_padding(input.to_vec());
    if value.len() > 32 {
        return Err(PkiError::new("ECDSA scalar is too large"));
    }
    let mut out = [0u8; 32];
    out[32 - value.len()..].copy_from_slice(&value);
    Ok(out)
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: i32, day: i32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 }.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2).div_euclid(5) + day - 1;
    let day_of_era =
        year_of_era * 365 + year_of_era.div_euclid(4) - year_of_era.div_euclid(100) + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn system_time_from_unix_seconds(seconds: i128) -> Option<SystemTime> {
    if seconds >= 0 {
        let seconds = u64::try_from(seconds).ok()?;
        UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
    } else {
        let seconds = u64::try_from(-seconds).ok()?;
        UNIX_EPOCH.checked_sub(Duration::from_secs(seconds))
    }
}

fn time_point_failure(message: impl Into<String>) -> super::ASN1Result<SystemTime> {
    super::ASN1Result {
        success: false,
        value: UNIX_EPOCH,
        bytes_consumed: 0,
        error: message.into(),
    }
}

fn seconds_since_unix_epoch(tp: SystemTime) -> i64 {
    match tp.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs().min(i64::MAX as u64) as i64,
        Err(error) => -(error.duration().as_secs().min(i64::MAX as u64) as i64),
    }
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u8, u8) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2).div_euclid(153);
    let day = doy - (153 * mp + 2).div_euclid(5) + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(month <= 2);
    (year as i32, month as u8, day as u8)
}

fn fill_random_bytes(out: &mut [u8]) -> PkiResult<()> {
    super::random::fill_random(out)
}
