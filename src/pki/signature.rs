//! Pure Rust certificate signature verification helpers.

use super::{
    Certificate, PkiError, PkiResult, SignatureAlgorithmId, parse_integer, parse_sequence,
    verify_ecdsa_p256_sha256, verify_ecdsa_p384_sha384, verify_ecdsa_p521_sha512,
    verify_ed448_signature, verify_ed25519_signature,
};
use ::rsa::pkcs1::DecodeRsaPublicKey;
use ::rsa::signature::Verifier;
use ::rsa::traits::PublicKeyParts;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RsaPublicKey {
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
}

pub fn verify_certificate_signature(
    certificate: &Certificate,
    issuer: &Certificate,
) -> PkiResult<bool> {
    verify_signature_bytes(
        certificate.signature_algorithm.signature,
        &certificate.tbs_der,
        &certificate.signature_value,
        &issuer.tbs.subject_public_key_info.public_key,
    )
}

pub fn verify_signature_bytes(
    algorithm: SignatureAlgorithmId,
    signed_payload: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PkiResult<bool> {
    match algorithm {
        SignatureAlgorithmId::RsaPkcs1Sha256
        | SignatureAlgorithmId::RsaPkcs1Sha384
        | SignatureAlgorithmId::RsaPkcs1Sha512 => {
            verify_rsa_pkcs1v15(algorithm, signed_payload, signature, public_key)
        }
        SignatureAlgorithmId::RsaPssSha256
        | SignatureAlgorithmId::RsaPssSha384
        | SignatureAlgorithmId::RsaPssSha512 => {
            verify_rsa_pss(algorithm, signed_payload, signature, public_key)
        }
        SignatureAlgorithmId::EcdsaSha256 => {
            verify_ecdsa_p256_sha256(signed_payload, signature, public_key)
        }
        SignatureAlgorithmId::EcdsaSha384 => {
            verify_ecdsa_p384_sha384(signed_payload, signature, public_key)
        }
        SignatureAlgorithmId::EcdsaSha512 => {
            verify_ecdsa_p521_sha512(signed_payload, signature, public_key)
        }
        SignatureAlgorithmId::Ed25519 => {
            verify_ed25519_signature(signed_payload, signature, public_key)
        }
        SignatureAlgorithmId::Ed448 => {
            verify_ed448_signature(signed_payload, signature, public_key)
        }
        SignatureAlgorithmId::Unknown => Err(PkiError::new(
            "Unsupported signature algorithm for verification",
        )),
    }
}

pub fn parse_rsa_public_key(public_key: &[u8]) -> PkiResult<RsaPublicKey> {
    parse_rsa_public_key_der(public_key).or_else(|_| parse_rsa_public_key_blob(public_key))
}

pub fn parse_rsa_public_key_der(der: &[u8]) -> PkiResult<RsaPublicKey> {
    if let Ok(key) = ::rsa::RsaPublicKey::from_pkcs1_der(der) {
        return validate_rsa_public_numbers(key.n().to_bytes_be(), key.e().to_bytes_be());
    }
    parse_rsa_public_key_der_lenient(der)
}

fn parse_rsa_public_key_der_lenient(der: &[u8]) -> PkiResult<RsaPublicKey> {
    let seq = parse_sequence(der)?;
    let modulus = parse_integer(&seq.value)?;
    let exponent = parse_integer(&seq.value[modulus.bytes_consumed..])?;
    let modulus = strip_integer_padding(modulus.value);
    let exponent = strip_integer_padding(exponent.value);
    validate_rsa_public_numbers(modulus, exponent)
}

pub fn parse_rsa_public_key_blob(blob: &[u8]) -> PkiResult<RsaPublicKey> {
    let mut offset = 0usize;
    let modulus_len = read_u32_be(blob, &mut offset)? as usize;
    if modulus_len == 0 || offset + modulus_len > blob.len() {
        return Err(PkiError::new("Invalid RSA public key modulus length"));
    }
    let modulus = blob[offset..offset + modulus_len].to_vec();
    offset += modulus_len;
    let exponent_len = read_u32_be(blob, &mut offset)? as usize;
    if exponent_len == 0 || offset + exponent_len > blob.len() {
        return Err(PkiError::new("Invalid RSA public key exponent length"));
    }
    let exponent = blob[offset..offset + exponent_len].to_vec();
    offset += exponent_len;
    if offset != blob.len() {
        return Err(PkiError::new("Trailing bytes in RSA public key blob"));
    }
    validate_rsa_public_numbers(
        strip_integer_padding(modulus),
        strip_integer_padding(exponent),
    )
}

pub fn rsa_public_key_blob(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let modulus = strip_integer_padding(modulus.to_vec());
    let exponent = strip_integer_padding(exponent.to_vec());
    let mut out = Vec::with_capacity(8 + modulus.len() + exponent.len());
    out.extend((modulus.len() as u32).to_be_bytes());
    out.extend(modulus);
    out.extend((exponent.len() as u32).to_be_bytes());
    out.extend(exponent);
    out
}

fn validate_rsa_public_numbers(modulus: Vec<u8>, exponent: Vec<u8>) -> PkiResult<RsaPublicKey> {
    if modulus.is_empty() || exponent.is_empty() {
        return Err(PkiError::new("RSA public key is empty"));
    }
    if modulus.iter().all(|byte| *byte == 0) || exponent.iter().all(|byte| *byte == 0) {
        return Err(PkiError::new("RSA public key contains zero value"));
    }
    Ok(RsaPublicKey { modulus, exponent })
}

fn verify_rsa_pkcs1v15(
    algorithm: SignatureAlgorithmId,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PkiResult<bool> {
    let key = parse_rsa_public_key(public_key)?;
    let key = super::rsa::ecosystem_public_key(&key.modulus, &key.exponent)?;
    let signature = ::rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|err| PkiError::new(format!("invalid RSA PKCS#1 signature: {err}")))?;
    let verified = match algorithm {
        SignatureAlgorithmId::RsaPkcs1Sha256 => {
            let verifier = ::rsa::pkcs1v15::VerifyingKey::<::rsa::sha2::Sha256>::new(key);
            verifier.verify(message, &signature).is_ok()
        }
        SignatureAlgorithmId::RsaPkcs1Sha384 => {
            let verifier = ::rsa::pkcs1v15::VerifyingKey::<::rsa::sha2::Sha384>::new(key);
            verifier.verify(message, &signature).is_ok()
        }
        SignatureAlgorithmId::RsaPkcs1Sha512 => {
            let verifier = ::rsa::pkcs1v15::VerifyingKey::<::rsa::sha2::Sha512>::new(key);
            verifier.verify(message, &signature).is_ok()
        }
        _ => return Err(PkiError::new("Unsupported RSA PKCS#1 hash algorithm")),
    };
    Ok(verified)
}

fn verify_rsa_pss(
    algorithm: SignatureAlgorithmId,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PkiResult<bool> {
    let key = parse_rsa_public_key(public_key)?;
    let max_salt_len = key.modulus.len().saturating_sub(
        match algorithm {
            SignatureAlgorithmId::RsaPssSha256 => 32,
            SignatureAlgorithmId::RsaPssSha384 => 48,
            SignatureAlgorithmId::RsaPssSha512 => 64,
            _ => return Err(PkiError::new("Unsupported RSA-PSS hash algorithm")),
        } + 2,
    );
    let key = super::rsa::ecosystem_public_key(&key.modulus, &key.exponent)?;
    let signature = ::rsa::pss::Signature::try_from(signature)
        .map_err(|err| PkiError::new(format!("invalid RSA-PSS signature: {err}")))?;
    let verified = match algorithm {
        SignatureAlgorithmId::RsaPssSha256 => {
            verify_rsa_pss_sha256(key, message, &signature, max_salt_len)
        }
        SignatureAlgorithmId::RsaPssSha384 => {
            verify_rsa_pss_sha384(key, message, &signature, max_salt_len)
        }
        SignatureAlgorithmId::RsaPssSha512 => {
            verify_rsa_pss_sha512(key, message, &signature, max_salt_len)
        }
        _ => return Err(PkiError::new("Unsupported RSA-PSS hash algorithm")),
    };
    Ok(verified)
}

fn verify_rsa_pss_sha256(
    key: ::rsa::RsaPublicKey,
    message: &[u8],
    signature: &::rsa::pss::Signature,
    max_salt_len: usize,
) -> bool {
    let verifier = ::rsa::pss::VerifyingKey::<::rsa::sha2::Sha256>::new(key.clone());
    if verifier.verify(message, signature).is_ok() {
        return true;
    }
    verify_rsa_pss_sha256_with_salt_range(key, message, signature, max_salt_len)
}

fn verify_rsa_pss_sha384(
    key: ::rsa::RsaPublicKey,
    message: &[u8],
    signature: &::rsa::pss::Signature,
    max_salt_len: usize,
) -> bool {
    let verifier = ::rsa::pss::VerifyingKey::<::rsa::sha2::Sha384>::new(key.clone());
    if verifier.verify(message, signature).is_ok() {
        return true;
    }
    verify_rsa_pss_sha384_with_salt_range(key, message, signature, max_salt_len)
}

fn verify_rsa_pss_sha512(
    key: ::rsa::RsaPublicKey,
    message: &[u8],
    signature: &::rsa::pss::Signature,
    max_salt_len: usize,
) -> bool {
    let verifier = ::rsa::pss::VerifyingKey::<::rsa::sha2::Sha512>::new(key.clone());
    if verifier.verify(message, signature).is_ok() {
        return true;
    }
    verify_rsa_pss_sha512_with_salt_range(key, message, signature, max_salt_len)
}

fn verify_rsa_pss_sha256_with_salt_range(
    key: ::rsa::RsaPublicKey,
    message: &[u8],
    signature: &::rsa::pss::Signature,
    max_salt_len: usize,
) -> bool {
    (0..=max_salt_len).any(|salt_len| {
        salt_len != 32
            && ::rsa::pss::VerifyingKey::<::rsa::sha2::Sha256>::new_with_salt_len(
                key.clone(),
                salt_len,
            )
            .verify(message, signature)
            .is_ok()
    })
}

fn verify_rsa_pss_sha384_with_salt_range(
    key: ::rsa::RsaPublicKey,
    message: &[u8],
    signature: &::rsa::pss::Signature,
    max_salt_len: usize,
) -> bool {
    (0..=max_salt_len).any(|salt_len| {
        salt_len != 48
            && ::rsa::pss::VerifyingKey::<::rsa::sha2::Sha384>::new_with_salt_len(
                key.clone(),
                salt_len,
            )
            .verify(message, signature)
            .is_ok()
    })
}

fn verify_rsa_pss_sha512_with_salt_range(
    key: ::rsa::RsaPublicKey,
    message: &[u8],
    signature: &::rsa::pss::Signature,
    max_salt_len: usize,
) -> bool {
    (0..=max_salt_len).any(|salt_len| {
        salt_len != 64
            && ::rsa::pss::VerifyingKey::<::rsa::sha2::Sha512>::new_with_salt_len(
                key.clone(),
                salt_len,
            )
            .verify(message, signature)
            .is_ok()
    })
}

fn strip_integer_padding(mut value: Vec<u8>) -> Vec<u8> {
    while value.len() > 1 && value.first() == Some(&0) {
        value.remove(0);
    }
    value
}

fn read_u32_be(input: &[u8], offset: &mut usize) -> PkiResult<u32> {
    if *offset + 4 > input.len() {
        return Err(PkiError::new("truncated RSA public key blob"));
    }
    let value = u32::from_be_bytes([
        input[*offset],
        input[*offset + 1],
        input[*offset + 2],
        input[*offset + 3],
    ]);
    *offset += 4;
    Ok(value)
}
