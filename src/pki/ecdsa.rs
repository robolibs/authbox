//! ECDSA helpers — thin delegations into the sibling `keylock` crate.
//!
//! authbox owns PKI/X.509 framing; all ECDSA primitives live in keylock.

use super::{PkiError, PkiResult};

pub fn verify_ecdsa_p256_sha256(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PkiResult<bool> {
    keylock::crypto::ecdsa_p256::verify_detached(message, signature, public_key)
        .map_err(PkiError::new)
}

pub fn verify_ecdsa_p384_sha384(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PkiResult<bool> {
    keylock::crypto::ecdsa_p384::verify_detached(message, signature, public_key)
        .map_err(PkiError::new)
}

pub fn verify_ecdsa_p521_sha512(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PkiResult<bool> {
    keylock::crypto::ecdsa_p521::verify_detached(message, signature, public_key)
        .map_err(PkiError::new)
}

pub fn sign_ecdsa_p256_sha256(message: &[u8], private_key: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ecdsa_p256::sign_detached(message, private_key).map_err(PkiError::new)
}

pub fn sign_ecdsa_p384_sha384(message: &[u8], private_key: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ecdsa_p384::sign_detached(message, private_key).map_err(PkiError::new)
}

pub fn sign_ecdsa_p521_sha512(message: &[u8], private_key: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ecdsa_p521::sign_detached(message, private_key).map_err(PkiError::new)
}

/// Compatibility-only helper. The fixed-nonce surface is preserved so existing
/// PKI test vectors keep their call shape; the actual signature is produced by
/// keylock's deterministic-by-default P-256 signer (the nonce is validated for
/// length and non-zero but not threaded into the inner RFC 6979 derivation).
pub fn sign_ecdsa_p256_sha256_with_nonce(
    message: &[u8],
    private_key: &[u8],
    nonce: &[u8],
) -> PkiResult<Vec<u8>> {
    if nonce.is_empty() || nonce.iter().all(|byte| *byte == 0) {
        return Err(PkiError::new("invalid ECDSA nonce"));
    }
    sign_ecdsa_p256_sha256(message, private_key)
}

pub fn p256_public_key_from_private(private_key: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ecdsa_p256::derive_public_key(private_key).map_err(PkiError::new)
}

pub fn p384_public_key_from_private(private_key: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ecdsa_p384::public_key_from_private(private_key).map_err(PkiError::new)
}

pub fn p521_public_key_from_private(private_key: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ecdsa_p521::public_key_from_private(private_key).map_err(PkiError::new)
}

pub fn encode_ecdsa_p256_signature_der(signature: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ecdsa_p256::signature_to_der(signature).map_err(PkiError::new)
}

pub fn encode_ecdsa_p384_signature_der(signature: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ecdsa_p384::signature_to_der(signature).map_err(PkiError::new)
}

pub fn encode_ecdsa_p521_signature_der(signature: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ecdsa_p521::signature_to_der(signature).map_err(PkiError::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecdsa_p256_verifies_openssl_vector() {
        let public_key = hex(
            "04ab7e085fcc8b702bf70ac4b9d7c03e7b0f4b415955b6c0b93494a2628fe67f8\
             c7aeb87c58c5731c34a62841fceef3b7c220db942115c27f985bf77c8e3b9a4a1",
        );
        let signature = hex(
            "3044022100f83db0d7c73ca010d9e81659798dc39f839dd44a673e0cfd0e987426\
             613d8f4d021f2244efce0304ef8fc5792f4c9ac0b1f3a02342346f13596300aec\
             46466399d",
        );

        assert!(verify_ecdsa_p256_sha256(b"ecdsa", &signature, &public_key).unwrap());
        let raw_signature = hex(
            "f83db0d7c73ca010d9e81659798dc39f839dd44a673e0cfd0e987426613d8f4d\
             002244efce0304ef8fc5792f4c9ac0b1f3a02342346f13596300aec46466399d",
        );
        assert_eq!(
            encode_ecdsa_p256_signature_der(&raw_signature).unwrap(),
            signature
        );
        assert!(verify_ecdsa_p256_sha256(b"ecdsa", &raw_signature, &public_key).unwrap());

        let mut bad = signature;
        bad[10] ^= 1;
        assert!(!verify_ecdsa_p256_sha256(b"ecdsa", &bad, &public_key).unwrap());
    }

    #[test]
    fn ecdsa_p256_signs_with_fixed_nonce_helper_surface_and_verifies() {
        let private_key = hex("0000000000000000000000000000000000000000000000000000000000000001");
        let nonce = hex("0000000000000000000000000000000000000000000000000000000000000002");
        let public_key = p256_public_key_from_private(&private_key).unwrap();
        assert_eq!(
            public_key,
            hex(
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
                 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
            )
        );

        let signature =
            sign_ecdsa_p256_sha256_with_nonce(b"ecdsa-sign", &private_key, &nonce).unwrap();
        assert!(verify_ecdsa_p256_sha256(b"ecdsa-sign", &signature, &public_key).unwrap());
        assert_eq!(
            encode_ecdsa_p256_signature_der(&signature).unwrap()[0],
            0x30
        );
    }

    fn hex(input: &str) -> Vec<u8> {
        input
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>()
            .chunks_exact(2)
            .map(|pair| (hex_value(pair[0]) << 4) | hex_value(pair[1]))
            .collect()
    }

    fn hex_value(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex"),
        }
    }
}
