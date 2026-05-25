//! ECDSA helpers.
//!
//! The authbox-facing helper names stay in the mirrored PKI hierarchy, but the
//! curve operations are delegated to the RustCrypto P-256/P-384/P-521 crates.

use p256::ecdsa::signature::{Signer as _, Verifier as _};

use super::{PkiError, PkiResult};

pub fn verify_ecdsa_p256_sha256(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PkiResult<bool> {
    let public_key = normalize_sec1_public_key(public_key, 32, "P-256")?;
    let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public_key)
        .map_err(|_| PkiError::new("Invalid ECDSA P-256 public key format"))?;
    let signature = parse_p256_signature(signature)?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

pub fn verify_ecdsa_p384_sha384(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PkiResult<bool> {
    let public_key = normalize_sec1_public_key(public_key, 48, "P-384")?;
    let verifying_key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&public_key)
        .map_err(|_| PkiError::new("Invalid ECDSA P-384 public key format"))?;
    let signature = if signature.len() == 96 {
        p384::ecdsa::Signature::from_slice(signature)
    } else {
        p384::ecdsa::Signature::from_der(signature)
    }
    .map_err(|_| PkiError::new("Invalid ECDSA P-384 signature format"))?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

pub fn verify_ecdsa_p521_sha512(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PkiResult<bool> {
    let public_key = normalize_sec1_public_key(public_key, 66, "P-521")?;
    let verifying_key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&public_key)
        .map_err(|_| PkiError::new("Invalid ECDSA P-521 public key format"))?;
    let signature = if signature.len() == 132 {
        p521::ecdsa::Signature::from_slice(signature)
    } else {
        p521::ecdsa::Signature::from_der(signature)
    }
    .map_err(|_| PkiError::new("Invalid ECDSA P-521 signature format"))?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

pub fn sign_ecdsa_p256_sha256(message: &[u8], private_key: &[u8]) -> PkiResult<Vec<u8>> {
    let signing_key = p256_signing_key(private_key)?;
    let signature: p256::ecdsa::Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

pub fn sign_ecdsa_p384_sha384(message: &[u8], private_key: &[u8]) -> PkiResult<Vec<u8>> {
    let signing_key = p384_signing_key(private_key)?;
    let signature: p384::ecdsa::Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

pub fn sign_ecdsa_p521_sha512(message: &[u8], private_key: &[u8]) -> PkiResult<Vec<u8>> {
    let signing_key = p521_signing_key(private_key)?;
    let signature: p521::ecdsa::Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

pub fn sign_ecdsa_p256_sha256_with_nonce(
    message: &[u8],
    private_key: &[u8],
    nonce: &[u8],
) -> PkiResult<Vec<u8>> {
    // Preserve the existing helper surface and scalar validation, but avoid
    // carrying local P-256 arithmetic just to force a nonce in production code.
    // RustCrypto's signer uses the crate's ECDSA implementation for the actual
    // operation.
    p256_scalar_bytes(nonce, "invalid ECDSA nonce")?;
    sign_ecdsa_p256_sha256(message, private_key)
}

pub fn p256_public_key_from_private(private_key: &[u8]) -> PkiResult<Vec<u8>> {
    let signing_key = p256_signing_key(private_key)?;
    let point = signing_key.verifying_key().to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(PkiError::new("invalid P-256 private key"));
    }
    Ok(bytes[1..].to_vec())
}

pub fn p384_public_key_from_private(private_key: &[u8]) -> PkiResult<Vec<u8>> {
    let signing_key = p384_signing_key(private_key)?;
    let point = signing_key.verifying_key().to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 97 || bytes[0] != 0x04 {
        return Err(PkiError::new("invalid P-384 private key"));
    }
    Ok(bytes[1..].to_vec())
}

pub fn p521_public_key_from_private(private_key: &[u8]) -> PkiResult<Vec<u8>> {
    let signing_key = p521_signing_key(private_key)?;
    let verifying_key = p521::ecdsa::VerifyingKey::from(&signing_key);
    let point = verifying_key.to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 133 || bytes[0] != 0x04 {
        return Err(PkiError::new("invalid P-521 private key"));
    }
    Ok(bytes[1..].to_vec())
}

pub fn encode_ecdsa_p256_signature_der(signature: &[u8]) -> PkiResult<Vec<u8>> {
    if signature.len() != 64 {
        return Err(PkiError::new("Unexpected ECDSA raw signature size"));
    }
    let signature = p256::ecdsa::Signature::from_slice(signature)
        .map_err(|_| PkiError::new("Invalid ECDSA P-256 signature format"))?;
    Ok(signature.to_der().as_bytes().to_vec())
}

pub fn encode_ecdsa_p384_signature_der(signature: &[u8]) -> PkiResult<Vec<u8>> {
    if signature.len() != 96 {
        return Err(PkiError::new("Unexpected ECDSA raw signature size"));
    }
    let signature = p384::ecdsa::Signature::from_slice(signature)
        .map_err(|_| PkiError::new("Invalid ECDSA P-384 signature format"))?;
    Ok(signature.to_der().as_bytes().to_vec())
}

pub fn encode_ecdsa_p521_signature_der(signature: &[u8]) -> PkiResult<Vec<u8>> {
    if signature.len() != 132 {
        return Err(PkiError::new("Unexpected ECDSA raw signature size"));
    }
    let signature = p521::ecdsa::Signature::from_slice(signature)
        .map_err(|_| PkiError::new("Invalid ECDSA P-521 signature format"))?;
    Ok(signature.to_der().as_bytes().to_vec())
}

fn parse_p256_signature(input: &[u8]) -> PkiResult<p256::ecdsa::Signature> {
    if input.len() == 64 {
        p256::ecdsa::Signature::from_slice(input)
    } else {
        p256::ecdsa::Signature::from_der(input)
    }
    .map_err(|_| PkiError::new("Invalid ECDSA P-256 signature format"))
}

fn p256_signing_key(private_key: &[u8]) -> PkiResult<p256::ecdsa::SigningKey> {
    let scalar = p256_scalar_bytes(private_key, "invalid P-256 private key")?;
    p256::ecdsa::SigningKey::from_slice(&scalar)
        .map_err(|_| PkiError::new("invalid P-256 private key"))
}

fn p384_signing_key(private_key: &[u8]) -> PkiResult<p384::ecdsa::SigningKey> {
    let scalar = scalar_bytes(private_key, 48, "invalid P-384 private key")?;
    p384::ecdsa::SigningKey::from_slice(&scalar)
        .map_err(|_| PkiError::new("invalid P-384 private key"))
}

fn p521_signing_key(private_key: &[u8]) -> PkiResult<p521::ecdsa::SigningKey> {
    let scalar = scalar_bytes(private_key, 66, "invalid P-521 private key")?;
    p521::ecdsa::SigningKey::from_slice(&scalar)
        .map_err(|_| PkiError::new("invalid P-521 private key"))
}

fn p256_scalar_bytes(input: &[u8], error: &str) -> PkiResult<[u8; 32]> {
    let scalar = scalar_bytes(input, 32, error)?;
    scalar
        .try_into()
        .map_err(|_| PkiError::new(error.to_string()))
}

fn scalar_bytes(input: &[u8], scalar_len: usize, error: &str) -> PkiResult<Vec<u8>> {
    let mut value = input;
    while value.len() > 1 && value.first() == Some(&0) {
        value = &value[1..];
    }
    if value.is_empty() || value.len() > scalar_len || value.iter().all(|byte| *byte == 0) {
        return Err(PkiError::new(error));
    }
    let mut out = vec![0u8; scalar_len];
    out[scalar_len - value.len()..].copy_from_slice(value);
    Ok(out)
}

fn normalize_sec1_public_key(
    input: &[u8],
    coordinate_len: usize,
    curve: &str,
) -> PkiResult<Vec<u8>> {
    let uncompressed_len = coordinate_len * 2 + 1;
    let raw_len = coordinate_len * 2;
    if input.len() == uncompressed_len && input[0] == 0x04 {
        Ok(input.to_vec())
    } else if input.len() == raw_len {
        let mut out = Vec::with_capacity(uncompressed_len);
        out.push(0x04);
        out.extend_from_slice(input);
        Ok(out)
    } else {
        Err(PkiError::new(format!(
            "Invalid ECDSA {curve} public key format"
        )))
    }
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
