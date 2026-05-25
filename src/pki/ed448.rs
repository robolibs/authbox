//! Ed448 helpers.
//!
//! Keep the authbox-facing API in the mirrored PKI hierarchy, but delegate the
//! Ed448 implementation to the Rust ecosystem instead of carrying local
//! Edwards/Goldilocks arithmetic in this port.

use super::{PkiError, PkiResult};

pub fn verify_ed448_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PkiResult<bool> {
    if public_key.len() != 57 {
        return Err(PkiError::new("Invalid Ed448 public key size"));
    }
    if signature.len() != 114 {
        return Ok(false);
    }

    let public_key: [u8; 57] = public_key.try_into().expect("length checked");
    let Ok(verifying_key) = ed448_goldilocks_plus::VerifyingKey::from_bytes(&public_key) else {
        return Ok(false);
    };
    let signature: [u8; 114] = signature.try_into().expect("length checked");
    let Ok(signature) = ed448_goldilocks_plus::Signature::from_bytes(&signature) else {
        return Ok(false);
    };
    Ok(verifying_key.verify_raw(&signature, message).is_ok())
}

pub fn sign_ed448_detached(message: &[u8], private_key: &[u8]) -> PkiResult<Vec<u8>> {
    let seed = ed448_seed(private_key)?;
    let signing_key = ed448_goldilocks_plus::SigningKey::try_from(seed)
        .map_err(|_| PkiError::new("Invalid Ed448 private key size"))?;
    Ok(signing_key.sign_raw(message).to_bytes().to_vec())
}

pub fn ed448_public_key_from_seed(seed: &[u8]) -> PkiResult<Vec<u8>> {
    if seed.len() != 57 {
        return Err(PkiError::new("Invalid Ed448 seed size"));
    }
    let signing_key = ed448_goldilocks_plus::SigningKey::try_from(seed)
        .map_err(|_| PkiError::new("Invalid Ed448 seed size"))?;
    Ok(signing_key.verifying_key().to_bytes().to_vec())
}

fn ed448_seed(private_key: &[u8]) -> PkiResult<&[u8]> {
    match private_key.len() {
        57 => Ok(private_key),
        114 => {
            let seed = &private_key[..57];
            let public_key = ed448_public_key_from_seed(seed)?;
            if public_key.as_slice() != &private_key[57..] {
                return Err(PkiError::new("Ed448 private key public half mismatch"));
            }
            Ok(seed)
        }
        _ => Err(PkiError::new("Invalid Ed448 private key size")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed448_signs_and_verifies_with_ecosystem_crate() {
        let seed = [0x42u8; 57];
        let public_key = ed448_public_key_from_seed(&seed).unwrap();
        let mut private_key = seed.to_vec();
        private_key.extend(&public_key);

        let signature = sign_ed448_detached(b"ed448-message", &private_key).unwrap();
        assert_eq!(signature.len(), 114);
        assert!(verify_ed448_signature(b"ed448-message", &signature, &public_key).unwrap());

        let mut tampered = signature;
        tampered[0] ^= 1;
        assert!(!verify_ed448_signature(b"ed448-message", &tampered, &public_key).unwrap());
    }
}
