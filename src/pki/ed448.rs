//! Ed448 helpers — thin delegations into the sibling `keylock` crate.

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
    Ok(keylock::crypto::ed448::verify_detached(
        message, signature, public_key,
    ))
}

pub fn sign_ed448_detached(message: &[u8], private_key: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ed448::sign_detached(message, private_key).map_err(PkiError::new)
}

pub fn ed448_public_key_from_seed(seed: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ed448::public_key_from_seed(seed).map_err(PkiError::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed448_signs_and_verifies_with_keylock_delegation() {
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
