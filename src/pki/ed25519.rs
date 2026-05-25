//! Ed25519 helpers — thin delegations into the sibling `keylock` crate.
//!
//! authbox owns PKI/X.509 framing; all crypto primitives live in keylock.

use super::{PkiError, PkiResult};

pub fn verify_ed25519_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PkiResult<bool> {
    if public_key.len() != 32 {
        return Err(PkiError::new("Invalid Ed25519 public key size"));
    }
    if signature.len() != 64 {
        return Ok(false);
    }
    Ok(keylock::crypto::ed25519::verify_detached(
        signature, message, public_key,
    ))
}

pub fn sign_ed25519_detached(message: &[u8], private_key: &[u8]) -> PkiResult<Vec<u8>> {
    keylock::crypto::ed25519::sign_detached(message, private_key).map_err(PkiError::new)
}

pub fn ed25519_public_key_from_seed(seed: &[u8]) -> PkiResult<Vec<u8>> {
    let (public_key, _) =
        keylock::crypto::ed25519::keypair_from_seed(seed).map_err(PkiError::new)?;
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_verifies_rfc8032_empty_message_vector() {
        let private_key = hex64(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60\
             d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        );
        let public_key = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = hex64(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );

        assert!(verify_ed25519_signature(b"", &signature, &public_key).unwrap());
        assert_eq!(
            ed25519_public_key_from_seed(&private_key[..32]).unwrap(),
            public_key.to_vec()
        );
        assert_eq!(
            sign_ed25519_detached(b"", &private_key).unwrap(),
            signature.to_vec()
        );

        let mut tampered = signature;
        tampered[0] ^= 1;
        assert!(!verify_ed25519_signature(b"", &tampered, &public_key).unwrap());
    }

    fn hex32(input: &str) -> [u8; 32] {
        hex(input).try_into().unwrap()
    }

    fn hex64(input: &str) -> [u8; 64] {
        hex(input).try_into().unwrap()
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
