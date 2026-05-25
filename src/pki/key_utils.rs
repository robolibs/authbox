use super::{
    AlgorithmIdentifier, CurveId, HashAlgorithm, PkiError, PkiResult, SignatureAlgorithmId,
    SubjectPublicKeyInfo, der, encode_certificate_subject_public_key_info,
    p256_public_key_from_private, p384_public_key_from_private, p521_public_key_from_private,
    parse_rsa_public_key, rsa_public_key_blob,
};
use ::sec1::{
    EcParameters, EcPrivateKey,
    der::{Encode as _, asn1::ObjectIdentifier},
};

const P256_NAMED_CURVE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const P384_NAMED_CURVE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const P521_NAMED_CURVE_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// `KeyPair` is re-exported from [`keylock::crypto::KeyPair`] — all keygen lives
/// in the sibling `keylock` crate. authbox keeps only PKI-specific glue here.
pub use keylock::crypto::KeyPair;

fn to_pki(result: Result<KeyPair, String>) -> PkiResult<KeyPair> {
    result.map_err(PkiError::new)
}

pub fn generate_ed25519_keypair() -> PkiResult<KeyPair> {
    to_pki(keylock::generate_ed25519_keypair())
}

pub fn generate_ed448_keypair() -> PkiResult<KeyPair> {
    to_pki(keylock::generate_ed448_keypair())
}

pub fn generate_ecdsa_p256_keypair() -> PkiResult<KeyPair> {
    to_pki(keylock::generate_ecdsa_p256_keypair())
}

pub fn generate_ecdsa_p384_keypair() -> PkiResult<KeyPair> {
    to_pki(keylock::generate_ecdsa_p384_keypair())
}

pub fn generate_ecdsa_p521_keypair() -> PkiResult<KeyPair> {
    to_pki(keylock::generate_ecdsa_p521_keypair())
}

pub fn generate_rsa_keypair(bits: usize) -> PkiResult<KeyPair> {
    if bits < 1024 {
        return Err(PkiError::new("RSA key size must be at least 1024 bits"));
    }
    to_pki(keylock::generate_rsa_keypair_with_bits(bits))
}

pub fn generate_rsa_2048_keypair() -> PkiResult<KeyPair> {
    to_pki(keylock::generate_rsa_keypair_with_bits(2048))
}

pub fn ed25519_subject_public_key_info(public_key: impl Into<Vec<u8>>) -> SubjectPublicKeyInfo {
    SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            signature: SignatureAlgorithmId::Ed25519,
            hash: HashAlgorithm::Sha256,
            curve: CurveId::Ed25519,
        },
        public_key: public_key.into(),
        unused_bits: 0,
    }
}

pub fn ed448_subject_public_key_info(public_key: impl Into<Vec<u8>>) -> SubjectPublicKeyInfo {
    SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            signature: SignatureAlgorithmId::Ed448,
            hash: HashAlgorithm::Sha512,
            curve: CurveId::Ed448,
        },
        public_key: public_key.into(),
        unused_bits: 0,
    }
}

pub fn ecdsa_p256_subject_public_key_info(public_key: impl Into<Vec<u8>>) -> SubjectPublicKeyInfo {
    ecdsa_subject_public_key_info(
        public_key,
        SignatureAlgorithmId::EcdsaSha256,
        HashAlgorithm::Sha256,
        CurveId::Secp256r1,
    )
}

pub fn ecdsa_p384_subject_public_key_info(public_key: impl Into<Vec<u8>>) -> SubjectPublicKeyInfo {
    ecdsa_subject_public_key_info(
        public_key,
        SignatureAlgorithmId::EcdsaSha384,
        HashAlgorithm::Sha384,
        CurveId::Secp384r1,
    )
}

pub fn ecdsa_p521_subject_public_key_info(public_key: impl Into<Vec<u8>>) -> SubjectPublicKeyInfo {
    ecdsa_subject_public_key_info(
        public_key,
        SignatureAlgorithmId::EcdsaSha512,
        HashAlgorithm::Sha512,
        CurveId::Secp521r1,
    )
}

pub fn rsa_subject_public_key_info(public_key: impl Into<Vec<u8>>) -> SubjectPublicKeyInfo {
    rsa_subject_public_key_info_with_options(public_key, HashAlgorithm::Sha256, false)
}

pub fn rsa_subject_public_key_info_with_options(
    public_key: impl Into<Vec<u8>>,
    hash: HashAlgorithm,
    pss: bool,
) -> SubjectPublicKeyInfo {
    SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            signature: rsa_signature_algorithm_for_hash(hash, pss),
            hash,
            curve: CurveId::Unknown,
        },
        public_key: public_key.into(),
        unused_bits: 0,
    }
}

fn ecdsa_subject_public_key_info(
    public_key: impl Into<Vec<u8>>,
    signature: SignatureAlgorithmId,
    hash: HashAlgorithm,
    curve: CurveId,
) -> SubjectPublicKeyInfo {
    SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            signature,
            hash,
            curve,
        },
        public_key: public_key.into(),
        unused_bits: 0,
    }
}

pub fn spki_from_ed25519_public(public_key: &[u8]) -> PkiResult<Vec<u8>> {
    encode_certificate_subject_public_key_info(&ed25519_subject_public_key_info(
        public_key.to_vec(),
    ))
}

pub fn spki_from_ed448_public(public_key: &[u8]) -> PkiResult<Vec<u8>> {
    encode_certificate_subject_public_key_info(&ed448_subject_public_key_info(public_key.to_vec()))
}

pub fn spki_from_ecdsa_p256_public(public_key: &[u8]) -> PkiResult<Vec<u8>> {
    encode_certificate_subject_public_key_info(&ecdsa_p256_subject_public_key_info(
        normalize_ec_public_key(public_key, 32, "P-256")?.to_vec(),
    ))
}

pub fn spki_from_ecdsa_p384_public(public_key: &[u8]) -> PkiResult<Vec<u8>> {
    encode_certificate_subject_public_key_info(&ecdsa_p384_subject_public_key_info(
        normalize_ec_public_key(public_key, 48, "P-384")?.to_vec(),
    ))
}

pub fn spki_from_ecdsa_p521_public(public_key: &[u8]) -> PkiResult<Vec<u8>> {
    encode_certificate_subject_public_key_info(&ecdsa_p521_subject_public_key_info(
        normalize_ec_public_key(public_key, 66, "P-521")?.to_vec(),
    ))
}

pub fn spki_from_rsa_public(public_key: &[u8]) -> PkiResult<Vec<u8>> {
    spki_from_rsa_public_with_options(public_key, HashAlgorithm::Sha256, false)
}

pub fn spki_from_rsa_public_with_options(
    public_key: &[u8],
    hash: HashAlgorithm,
    pss: bool,
) -> PkiResult<Vec<u8>> {
    encode_certificate_subject_public_key_info(&rsa_subject_public_key_info_with_options(
        normalize_rsa_public_key(public_key)?,
        hash,
        pss,
    ))
}

pub fn raw_ed25519_public_key_from_spki(spki_der: &[u8]) -> PkiResult<Vec<u8>> {
    let spki = super::parse_subject_public_key_info(spki_der)?;
    if spki.value.algorithm.signature != SignatureAlgorithmId::Ed25519 {
        return Err(PkiError::new("SPKI does not contain an Ed25519 key"));
    }
    if spki.value.public_key.len() != 32 {
        return Err(PkiError::new("Ed25519 SPKI public key length is invalid"));
    }
    Ok(spki.value.public_key)
}

pub fn raw_ed448_public_key_from_spki(spki_der: &[u8]) -> PkiResult<Vec<u8>> {
    let spki = super::parse_subject_public_key_info(spki_der)?;
    if spki.value.algorithm.signature != SignatureAlgorithmId::Ed448 {
        return Err(PkiError::new("SPKI does not contain an Ed448 key"));
    }
    if spki.value.public_key.len() != 57 {
        return Err(PkiError::new("Ed448 SPKI public key length is invalid"));
    }
    Ok(spki.value.public_key)
}

pub fn raw_ecdsa_p256_public_key_from_spki(spki_der: &[u8]) -> PkiResult<Vec<u8>> {
    raw_ecdsa_public_key_from_spki(spki_der, SignatureAlgorithmId::EcdsaSha256, 32, "P-256")
}

pub fn sec1_from_ecdsa_p256_private(private_key: &[u8]) -> PkiResult<Vec<u8>> {
    encode_sec1_ec_private_key(
        private_key,
        32,
        "P-256",
        P256_NAMED_CURVE_OID,
        p256_public_key_from_private,
    )
}

pub fn raw_ecdsa_p256_private_key_from_sec1(sec1_der: &[u8]) -> PkiResult<Vec<u8>> {
    decode_sec1_ec_private_key(
        sec1_der,
        32,
        "P-256",
        P256_NAMED_CURVE_OID,
        p256_public_key_from_private,
    )
}

pub fn sec1_from_ecdsa_p384_private(private_key: &[u8]) -> PkiResult<Vec<u8>> {
    encode_sec1_ec_private_key(
        private_key,
        48,
        "P-384",
        P384_NAMED_CURVE_OID,
        p384_public_key_from_private,
    )
}

pub fn raw_ecdsa_p384_private_key_from_sec1(sec1_der: &[u8]) -> PkiResult<Vec<u8>> {
    decode_sec1_ec_private_key(
        sec1_der,
        48,
        "P-384",
        P384_NAMED_CURVE_OID,
        p384_public_key_from_private,
    )
}

pub fn sec1_from_ecdsa_p521_private(private_key: &[u8]) -> PkiResult<Vec<u8>> {
    encode_sec1_ec_private_key(
        private_key,
        66,
        "P-521",
        P521_NAMED_CURVE_OID,
        p521_public_key_from_private,
    )
}

pub fn raw_ecdsa_p521_private_key_from_sec1(sec1_der: &[u8]) -> PkiResult<Vec<u8>> {
    decode_sec1_ec_private_key(
        sec1_der,
        66,
        "P-521",
        P521_NAMED_CURVE_OID,
        p521_public_key_from_private,
    )
}

fn encode_sec1_ec_private_key(
    private_key: &[u8],
    coordinate_len: usize,
    curve: &str,
    named_curve_oid: ObjectIdentifier,
    derive_public_key: fn(&[u8]) -> PkiResult<Vec<u8>>,
) -> PkiResult<Vec<u8>> {
    let private_key = normalize_ec_private_key(private_key, coordinate_len, curve)?;
    let public_key = derive_public_key(&private_key)?;
    let mut uncompressed_public_key = Vec::with_capacity(public_key.len() + 1);
    uncompressed_public_key.push(0x04);
    uncompressed_public_key.extend(public_key);

    EcPrivateKey {
        private_key: &private_key,
        parameters: Some(EcParameters::NamedCurve(named_curve_oid)),
        public_key: Some(&uncompressed_public_key),
    }
    .to_der()
    .map_err(|err| {
        PkiError::new(format!(
            "failed to encode ECDSA {curve} SEC1 private key: {err}"
        ))
    })
}

fn decode_sec1_ec_private_key(
    sec1_der: &[u8],
    coordinate_len: usize,
    curve: &str,
    named_curve_oid: ObjectIdentifier,
    derive_public_key: fn(&[u8]) -> PkiResult<Vec<u8>>,
) -> PkiResult<Vec<u8>> {
    let key = EcPrivateKey::try_from(sec1_der).map_err(|err| {
        PkiError::new(format!(
            "failed to decode ECDSA {curve} SEC1 private key: {err}"
        ))
    })?;
    if let Some(EcParameters::NamedCurve(oid)) = key.parameters
        && oid != named_curve_oid
    {
        return Err(PkiError::new(format!("SEC1 private key is not {curve}")));
    }

    let private_key = normalize_ec_private_key(key.private_key, coordinate_len, curve)?;
    let expected_public_key = derive_public_key(&private_key)?;
    if let Some(public_key) = key.public_key {
        let public_key = normalize_ec_public_key(public_key, coordinate_len, curve)?;
        if public_key != expected_public_key {
            return Err(PkiError::new("SEC1 public key does not match private key"));
        }
    }
    Ok(private_key)
}

pub fn raw_ecdsa_p384_public_key_from_spki(spki_der: &[u8]) -> PkiResult<Vec<u8>> {
    raw_ecdsa_public_key_from_spki(spki_der, SignatureAlgorithmId::EcdsaSha384, 48, "P-384")
}

pub fn raw_ecdsa_p521_public_key_from_spki(spki_der: &[u8]) -> PkiResult<Vec<u8>> {
    raw_ecdsa_public_key_from_spki(spki_der, SignatureAlgorithmId::EcdsaSha512, 66, "P-521")
}

pub fn raw_rsa_public_key_from_spki(spki_der: &[u8]) -> PkiResult<Vec<u8>> {
    let spki = super::parse_subject_public_key_info(spki_der)?;
    if !is_rsa_signature_algorithm(spki.value.algorithm.signature) {
        return Err(PkiError::new("SPKI does not contain an RSA key"));
    }
    normalize_rsa_public_key(&spki.value.public_key)
}

pub fn encode_private_key_octets(private_key: &[u8]) -> Vec<u8> {
    der::encode_octet_string(private_key)
}

pub fn encrypt_pkcs8_private_key_der(pkcs8_der: &[u8], password: &[u8]) -> PkiResult<Vec<u8>> {
    let private_key_info = pkcs8::PrivateKeyInfo::try_from(pkcs8_der).map_err(|err| {
        PkiError::new(format!(
            "failed to parse PKCS#8 private key for encryption: {err}"
        ))
    })?;
    let mut rng = rand::rngs::OsRng;
    private_key_info
        .encrypt(&mut rng, password)
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|err| PkiError::new(format!("failed to encrypt PKCS#8 private key: {err}")))
}

pub fn decrypt_pkcs8_private_key_der(encrypted_der: &[u8], password: &[u8]) -> PkiResult<Vec<u8>> {
    let encrypted = pkcs8::EncryptedPrivateKeyInfo::try_from(encrypted_der).map_err(|err| {
        PkiError::new(format!(
            "failed to parse encrypted PKCS#8 private key: {err}"
        ))
    })?;
    encrypted
        .decrypt(password)
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|err| PkiError::new(format!("failed to decrypt PKCS#8 private key: {err}")))
}

pub fn encrypt_pkcs8_private_key_pem(pkcs8_der: &[u8], password: &[u8]) -> PkiResult<String> {
    let encrypted_der = encrypt_pkcs8_private_key_der(pkcs8_der, password)?;
    Ok(super::pem::pem_encode_encrypted_private_key(&encrypted_der))
}

pub fn decrypt_pkcs8_private_key_pem(pem: &str, password: &[u8]) -> PkiResult<Vec<u8>> {
    let block = super::pem::pem_decode_encrypted_private_key_block(pem)?;
    decrypt_pkcs8_private_key_der(&block.data, password)
}

fn raw_ecdsa_public_key_from_spki(
    spki_der: &[u8],
    signature: SignatureAlgorithmId,
    coordinate_len: usize,
    curve: &str,
) -> PkiResult<Vec<u8>> {
    let spki = super::parse_subject_public_key_info(spki_der)?;
    if spki.value.algorithm.signature != signature {
        return Err(PkiError::new(format!(
            "SPKI does not contain an ECDSA {curve} key"
        )));
    }
    normalize_ec_public_key(&spki.value.public_key, coordinate_len, curve).map(Vec::from)
}

fn normalize_rsa_public_key(public_key: &[u8]) -> PkiResult<Vec<u8>> {
    let key = parse_rsa_public_key(public_key)?;
    Ok(rsa_public_key_blob(&key.modulus, &key.exponent))
}

fn rsa_signature_algorithm_for_hash(hash: HashAlgorithm, pss: bool) -> SignatureAlgorithmId {
    match (hash, pss) {
        (HashAlgorithm::Sha512, true) => SignatureAlgorithmId::RsaPssSha512,
        (HashAlgorithm::Sha384, true) => SignatureAlgorithmId::RsaPssSha384,
        (_, true) => SignatureAlgorithmId::RsaPssSha256,
        (HashAlgorithm::Sha512, false) => SignatureAlgorithmId::RsaPkcs1Sha512,
        (HashAlgorithm::Sha384, false) => SignatureAlgorithmId::RsaPkcs1Sha384,
        (_, false) => SignatureAlgorithmId::RsaPkcs1Sha256,
    }
}

fn is_rsa_signature_algorithm(signature: SignatureAlgorithmId) -> bool {
    matches!(
        signature,
        SignatureAlgorithmId::RsaPkcs1Sha256
            | SignatureAlgorithmId::RsaPkcs1Sha384
            | SignatureAlgorithmId::RsaPkcs1Sha512
            | SignatureAlgorithmId::RsaPssSha256
            | SignatureAlgorithmId::RsaPssSha384
            | SignatureAlgorithmId::RsaPssSha512
    )
}

fn normalize_ec_public_key<'a>(
    public_key: &'a [u8],
    coordinate_len: usize,
    curve: &str,
) -> PkiResult<&'a [u8]> {
    let raw_len = coordinate_len * 2;
    let uncompressed_len = raw_len + 1;
    if public_key.len() == raw_len {
        Ok(public_key)
    } else if public_key.len() == uncompressed_len && public_key[0] == 0x04 {
        Ok(&public_key[1..])
    } else {
        Err(PkiError::new(format!(
            "ECDSA {curve} public key length is invalid"
        )))
    }
}

fn normalize_ec_private_key(
    private_key: &[u8],
    coordinate_len: usize,
    curve: &str,
) -> PkiResult<Vec<u8>> {
    if private_key.is_empty() || private_key.len() > coordinate_len {
        return Err(PkiError::new(format!(
            "ECDSA {curve} private key length is invalid"
        )));
    }
    let mut out = vec![0u8; coordinate_len];
    let offset = coordinate_len - private_key.len();
    out[offset..].copy_from_slice(private_key);
    Ok(out)
}
