//! RSA helpers used by the PKI signing paths.

use super::{
    KeyPair, PkiError, PkiResult, RsaPublicKey, SignatureAlgorithmId, parse_integer,
    parse_rsa_public_key, parse_sequence, rsa_public_key_blob,
};
use ::rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use ::rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use ::rsa::signature::{RandomizedSigner, SignatureEncoding};
use ::rsa::traits::{PrivateKeyParts, PublicKeyParts};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RsaPrivateKey {
    pub modulus: Vec<u8>,
    pub public_exponent: Vec<u8>,
    pub private_exponent: Vec<u8>,
    pub primes: Vec<Vec<u8>>,
}

pub fn parse_rsa_private_key(der: &[u8]) -> PkiResult<RsaPrivateKey> {
    parse_rsa_private_key_der(der).or_else(|_| parse_rsa_private_key_blob(der))
}

pub fn parse_rsa_private_key_der(der: &[u8]) -> PkiResult<RsaPrivateKey> {
    if let Ok(key) = ::rsa::RsaPrivateKey::from_pkcs1_der(der) {
        return Ok(private_key_from_ecosystem_key(&key));
    }
    parse_rsa_private_key_der_lenient(der)
}

fn parse_rsa_private_key_der_lenient(der: &[u8]) -> PkiResult<RsaPrivateKey> {
    let seq = parse_sequence(der)?;
    let mut offset = 0usize;

    let version = parse_integer_at(&seq.value, &mut offset)?;
    if strip_integer_padding(version).iter().any(|byte| *byte != 0) {
        return Err(PkiError::new("unsupported RSA private key version"));
    }

    let modulus = strip_integer_padding(parse_integer_at(&seq.value, &mut offset)?);
    let public_exponent = strip_integer_padding(parse_integer_at(&seq.value, &mut offset)?);
    let private_exponent = strip_integer_padding(parse_integer_at(&seq.value, &mut offset)?);
    let mut primes = Vec::new();
    if offset < seq.value.len() {
        let prime = strip_integer_padding(parse_integer_at(&seq.value, &mut offset)?);
        if prime.iter().any(|byte| *byte != 0) {
            primes.push(prime);
        }
    }
    if offset < seq.value.len() {
        let prime = strip_integer_padding(parse_integer_at(&seq.value, &mut offset)?);
        if prime.iter().any(|byte| *byte != 0) {
            primes.push(prime);
        }
    }
    validate_rsa_private_numbers(modulus, public_exponent, private_exponent, primes)
}

pub fn parse_rsa_private_key_blob(blob: &[u8]) -> PkiResult<RsaPrivateKey> {
    let mut offset = 0usize;
    let modulus = read_len_prefixed(blob, &mut offset, "modulus")?;
    let public_exponent = read_len_prefixed(blob, &mut offset, "public exponent")?;
    let private_exponent = read_len_prefixed(blob, &mut offset, "private exponent")?;
    let mut primes = Vec::new();
    if offset < blob.len() {
        primes.push(read_len_prefixed(blob, &mut offset, "prime1")?);
    }
    if offset < blob.len() {
        primes.push(read_len_prefixed(blob, &mut offset, "prime2")?);
    }
    // keylock's CRT-extended blob layout appends `dp || dq || qinv`. Skip
    // those length-prefixed fields if present so blobs produced by keylock
    // round-trip through the authbox parser.
    while offset < blob.len() {
        read_len_prefixed(blob, &mut offset, "crt parameter")?;
    }
    validate_rsa_private_numbers(
        strip_integer_padding(modulus),
        strip_integer_padding(public_exponent),
        strip_integer_padding(private_exponent),
        primes.into_iter().map(strip_integer_padding).collect(),
    )
}

pub fn rsa_private_key_blob(
    modulus: &[u8],
    public_exponent: &[u8],
    private_exponent: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    write_len_prefixed(&mut out, modulus);
    write_len_prefixed(&mut out, public_exponent);
    write_len_prefixed(&mut out, private_exponent);
    out
}

pub fn rsa_private_key_blob_with_primes(
    modulus: &[u8],
    public_exponent: &[u8],
    private_exponent: &[u8],
    primes: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = rsa_private_key_blob(modulus, public_exponent, private_exponent);
    for prime in primes.iter().take(2) {
        write_len_prefixed(&mut out, prime);
    }
    out
}

pub fn rsa_public_key_spki_der(public_key: &[u8]) -> PkiResult<Vec<u8>> {
    let key = parse_rsa_public_key(public_key)?;
    let key = ecosystem_public_key(&key.modulus, &key.exponent)?;
    key.to_public_key_der()
        .map(|doc| doc.as_ref().to_vec())
        .map_err(|err| PkiError::new(format!("failed to encode RSA SPKI public key: {err}")))
}

pub fn rsa_public_key_from_spki_der(der: &[u8]) -> PkiResult<Vec<u8>> {
    let key = ::rsa::RsaPublicKey::from_public_key_der(der)
        .map_err(|err| PkiError::new(format!("failed to decode RSA SPKI public key: {err}")))?;
    Ok(rsa_public_key_blob(
        &key.n().to_bytes_be(),
        &key.e().to_bytes_be(),
    ))
}

pub fn rsa_private_key_pkcs8_der(private_key: &[u8]) -> PkiResult<Vec<u8>> {
    let key = parse_rsa_private_key(private_key)?;
    let key = ecosystem_private_key(&key)?;
    key.to_pkcs8_der()
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|err| PkiError::new(format!("failed to encode RSA PKCS#8 private key: {err}")))
}

pub fn rsa_private_key_pkcs1_der(private_key: &[u8]) -> PkiResult<Vec<u8>> {
    let key = parse_rsa_private_key(private_key)?;
    let key = ecosystem_private_key(&key)?;
    key.to_pkcs1_der()
        .map(|doc| doc.as_bytes().to_vec())
        .map_err(|err| PkiError::new(format!("failed to encode RSA PKCS#1 private key: {err}")))
}

pub fn rsa_private_key_from_pkcs1_der(der: &[u8]) -> PkiResult<Vec<u8>> {
    let key = ::rsa::RsaPrivateKey::from_pkcs1_der(der)
        .map_err(|err| PkiError::new(format!("failed to decode RSA PKCS#1 private key: {err}")))?;
    Ok(private_key_blob_from_ecosystem_key(&key))
}

pub fn rsa_private_key_from_pkcs8_der(der: &[u8]) -> PkiResult<Vec<u8>> {
    let key = ::rsa::RsaPrivateKey::from_pkcs8_der(der)
        .map_err(|err| PkiError::new(format!("failed to decode RSA PKCS#8 private key: {err}")))?;
    Ok(private_key_blob_from_ecosystem_key(&key))
}

fn private_key_from_ecosystem_key(key: &::rsa::RsaPrivateKey) -> RsaPrivateKey {
    let primes = key
        .primes()
        .iter()
        .map(|prime| prime.to_bytes_be())
        .collect::<Vec<_>>();
    RsaPrivateKey {
        modulus: key.n().to_bytes_be(),
        public_exponent: key.e().to_bytes_be(),
        private_exponent: key.d().to_bytes_be(),
        primes,
    }
}

fn private_key_blob_from_ecosystem_key(key: &::rsa::RsaPrivateKey) -> Vec<u8> {
    let key = private_key_from_ecosystem_key(key);
    rsa_private_key_blob_with_primes(
        &key.modulus,
        &key.public_exponent,
        &key.private_exponent,
        &key.primes,
    )
}

pub fn sign_rsa_pkcs1v15_keypair(
    algorithm: SignatureAlgorithmId,
    message: &[u8],
    key: &KeyPair,
) -> PkiResult<Vec<u8>> {
    let private_key = match parse_rsa_private_key(&key.private_key) {
        Ok(private_key) => private_key,
        Err(parse_error) => private_key_from_split_keypair(key, parse_error)?,
    };
    sign_rsa_pkcs1v15(algorithm, message, &private_key)
}

pub fn sign_rsa_pss_keypair(
    algorithm: SignatureAlgorithmId,
    message: &[u8],
    key: &KeyPair,
) -> PkiResult<Vec<u8>> {
    let private_key = match parse_rsa_private_key(&key.private_key) {
        Ok(private_key) => private_key,
        Err(parse_error) => private_key_from_split_keypair(key, parse_error)?,
    };
    sign_rsa_pss(algorithm, message, &private_key)
}

pub fn sign_rsa_pkcs1v15(
    algorithm: SignatureAlgorithmId,
    message: &[u8],
    private_key: &RsaPrivateKey,
) -> PkiResult<Vec<u8>> {
    let key = ecosystem_private_key(private_key)?;
    let mut rng = rand::rngs::OsRng;
    match algorithm {
        SignatureAlgorithmId::RsaPkcs1Sha256 => {
            let signing_key = ::rsa::pkcs1v15::SigningKey::<::rsa::sha2::Sha256>::new(key);
            Ok(signing_key.sign_with_rng(&mut rng, message).to_vec())
        }
        SignatureAlgorithmId::RsaPkcs1Sha384 => {
            let signing_key = ::rsa::pkcs1v15::SigningKey::<::rsa::sha2::Sha384>::new(key);
            Ok(signing_key.sign_with_rng(&mut rng, message).to_vec())
        }
        SignatureAlgorithmId::RsaPkcs1Sha512 => {
            let signing_key = ::rsa::pkcs1v15::SigningKey::<::rsa::sha2::Sha512>::new(key);
            Ok(signing_key.sign_with_rng(&mut rng, message).to_vec())
        }
        _ => Err(PkiError::new("Unsupported RSA PKCS#1 signing algorithm")),
    }
}

pub fn sign_rsa_pss(
    algorithm: SignatureAlgorithmId,
    message: &[u8],
    private_key: &RsaPrivateKey,
) -> PkiResult<Vec<u8>> {
    let key = ecosystem_private_key(private_key)?;
    let mut rng = rand::rngs::OsRng;
    match algorithm {
        SignatureAlgorithmId::RsaPssSha256 => {
            let signing_key = ::rsa::pss::BlindedSigningKey::<::rsa::sha2::Sha256>::new(key);
            Ok(signing_key.sign_with_rng(&mut rng, message).to_vec())
        }
        SignatureAlgorithmId::RsaPssSha384 => {
            let signing_key = ::rsa::pss::BlindedSigningKey::<::rsa::sha2::Sha384>::new(key);
            Ok(signing_key.sign_with_rng(&mut rng, message).to_vec())
        }
        SignatureAlgorithmId::RsaPssSha512 => {
            let signing_key = ::rsa::pss::BlindedSigningKey::<::rsa::sha2::Sha512>::new(key);
            Ok(signing_key.sign_with_rng(&mut rng, message).to_vec())
        }
        _ => Err(PkiError::new("Unsupported RSA-PSS signing algorithm")),
    }
}

fn private_key_from_split_keypair(
    key: &KeyPair,
    parse_error: PkiError,
) -> PkiResult<RsaPrivateKey> {
    let RsaPublicKey { modulus, exponent } = parse_rsa_public_key(&key.public_key)
        .map_err(|_| PkiError::new(format!("failed to parse RSA private key: {parse_error}")))?;
    let private_exponent = strip_integer_padding(key.private_key.clone());
    validate_rsa_private_numbers(modulus, exponent, private_exponent, Vec::new())
}

fn parse_integer_at(input: &[u8], offset: &mut usize) -> PkiResult<Vec<u8>> {
    let parsed = parse_integer(&input[*offset..])?;
    *offset += parsed.bytes_consumed;
    Ok(parsed.value)
}

fn validate_rsa_private_numbers(
    modulus: Vec<u8>,
    public_exponent: Vec<u8>,
    private_exponent: Vec<u8>,
    primes: Vec<Vec<u8>>,
) -> PkiResult<RsaPrivateKey> {
    if modulus.is_empty() || public_exponent.is_empty() || private_exponent.is_empty() {
        return Err(PkiError::new("RSA private key contains an empty integer"));
    }
    if modulus.iter().all(|byte| *byte == 0)
        || public_exponent.iter().all(|byte| *byte == 0)
        || private_exponent.iter().all(|byte| *byte == 0)
    {
        return Err(PkiError::new("RSA private key contains zero value"));
    }
    Ok(RsaPrivateKey {
        modulus,
        public_exponent,
        private_exponent,
        primes,
    })
}

pub(crate) fn ecosystem_public_key(
    modulus: &[u8],
    public_exponent: &[u8],
) -> PkiResult<::rsa::RsaPublicKey> {
    ::rsa::RsaPublicKey::new(
        ::rsa::BigUint::from_bytes_be(modulus),
        ::rsa::BigUint::from_bytes_be(public_exponent),
    )
    .map_err(|err| PkiError::new(format!("invalid RSA public key: {err}")))
}

pub(crate) fn ecosystem_private_key(key: &RsaPrivateKey) -> PkiResult<::rsa::RsaPrivateKey> {
    ::rsa::RsaPrivateKey::from_components(
        ::rsa::BigUint::from_bytes_be(&key.modulus),
        ::rsa::BigUint::from_bytes_be(&key.public_exponent),
        ::rsa::BigUint::from_bytes_be(&key.private_exponent),
        key.primes
            .iter()
            .map(|prime| ::rsa::BigUint::from_bytes_be(prime))
            .collect(),
    )
    .map_err(|err| PkiError::new(format!("invalid RSA private key: {err}")))
}

fn read_len_prefixed(input: &[u8], offset: &mut usize, label: &str) -> PkiResult<Vec<u8>> {
    if *offset + 4 > input.len() {
        return Err(PkiError::new(format!("truncated RSA private key {label}")));
    }
    let len = u32::from_be_bytes([
        input[*offset],
        input[*offset + 1],
        input[*offset + 2],
        input[*offset + 3],
    ]) as usize;
    *offset += 4;
    if len == 0 || *offset + len > input.len() {
        return Err(PkiError::new(format!(
            "Invalid RSA private key {label} length"
        )));
    }
    let value = input[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(value)
}

fn write_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend((value.len() as u32).to_be_bytes());
    out.extend(value);
}

fn strip_integer_padding(mut value: Vec<u8>) -> Vec<u8> {
    while value.len() > 1 && value.first() == Some(&0) {
        value.remove(0);
    }
    value
}
