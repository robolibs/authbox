use super::{
    AlgorithmIdentifier, Asn1Class, Asn1Read, Asn1Tag, CertificateBoolResult, CertificateResult,
    CertificateSignatureResult, Cursor, DistinguishedName, KeyPair, Oid, PkiError, PkiResult,
    RawExtension, SignatureAlgorithmId, SubjectPublicKeyInfo, der, encode_ecdsa_p256_signature_der,
    encode_ecdsa_p384_signature_der, encode_ecdsa_p521_signature_der, find_extension_by_oid,
    oid_for_signature, parse_bit_string, parse_boolean, parse_id_len, parse_integer,
    parse_name_full, parse_octet_string, parse_oid, parse_sequence, parse_subject_public_key_info,
    read_pem_or_der, sign_ecdsa_p256_sha256, sign_ecdsa_p384_sha384, sign_ecdsa_p521_sha512,
    sign_ed448_detached, sign_ed25519_detached, sign_rsa_pkcs1v15_keypair, sign_rsa_pss_keypair,
    verify_signature_bytes,
};
use std::path::Path;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CertificationRequestInfo {
    pub version: i32,
    pub subject: DistinguishedName,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub extensions: Vec<RawExtension>,
    pub der: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CertificateRequest {
    pub info: CertificationRequestInfo,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
    pub der: Vec<u8>,
    pub cri_der: Vec<u8>,
}

impl CertificateRequest {
    pub fn from_der(der: impl AsRef<[u8]>) -> PkiResult<Self> {
        parse_csr(der.as_ref())
    }

    pub fn from_der_result(der: impl AsRef<[u8]>) -> CertificateResult<Self> {
        parse_csr_result(der.as_ref())
    }

    pub fn from_pem(pem: &str) -> PkiResult<Self> {
        let block = super::pem_decode_block_with_expected_label(pem, Some("CERTIFICATE REQUEST"))?;
        parse_csr(&block.data)
    }

    pub fn from_pem_result(pem: &str) -> CertificateResult<Self> {
        match Self::from_pem(pem) {
            Ok(csr) => CertificateResult::ok(csr),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn to_pem(&self) -> String {
        super::pem_encode(&self.der, "CERTIFICATE REQUEST")
    }

    pub fn verify_signature(&self) -> PkiResult<bool> {
        verify_signature_bytes(
            self.signature_algorithm.signature,
            &self.cri_der,
            &self.signature,
            &self.info.subject_public_key_info.public_key,
        )
    }

    pub fn verify_signature_result(&self) -> CertificateBoolResult {
        match self.verify_signature() {
            Ok(valid) => CertificateResult::ok(valid),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn sign(&self, key: &KeyPair) -> PkiResult<Vec<u8>> {
        let signature = match self.signature_algorithm.signature {
            SignatureAlgorithmId::Ed25519 => {
                sign_ed25519_detached(&self.cri_der, &key.private_key)?
            }
            SignatureAlgorithmId::Ed448 => sign_ed448_detached(&self.cri_der, &key.private_key)?,
            SignatureAlgorithmId::EcdsaSha256 => {
                sign_ecdsa_p256_sha256(&self.cri_der, &key.private_key)?
            }
            SignatureAlgorithmId::EcdsaSha384 => {
                sign_ecdsa_p384_sha384(&self.cri_der, &key.private_key)?
            }
            SignatureAlgorithmId::EcdsaSha512 => {
                sign_ecdsa_p521_sha512(&self.cri_der, &key.private_key)?
            }
            SignatureAlgorithmId::RsaPkcs1Sha256
            | SignatureAlgorithmId::RsaPkcs1Sha384
            | SignatureAlgorithmId::RsaPkcs1Sha512 => {
                sign_rsa_pkcs1v15_keypair(self.signature_algorithm.signature, &self.cri_der, key)?
            }
            SignatureAlgorithmId::RsaPssSha256
            | SignatureAlgorithmId::RsaPssSha384
            | SignatureAlgorithmId::RsaPssSha512 => {
                sign_rsa_pss_keypair(self.signature_algorithm.signature, &self.cri_der, key)?
            }
            _ => {
                return Err(PkiError::new("Unsupported CSR signature algorithm"));
            }
        };
        normalize_signature_for_emit(signature, self.signature_algorithm.signature)
    }

    pub fn sign_result(&self, key: &KeyPair) -> CertificateSignatureResult {
        match self.sign(key) {
            Ok(signature) => CertificateResult::ok(signature),
            Err(error) => CertificateResult::failure(error.message),
        }
    }
}

fn normalize_signature_for_emit(
    signature: Vec<u8>,
    algorithm: SignatureAlgorithmId,
) -> PkiResult<Vec<u8>> {
    match algorithm {
        SignatureAlgorithmId::EcdsaSha256 => encode_ecdsa_p256_signature_der(&signature),
        SignatureAlgorithmId::EcdsaSha384 => encode_ecdsa_p384_signature_der(&signature),
        SignatureAlgorithmId::EcdsaSha512 => encode_ecdsa_p521_signature_der(&signature),
        _ => Ok(signature),
    }
}

pub fn parse_csr(input: &[u8]) -> PkiResult<CertificateRequest> {
    let seq = parse_sequence(input)?;
    let mut cursor = Cursor::new(&seq.value);

    let cri_seq = parse_sequence(cursor.remaining())?;
    let cri_der = cursor.remaining()[..cri_seq.bytes_consumed].to_vec();
    cursor.advance(cri_seq.bytes_consumed)?;

    let sig_alg = super::parse_algorithm_identifier_full(cursor.remaining())?;
    cursor.advance(sig_alg.bytes_consumed)?;

    let sig = parse_bit_string(cursor.remaining())?;
    cursor.advance(sig.bytes_consumed)?;
    if !cursor.empty() {
        return Err(PkiError::new("trailing data in CSR"));
    }

    let info = parse_certification_request_info_from_sequence(&cri_seq, cri_der.clone())?;
    Ok(CertificateRequest {
        info,
        signature_algorithm: sig_alg.value,
        signature: sig.value.bytes,
        der: input[..seq.bytes_consumed].to_vec(),
        cri_der,
    })
}

pub fn parse_csr_result(input: &[u8]) -> CertificateResult<CertificateRequest> {
    match parse_csr(input) {
        Ok(csr) => CertificateResult::ok(csr),
        Err(error) => CertificateResult::failure(error.message),
    }
}

fn parse_certification_request_info_from_sequence(
    seq: &Asn1Read<Vec<u8>>,
    cri_der: Vec<u8>,
) -> PkiResult<CertificationRequestInfo> {
    let mut cursor = Cursor::new(&seq.value);
    let version = parse_integer(cursor.remaining())?;
    cursor.advance(version.bytes_consumed)?;
    let version_value = integer_to_i32(&version.value)?;

    let subject = parse_name_full(cursor.remaining())?;
    cursor.advance(subject.bytes_consumed)?;

    let spki = parse_subject_public_key_info(cursor.remaining())?;
    cursor.advance(spki.bytes_consumed)?;

    let mut extensions = Vec::new();
    if !cursor.empty() {
        extensions = parse_csr_attributes(cursor.remaining())?.value;
    }

    Ok(CertificationRequestInfo {
        version: version_value,
        subject: subject.value,
        subject_public_key_info: spki.value,
        extensions,
        der: cri_der,
    })
}

fn integer_to_i32(bytes: &[u8]) -> PkiResult<i32> {
    if bytes.is_empty() || bytes.len() > 4 {
        return Err(PkiError::new("CSR version integer out of range"));
    }
    let mut out = 0i32;
    for byte in bytes {
        out = (out << 8) | i32::from(*byte);
    }
    Ok(out)
}

fn parse_csr_attributes(input: &[u8]) -> PkiResult<Asn1Read<Vec<RawExtension>>> {
    let header = parse_id_len(input)?;
    if header.value.identifier.tag_class != Asn1Class::ContextSpecific
        || header.value.identifier.tag_number != 0
        || !header.value.identifier.constructed
    {
        return Err(PkiError::new("expected CSR attributes"));
    }
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    let mut cursor = Cursor::new(&input[start..end]);
    let mut extensions = Vec::new();
    while !cursor.empty() {
        let attr_seq = parse_sequence(cursor.remaining())?;
        let mut attr_cursor = Cursor::new(&attr_seq.value);
        let attr_oid = parse_oid(attr_cursor.remaining())?;
        attr_cursor.advance(attr_oid.bytes_consumed)?;
        let values = super::parse_set(attr_cursor.remaining())?;
        attr_cursor.advance(values.bytes_consumed)?;
        if attr_oid.value.nodes == [1, 2, 840, 113549, 1, 9, 14] {
            let ext_seq = parse_csr_extension_request_values(&values.value)?;
            extensions.extend(ext_seq);
        }
        cursor.advance(attr_seq.bytes_consumed)?;
    }
    Ok(Asn1Read::new(
        extensions,
        header.value.header_bytes + header.value.length,
    ))
}

fn parse_csr_extension_request_values(input: &[u8]) -> PkiResult<Vec<RawExtension>> {
    let mut cursor = Cursor::new(input);
    let mut out = Vec::new();
    while !cursor.empty() {
        let ext_seq = parse_sequence(cursor.remaining())?;
        let mut ext_cursor = Cursor::new(&ext_seq.value);
        while !ext_cursor.empty() {
            let entry = parse_sequence(ext_cursor.remaining())?;
            let mut entry_cursor = Cursor::new(&entry.value);
            let oid = parse_oid(entry_cursor.remaining())?;
            entry_cursor.advance(oid.bytes_consumed)?;
            let mut critical = false;
            if !entry_cursor.empty() {
                let next = parse_id_len(entry_cursor.remaining())?;
                if next.value.identifier.tag_class == Asn1Class::Universal
                    && next.value.identifier.tag_number == Asn1Tag::Boolean as u32
                {
                    let parsed = parse_boolean(entry_cursor.remaining())?;
                    critical = parsed.value;
                    entry_cursor.advance(parsed.bytes_consumed)?;
                }
            }
            let value = parse_octet_string(entry_cursor.remaining())?;
            entry_cursor.advance(value.bytes_consumed)?;
            if !entry_cursor.empty() {
                return Err(PkiError::new("trailing data in CSR extension"));
            }
            out.push(RawExtension {
                id: find_extension_by_oid(&oid.value),
                oid: oid.value,
                critical,
                value: value.value,
            });
            ext_cursor.advance(entry.bytes_consumed)?;
        }
        cursor.advance(ext_seq.bytes_consumed)?;
    }
    Ok(out)
}

pub fn encode_algorithm_identifier(algorithm: &AlgorithmIdentifier) -> PkiResult<Vec<u8>> {
    let oid = oid_for_signature(algorithm.signature)
        .ok_or_else(|| PkiError::new("unsupported signature algorithm"))?;
    Ok(der::encode_sequence(&der::encode_oid(&oid)))
}

pub fn encode_subject_public_key_info(spki: &SubjectPublicKeyInfo) -> PkiResult<Vec<u8>> {
    let alg = encode_algorithm_identifier(&spki.algorithm)?;
    Ok(der::encode_sequence(&der::concat(&[
        alg,
        der::encode_bit_string_with_unused_bits(&spki.public_key, spki.unused_bits),
    ])))
}

pub fn encode_extension(extension: &RawExtension) -> Vec<u8> {
    let mut fields = vec![der::encode_oid(&extension.oid)];
    if extension.critical {
        fields.push(der::encode_boolean(true));
    }
    fields.push(der::encode_octet_string(&extension.value));
    der::encode_sequence(&der::concat(&fields))
}

pub fn encode_extensions_sequence(extensions: &[RawExtension]) -> Vec<u8> {
    let entries = extensions.iter().map(encode_extension).collect::<Vec<_>>();
    der::encode_sequence(&der::concat(&entries))
}

pub fn encode_csr_attributes(extensions: &[RawExtension]) -> Vec<u8> {
    if extensions.is_empty() {
        return der::encode_context_constructed(0, &[]);
    }
    let extension_request_oid = Oid::new([1, 2, 840, 113549, 1, 9, 14]);
    let attr = der::encode_sequence(&der::concat(&[
        der::encode_oid(&extension_request_oid),
        der::encode_set(&encode_extensions_sequence(extensions)),
    ]));
    der::encode_context_constructed(0, &attr)
}

pub fn load_csr(path: impl AsRef<Path>) -> PkiResult<CertificateRequest> {
    let loaded = read_pem_or_der(path, Some("CERTIFICATE REQUEST"))?;
    parse_csr(loaded.der_bytes())
}

pub fn load_csr_result(path: impl AsRef<Path>) -> CertificateResult<CertificateRequest> {
    match load_csr(path) {
        Ok(csr) => CertificateResult::ok(csr),
        Err(error) => CertificateResult::failure(error.message),
    }
}
