use super::parser::parse_certificate_context;
use super::{
    AlgorithmIdentifier, Asn1Class, CertificateContext, CertificatePurpose, Cursor, DerTime,
    DistinguishedName, DistinguishedNameAttribute, ExtendedKeyUsage, ExtensionId, GeneralName,
    GeneralNameType, HashAlgorithm, KeyPair, KeyPurposeId, PkiError, PkiResult, PolicyConstraints,
    PolicyMapping, RawExtension, SignatureAlgorithmId, TbsCertificate, Validity, digest,
    encode_certificate_subject_public_key_info, encode_ecdsa_p256_signature_der,
    encode_ecdsa_p384_signature_der, encode_ecdsa_p521_signature_der, key_usage, parse_bit_string,
    parse_boolean, parse_id_len, parse_integer, parse_oid, parse_sequence,
    pem_decode_certificate_block, read_binary_bytes, sign_ecdsa_p256_sha256,
    sign_ecdsa_p384_sha384, sign_ecdsa_p521_sha512, sign_ed448_detached, sign_ed25519_detached,
    sign_rsa_pkcs1v15_keypair, sign_rsa_pss_keypair, verify_certificate_signature,
    write_binary_result,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CertificateFormat {
    Der,
    #[default]
    Pem,
}

#[allow(non_upper_case_globals)]
impl CertificateFormat {
    pub const DER: Self = Self::Der;
    pub const PEM: Self = Self::Pem;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateResult<T> {
    pub success: bool,
    pub value: T,
    pub error: String,
}

impl<T> CertificateResult<T> {
    pub fn ok(value: T) -> Self {
        Self {
            success: true,
            value,
            error: String::new(),
        }
    }

    pub fn into_result(self) -> PkiResult<T> {
        if self.success {
            Ok(self.value)
        } else {
            Err(PkiError::new(self.error))
        }
    }
}

impl<T: Default> CertificateResult<T> {
    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            value: T::default(),
            error: error.into(),
        }
    }
}

impl<T: Default> Default for CertificateResult<T> {
    fn default() -> Self {
        Self {
            success: false,
            value: T::default(),
            error: String::new(),
        }
    }
}

pub type CertificateParseResult = CertificateResult<Certificate>;
pub type CertificateChainResult = CertificateResult<Vec<Certificate>>;
pub type CertificateSignatureResult = CertificateResult<Vec<u8>>;
pub type CertificateBoolResult = CertificateResult<bool>;

#[derive(Clone, Debug, Default)]
pub struct Certificate {
    pub der: Vec<u8>,
    pub tbs: TbsCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: Vec<u8>,
    pub tbs_der: Vec<u8>,
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.der == other.der
    }
}

impl Eq for Certificate {}

impl Certificate {
    pub fn from_der(der: impl Into<Vec<u8>>) -> Self {
        Self {
            der: der.into(),
            ..Self::default()
        }
    }

    pub fn parse_der_with_relaxed(der: &[u8], relaxed: bool) -> PkiResult<Self> {
        if der.is_empty() {
            return Err(PkiError::new("empty DER buffer"));
        }
        let ctx = parse_certificate_context(der, relaxed)?;
        Ok(Self::from_context(ctx))
    }

    pub fn parse_der(der: &[u8]) -> PkiResult<Self> {
        Self::parse_der_with_relaxed(der, false)
    }

    pub fn parse_der_result_with_relaxed(der: &[u8], relaxed: bool) -> CertificateParseResult {
        match Self::parse_der_with_relaxed(der, relaxed) {
            Ok(cert) => CertificateResult::ok(cert),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn parse_der_result(der: &[u8]) -> CertificateParseResult {
        Self::parse_der_result_with_relaxed(der, false)
    }

    pub fn parse_with_relaxed(der: &[u8], relaxed: bool) -> PkiResult<Self> {
        Self::parse_der_with_relaxed(der, relaxed)
    }

    pub fn parse(der: &[u8]) -> PkiResult<Self> {
        Self::parse_der(der)
    }

    pub fn parse_result_with_relaxed(der: &[u8], relaxed: bool) -> CertificateParseResult {
        Self::parse_der_result_with_relaxed(der, relaxed)
    }

    pub fn parse_result(der: &[u8]) -> CertificateParseResult {
        Self::parse_der_result(der)
    }

    pub fn from_context(ctx: CertificateContext) -> Self {
        Self {
            tbs: TbsCertificate {
                version: ctx.version,
                serial_number: ctx.serial_number,
                signature: ctx.tbs_signature,
                issuer: ctx.issuer,
                validity: Validity {
                    not_before: ctx.not_before,
                    not_after: ctx.not_after,
                },
                subject: ctx.subject,
                subject_public_key_info: ctx.subject_public_key_info,
                extensions: ctx.extensions,
            },
            signature_algorithm: ctx.outer_signature,
            signature_value: ctx.signature_value,
            der: ctx.der,
            tbs_der: ctx.tbs_certificate,
        }
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn tbs(&self) -> &TbsCertificate {
        &self.tbs
    }

    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    pub fn signature_value(&self) -> &[u8] {
        &self.signature_value
    }

    pub fn tbs_der(&self) -> &[u8] {
        &self.tbs_der
    }

    pub fn to_der(&self) -> Vec<u8> {
        self.der.clone()
    }

    pub fn to_pem(&self) -> String {
        self.to_pem_with_line_length(64)
    }

    pub fn to_pem_with_line_length(&self, line_length: usize) -> String {
        super::pem_encode_with_line_length(&self.der, "CERTIFICATE", line_length)
    }

    pub fn save(&self, path: impl AsRef<std::path::Path>) -> PkiResult<()> {
        self.save_as(path, CertificateFormat::Pem)
    }

    pub fn save_as(
        &self,
        path: impl AsRef<std::path::Path>,
        format: CertificateFormat,
    ) -> PkiResult<()> {
        match format {
            CertificateFormat::Der => write_binary_result(&self.der, path),
            CertificateFormat::Pem => write_binary_result(self.to_pem().as_bytes(), path),
        }
    }

    pub fn from_pem(pem: &str) -> PkiResult<Self> {
        Ok(Self {
            der: pem_decode_certificate_block(pem)?.data,
            ..Self::default()
        })
    }

    pub fn parse_pem_with_relaxed(pem: &str, relaxed: bool) -> PkiResult<Self> {
        Self::parse_der_with_relaxed(&pem_decode_certificate_block(pem)?.data, relaxed)
    }

    pub fn parse_pem(pem: &str) -> PkiResult<Self> {
        Self::parse_pem_with_relaxed(pem, false)
    }

    pub fn parse_pem_result_with_relaxed(pem: &str, relaxed: bool) -> CertificateParseResult {
        match Self::parse_pem_with_relaxed(pem, relaxed) {
            Ok(cert) => CertificateResult::ok(cert),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn parse_pem_result(pem: &str) -> CertificateParseResult {
        Self::parse_pem_result_with_relaxed(pem, false)
    }

    pub fn parse_pem_chain_with_relaxed(pem: &str, relaxed: bool) -> PkiResult<Vec<Self>> {
        let mut certificates = Vec::new();
        let mut cursor = 0usize;
        while cursor < pem.len() {
            let Some(begin_rel) = pem[cursor..].find("-----BEGIN") else {
                break;
            };
            let begin = cursor + begin_rel;
            let label_start = begin + "-----BEGIN ".len();
            let Some(label_end_rel) = pem[label_start..].find("-----") else {
                break;
            };
            let label_end = label_start + label_end_rel;
            if &pem[label_start..label_end] != "CERTIFICATE" {
                cursor = label_end + "-----".len();
                continue;
            }

            let block = pem_decode_certificate_block(&pem[begin..])?;
            certificates.push(Self::parse_der_with_relaxed(&block.data, relaxed)?);

            let end_marker = "-----END CERTIFICATE-----";
            let Some(end_rel) = pem[begin..].find(end_marker) else {
                break;
            };
            cursor = begin + end_rel + end_marker.len();
        }
        if certificates.is_empty() {
            return Err(super::PkiError::new("no certificates found in PEM data"));
        }
        Ok(certificates)
    }

    pub fn parse_pem_chain(pem: &str) -> PkiResult<Vec<Self>> {
        Self::parse_pem_chain_with_relaxed(pem, false)
    }

    pub fn parse_pem_chain_result_with_relaxed(pem: &str, relaxed: bool) -> CertificateChainResult {
        match Self::parse_pem_chain_with_relaxed(pem, relaxed) {
            Ok(certs) => CertificateResult::ok(certs),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn parse_pem_chain_result(pem: &str) -> CertificateChainResult {
        Self::parse_pem_chain_result_with_relaxed(pem, false)
    }

    pub fn parse_der_chain_with_relaxed(der: &[u8], relaxed: bool) -> PkiResult<Vec<Self>> {
        let mut certificates = Vec::new();
        let mut offset = 0usize;
        while offset < der.len() {
            let seq = match parse_sequence(&der[offset..]) {
                Ok(seq) => seq,
                Err(err) if certificates.is_empty() => return Err(err),
                Err(_) => break,
            };
            if seq.bytes_consumed == 0 || offset + seq.bytes_consumed > der.len() {
                return Err(super::PkiError::new("truncated DER certificate"));
            }
            certificates.push(Self::parse_der_with_relaxed(
                &der[offset..offset + seq.bytes_consumed],
                relaxed,
            )?);
            offset += seq.bytes_consumed;
        }
        if certificates.is_empty() {
            return Err(super::PkiError::new("no DER certificates found"));
        }
        Ok(certificates)
    }

    pub fn parse_der_chain(der: &[u8]) -> PkiResult<Vec<Self>> {
        Self::parse_der_chain_with_relaxed(der, false)
    }

    pub fn parse_der_chain_result_with_relaxed(
        der: &[u8],
        relaxed: bool,
    ) -> CertificateChainResult {
        match Self::parse_der_chain_with_relaxed(der, relaxed) {
            Ok(certs) => CertificateResult::ok(certs),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn parse_der_chain_result(der: &[u8]) -> CertificateChainResult {
        Self::parse_der_chain_result_with_relaxed(der, false)
    }

    pub fn load_with_relaxed(
        path: impl AsRef<std::path::Path>,
        relaxed: bool,
    ) -> PkiResult<Vec<Self>> {
        let bytes = read_binary_bytes(path)?;
        if bytes.is_empty() {
            return Err(super::PkiError::new("certificate file is empty"));
        }
        if bytes
            .windows(b"-----BEGIN".len())
            .any(|window| window == b"-----BEGIN")
        {
            let pem = std::str::from_utf8(&bytes)
                .map_err(|_| super::PkiError::new("PEM certificate file is not UTF-8"))?;
            Self::parse_pem_chain_with_relaxed(pem, relaxed)
        } else {
            Self::parse_der_chain_with_relaxed(&bytes, relaxed)
        }
    }

    pub fn load(path: impl AsRef<std::path::Path>) -> PkiResult<Vec<Self>> {
        Self::load_with_relaxed(path, false)
    }

    pub fn load_result_with_relaxed(
        path: impl AsRef<std::path::Path>,
        relaxed: bool,
    ) -> CertificateChainResult {
        match Self::load_with_relaxed(path, relaxed) {
            Ok(certs) => CertificateResult::ok(certs),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn load_result(path: impl AsRef<std::path::Path>) -> CertificateChainResult {
        Self::load_result_with_relaxed(path, false)
    }

    pub fn find_extension(&self, id: ExtensionId) -> Option<&RawExtension> {
        self.tbs.extensions.iter().find(|ext| ext.id == id)
    }

    pub fn public_key_der(&self) -> Vec<u8> {
        encode_certificate_subject_public_key_info(&self.tbs.subject_public_key_info)
            .unwrap_or_default()
    }

    pub fn fingerprint(&self, algorithm: HashAlgorithm) -> PkiResult<Vec<u8>> {
        digest(algorithm, &self.der)
    }

    pub fn verify_signature(&self, issuer: &Certificate) -> PkiResult<bool> {
        verify_certificate_signature(self, issuer)
    }

    pub fn verify_signature_result(&self, issuer: &Certificate) -> CertificateBoolResult {
        match self.verify_signature(issuer) {
            Ok(valid) => CertificateResult::ok(valid),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn sign(&self, issuer_key: &KeyPair) -> PkiResult<Vec<u8>> {
        self.sign_with_hash(issuer_key, HashAlgorithm::Sha256)
    }

    pub fn sign_with_hash(
        &self,
        issuer_key: &KeyPair,
        hash_alg: HashAlgorithm,
    ) -> PkiResult<Vec<u8>> {
        let _ = hash_alg;
        let signature = match self.signature_algorithm.signature {
            SignatureAlgorithmId::Ed25519 => {
                sign_ed25519_detached(&self.tbs_der, &issuer_key.private_key)?
            }
            SignatureAlgorithmId::Ed448 => {
                sign_ed448_detached(&self.tbs_der, &issuer_key.private_key)?
            }
            SignatureAlgorithmId::EcdsaSha256 => {
                sign_ecdsa_p256_sha256(&self.tbs_der, &issuer_key.private_key)?
            }
            SignatureAlgorithmId::EcdsaSha384 => {
                sign_ecdsa_p384_sha384(&self.tbs_der, &issuer_key.private_key)?
            }
            SignatureAlgorithmId::EcdsaSha512 => {
                sign_ecdsa_p521_sha512(&self.tbs_der, &issuer_key.private_key)?
            }
            SignatureAlgorithmId::RsaPkcs1Sha256
            | SignatureAlgorithmId::RsaPkcs1Sha384
            | SignatureAlgorithmId::RsaPkcs1Sha512 => sign_rsa_pkcs1v15_keypair(
                self.signature_algorithm.signature,
                &self.tbs_der,
                issuer_key,
            )?,
            SignatureAlgorithmId::RsaPssSha256
            | SignatureAlgorithmId::RsaPssSha384
            | SignatureAlgorithmId::RsaPssSha512 => sign_rsa_pss_keypair(
                self.signature_algorithm.signature,
                &self.tbs_der,
                issuer_key,
            )?,
            _ => {
                return Err(PkiError::new("Unsupported signature algorithm for signing"));
            }
        };
        normalize_signature_for_emit(signature, self.signature_algorithm.signature)
    }

    pub fn sign_result(&self, issuer_key: &KeyPair) -> CertificateSignatureResult {
        self.sign_result_with_hash(issuer_key, HashAlgorithm::Sha256)
    }

    pub fn sign_result_with_hash(
        &self,
        issuer_key: &KeyPair,
        hash_alg: HashAlgorithm,
    ) -> CertificateSignatureResult {
        match self.sign_with_hash(issuer_key, hash_alg) {
            Ok(signature) => CertificateResult::ok(signature),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn check_revocation<T: super::Transport>(
        &self,
        client: &mut super::Client<T>,
    ) -> PkiResult<bool> {
        Ok(client.verify_chain(std::slice::from_ref(self))?.valid)
    }

    pub fn check_revocation_result<T: super::Transport>(
        &self,
        client: &mut super::Client<T>,
    ) -> CertificateBoolResult {
        match self.check_revocation(client) {
            Ok(valid) => CertificateResult::ok(valid),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn check_validity(&self) -> bool {
        self.check_validity_at(&current_der_time_utc())
    }

    pub fn check_validity_at(&self, check_time: &DerTime) -> bool {
        self.tbs.validity.contains(check_time)
    }

    pub fn check_validity_now(&self) -> bool {
        self.check_validity()
    }

    pub fn print_info(&self) -> String {
        format!(
            "Certificate\n  Subject: {}\n  Issuer: {}\n  Serial: {}\n  Signature: {:?}\n",
            self.tbs.subject,
            self.tbs.issuer,
            hex_lower(&self.tbs.serial_number),
            self.signature_algorithm.signature
        )
    }

    pub fn to_json(&self) -> String {
        format!(
            "{{\"subject\":\"{}\",\"issuer\":\"{}\",\"serial\":\"{}\",\"signatureAlgorithm\":\"{:?}\"}}",
            crate::json::escape(&self.tbs.subject.to_string()),
            crate::json::escape(&self.tbs.issuer.to_string()),
            hex_lower(&self.tbs.serial_number),
            self.signature_algorithm.signature
        )
    }

    pub fn basic_constraints_ca(&self) -> Option<bool> {
        let ext = self.find_extension(ExtensionId::BasicConstraints)?;
        let seq = parse_sequence(&ext.value).ok()?;
        let cursor = Cursor::new(&seq.value);
        if cursor.empty() {
            return Some(false);
        }
        Some(parse_boolean(cursor.remaining()).ok()?.value)
    }

    pub fn basic_constraints_path_length(&self) -> Option<u32> {
        let ext = self.find_extension(ExtensionId::BasicConstraints)?;
        let seq = parse_sequence(&ext.value).ok()?;
        let mut cursor = Cursor::new(&seq.value);
        if let Ok(ca) = parse_boolean(cursor.remaining()) {
            cursor.advance(ca.bytes_consumed).ok()?;
        }
        if cursor.empty() {
            return None;
        }
        let int = parse_integer(cursor.remaining()).ok()?;
        uint_from_bytes(&int.value)
    }

    pub fn key_usage_bits(&self) -> Option<u16> {
        let ext = self.find_extension(ExtensionId::KeyUsage)?;
        let bit = parse_bit_string(&ext.value).ok()?;
        let mut value = 0u16;
        for byte in bit.value.bytes {
            value = (value << 8) | u16::from(byte);
        }
        Some(value)
    }

    pub fn subject_alt_names(&self) -> Vec<GeneralName> {
        self.general_names(ExtensionId::SubjectAltName)
    }

    pub fn issuer_alt_names(&self) -> Vec<GeneralName> {
        self.general_names(ExtensionId::IssuerAltName)
    }

    fn general_names(&self, extension: ExtensionId) -> Vec<GeneralName> {
        let Some(ext) = self.find_extension(extension) else {
            return Vec::new();
        };
        let Ok(seq) = parse_sequence(&ext.value) else {
            return Vec::new();
        };
        parse_general_names_sequence(&seq.value)
    }

    pub fn extended_key_usage(&self) -> Option<ExtendedKeyUsage> {
        let ext = self.find_extension(ExtensionId::ExtendedKeyUsage)?;
        let seq = parse_sequence(&ext.value).ok()?;
        let mut cursor = Cursor::new(&seq.value);
        let mut purpose_oids = Vec::new();
        while !cursor.empty() {
            let oid = parse_oid(cursor.remaining()).ok()?;
            cursor.advance(oid.bytes_consumed).ok()?;
            purpose_oids.push(oid.value);
        }
        Some(ExtendedKeyUsage {
            critical: ext.critical,
            purpose_oids,
        })
    }

    pub fn policy_mappings(&self) -> Vec<PolicyMapping> {
        let Some(ext) = self.find_extension(ExtensionId::PolicyMappings) else {
            return Vec::new();
        };
        let Ok(seq) = parse_sequence(&ext.value) else {
            return Vec::new();
        };
        let mut cursor = Cursor::new(&seq.value);
        let mut mappings = Vec::new();
        while !cursor.empty() {
            let Ok(mapping_seq) = parse_sequence(cursor.remaining()) else {
                break;
            };
            let mut mapping_cursor = Cursor::new(&mapping_seq.value);
            let Ok(issuer_oid) = parse_oid(mapping_cursor.remaining()) else {
                break;
            };
            if mapping_cursor.advance(issuer_oid.bytes_consumed).is_err() {
                break;
            }
            let Ok(subject_oid) = parse_oid(mapping_cursor.remaining()) else {
                break;
            };
            mappings.push(PolicyMapping {
                issuer_domain_policy: issuer_oid.value.nodes,
                subject_domain_policy: subject_oid.value.nodes,
            });
            if cursor.advance(mapping_seq.bytes_consumed).is_err() {
                break;
            }
        }
        mappings
    }

    pub fn policy_constraints(&self) -> Option<PolicyConstraints> {
        let ext = self.find_extension(ExtensionId::PolicyConstraints)?;
        let seq = parse_sequence(&ext.value).ok()?;
        let mut offset = 0usize;
        let mut require_explicit_policy = None;
        let mut inhibit_policy_mapping = None;

        if offset < seq.value.len() {
            let header = parse_id_len(&seq.value[offset..]).ok()?;
            if header.value.identifier.tag_class == Asn1Class::ContextSpecific
                && header.value.identifier.tag_number == 0
            {
                let start = offset + header.value.header_bytes;
                let end = start + header.value.length;
                require_explicit_policy = uint_from_bytes(&seq.value[start..end]);
                offset += header.bytes_consumed;
            }
        }
        if offset < seq.value.len() {
            let header = parse_id_len(&seq.value[offset..]).ok()?;
            if header.value.identifier.tag_class == Asn1Class::ContextSpecific
                && header.value.identifier.tag_number == 1
            {
                let start = offset + header.value.header_bytes;
                let end = start + header.value.length;
                inhibit_policy_mapping = uint_from_bytes(&seq.value[start..end]);
            }
        }
        if require_explicit_policy.is_none() && inhibit_policy_mapping.is_none() {
            return None;
        }
        Some(PolicyConstraints {
            critical: ext.critical,
            require_explicit_policy,
            inhibit_policy_mapping,
        })
    }

    pub fn inhibit_any_policy(&self) -> Option<u32> {
        let ext = self.find_extension(ExtensionId::InhibitAnyPolicy)?;
        let int = parse_integer(&ext.value).ok()?;
        let value = uint_from_bytes(&int.value)?;
        (value <= 64).then_some(value)
    }

    pub fn verify_key_usage(&self, required_bits: u16) -> bool {
        self.key_usage_bits()
            .map(|bits| bits & required_bits == required_bits)
            .unwrap_or(required_bits == 0)
    }

    pub fn verify_extensions(&self, purpose: CertificatePurpose) -> bool {
        let eku = self.extended_key_usage();
        let require_eku = |purpose_id| {
            eku.as_ref()
                .map(|eku| eku.has_purpose(purpose_id))
                .unwrap_or(true)
        };
        match purpose {
            CertificatePurpose::TlsServer => {
                if !require_eku(KeyPurposeId::ServerAuth) {
                    return false;
                }
                self.key_usage_bits()
                    .map(|bits| {
                        bits & key_usage::DIGITAL_SIGNATURE != 0
                            || bits & key_usage::KEY_ENCIPHERMENT != 0
                    })
                    .unwrap_or(true)
            }
            CertificatePurpose::TlsClient => {
                require_eku(KeyPurposeId::ClientAuth)
                    && self.verify_key_usage(key_usage::DIGITAL_SIGNATURE)
            }
            CertificatePurpose::CodeSigning => {
                require_eku(KeyPurposeId::CodeSigning)
                    && self
                        .verify_key_usage(key_usage::DIGITAL_SIGNATURE | key_usage::NON_REPUDIATION)
            }
        }
    }

    pub fn match_hostname(&self, hostname: &str) -> bool {
        let names = self.subject_alt_names();
        let has_san = !names.is_empty();
        if let Some(ip) = parse_ipv4(hostname) {
            for name in &names {
                if name.type_ == GeneralNameType::IpAddress && name.value.as_slice() == ip {
                    return true;
                }
            }
            return false;
        }
        for name in &names {
            if name.type_ == GeneralNameType::DnsName
                && wildcard_match(&name.value_string(), hostname)
            {
                return true;
            }
        }
        if has_san {
            return false;
        }
        self.tbs
            .subject
            .first(DistinguishedNameAttribute::CommonName)
            .map(|cn| wildcard_match(cn, hostname))
            .unwrap_or(false)
    }

    pub fn match_subject(&self, dn: &DistinguishedName) -> bool {
        self.tbs.subject.der() == dn.der()
    }

    pub fn equals_identity(&self, other: &Self) -> bool {
        self.tbs.subject.der() == other.tbs.subject.der()
            && self.tbs.subject_public_key_info.public_key
                == other.tbs.subject_public_key_info.public_key
    }
}

fn normalize_signature_for_emit(
    signature: Vec<u8>,
    algorithm: SignatureAlgorithmId,
) -> PkiResult<Vec<u8>> {
    match algorithm {
        SignatureAlgorithmId::EcdsaSha256 if signature.len() == 64 => {
            encode_ecdsa_p256_signature_der(&signature)
        }
        SignatureAlgorithmId::EcdsaSha384 if signature.len() == 96 => {
            encode_ecdsa_p384_signature_der(&signature)
        }
        SignatureAlgorithmId::EcdsaSha512 if signature.len() == 132 => {
            encode_ecdsa_p521_signature_der(&signature)
        }
        SignatureAlgorithmId::EcdsaSha256
        | SignatureAlgorithmId::EcdsaSha384
        | SignatureAlgorithmId::EcdsaSha512
            if signature.first() != Some(&0x30) =>
        {
            Err(PkiError::new("Unexpected ECDSA raw signature size"))
        }
        _ => Ok(signature),
    }
}

fn current_der_time_utc() -> DerTime {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = now.as_secs() as i64;
    let days = seconds / 86_400;
    let seconds_of_day = seconds % 86_400;
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

fn civil_from_days(days_since_unix_epoch: i64) -> (i32, u8, u8) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + i64::from(month <= 2);
    (year as i32, month as u8, day as u8)
}

fn uint_from_bytes(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 4 {
        return None;
    }
    let mut value = 0u32;
    for byte in bytes {
        value = (value << 8) | u32::from(*byte);
    }
    Some(value)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn parse_general_names_sequence(value: &[u8]) -> Vec<GeneralName> {
    let mut names = Vec::new();
    let mut offset = 0usize;
    while offset < value.len() {
        let Ok(header) = parse_id_len(&value[offset..]) else {
            break;
        };
        let id = &header.value.identifier;
        if id.tag_class != Asn1Class::ContextSpecific {
            break;
        }
        let start = offset + header.value.header_bytes;
        let end = start + header.value.length;
        let type_ = match id.tag_number {
            1 => GeneralNameType::Email,
            2 => GeneralNameType::DnsName,
            6 => GeneralNameType::Uri,
            7 => GeneralNameType::IpAddress,
            _ => GeneralNameType::Other,
        };
        names.push(GeneralName {
            type_,
            value: value[start..end].to_vec(),
        });
        offset += header.bytes_consumed;
    }
    names
}

fn parse_ipv4(input: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut count = 0usize;
    for part in input.split('.') {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
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

fn label_count(name: &str) -> usize {
    if name.is_empty() {
        0
    } else {
        name.bytes().filter(|b| *b == b'.').count() + 1
    }
}

fn wildcard_match(pattern: &str, hostname: &str) -> bool {
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
