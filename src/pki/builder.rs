use super::{
    AlgorithmIdentifier, Certificate, CertificateResult, CurveId, DerTime, DistinguishedName,
    ExtendedKeyUsage, ExtensionId, GeneralName, GeneralNameType, HashAlgorithm, KeyPair, Oid,
    PkiError, PkiResult, RawExtension, SignatureAlgorithmId, SubjectPublicKeyInfo, TbsCertificate,
    Validity, der, encode_der_time, encode_ecdsa_p256_signature_der,
    encode_ecdsa_p384_signature_der, encode_ecdsa_p521_signature_der, oid_for_extension,
    oid_for_signature, sign_ecdsa_p256_sha256, sign_ecdsa_p384_sha384, sign_ecdsa_p521_sha512,
    sign_ed448_detached, sign_ed25519_detached, sign_rsa_pkcs1v15_keypair, sign_rsa_pss_keypair,
};

#[derive(Clone, Debug)]
pub struct CertificateBuilder {
    version: i32,
    serial_number: Vec<u8>,
    issuer_explicit: bool,
    subject_explicit: bool,
    issuer: DistinguishedName,
    subject: DistinguishedName,
    validity: Validity,
    subject_public_key_info: SubjectPublicKeyInfo,
    signature_algorithm: AlgorithmIdentifier,
    extensions: Vec<RawExtension>,
}

impl Default for CertificateBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CertificateBuilder {
    pub fn new() -> Self {
        Self {
            version: 3,
            serial_number: Vec::new(),
            issuer_explicit: false,
            subject_explicit: false,
            issuer: DistinguishedName::default(),
            subject: DistinguishedName::default(),
            validity: Validity::default(),
            subject_public_key_info: SubjectPublicKeyInfo::default(),
            signature_algorithm: AlgorithmIdentifier {
                signature: SignatureAlgorithmId::Ed25519,
                hash: HashAlgorithm::Sha256,
                curve: CurveId::Ed25519,
            },
            extensions: Vec::new(),
        }
    }

    pub fn set_version(mut self, version: i32) -> Self {
        self.version = version.clamp(1, 3);
        self
    }

    pub fn set_serial(mut self, serial: impl Into<Vec<u8>>) -> Self {
        self.serial_number = serial.into();
        if let Some(first) = self.serial_number.first_mut() {
            *first &= 0x7f;
        }
        self
    }

    pub fn set_serial_u64(self, serial: u64) -> Self {
        let mut bytes = Vec::new();
        let mut started = false;
        for shift in (0..=56).rev().step_by(8) {
            let byte = ((serial >> shift) & 0xff) as u8;
            if !started && byte == 0 {
                continue;
            }
            started = true;
            bytes.push(byte);
        }
        if bytes.is_empty() {
            bytes.push(0);
        }
        self.set_serial(bytes)
    }

    pub fn set_signature_algorithm(mut self, signature: SignatureAlgorithmId) -> Self {
        self.signature_algorithm.signature = signature;
        if signature == SignatureAlgorithmId::Ed25519 {
            self.signature_algorithm.curve = CurveId::Ed25519;
        }
        self
    }

    pub fn set_signature_algorithm_with_hash(
        mut self,
        signature: SignatureAlgorithmId,
        hash: HashAlgorithm,
    ) -> Self {
        self.signature_algorithm.signature = signature;
        self.signature_algorithm.hash = hash;
        self.signature_algorithm.curve = match signature {
            SignatureAlgorithmId::Ed25519 => CurveId::Ed25519,
            SignatureAlgorithmId::EcdsaSha256 => CurveId::Secp256r1,
            SignatureAlgorithmId::EcdsaSha384 => CurveId::Secp384r1,
            SignatureAlgorithmId::EcdsaSha512 => CurveId::Secp521r1,
            _ => CurveId::Unknown,
        };
        self
    }

    pub fn set_issuer(mut self, issuer: DistinguishedName) -> Self {
        self.issuer = issuer;
        self.issuer_explicit = true;
        self
    }

    pub fn set_issuer_from_string(mut self, issuer: &str) -> PkiResult<Self> {
        self.issuer = DistinguishedName::from_string(issuer)?;
        self.issuer_explicit = true;
        Ok(self)
    }

    pub fn set_subject(mut self, subject: DistinguishedName) -> Self {
        self.subject = subject;
        self.subject_explicit = true;
        self
    }

    pub fn set_subject_from_string(mut self, subject: &str) -> PkiResult<Self> {
        self.subject = DistinguishedName::from_string(subject)?;
        self.subject_explicit = true;
        Ok(self)
    }

    pub fn set_validity(mut self, not_before: DerTime, not_after: DerTime) -> Self {
        self.validity = Validity {
            not_before,
            not_after,
        };
        self
    }

    pub fn set_subject_public_key_info(mut self, spki: SubjectPublicKeyInfo) -> Self {
        self.subject_public_key_info = spki;
        self
    }

    pub fn set_subject_public_key_ed25519(mut self, public_key: impl Into<Vec<u8>>) -> Self {
        self.subject_public_key_info = super::ed25519_subject_public_key_info(public_key);
        self
    }

    pub fn set_subject_public_key_ed448(mut self, public_key: impl Into<Vec<u8>>) -> Self {
        self.subject_public_key_info = super::ed448_subject_public_key_info(public_key);
        self
    }

    pub fn set_subject_public_key_ecdsa_p256(mut self, public_key_xy: impl Into<Vec<u8>>) -> Self {
        self.subject_public_key_info = super::ecdsa_p256_subject_public_key_info(public_key_xy);
        self
    }

    pub fn set_subject_public_key_ecdsa_p384(mut self, public_key_xy: impl Into<Vec<u8>>) -> Self {
        self.subject_public_key_info = super::ecdsa_p384_subject_public_key_info(public_key_xy);
        self
    }

    pub fn set_subject_public_key_ecdsa_p521(mut self, public_key_xy: impl Into<Vec<u8>>) -> Self {
        self.subject_public_key_info = super::ecdsa_p521_subject_public_key_info(public_key_xy);
        self
    }

    pub fn set_subject_public_key_rsa(self, public_key: impl Into<Vec<u8>>) -> Self {
        self.set_subject_public_key_rsa_with_options(public_key, HashAlgorithm::Sha256, false)
    }

    pub fn set_subject_public_key_rsa_with_options(
        mut self,
        public_key: impl Into<Vec<u8>>,
        hash: HashAlgorithm,
        pss: bool,
    ) -> Self {
        let signature = rsa_signature_algorithm_for_hash(hash, pss);
        self.subject_public_key_info = SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                signature,
                hash,
                curve: CurveId::Unknown,
            },
            public_key: public_key.into(),
            unused_bits: 0,
        };
        self
    }

    pub fn add_extension(mut self, extension: RawExtension) -> Self {
        if let Some(existing) = self
            .extensions
            .iter_mut()
            .find(|ext| ext.id == extension.id)
        {
            *existing = extension;
        } else {
            self.extensions.push(extension);
        }
        self
    }

    pub fn set_basic_constraints(self, is_ca: bool, path_length: Option<u32>) -> PkiResult<Self> {
        self.set_basic_constraints_with_critical(is_ca, path_length, true)
    }

    pub fn set_basic_constraints_with_critical(
        self,
        is_ca: bool,
        path_length: Option<u32>,
        critical: bool,
    ) -> PkiResult<Self> {
        Ok(self.add_extension(build_basic_constraints_extension(
            is_ca,
            path_length,
            critical,
        )?))
    }

    pub fn set_key_usage(self, bits: u16) -> PkiResult<Self> {
        self.set_key_usage_with_critical(bits, true)
    }

    pub fn set_key_usage_with_critical(self, bits: u16, critical: bool) -> PkiResult<Self> {
        Ok(self.add_extension(build_key_usage_extension(bits, critical)?))
    }

    pub fn set_extended_key_usage(self, purpose_oids: &[Oid]) -> PkiResult<Self> {
        self.set_extended_key_usage_with_critical(purpose_oids, false)
    }

    pub fn set_extended_key_usage_with_critical(
        self,
        purpose_oids: &[Oid],
        critical: bool,
    ) -> PkiResult<Self> {
        if purpose_oids.is_empty() {
            return Ok(self);
        }
        Ok(self.add_extension(build_extended_key_usage_extension(purpose_oids, critical)?))
    }

    pub fn set_subject_alt_name(self, names: &[GeneralName]) -> PkiResult<Self> {
        self.set_subject_alt_name_with_critical(names, false)
    }

    pub fn set_subject_alt_name_with_critical(
        self,
        names: &[GeneralName],
        critical: bool,
    ) -> PkiResult<Self> {
        if names.is_empty() {
            return Ok(self);
        }
        Ok(self.add_extension(build_subject_alt_name_extension(names, critical)?))
    }

    pub fn set_subject_key_identifier(self, key_id: &[u8]) -> PkiResult<Self> {
        self.set_subject_key_identifier_with_critical(key_id, false)
    }

    pub fn set_subject_key_identifier_with_critical(
        self,
        key_id: &[u8],
        critical: bool,
    ) -> PkiResult<Self> {
        Ok(self.add_extension(build_key_identifier_extension(
            key_id,
            critical,
            ExtensionId::SubjectKeyIdentifier,
        )?))
    }

    pub fn set_authority_key_identifier(self, key_id: &[u8]) -> PkiResult<Self> {
        self.set_authority_key_identifier_with_critical(key_id, false)
    }

    pub fn set_authority_key_identifier_with_critical(
        self,
        key_id: &[u8],
        critical: bool,
    ) -> PkiResult<Self> {
        Ok(self.add_extension(build_key_identifier_extension(
            key_id,
            critical,
            ExtensionId::AuthorityKeyIdentifier,
        )?))
    }

    pub fn build_with_signature(
        self,
        signature: impl Into<Vec<u8>>,
        self_signed: bool,
    ) -> PkiResult<Certificate> {
        self.validate_inputs(self_signed)?;
        let signature_value =
            normalize_signature_for_emit(signature.into(), self.signature_algorithm.signature)?;
        let serial = self.serial_or_random()?;
        let issuer = if self_signed {
            self.subject.clone()
        } else if self.issuer_explicit {
            self.issuer.clone()
        } else {
            self.subject.clone()
        };
        let tbs_der = self.encode_tbs_certificate(&serial, &issuer)?;
        let der = der::encode_sequence(&der::concat(&[
            tbs_der.clone(),
            encode_certificate_algorithm_identifier(&self.signature_algorithm)?,
            der::encode_bit_string(&signature_value),
        ]));
        Ok(Certificate {
            der,
            tbs: TbsCertificate {
                version: self.version,
                serial_number: serial,
                signature: self.signature_algorithm.clone(),
                issuer,
                validity: self.validity.clone(),
                subject: self.subject,
                subject_public_key_info: self.subject_public_key_info,
                extensions: self.extensions,
            },
            signature_algorithm: self.signature_algorithm,
            signature_value,
            tbs_der,
        })
    }

    pub fn build_with_signature_result(
        self,
        signature: impl Into<Vec<u8>>,
        self_signed: bool,
    ) -> CertificateResult<Certificate> {
        match self.build_with_signature(signature, self_signed) {
            Ok(cert) => CertificateResult::ok(cert),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build(self, issuer_key: &KeyPair) -> PkiResult<Certificate> {
        self.build_with_self_signed(issuer_key, false)
    }

    pub fn build_with_self_signed(
        self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> PkiResult<Certificate> {
        match self.signature_algorithm.signature {
            SignatureAlgorithmId::Ed25519 => {
                self.build_ed25519_with_self_signed(issuer_key, self_signed)
            }
            SignatureAlgorithmId::Ed448 => {
                self.build_ed448_with_self_signed(issuer_key, self_signed)
            }
            SignatureAlgorithmId::EcdsaSha256 => {
                self.build_ecdsa_p256_sha256_with_self_signed(issuer_key, self_signed)
            }
            SignatureAlgorithmId::EcdsaSha384 => {
                self.build_ecdsa_p384_sha384_with_self_signed(issuer_key, self_signed)
            }
            SignatureAlgorithmId::EcdsaSha512 => {
                self.build_ecdsa_p521_sha512_with_self_signed(issuer_key, self_signed)
            }
            SignatureAlgorithmId::RsaPkcs1Sha256
            | SignatureAlgorithmId::RsaPkcs1Sha384
            | SignatureAlgorithmId::RsaPkcs1Sha512 => {
                self.build_rsa_pkcs1v15_with_self_signed(issuer_key, self_signed)
            }
            SignatureAlgorithmId::RsaPssSha256
            | SignatureAlgorithmId::RsaPssSha384
            | SignatureAlgorithmId::RsaPssSha512 => {
                self.build_rsa_pss_with_self_signed(issuer_key, self_signed)
            }
            _ => Err(PkiError::new("Unsupported signature algorithm for builder")),
        }
    }

    pub fn build_result(self, issuer_key: &KeyPair) -> CertificateResult<Certificate> {
        self.build_result_with_self_signed(issuer_key, false)
    }

    pub fn build_result_with_self_signed(
        self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> CertificateResult<Certificate> {
        match self.build_with_self_signed(issuer_key, self_signed) {
            Ok(cert) => CertificateResult::ok(cert),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ed25519(self, issuer_key: &KeyPair) -> PkiResult<Certificate> {
        self.build_ed25519_with_self_signed(issuer_key, false)
    }

    pub fn build_ed25519_with_self_signed(
        mut self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> PkiResult<Certificate> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::Ed25519,
            hash: HashAlgorithm::Sha256,
            curve: CurveId::Ed25519,
        };
        if self.serial_number.is_empty() {
            self.serial_number = make_random_serial()?;
        }
        let tbs_der = self.build_unsigned_tbs(self_signed)?;
        let signature = sign_ed25519_detached(&tbs_der, &issuer_key.private_key)?;
        self.build_with_signature(signature, self_signed)
    }

    pub fn build_ed25519_result(self, issuer_key: &KeyPair) -> CertificateResult<Certificate> {
        self.build_ed25519_result_with_self_signed(issuer_key, false)
    }

    pub fn build_ed25519_result_with_self_signed(
        self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> CertificateResult<Certificate> {
        match self.build_ed25519_with_self_signed(issuer_key, self_signed) {
            Ok(cert) => CertificateResult::ok(cert),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ed448_with_self_signed(
        mut self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> PkiResult<Certificate> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::Ed448,
            hash: HashAlgorithm::Sha512,
            curve: CurveId::Ed448,
        };
        if self.serial_number.is_empty() {
            self.serial_number = make_random_serial()?;
        }
        let tbs_der = self.build_unsigned_tbs(self_signed)?;
        let signature = sign_ed448_detached(&tbs_der, &issuer_key.private_key)?;
        self.build_with_signature(signature, self_signed)
    }

    pub fn build_ecdsa_p256_sha256(self, issuer_key: &KeyPair) -> PkiResult<Certificate> {
        self.build_ecdsa_p256_sha256_with_self_signed(issuer_key, false)
    }

    pub fn build_ecdsa_p256_sha256_with_self_signed(
        mut self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> PkiResult<Certificate> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::EcdsaSha256,
            hash: HashAlgorithm::Sha256,
            curve: CurveId::Secp256r1,
        };
        if self.serial_number.is_empty() {
            self.serial_number = make_random_serial()?;
        }
        let tbs_der = self.build_unsigned_tbs(self_signed)?;
        let signature = sign_ecdsa_p256_sha256(&tbs_der, &issuer_key.private_key)?;
        self.build_with_signature(signature, self_signed)
    }

    pub fn build_ecdsa_p256_sha256_result(
        self,
        issuer_key: &KeyPair,
    ) -> CertificateResult<Certificate> {
        self.build_ecdsa_p256_sha256_result_with_self_signed(issuer_key, false)
    }

    pub fn build_ecdsa_p256_sha256_result_with_self_signed(
        self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> CertificateResult<Certificate> {
        match self.build_ecdsa_p256_sha256_with_self_signed(issuer_key, self_signed) {
            Ok(cert) => CertificateResult::ok(cert),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ecdsa_p384_sha384(self, issuer_key: &KeyPair) -> PkiResult<Certificate> {
        self.build_ecdsa_p384_sha384_with_self_signed(issuer_key, false)
    }

    pub fn build_ecdsa_p384_sha384_with_self_signed(
        mut self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> PkiResult<Certificate> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::EcdsaSha384,
            hash: HashAlgorithm::Sha384,
            curve: CurveId::Secp384r1,
        };
        if self.serial_number.is_empty() {
            self.serial_number = make_random_serial()?;
        }
        let tbs_der = self.build_unsigned_tbs(self_signed)?;
        let signature = sign_ecdsa_p384_sha384(&tbs_der, &issuer_key.private_key)?;
        self.build_with_signature(signature, self_signed)
    }

    pub fn build_ecdsa_p384_sha384_result(
        self,
        issuer_key: &KeyPair,
    ) -> CertificateResult<Certificate> {
        self.build_ecdsa_p384_sha384_result_with_self_signed(issuer_key, false)
    }

    pub fn build_ecdsa_p384_sha384_result_with_self_signed(
        self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> CertificateResult<Certificate> {
        match self.build_ecdsa_p384_sha384_with_self_signed(issuer_key, self_signed) {
            Ok(cert) => CertificateResult::ok(cert),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ecdsa_p521_sha512(self, issuer_key: &KeyPair) -> PkiResult<Certificate> {
        self.build_ecdsa_p521_sha512_with_self_signed(issuer_key, false)
    }

    pub fn build_ecdsa_p521_sha512_with_self_signed(
        mut self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> PkiResult<Certificate> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::EcdsaSha512,
            hash: HashAlgorithm::Sha512,
            curve: CurveId::Secp521r1,
        };
        if self.serial_number.is_empty() {
            self.serial_number = make_random_serial()?;
        }
        let tbs_der = self.build_unsigned_tbs(self_signed)?;
        let signature = sign_ecdsa_p521_sha512(&tbs_der, &issuer_key.private_key)?;
        self.build_with_signature(signature, self_signed)
    }

    pub fn build_ecdsa_p521_sha512_result(
        self,
        issuer_key: &KeyPair,
    ) -> CertificateResult<Certificate> {
        self.build_ecdsa_p521_sha512_result_with_self_signed(issuer_key, false)
    }

    pub fn build_ecdsa_p521_sha512_result_with_self_signed(
        self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> CertificateResult<Certificate> {
        match self.build_ecdsa_p521_sha512_with_self_signed(issuer_key, self_signed) {
            Ok(cert) => CertificateResult::ok(cert),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_rsa_pkcs1v15(self, issuer_key: &KeyPair) -> PkiResult<Certificate> {
        self.build_rsa_pkcs1v15_with_self_signed(issuer_key, false)
    }

    pub fn build_rsa_pkcs1v15_with_self_signed(
        mut self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> PkiResult<Certificate> {
        if self.serial_number.is_empty() {
            self.serial_number = make_random_serial()?;
        }
        let tbs_der = self.build_unsigned_tbs(self_signed)?;
        let signature =
            sign_rsa_pkcs1v15_keypair(self.signature_algorithm.signature, &tbs_der, issuer_key)?;
        self.build_with_signature(signature, self_signed)
    }

    pub fn build_rsa_pkcs1v15_result(self, issuer_key: &KeyPair) -> CertificateResult<Certificate> {
        self.build_rsa_pkcs1v15_result_with_self_signed(issuer_key, false)
    }

    pub fn build_rsa_pkcs1v15_result_with_self_signed(
        self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> CertificateResult<Certificate> {
        match self.build_rsa_pkcs1v15_with_self_signed(issuer_key, self_signed) {
            Ok(cert) => CertificateResult::ok(cert),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_rsa_pss(self, issuer_key: &KeyPair) -> PkiResult<Certificate> {
        self.build_rsa_pss_with_self_signed(issuer_key, false)
    }

    pub fn build_rsa_pss_with_self_signed(
        mut self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> PkiResult<Certificate> {
        if self.serial_number.is_empty() {
            self.serial_number = make_random_serial()?;
        }
        let tbs_der = self.build_unsigned_tbs(self_signed)?;
        let signature =
            sign_rsa_pss_keypair(self.signature_algorithm.signature, &tbs_der, issuer_key)?;
        self.build_with_signature(signature, self_signed)
    }

    pub fn build_rsa_pss_result(self, issuer_key: &KeyPair) -> CertificateResult<Certificate> {
        self.build_rsa_pss_result_with_self_signed(issuer_key, false)
    }

    pub fn build_rsa_pss_result_with_self_signed(
        self,
        issuer_key: &KeyPair,
        self_signed: bool,
    ) -> CertificateResult<Certificate> {
        match self.build_rsa_pss_with_self_signed(issuer_key, self_signed) {
            Ok(cert) => CertificateResult::ok(cert),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_unsigned_tbs(&self, self_signed: bool) -> PkiResult<Vec<u8>> {
        self.validate_inputs(self_signed)?;
        let serial = self.serial_or_random()?;
        let issuer = if self_signed {
            self.subject.clone()
        } else if self.issuer_explicit {
            self.issuer.clone()
        } else {
            self.subject.clone()
        };
        self.encode_tbs_certificate(&serial, &issuer)
    }

    pub fn build_unsigned_tbs_result(&self, self_signed: bool) -> CertificateResult<Vec<u8>> {
        match self.build_unsigned_tbs(self_signed) {
            Ok(tbs) => CertificateResult::ok(tbs),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    fn serial_or_random(&self) -> PkiResult<Vec<u8>> {
        if self.serial_number.is_empty() {
            make_random_serial()
        } else {
            Ok(self.serial_number.clone())
        }
    }

    fn validate_inputs(&self, self_signed: bool) -> PkiResult<()> {
        if !self.subject_explicit {
            return Err(PkiError::new("Subject not set"));
        }
        if !self.issuer_explicit && !self_signed {
            return Err(PkiError::new("Issuer not set"));
        }
        if self.subject_public_key_info.public_key.is_empty() {
            return Err(PkiError::new("Subject public key not provided"));
        }
        if !validity_range_is_valid(&self.validity) {
            return Err(PkiError::new("Invalid validity range"));
        }
        if oid_for_signature(self.signature_algorithm.signature).is_none() {
            return Err(PkiError::new("Unsupported signature algorithm for builder"));
        }
        Ok(())
    }

    fn encode_tbs_certificate(
        &self,
        serial: &[u8],
        issuer: &DistinguishedName,
    ) -> PkiResult<Vec<u8>> {
        let mut fields = Vec::new();
        if self.version != 1 {
            let version_value = der::encode_integer((self.version - 1) as u64);
            fields.push(der::encode_context_constructed(0, &version_value));
        }
        fields.push(der::encode_integer_bytes(serial));
        fields.push(encode_certificate_algorithm_identifier(
            &self.signature_algorithm,
        )?);
        fields.push(issuer.der().to_vec());
        fields.push(encode_validity(&self.validity));
        fields.push(self.subject.der().to_vec());
        fields.push(encode_certificate_subject_public_key_info(
            &self.subject_public_key_info,
        )?);
        if !self.extensions.is_empty() {
            fields.push(der::encode_context_constructed(
                3,
                &encode_certificate_extensions(&self.extensions),
            ));
        }
        Ok(der::encode_sequence(&der::concat(&fields)))
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

pub fn build_basic_constraints_extension(
    is_ca: bool,
    path_length: Option<u32>,
    critical: bool,
) -> PkiResult<RawExtension> {
    let mut fields = Vec::new();
    if is_ca {
        fields.push(der::encode_boolean(true));
        if let Some(path_length) = path_length {
            fields.push(der::encode_integer(u64::from(path_length)));
        }
    } else if let Some(path_length) = path_length {
        fields.push(der::encode_integer(u64::from(path_length)));
    }
    raw_extension(
        ExtensionId::BasicConstraints,
        critical,
        der::encode_sequence(&der::concat(&fields)),
    )
}

pub fn build_key_usage_extension(bits: u16, critical: bool) -> PkiResult<RawExtension> {
    let mut buffer = Vec::new();
    if bits > 0xff {
        buffer.push(((bits >> 8) & 0xff) as u8);
    }
    buffer.push((bits & 0xff) as u8);
    raw_extension(
        ExtensionId::KeyUsage,
        critical,
        der::encode_bit_string(&buffer),
    )
}

pub fn build_extended_key_usage_extension(
    purpose_oids: &[Oid],
    critical: bool,
) -> PkiResult<RawExtension> {
    let encoded = purpose_oids.iter().map(der::encode_oid).collect::<Vec<_>>();
    raw_extension(
        ExtensionId::ExtendedKeyUsage,
        critical,
        der::encode_sequence(&der::concat(&encoded)),
    )
}

pub fn build_subject_alt_name_extension(
    names: &[GeneralName],
    critical: bool,
) -> PkiResult<RawExtension> {
    raw_extension(
        ExtensionId::SubjectAltName,
        critical,
        der::encode_sequence(&encode_general_names(names)),
    )
}

pub fn build_key_identifier_extension(
    key_id: &[u8],
    critical: bool,
    id: ExtensionId,
) -> PkiResult<RawExtension> {
    raw_extension(id, critical, der::encode_octet_string(key_id))
}

pub fn encode_certificate_algorithm_identifier(
    algorithm: &AlgorithmIdentifier,
) -> PkiResult<Vec<u8>> {
    let oid = oid_for_signature(algorithm.signature)
        .ok_or_else(|| PkiError::new("unsupported signature algorithm"))?;
    Ok(der::encode_sequence(&der::encode_oid(&oid)))
}

pub fn encode_certificate_subject_public_key_info(
    spki: &SubjectPublicKeyInfo,
) -> PkiResult<Vec<u8>> {
    Ok(der::encode_sequence(&der::concat(&[
        encode_certificate_algorithm_identifier(&spki.algorithm)?,
        der::encode_bit_string_with_unused_bits(&spki.public_key, spki.unused_bits),
    ])))
}

pub fn encode_validity(validity: &Validity) -> Vec<u8> {
    der::encode_sequence(&der::concat(&[
        encode_der_time(&validity.not_before),
        encode_der_time(&validity.not_after),
    ]))
}

pub fn encode_certificate_extensions(extensions: &[RawExtension]) -> Vec<u8> {
    let encoded = extensions
        .iter()
        .map(encode_certificate_extension)
        .collect::<Vec<_>>();
    der::encode_sequence(&der::concat(&encoded))
}

pub fn encode_certificate_extension(extension: &RawExtension) -> Vec<u8> {
    let mut fields = vec![der::encode_oid(&extension.oid)];
    if extension.critical {
        fields.push(der::encode_boolean(true));
    }
    fields.push(der::encode_octet_string(&extension.value));
    der::encode_sequence(&der::concat(&fields))
}

pub fn encode_general_names(names: &[GeneralName]) -> Vec<u8> {
    let encoded = names
        .iter()
        .filter_map(|name| match name.type_ {
            GeneralNameType::Email => Some(der::encode_context_primitive(1, &name.value)),
            GeneralNameType::DnsName => Some(der::encode_context_primitive(2, &name.value)),
            GeneralNameType::Uri => Some(der::encode_context_primitive(6, &name.value)),
            GeneralNameType::IpAddress => Some(der::encode_context_primitive(
                7,
                &encode_ip_address_value(&name.value),
            )),
            GeneralNameType::Other => None,
        })
        .collect::<Vec<_>>();
    der::concat(&encoded)
}

fn encode_ip_address_value(value: &[u8]) -> Vec<u8> {
    if let Ok(text) = std::str::from_utf8(value) {
        if text.contains('.') {
            let octets = text
                .split('.')
                .map(|part| part.parse::<u8>())
                .collect::<Result<Vec<_>, _>>();
            if let Ok(octets) = octets {
                return octets;
            }
        }
        if text.contains(':') {
            let mut bytes = Vec::new();
            for segment in text.split(':').filter(|segment| !segment.is_empty()) {
                if let Ok(value) = u16::from_str_radix(segment, 16) {
                    bytes.push(((value >> 8) & 0xff) as u8);
                    bytes.push((value & 0xff) as u8);
                } else {
                    return value.to_vec();
                }
            }
            return bytes;
        }
    }
    value.to_vec()
}

fn raw_extension(id: ExtensionId, critical: bool, value: Vec<u8>) -> PkiResult<RawExtension> {
    let oid = oid_for_extension(id).ok_or_else(|| PkiError::new("unsupported extension id"))?;
    Ok(RawExtension {
        oid,
        id,
        critical,
        value,
    })
}

fn validity_range_is_valid(validity: &Validity) -> bool {
    time_tuple(&validity.not_before) < time_tuple(&validity.not_after)
}

fn time_tuple(time: &DerTime) -> (i32, u8, u8, u8, u8, u8) {
    (
        time.year,
        time.month,
        time.day,
        time.hour,
        time.minute,
        time.second,
    )
}

pub fn key_purpose_oid(purpose: super::KeyPurposeId) -> Oid {
    ExtendedKeyUsage::purpose_to_oid(purpose)
}

pub fn make_random_serial() -> PkiResult<Vec<u8>> {
    super::detail::make_random_serial()
}

pub fn rsa_signature_algorithm_for_hash(hash: HashAlgorithm, pss: bool) -> SignatureAlgorithmId {
    match (hash, pss) {
        (HashAlgorithm::Sha256, false) => SignatureAlgorithmId::RsaPkcs1Sha256,
        (HashAlgorithm::Sha384, false) => SignatureAlgorithmId::RsaPkcs1Sha384,
        (HashAlgorithm::Sha512, false) => SignatureAlgorithmId::RsaPkcs1Sha512,
        (HashAlgorithm::Sha256, true) => SignatureAlgorithmId::RsaPssSha256,
        (HashAlgorithm::Sha384, true) => SignatureAlgorithmId::RsaPssSha384,
        (HashAlgorithm::Sha512, true) => SignatureAlgorithmId::RsaPssSha512,
        (HashAlgorithm::Blake2b | HashAlgorithm::Keccak256, false) => {
            SignatureAlgorithmId::RsaPkcs1Sha256
        }
        (HashAlgorithm::Blake2b | HashAlgorithm::Keccak256, true) => {
            SignatureAlgorithmId::RsaPssSha256
        }
    }
}
