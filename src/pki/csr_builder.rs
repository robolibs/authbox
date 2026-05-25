use super::{
    AlgorithmIdentifier, CertificateRequest, CertificateResult, CertificationRequestInfo, CurveId,
    DistinguishedName, HashAlgorithm, KeyPair, PkiError, PkiResult, RawExtension,
    SignatureAlgorithmId, SubjectPublicKeyInfo, der, encode_algorithm_identifier,
    encode_csr_attributes, encode_ecdsa_p256_signature_der, encode_ecdsa_p384_signature_der,
    encode_ecdsa_p521_signature_der, encode_subject_public_key_info, sign_ecdsa_p256_sha256,
    sign_ecdsa_p384_sha384, sign_ecdsa_p521_sha512, sign_ed448_detached, sign_ed25519_detached,
    sign_rsa_pkcs1v15_keypair, sign_rsa_pss_keypair,
};

#[derive(Clone, Debug)]
pub struct CsrBuilder {
    info: CertificationRequestInfo,
    subject_set: bool,
    spki_set: bool,
    signature_algorithm: AlgorithmIdentifier,
}

impl Default for CsrBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CsrBuilder {
    pub fn new() -> Self {
        Self {
            info: CertificationRequestInfo::default(),
            subject_set: false,
            spki_set: false,
            signature_algorithm: AlgorithmIdentifier {
                signature: SignatureAlgorithmId::Ed25519,
                hash: HashAlgorithm::Sha256,
                curve: CurveId::Ed25519,
            },
        }
    }

    pub fn set_subject(mut self, subject: DistinguishedName) -> Self {
        self.info.subject = subject;
        self.subject_set = true;
        self
    }

    pub fn set_subject_from_string(mut self, subject: &str) -> PkiResult<Self> {
        self.info.subject = DistinguishedName::from_string(subject)?;
        self.subject_set = true;
        Ok(self)
    }

    pub fn set_subject_public_key(mut self, spki: SubjectPublicKeyInfo) -> Self {
        self.info.subject_public_key_info = spki;
        self.spki_set = true;
        self
    }

    pub fn set_subject_public_key_ed25519(mut self, public_key: impl Into<Vec<u8>>) -> Self {
        self.info.subject_public_key_info = super::ed25519_subject_public_key_info(public_key);
        self.spki_set = true;
        self
    }

    pub fn set_subject_public_key_ed448(mut self, public_key: impl Into<Vec<u8>>) -> Self {
        self.info.subject_public_key_info = super::ed448_subject_public_key_info(public_key);
        self.spki_set = true;
        self
    }

    pub fn set_subject_public_key_ecdsa_p256(mut self, public_key: impl Into<Vec<u8>>) -> Self {
        self.info.subject_public_key_info = super::ecdsa_p256_subject_public_key_info(public_key);
        self.spki_set = true;
        self
    }

    pub fn set_subject_public_key_ecdsa_p384(mut self, public_key: impl Into<Vec<u8>>) -> Self {
        self.info.subject_public_key_info = super::ecdsa_p384_subject_public_key_info(public_key);
        self.spki_set = true;
        self
    }

    pub fn set_subject_public_key_ecdsa_p521(mut self, public_key: impl Into<Vec<u8>>) -> Self {
        self.info.subject_public_key_info = super::ecdsa_p521_subject_public_key_info(public_key);
        self.spki_set = true;
        self
    }

    pub fn set_signature_algorithm(mut self, signature: SignatureAlgorithmId) -> Self {
        self.signature_algorithm.signature = signature;
        if signature == SignatureAlgorithmId::Ed25519 {
            self.signature_algorithm.curve = CurveId::Ed25519;
        }
        self
    }

    pub fn add_extension(mut self, extension: RawExtension) -> Self {
        self.info.extensions.push(extension);
        self
    }

    pub fn build_with_signature(
        mut self,
        signature: impl Into<Vec<u8>>,
    ) -> PkiResult<CertificateRequest> {
        self.validate_inputs()?;
        let cri_der = self.encode_cri()?;
        let signature =
            normalize_signature_for_emit(signature.into(), self.signature_algorithm.signature)?;
        let der = der::encode_sequence(&der::concat(&[
            cri_der.clone(),
            encode_algorithm_identifier(&self.signature_algorithm)?,
            der::encode_bit_string(&signature),
        ]));
        self.info.der = cri_der.clone();
        Ok(CertificateRequest {
            info: self.info,
            signature_algorithm: self.signature_algorithm,
            signature,
            der,
            cri_der,
        })
    }

    pub fn build(self, key: &KeyPair) -> PkiResult<CertificateRequest> {
        match self.signature_algorithm.signature {
            SignatureAlgorithmId::Ed25519 => self.build_ed25519(key),
            SignatureAlgorithmId::Ed448 => self.build_ed448(key),
            SignatureAlgorithmId::EcdsaSha256 => self.build_ecdsa_p256_sha256(key),
            SignatureAlgorithmId::EcdsaSha384 => self.build_ecdsa_p384_sha384(key),
            SignatureAlgorithmId::EcdsaSha512 => self.build_ecdsa_p521_sha512(key),
            SignatureAlgorithmId::RsaPkcs1Sha256
            | SignatureAlgorithmId::RsaPkcs1Sha384
            | SignatureAlgorithmId::RsaPkcs1Sha512 => self.build_rsa_pkcs1v15(key),
            SignatureAlgorithmId::RsaPssSha256
            | SignatureAlgorithmId::RsaPssSha384
            | SignatureAlgorithmId::RsaPssSha512 => self.build_rsa_pss(key),
            _ => Err(PkiError::new("Unsupported CSR signature algorithm")),
        }
    }

    pub fn build_result(self, key: &KeyPair) -> CertificateResult<CertificateRequest> {
        match self.build(key) {
            Ok(csr) => CertificateResult::ok(csr),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ed25519(mut self, key: &KeyPair) -> PkiResult<CertificateRequest> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::Ed25519,
            hash: HashAlgorithm::Sha256,
            curve: CurveId::Ed25519,
        };
        self.validate_inputs()?;
        let cri_der = self.encode_cri()?;
        let signature = sign_ed25519_detached(&cri_der, &key.private_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_ed25519_result(self, key: &KeyPair) -> CertificateResult<CertificateRequest> {
        match self.build_ed25519(key) {
            Ok(csr) => CertificateResult::ok(csr),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ed448(mut self, key: &KeyPair) -> PkiResult<CertificateRequest> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::Ed448,
            hash: HashAlgorithm::Sha512,
            curve: CurveId::Ed448,
        };
        self.validate_inputs()?;
        let cri_der = self.encode_cri()?;
        let signature = sign_ed448_detached(&cri_der, &key.private_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_ecdsa_p256_sha256(mut self, key: &KeyPair) -> PkiResult<CertificateRequest> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::EcdsaSha256,
            hash: HashAlgorithm::Sha256,
            curve: CurveId::Secp256r1,
        };
        self.validate_inputs()?;
        let cri_der = self.encode_cri()?;
        let signature = sign_ecdsa_p256_sha256(&cri_der, &key.private_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_ecdsa_p256_sha256_result(
        self,
        key: &KeyPair,
    ) -> CertificateResult<CertificateRequest> {
        match self.build_ecdsa_p256_sha256(key) {
            Ok(csr) => CertificateResult::ok(csr),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ecdsa_p384_sha384(mut self, key: &KeyPair) -> PkiResult<CertificateRequest> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::EcdsaSha384,
            hash: HashAlgorithm::Sha384,
            curve: CurveId::Secp384r1,
        };
        self.validate_inputs()?;
        let cri_der = self.encode_cri()?;
        let signature = sign_ecdsa_p384_sha384(&cri_der, &key.private_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_ecdsa_p384_sha384_result(
        self,
        key: &KeyPair,
    ) -> CertificateResult<CertificateRequest> {
        match self.build_ecdsa_p384_sha384(key) {
            Ok(csr) => CertificateResult::ok(csr),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ecdsa_p521_sha512(mut self, key: &KeyPair) -> PkiResult<CertificateRequest> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::EcdsaSha512,
            hash: HashAlgorithm::Sha512,
            curve: CurveId::Secp521r1,
        };
        self.validate_inputs()?;
        let cri_der = self.encode_cri()?;
        let signature = sign_ecdsa_p521_sha512(&cri_der, &key.private_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_ecdsa_p521_sha512_result(
        self,
        key: &KeyPair,
    ) -> CertificateResult<CertificateRequest> {
        match self.build_ecdsa_p521_sha512(key) {
            Ok(csr) => CertificateResult::ok(csr),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_rsa_pkcs1v15(self, key: &KeyPair) -> PkiResult<CertificateRequest> {
        self.validate_inputs()?;
        let cri_der = self.encode_cri()?;
        let signature =
            sign_rsa_pkcs1v15_keypair(self.signature_algorithm.signature, &cri_der, key)?;
        self.build_with_signature(signature)
    }

    pub fn build_rsa_pkcs1v15_result(self, key: &KeyPair) -> CertificateResult<CertificateRequest> {
        match self.build_rsa_pkcs1v15(key) {
            Ok(csr) => CertificateResult::ok(csr),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_rsa_pss(self, key: &KeyPair) -> PkiResult<CertificateRequest> {
        self.validate_inputs()?;
        let cri_der = self.encode_cri()?;
        let signature = sign_rsa_pss_keypair(self.signature_algorithm.signature, &cri_der, key)?;
        self.build_with_signature(signature)
    }

    pub fn build_rsa_pss_result(self, key: &KeyPair) -> CertificateResult<CertificateRequest> {
        match self.build_rsa_pss(key) {
            Ok(csr) => CertificateResult::ok(csr),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_unsigned_for_signing(mut self) -> PkiResult<CertificationRequestInfo> {
        self.validate_inputs()?;
        self.info.der = self.encode_cri()?;
        Ok(self.info)
    }

    pub fn build_unsigned_for_signing_result(self) -> CertificateResult<CertificationRequestInfo> {
        match self.build_unsigned_for_signing() {
            Ok(info) => CertificateResult::ok(info),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    fn validate_inputs(&self) -> PkiResult<()> {
        if !self.subject_set {
            return Err(PkiError::new("subject not set"));
        }
        if !self.spki_set {
            return Err(PkiError::new("subject public key not set"));
        }
        Ok(())
    }

    fn encode_cri(&self) -> PkiResult<Vec<u8>> {
        Ok(der::encode_sequence(&der::concat(&[
            der::encode_integer(self.info.version as u64),
            self.info.subject.der().to_vec(),
            encode_subject_public_key_info(&self.info.subject_public_key_info)?,
            encode_csr_attributes(&self.info.extensions),
        ])))
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
