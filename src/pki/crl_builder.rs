use super::{
    AlgorithmIdentifier, CertificateResult, Crl, CrlReason, CurveId, DerTime, DistinguishedName,
    HashAlgorithm, KeyPair, Oid, PkiError, PkiResult, RevokedCertificate, SignatureAlgorithmId,
    der, encode_crl_reason, encode_der_time, encode_ecdsa_p256_signature_der,
    encode_ecdsa_p384_signature_der, encode_ecdsa_p521_signature_der, oid_for_signature,
    sign_ecdsa_p256_sha256, sign_ecdsa_p384_sha384, sign_ecdsa_p521_sha512, sign_ed448_detached,
    sign_ed25519_detached, sign_rsa_pkcs1v15_keypair, sign_rsa_pss_keypair,
};

#[derive(Clone, Debug)]
pub struct CrlBuilder {
    issuer: DistinguishedName,
    issuer_set: bool,
    this_update: Option<DerTime>,
    next_update: Option<DerTime>,
    entries: Vec<RevokedCertificate>,
    signature_algorithm: AlgorithmIdentifier,
}

impl Default for CrlBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CrlBuilder {
    pub fn new() -> Self {
        Self {
            issuer: DistinguishedName::default(),
            issuer_set: false,
            this_update: None,
            next_update: None,
            entries: Vec::new(),
            signature_algorithm: AlgorithmIdentifier {
                signature: SignatureAlgorithmId::Ed25519,
                hash: HashAlgorithm::Sha256,
                curve: CurveId::Ed25519,
            },
        }
    }

    pub fn set_issuer(mut self, issuer: DistinguishedName) -> Self {
        self.issuer = issuer;
        self.issuer_set = true;
        self
    }

    pub fn set_issuer_from_string(mut self, issuer: &str) -> PkiResult<Self> {
        self.issuer = DistinguishedName::from_string(issuer)?;
        self.issuer_set = true;
        Ok(self)
    }

    pub fn set_this_update(mut self, time: DerTime) -> Self {
        self.this_update = Some(time);
        self
    }

    pub fn set_next_update(mut self, time: DerTime) -> Self {
        self.next_update = Some(time);
        self
    }

    pub fn add_revoked(mut self, entry: RevokedCertificate) -> Self {
        self.entries.push(entry);
        self
    }

    pub fn add_revoked_serial(self, serial: impl Into<Vec<u8>>, when: DerTime) -> Self {
        self.add_revoked_serial_with_options(serial, when, None, None)
    }

    pub fn add_revoked_serial_with_reason(
        self,
        serial: impl Into<Vec<u8>>,
        when: DerTime,
        reason: CrlReason,
    ) -> Self {
        self.add_revoked_serial_with_options(serial, when, Some(reason), None)
    }

    pub fn add_revoked_serial_with_options(
        mut self,
        serial: impl Into<Vec<u8>>,
        when: DerTime,
        reason: Option<CrlReason>,
        invalidity: Option<DerTime>,
    ) -> Self {
        self.entries.push(RevokedCertificate {
            serial_number: serial.into(),
            revocation_date: when,
            reason,
            invalidity_date: invalidity,
            ..RevokedCertificate::default()
        });
        self
    }

    pub fn set_signature_algorithm(mut self, algorithm: SignatureAlgorithmId) -> Self {
        self.signature_algorithm.signature = algorithm;
        if algorithm == SignatureAlgorithmId::Ed25519 {
            self.signature_algorithm.curve = CurveId::Ed25519;
        }
        self
    }

    pub fn build(self, issuer_key: &KeyPair) -> PkiResult<Crl> {
        match self.signature_algorithm.signature {
            SignatureAlgorithmId::Ed25519 => self.build_ed25519(issuer_key),
            SignatureAlgorithmId::Ed448 => self.build_ed448(issuer_key),
            SignatureAlgorithmId::EcdsaSha256 => self.build_ecdsa_p256_sha256(issuer_key),
            SignatureAlgorithmId::EcdsaSha384 => self.build_ecdsa_p384_sha384(issuer_key),
            SignatureAlgorithmId::EcdsaSha512 => self.build_ecdsa_p521_sha512(issuer_key),
            SignatureAlgorithmId::RsaPkcs1Sha256
            | SignatureAlgorithmId::RsaPkcs1Sha384
            | SignatureAlgorithmId::RsaPkcs1Sha512 => self.build_rsa_pkcs1v15(issuer_key),
            SignatureAlgorithmId::RsaPssSha256
            | SignatureAlgorithmId::RsaPssSha384
            | SignatureAlgorithmId::RsaPssSha512 => self.build_rsa_pss(issuer_key),
            _ => Err(PkiError::new("Unsupported CRL signature algorithm")),
        }
    }

    pub fn build_result(self, issuer_key: &KeyPair) -> CertificateResult<Crl> {
        match self.build(issuer_key) {
            Ok(crl) => CertificateResult::ok(crl),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ed25519(mut self, issuer_key: &KeyPair) -> PkiResult<Crl> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::Ed25519,
            hash: HashAlgorithm::Sha256,
            curve: CurveId::Ed25519,
        };
        let tbs_der = self.build_unsigned_tbs()?;
        let signature = sign_ed25519_detached(&tbs_der, &issuer_key.private_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_ed25519_result(self, issuer_key: &KeyPair) -> CertificateResult<Crl> {
        match self.build_ed25519(issuer_key) {
            Ok(crl) => CertificateResult::ok(crl),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ed448(mut self, issuer_key: &KeyPair) -> PkiResult<Crl> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::Ed448,
            hash: HashAlgorithm::Sha512,
            curve: CurveId::Ed448,
        };
        let tbs_der = self.build_unsigned_tbs()?;
        let signature = sign_ed448_detached(&tbs_der, &issuer_key.private_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_ecdsa_p256_sha256(mut self, issuer_key: &KeyPair) -> PkiResult<Crl> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::EcdsaSha256,
            hash: HashAlgorithm::Sha256,
            curve: CurveId::Secp256r1,
        };
        let tbs_der = self.build_unsigned_tbs()?;
        let signature = sign_ecdsa_p256_sha256(&tbs_der, &issuer_key.private_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_ecdsa_p256_sha256_result(self, issuer_key: &KeyPair) -> CertificateResult<Crl> {
        match self.build_ecdsa_p256_sha256(issuer_key) {
            Ok(crl) => CertificateResult::ok(crl),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ecdsa_p384_sha384(mut self, issuer_key: &KeyPair) -> PkiResult<Crl> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::EcdsaSha384,
            hash: HashAlgorithm::Sha384,
            curve: CurveId::Secp384r1,
        };
        let tbs_der = self.build_unsigned_tbs()?;
        let signature = sign_ecdsa_p384_sha384(&tbs_der, &issuer_key.private_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_ecdsa_p384_sha384_result(self, issuer_key: &KeyPair) -> CertificateResult<Crl> {
        match self.build_ecdsa_p384_sha384(issuer_key) {
            Ok(crl) => CertificateResult::ok(crl),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_ecdsa_p521_sha512(mut self, issuer_key: &KeyPair) -> PkiResult<Crl> {
        self.signature_algorithm = AlgorithmIdentifier {
            signature: SignatureAlgorithmId::EcdsaSha512,
            hash: HashAlgorithm::Sha512,
            curve: CurveId::Secp521r1,
        };
        let tbs_der = self.build_unsigned_tbs()?;
        let signature = sign_ecdsa_p521_sha512(&tbs_der, &issuer_key.private_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_ecdsa_p521_sha512_result(self, issuer_key: &KeyPair) -> CertificateResult<Crl> {
        match self.build_ecdsa_p521_sha512(issuer_key) {
            Ok(crl) => CertificateResult::ok(crl),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_rsa_pkcs1v15(self, issuer_key: &KeyPair) -> PkiResult<Crl> {
        let tbs_der = self.build_unsigned_tbs()?;
        let signature =
            sign_rsa_pkcs1v15_keypair(self.signature_algorithm.signature, &tbs_der, issuer_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_rsa_pkcs1v15_result(self, issuer_key: &KeyPair) -> CertificateResult<Crl> {
        match self.build_rsa_pkcs1v15(issuer_key) {
            Ok(crl) => CertificateResult::ok(crl),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_rsa_pss(self, issuer_key: &KeyPair) -> PkiResult<Crl> {
        let tbs_der = self.build_unsigned_tbs()?;
        let signature =
            sign_rsa_pss_keypair(self.signature_algorithm.signature, &tbs_der, issuer_key)?;
        self.build_with_signature(signature)
    }

    pub fn build_rsa_pss_result(self, issuer_key: &KeyPair) -> CertificateResult<Crl> {
        match self.build_rsa_pss(issuer_key) {
            Ok(crl) => CertificateResult::ok(crl),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_with_signature(self, signature: impl Into<Vec<u8>>) -> PkiResult<Crl> {
        self.validate_inputs()?;
        let this_update = self.this_update.clone().expect("validated this_update");
        let tbs_der = self.encode_tbs()?;
        let signature_value =
            normalize_signature_for_emit(signature.into(), self.signature_algorithm.signature)?;
        let alg = self.signature_algorithm.clone();
        let der = der::encode_sequence(&der::concat(&[
            tbs_der.clone(),
            encode_algorithm_identifier(alg.signature)?,
            der::encode_bit_string(&signature_value),
        ]));
        Ok(Crl {
            version: 2,
            signature: alg.clone(),
            issuer: self.issuer,
            this_update,
            next_update: self.next_update,
            revoked: self.entries,
            outer_signature: alg,
            signature_value,
            der,
            tbs_der,
            ..Crl::default()
        })
    }

    pub fn build_with_signature_result(
        self,
        signature: impl Into<Vec<u8>>,
    ) -> CertificateResult<Crl> {
        match self.build_with_signature(signature) {
            Ok(crl) => CertificateResult::ok(crl),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn build_unsigned_tbs(&self) -> PkiResult<Vec<u8>> {
        self.validate_inputs()?;
        self.encode_tbs()
    }

    pub fn build_unsigned_tbs_result(&self) -> CertificateResult<Vec<u8>> {
        match self.build_unsigned_tbs() {
            Ok(tbs) => CertificateResult::ok(tbs),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    fn validate_inputs(&self) -> PkiResult<()> {
        if !self.issuer_set {
            return Err(PkiError::new("issuer not set"));
        }
        if self.this_update.is_none() {
            return Err(PkiError::new("thisUpdate not set"));
        }
        if oid_for_signature(self.signature_algorithm.signature).is_none() {
            return Err(PkiError::new("unsupported CRL signature algorithm"));
        }
        Ok(())
    }

    fn encode_tbs(&self) -> PkiResult<Vec<u8>> {
        let mut fields = vec![
            der::encode_integer(1),
            encode_algorithm_identifier(self.signature_algorithm.signature)?,
            self.issuer.der().to_vec(),
            encode_der_time(self.this_update.as_ref().expect("validated this_update")),
        ];
        if let Some(next_update) = &self.next_update {
            fields.push(encode_der_time(next_update));
        }
        if !self.entries.is_empty() {
            fields.push(self.encode_revoked_entries());
        }
        Ok(der::encode_sequence(&der::concat(&fields)))
    }

    fn encode_revoked_entries(&self) -> Vec<u8> {
        let entries = self
            .entries
            .iter()
            .map(|entry| {
                let mut fields = vec![
                    der::encode_integer_bytes(&entry.serial_number),
                    encode_der_time(&entry.revocation_date),
                ];
                let extensions = encode_entry_extensions(entry);
                if !extensions.is_empty() {
                    fields.push(der::encode_sequence(&der::concat(&extensions)));
                }
                der::encode_sequence(&der::concat(&fields))
            })
            .collect::<Vec<_>>();
        der::encode_sequence(&der::concat(&entries))
    }
}

fn encode_algorithm_identifier(algorithm: SignatureAlgorithmId) -> PkiResult<Vec<u8>> {
    let oid = oid_for_signature(algorithm)
        .ok_or_else(|| PkiError::new("unsupported CRL signature algorithm"))?;
    Ok(der::encode_sequence(&der::encode_oid(&oid)))
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

fn encode_entry_extensions(entry: &RevokedCertificate) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(reason) = entry.reason {
        out.push(der::encode_sequence(&der::concat(&[
            der::encode_oid(&Oid::new([2, 5, 29, 21])),
            der::encode_octet_string(&encode_crl_reason(reason)),
        ])));
    }
    if let Some(invalidity) = &entry.invalidity_date {
        out.push(der::encode_sequence(&der::concat(&[
            der::encode_oid(&Oid::new([2, 5, 29, 24])),
            der::encode_octet_string(&der::encode_generalized_time(&format!(
                "{:04}{:02}{:02}{:02}{:02}{:02}Z",
                invalidity.year,
                invalidity.month,
                invalidity.day,
                invalidity.hour,
                invalidity.minute,
                invalidity.second
            ))),
        ])));
    }
    out.extend(entry.extensions.iter().map(|extension| {
        let mut fields = vec![der::encode_oid(&extension.oid)];
        if extension.critical {
            fields.push(der::encode_boolean(true));
        }
        fields.push(der::encode_octet_string(&extension.value));
        der::encode_sequence(&der::concat(&fields))
    }));
    out
}
