use super::{
    AlgorithmIdentifier, Asn1Class, Asn1Read, Asn1Tag, Certificate, CertificateBoolResult,
    CertificateResult, CertificateSignatureResult, CrlEntryExtensionId, CrlExtensionId, Cursor,
    DerTime, DistinguishedName, KeyPair, Oid, PkiError, PkiResult, SignatureAlgorithmId, der,
    find_sig_alg_by_oid, parse_bit_string, parse_boolean, parse_generalized_time, parse_id_len,
    parse_integer, parse_octet_string, parse_oid, parse_sequence, parse_utc_time, read_pem_or_der,
    sign_ecdsa_p256_sha256, sign_ecdsa_p384_sha384, sign_ecdsa_p521_sha512, sign_ed448_detached,
    sign_ed25519_detached, sign_rsa_pkcs1v15_keypair, sign_rsa_pss_keypair, verify_signature_bytes,
};
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CrlReason {
    Unspecified = 0,
    KeyCompromise = 1,
    CaCompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    RemoveFromCrl = 8,
    PrivilegeWithdrawn = 9,
    AaCompromise = 10,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CrlEntryExtension {
    pub id: CrlEntryExtensionId,
    pub oid: Oid,
    pub critical: bool,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CrlExtension {
    pub id: CrlExtensionId,
    pub oid: Oid,
    pub critical: bool,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CrlDerCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> CrlDerCursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }

    pub fn empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn advance(&mut self, bytes: usize) -> bool {
        if self.offset + bytes > self.data.len() {
            return false;
        }
        self.offset += bytes;
        true
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevokedCertificate {
    pub serial_number: Vec<u8>,
    pub revocation_date: DerTime,
    pub reason: Option<CrlReason>,
    pub invalidity_date: Option<DerTime>,
    pub certificate_issuer: Option<DistinguishedName>,
    pub extensions: Vec<CrlEntryExtension>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Crl {
    pub version: i32,
    pub signature: AlgorithmIdentifier,
    pub issuer: DistinguishedName,
    pub this_update: DerTime,
    pub next_update: Option<DerTime>,
    pub revoked: Vec<RevokedCertificate>,
    pub extensions: Vec<CrlExtension>,
    pub authority_key_identifier: Option<Vec<u8>>,
    pub crl_number: Option<Vec<u8>>,
    pub delta_crl_indicator: Option<Vec<u8>>,
    pub has_issuing_distribution_point: bool,
    pub outer_signature: AlgorithmIdentifier,
    pub signature_value: Vec<u8>,
    pub der: Vec<u8>,
    pub tbs_der: Vec<u8>,
}

impl Crl {
    pub fn is_certificate_revoked(&self, serial: &[u8]) -> bool {
        self.find_revoked_cert(serial).is_some()
    }

    pub fn find_revoked_cert(&self, serial: &[u8]) -> Option<&RevokedCertificate> {
        self.revoked
            .iter()
            .find(|entry| entry.serial_number == serial)
    }

    pub fn check_validity(&self) -> bool {
        self.check_validity_at(&current_der_time_utc())
    }

    pub fn check_validity_at(&self, check_time: &DerTime) -> bool {
        if compare_der_time(check_time, &self.this_update).is_lt() {
            return false;
        }
        if let Some(next_update) = &self.next_update
            && compare_der_time(check_time, next_update).is_gt()
        {
            return false;
        }
        true
    }

    pub fn check_validity_now(&self) -> bool {
        self.check_validity()
    }

    pub fn find_extension(&self, id: CrlExtensionId) -> Option<&CrlExtension> {
        self.extensions.iter().find(|ext| ext.id == id)
    }

    pub fn to_pem(&self) -> String {
        super::pem_encode(&self.der, "X509 CRL")
    }

    pub fn from_der(der: impl AsRef<[u8]>) -> PkiResult<Self> {
        parse_crl(der.as_ref())
    }

    pub fn from_der_result(der: impl AsRef<[u8]>) -> CertificateResult<Self> {
        parse_crl_result(der.as_ref())
    }

    pub fn from_pem(pem: &str) -> PkiResult<Self> {
        parse_pem_crl_chain(pem)?
            .into_iter()
            .next()
            .ok_or_else(|| PkiError::new("no CRLs found in PEM"))
    }

    pub fn from_pem_result(pem: &str) -> CertificateResult<Self> {
        match Self::from_pem(pem) {
            Ok(crl) => CertificateResult::ok(crl),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn verify_signature(&self, issuer: &Certificate) -> PkiResult<bool> {
        if !matches!(
            self.outer_signature.signature,
            SignatureAlgorithmId::Ed25519
                | SignatureAlgorithmId::RsaPkcs1Sha256
                | SignatureAlgorithmId::RsaPkcs1Sha384
                | SignatureAlgorithmId::RsaPkcs1Sha512
                | SignatureAlgorithmId::RsaPssSha256
                | SignatureAlgorithmId::RsaPssSha384
                | SignatureAlgorithmId::RsaPssSha512
                | SignatureAlgorithmId::EcdsaSha256
                | SignatureAlgorithmId::EcdsaSha384
                | SignatureAlgorithmId::EcdsaSha512
        ) {
            return Err(PkiError::new(
                "Unsupported signature algorithm for CRL verification",
            ));
        }
        verify_signature_bytes(
            self.outer_signature.signature,
            &self.tbs_der,
            &self.signature_value,
            &issuer.tbs.subject_public_key_info.public_key,
        )
    }

    pub fn verify_signature_result(&self, issuer: &Certificate) -> CertificateBoolResult {
        match self.verify_signature(issuer) {
            Ok(valid) => CertificateResult::ok(valid),
            Err(error) => CertificateResult::failure(error.message),
        }
    }

    pub fn sign(&self, issuer_key: &KeyPair) -> PkiResult<Vec<u8>> {
        match self.outer_signature.signature {
            SignatureAlgorithmId::Ed25519 => {
                sign_ed25519_detached(&self.tbs_der, &issuer_key.private_key)
            }
            SignatureAlgorithmId::Ed448 => {
                sign_ed448_detached(&self.tbs_der, &issuer_key.private_key)
            }
            SignatureAlgorithmId::EcdsaSha256 => {
                sign_ecdsa_p256_sha256(&self.tbs_der, &issuer_key.private_key)
            }
            SignatureAlgorithmId::EcdsaSha384 => {
                sign_ecdsa_p384_sha384(&self.tbs_der, &issuer_key.private_key)
            }
            SignatureAlgorithmId::EcdsaSha512 => {
                sign_ecdsa_p521_sha512(&self.tbs_der, &issuer_key.private_key)
            }
            SignatureAlgorithmId::RsaPkcs1Sha256
            | SignatureAlgorithmId::RsaPkcs1Sha384
            | SignatureAlgorithmId::RsaPkcs1Sha512 => {
                sign_rsa_pkcs1v15_keypair(self.outer_signature.signature, &self.tbs_der, issuer_key)
            }
            SignatureAlgorithmId::RsaPssSha256
            | SignatureAlgorithmId::RsaPssSha384
            | SignatureAlgorithmId::RsaPssSha512 => {
                sign_rsa_pss_keypair(self.outer_signature.signature, &self.tbs_der, issuer_key)
            }
            _ => Err(PkiError::new("Unsupported CRL signature algorithm")),
        }
    }

    pub fn sign_result(&self, issuer_key: &KeyPair) -> CertificateSignatureResult {
        match self.sign(issuer_key) {
            Ok(signature) => CertificateResult::ok(signature),
            Err(error) => CertificateResult::failure(error.message),
        }
    }
}

impl Certificate {
    pub fn is_revoked(&self, crl: &Crl) -> bool {
        crl.is_certificate_revoked(&self.tbs.serial_number)
    }
}

fn compare_der_time(a: &DerTime, b: &DerTime) -> std::cmp::Ordering {
    (a.year, a.month, a.day, a.hour, a.minute, a.second)
        .cmp(&(b.year, b.month, b.day, b.hour, b.minute, b.second))
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

pub fn parse_crl(input: &[u8]) -> PkiResult<Crl> {
    parse_crl_with_relaxed(input, false)
}

pub fn parse_crl_with_relaxed(input: &[u8], relaxed: bool) -> PkiResult<Crl> {
    parse_crl_inner(input, relaxed)
}

pub fn parse_crl_result(input: &[u8]) -> CertificateResult<Crl> {
    parse_crl_result_with_relaxed(input, false)
}

pub fn parse_crl_result_with_relaxed(input: &[u8], relaxed: bool) -> CertificateResult<Crl> {
    match parse_crl_with_relaxed(input, relaxed) {
        Ok(crl) => CertificateResult::ok(crl),
        Err(error) => CertificateResult::failure(error.message),
    }
}

pub fn parse_crl_relaxed(input: &[u8]) -> PkiResult<Crl> {
    parse_crl_with_relaxed(input, true)
}

pub fn parse_crl_relaxed_result(input: &[u8]) -> CertificateResult<Crl> {
    parse_crl_result_with_relaxed(input, true)
}

fn parse_crl_inner(input: &[u8], relaxed: bool) -> PkiResult<Crl> {
    let top =
        parse_sequence(input).map_err(|err| PkiError::new(format!("CRL outer sequence: {err}")))?;
    let mut top_cursor = Cursor::new(&top.value);

    let tbs = parse_sequence(top_cursor.remaining())?;
    let tbs_der = top_cursor.remaining()[..tbs.bytes_consumed].to_vec();
    top_cursor.advance(tbs.bytes_consumed)?;

    let outer_signature = crl_parse_algorithm_identifier(top_cursor.remaining())?;
    top_cursor.advance(outer_signature.bytes_consumed)?;

    let signature = parse_bit_string(top_cursor.remaining())?;
    top_cursor.advance(signature.bytes_consumed)?;
    if !relaxed && !top_cursor.empty() {
        return Err(PkiError::new("unexpected trailing data in CRL"));
    }

    let mut crl = Crl {
        version: 1,
        outer_signature: outer_signature.value,
        signature_value: signature.value.bytes,
        der: input[..top.bytes_consumed].to_vec(),
        tbs_der,
        ..Crl::default()
    };

    parse_tbs_crl(&tbs.value, &mut crl)?;
    Ok(crl)
}

fn parse_tbs_crl(input: &[u8], crl: &mut Crl) -> PkiResult<()> {
    let mut cursor = Cursor::new(input);
    if !cursor.empty() {
        let header = parse_id_len(cursor.remaining())?;
        if header.value.identifier.tag_class == Asn1Class::Universal
            && header.value.identifier.tag_number == Asn1Tag::Integer as u32
        {
            let version = parse_integer(cursor.remaining())?;
            crl.version = integer_to_i32(&version.value)? + 1;
            cursor.advance(version.bytes_consumed)?;
        } else if header.value.identifier.tag_class == Asn1Class::ContextSpecific
            && header.value.identifier.tag_number == 0
        {
            let start = header.value.header_bytes;
            let end = start + header.value.length;
            let version = parse_integer(&cursor.remaining()[start..end])?;
            crl.version = integer_to_i32(&version.value)? + 1;
            cursor.advance(header.bytes_consumed)?;
        }
    }

    let signature = crl_parse_algorithm_identifier(cursor.remaining())?;
    crl.signature = signature.value;
    cursor.advance(signature.bytes_consumed)?;

    let issuer = crl_parse_name(cursor.remaining())?;
    crl.issuer = issuer.value;
    cursor.advance(issuer.bytes_consumed)?;

    let this_update = crl_parse_time(cursor.remaining())?;
    crl.this_update = this_update.value;
    cursor.advance(this_update.bytes_consumed)?;

    if !cursor.empty() && is_time_tag(cursor.remaining()[0]) {
        let next_update = crl_parse_time(cursor.remaining())?;
        crl.next_update = Some(next_update.value);
        cursor.advance(next_update.bytes_consumed)?;
    }

    if !cursor.empty() {
        let header = parse_id_len(cursor.remaining())?;
        if header.value.identifier.tag_class == Asn1Class::Universal
            && header.value.identifier.tag_number == Asn1Tag::Sequence as u32
        {
            let revoked = parse_revoked_certificates(cursor.remaining())?;
            crl.revoked = revoked.value;
            cursor.advance(revoked.bytes_consumed)?;
        }
    }

    if !cursor.empty()
        && crl.version >= 2
        && let Ok(extensions) = parse_crl_extensions(cursor.remaining(), crl)
    {
        crl.extensions = extensions.value;
        cursor.advance(extensions.bytes_consumed)?;
    }

    Ok(())
}

fn integer_to_i32(bytes: &[u8]) -> PkiResult<i32> {
    if bytes.is_empty() || bytes.len() > 4 {
        return Err(PkiError::new("integer out of range"));
    }
    let mut out = 0i32;
    for byte in bytes {
        out = (out << 8) | i32::from(*byte);
    }
    Ok(out)
}

pub fn crl_copy_span(input: &[u8]) -> Vec<u8> {
    input.to_vec()
}

pub fn crl_parse_name(input: &[u8]) -> PkiResult<Asn1Read<DistinguishedName>> {
    let seq = parse_sequence(input)?;
    let encoded = crl_copy_span(&input[..seq.bytes_consumed]);
    Ok(Asn1Read::new(
        DistinguishedName::from_der(encoded)?,
        seq.bytes_consumed,
    ))
}

pub fn crl_parse_algorithm_identifier(input: &[u8]) -> PkiResult<Asn1Read<AlgorithmIdentifier>> {
    let seq = parse_sequence(input)?;
    let mut cursor = Cursor::new(&seq.value);
    let oid = parse_oid(cursor.remaining())?;
    cursor.advance(oid.bytes_consumed)?;
    let mut identifier = AlgorithmIdentifier {
        signature: find_sig_alg_by_oid(&oid.value),
        ..AlgorithmIdentifier::default()
    };
    if let Some(hash) = super::find_hash_by_oid(&oid.value) {
        identifier.hash = hash;
    }
    Ok(Asn1Read::new(identifier, seq.bytes_consumed))
}

pub fn crl_parse_time(input: &[u8]) -> PkiResult<Asn1Read<DerTime>> {
    if input.is_empty() {
        return Err(PkiError::new("empty time"));
    }
    match input[0] & 0x1f {
        tag if tag == Asn1Tag::UtcTime as u8 => parse_utc_time(input),
        tag if tag == Asn1Tag::GeneralizedTime as u8 => parse_generalized_time(input),
        _ => Err(PkiError::new("unsupported time type")),
    }
}

fn is_time_tag(byte: u8) -> bool {
    let tag = byte & 0x1f;
    tag == Asn1Tag::UtcTime as u8 || tag == Asn1Tag::GeneralizedTime as u8
}

pub fn parse_reason_code(input: &[u8]) -> Option<CrlReason> {
    if input.len() != 3 || input[0] != Asn1Tag::Enumerated as u8 || input[1] != 0x01 {
        return None;
    }
    match input[2] {
        0 => Some(CrlReason::Unspecified),
        1 => Some(CrlReason::KeyCompromise),
        2 => Some(CrlReason::CaCompromise),
        3 => Some(CrlReason::AffiliationChanged),
        4 => Some(CrlReason::Superseded),
        5 => Some(CrlReason::CessationOfOperation),
        6 => Some(CrlReason::CertificateHold),
        8 => Some(CrlReason::RemoveFromCrl),
        9 => Some(CrlReason::PrivilegeWithdrawn),
        10 => Some(CrlReason::AaCompromise),
        _ => None,
    }
}

pub fn identify_crl_entry_extension(oid: &Oid) -> CrlEntryExtensionId {
    match oid.nodes.as_slice() {
        [2, 5, 29, 21] => CrlEntryExtensionId::ReasonCode,
        [2, 5, 29, 24] => CrlEntryExtensionId::InvalidityDate,
        [2, 5, 29, 29] => CrlEntryExtensionId::CertificateIssuer,
        _ => CrlEntryExtensionId::Unknown,
    }
}

pub fn identify_crl_extension(oid: &Oid) -> CrlExtensionId {
    match oid.nodes.as_slice() {
        [2, 5, 29, 35] => CrlExtensionId::AuthorityKeyIdentifier,
        [2, 5, 29, 18] => CrlExtensionId::IssuerAltName,
        [2, 5, 29, 20] => CrlExtensionId::CrlNumber,
        [2, 5, 29, 27] => CrlExtensionId::DeltaCrlIndicator,
        [2, 5, 29, 28] => CrlExtensionId::IssuingDistributionPoint,
        [2, 5, 29, 46] => CrlExtensionId::FreshestCrl,
        [1, 3, 6, 1, 5, 5, 7, 1, 1] => CrlExtensionId::AuthorityInfoAccess,
        [2, 5, 29, 60] => CrlExtensionId::ExpiredCertsOnCrl,
        _ => CrlExtensionId::Unknown,
    }
}

pub fn parse_crl_entry_extensions(
    input: &[u8],
    revoked: &mut RevokedCertificate,
) -> PkiResult<Asn1Read<Vec<CrlEntryExtension>>> {
    let seq = parse_sequence(input)?;
    let mut cursor = Cursor::new(&seq.value);
    let mut extensions = Vec::new();
    while !cursor.empty() {
        let ext_seq = parse_sequence(cursor.remaining())?;
        let mut ext_cursor = Cursor::new(&ext_seq.value);
        let oid = parse_oid(ext_cursor.remaining())?;
        ext_cursor.advance(oid.bytes_consumed)?;
        let mut critical = false;
        if !ext_cursor.empty() {
            let next = parse_id_len(ext_cursor.remaining())?;
            if next.value.identifier.tag_class == Asn1Class::Universal
                && next.value.identifier.tag_number == Asn1Tag::Boolean as u32
            {
                let parsed = parse_boolean(ext_cursor.remaining())?;
                critical = parsed.value;
                ext_cursor.advance(parsed.bytes_consumed)?;
            }
        }
        let value = parse_octet_string(ext_cursor.remaining())?;
        ext_cursor.advance(value.bytes_consumed)?;
        let id = identify_crl_entry_extension(&oid.value);
        match id {
            CrlEntryExtensionId::ReasonCode => revoked.reason = parse_reason_code(&value.value),
            CrlEntryExtensionId::InvalidityDate => {
                if let Ok(time) = parse_generalized_time(&value.value) {
                    revoked.invalidity_date = Some(time.value);
                }
            }
            CrlEntryExtensionId::CertificateIssuer => {
                if let Ok(name) = crl_parse_name(&value.value) {
                    revoked.certificate_issuer = Some(name.value);
                }
            }
            CrlEntryExtensionId::Unknown => {}
        }
        extensions.push(CrlEntryExtension {
            id,
            oid: oid.value,
            critical,
            value: value.value,
        });
        cursor.advance(ext_seq.bytes_consumed)?;
    }
    Ok(Asn1Read::new(extensions, seq.bytes_consumed))
}

fn parse_revoked_certificates(input: &[u8]) -> PkiResult<Asn1Read<Vec<RevokedCertificate>>> {
    let seq = parse_sequence(input)?;
    let mut cursor = Cursor::new(&seq.value);
    let mut revoked = Vec::new();
    while !cursor.empty() {
        let Ok(entry_seq) = parse_sequence(cursor.remaining()) else {
            break;
        };
        let mut entry_cursor = Cursor::new(&entry_seq.value);
        let serial = parse_integer(entry_cursor.remaining())
            .map_err(|err| PkiError::new(format!("failed to parse revoked cert serial: {err}")))?;
        entry_cursor.advance(serial.bytes_consumed)?;
        let revocation_date = crl_parse_time(entry_cursor.remaining())
            .map_err(|err| PkiError::new(format!("failed to parse revocation time: {err}")))?;
        entry_cursor.advance(revocation_date.bytes_consumed)?;
        let mut entry = RevokedCertificate {
            serial_number: serial.value,
            revocation_date: revocation_date.value,
            ..RevokedCertificate::default()
        };
        if !entry_cursor.empty()
            && let Ok(extensions) = parse_crl_entry_extensions(entry_cursor.remaining(), &mut entry)
        {
            entry.extensions = extensions.value;
        }
        revoked.push(entry);
        cursor.advance(entry_seq.bytes_consumed)?;
    }
    Ok(Asn1Read::new(revoked, seq.bytes_consumed))
}

pub fn parse_crl_extensions(input: &[u8], crl: &mut Crl) -> PkiResult<Asn1Read<Vec<CrlExtension>>> {
    let explicit = parse_id_len(input)?;
    if explicit.value.identifier.tag_class != Asn1Class::ContextSpecific
        || explicit.value.identifier.tag_number != 0
        || !explicit.value.identifier.constructed
    {
        return Err(PkiError::new(
            "expected context-specific [0] tag for CRL extensions",
        ));
    }
    let start = explicit.value.header_bytes;
    let end = start + explicit.value.length;
    let seq = parse_sequence(&input[start..end])?;
    let mut cursor = Cursor::new(&seq.value);
    let mut extensions = Vec::new();
    while !cursor.empty() {
        let ext_seq = parse_sequence(cursor.remaining())?;
        let mut ext_cursor = Cursor::new(&ext_seq.value);
        let oid = parse_oid(ext_cursor.remaining())?;
        ext_cursor.advance(oid.bytes_consumed)?;
        let mut critical = false;
        if !ext_cursor.empty() {
            let next = parse_id_len(ext_cursor.remaining())?;
            if next.value.identifier.tag_class == Asn1Class::Universal
                && next.value.identifier.tag_number == Asn1Tag::Boolean as u32
            {
                let parsed = parse_boolean(ext_cursor.remaining())?;
                critical = parsed.value;
                ext_cursor.advance(parsed.bytes_consumed)?;
            }
        }
        let value = parse_octet_string(ext_cursor.remaining())?;
        ext_cursor.advance(value.bytes_consumed)?;
        let id = identify_crl_extension(&oid.value);
        match id {
            CrlExtensionId::AuthorityKeyIdentifier => {
                parse_authority_key_identifier(&value.value, crl)
            }
            CrlExtensionId::CrlNumber => {
                if let Ok(parsed) = parse_integer(&value.value) {
                    crl.crl_number = Some(parsed.value);
                }
            }
            CrlExtensionId::DeltaCrlIndicator => {
                if let Ok(parsed) = parse_integer(&value.value) {
                    crl.delta_crl_indicator = Some(parsed.value);
                }
            }
            CrlExtensionId::IssuingDistributionPoint => crl.has_issuing_distribution_point = true,
            _ => {}
        }
        extensions.push(CrlExtension {
            id,
            oid: oid.value,
            critical,
            value: value.value,
        });
        cursor.advance(ext_seq.bytes_consumed)?;
    }
    Ok(Asn1Read::new(
        extensions,
        explicit.value.header_bytes + explicit.value.length,
    ))
}

fn parse_authority_key_identifier(input: &[u8], crl: &mut Crl) {
    let Ok(seq) = parse_sequence(input) else {
        return;
    };
    let cursor = Cursor::new(&seq.value);
    if cursor.empty() {
        return;
    }
    let Ok(header) = parse_id_len(cursor.remaining()) else {
        return;
    };
    if header.value.identifier.tag_class == Asn1Class::ContextSpecific
        && header.value.identifier.tag_number == 0
    {
        let start = header.value.header_bytes;
        let end = start + header.value.length;
        crl.authority_key_identifier = Some(cursor.remaining()[start..end].to_vec());
    }
}

pub fn parse_pem_crl_chain(pem: &str) -> PkiResult<Vec<Crl>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some(rel_start) = pem[pos..].find("-----BEGIN") {
        let start = pos + rel_start;
        let tail = &pem[start..];
        let block = super::pem_decode_block_with_expected_label(tail, Some("CRL"))
            .or_else(|_| super::pem_decode_block_with_expected_label(tail, Some("X509 CRL")))?;
        out.push(parse_crl(&block.data)?);
        let Some(rel_end) = tail.find("-----END") else {
            break;
        };
        pos = start + rel_end + 1;
    }
    if out.is_empty() {
        return Err(PkiError::new("no CRLs found in PEM"));
    }
    Ok(out)
}

pub fn parse_pem_crl_chain_result(pem: &str) -> CertificateResult<Vec<Crl>> {
    match parse_pem_crl_chain(pem) {
        Ok(crls) => CertificateResult::ok(crls),
        Err(error) => CertificateResult::failure(error.message),
    }
}

pub fn load_crl(path: impl AsRef<Path>) -> PkiResult<Crl> {
    let loaded = read_pem_or_der(path, None)?;
    match loaded {
        super::PemOrDer::Der(bytes) => parse_crl(&bytes),
        super::PemOrDer::Pem(block) => {
            if block.label == "CRL" || block.label == "X509 CRL" {
                parse_crl(&block.data)
            } else {
                Err(PkiError::new("PEM block is not a CRL"))
            }
        }
    }
}

pub fn load_crl_result(path: impl AsRef<Path>) -> CertificateResult<Crl> {
    match load_crl(path) {
        Ok(crl) => CertificateResult::ok(crl),
        Err(error) => CertificateResult::failure(error.message),
    }
}

pub fn encode_der_time(time: &DerTime) -> Vec<u8> {
    if (1950..=2049).contains(&time.year) {
        der::encode_utctime(&format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            time.year % 100,
            time.month,
            time.day,
            time.hour,
            time.minute,
            time.second
        ))
    } else {
        der::encode_generalized_time(&format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            time.year, time.month, time.day, time.hour, time.minute, time.second
        ))
    }
}

pub fn encode_crl_reason(reason: CrlReason) -> Vec<u8> {
    der::encode_tlv(
        Asn1Class::Universal,
        false,
        Asn1Tag::Enumerated as u32,
        &[reason as u8],
    )
}
