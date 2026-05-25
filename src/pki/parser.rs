use super::{
    AlgorithmIdentifier, Asn1Class, Asn1Read, Asn1Tag, Cursor, DerTime, DistinguishedName,
    PkiError, PkiResult, RawExtension, SubjectPublicKeyInfo, find_curve_by_oid,
    find_extension_by_oid, find_hash_by_oid, find_sig_alg_by_oid, parse_bit_string, parse_boolean,
    parse_generalized_time, parse_id_len, parse_integer, parse_octet_string, parse_oid,
    parse_sequence, parse_utc_time,
};
pub fn parse_algorithm_identifier(input: &[u8]) -> PkiResult<Asn1Read<AlgorithmIdentifier>> {
    parse_algorithm_identifier_full(input)
}

pub fn parse_algorithm_identifier_full(input: &[u8]) -> PkiResult<Asn1Read<AlgorithmIdentifier>> {
    let seq = parse_sequence(input)?;
    let mut cursor = Cursor::new(&seq.value);
    let oid = parse_oid(cursor.remaining())?;
    cursor.advance(oid.bytes_consumed)?;
    let mut parameter_oid = None;
    if !cursor.empty() {
        let header = parse_id_len(cursor.remaining())?;
        if header.value.identifier.tag_class == Asn1Class::Universal
            && header.value.identifier.tag_number == Asn1Tag::ObjectIdentifier as u32
        {
            let parsed = parse_oid(cursor.remaining())?;
            parameter_oid = Some(parsed.value);
            cursor.advance(parsed.bytes_consumed)?;
        } else {
            cursor.advance(header.value.header_bytes + header.value.length)?;
        }
    }
    let identifier = AlgorithmIdentifier {
        signature: find_sig_alg_by_oid(&oid.value),
        hash: find_hash_by_oid(&oid.value).unwrap_or_default(),
        curve: parameter_oid
            .as_ref()
            .map(find_curve_by_oid)
            .unwrap_or_default(),
    };
    Ok(Asn1Read::new(identifier, seq.bytes_consumed))
}

pub fn parse_subject_public_key_info(input: &[u8]) -> PkiResult<Asn1Read<SubjectPublicKeyInfo>> {
    parse_subject_public_key_info_full(input)
}

pub fn parse_subject_public_key_info_full(
    input: &[u8],
) -> PkiResult<Asn1Read<SubjectPublicKeyInfo>> {
    let seq = parse_sequence(input)?;
    let mut cursor = Cursor::new(&seq.value);
    let alg = parse_algorithm_identifier_full(cursor.remaining())?;
    cursor.advance(alg.bytes_consumed)?;
    let bit_string = parse_bit_string(cursor.remaining())?;
    cursor.advance(bit_string.bytes_consumed)?;
    if !cursor.empty() {
        return Err(PkiError::new("extra data in SubjectPublicKeyInfo"));
    }
    Ok(Asn1Read::new(
        SubjectPublicKeyInfo {
            algorithm: alg.value,
            public_key: bit_string.value.bytes,
            unused_bits: bit_string.value.unused_bits,
        },
        seq.bytes_consumed,
    ))
}

pub fn parse_extensions(input: &[u8]) -> PkiResult<Asn1Read<Vec<RawExtension>>> {
    let header = parse_id_len(input)?;
    if header.value.identifier.tag_class != Asn1Class::ContextSpecific
        || !header.value.identifier.constructed
    {
        return Err(PkiError::new("expected extensions"));
    }
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    let seq = parse_sequence(&input[start..end])?;
    let mut cursor = Cursor::new(&seq.value);
    let mut extensions = Vec::new();
    while !cursor.empty() {
        let ext_seq = parse_sequence(cursor.remaining())?;
        let mut ext_cursor = Cursor::new(&ext_seq.value);
        let oid = parse_oid(ext_cursor.remaining())?;
        ext_cursor.advance(oid.bytes_consumed)?;
        let mut critical = false;
        if let Ok(boolean) = parse_boolean(ext_cursor.remaining()) {
            critical = boolean.value;
            ext_cursor.advance(boolean.bytes_consumed)?;
        }
        let value = parse_octet_string(ext_cursor.remaining())?;
        extensions.push(RawExtension {
            id: find_extension_by_oid(&oid.value),
            oid: oid.value,
            critical,
            value: value.value,
        });
        cursor.advance(ext_seq.bytes_consumed)?;
    }
    Ok(Asn1Read::new(
        extensions,
        header.value.header_bytes + header.value.length,
    ))
}

pub fn parse_extension_sequence(input: &[u8]) -> PkiResult<Asn1Read<Vec<RawExtension>>> {
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
        if ext_cursor.empty() {
            return Err(PkiError::new("extension missing value"));
        }
        let value = parse_octet_string(ext_cursor.remaining())?;
        ext_cursor.advance(value.bytes_consumed)?;
        if !ext_cursor.empty() {
            return Err(PkiError::new("extra data inside extension"));
        }
        extensions.push(RawExtension {
            id: find_extension_by_oid(&oid.value),
            oid: oid.value,
            critical,
            value: value.value,
        });
        cursor.advance(ext_seq.bytes_consumed)?;
    }
    Ok(Asn1Read::new(extensions, seq.bytes_consumed))
}

pub fn parse_extensions_explicit(input: &[u8]) -> PkiResult<Asn1Read<Vec<RawExtension>>> {
    let header = parse_id_len(input)?;
    if header.value.identifier.tag_class != Asn1Class::ContextSpecific
        || header.value.identifier.tag_number != 3
        || !header.value.identifier.constructed
    {
        return Err(PkiError::new("expected [3] EXPLICIT extensions"));
    }
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    let mut parsed = parse_extension_sequence(&input[start..end])?;
    parsed.bytes_consumed = end;
    Ok(parsed)
}

pub fn parse_extensions_full(input: &[u8]) -> PkiResult<Asn1Read<Vec<RawExtension>>> {
    parse_extensions_explicit(input)
}

pub fn parse_version(input: &[u8]) -> PkiResult<Asn1Read<i32>> {
    let header = parse_id_len(input)?;
    if header.value.identifier.tag_class != Asn1Class::ContextSpecific
        || header.value.identifier.tag_number != 0
        || !header.value.identifier.constructed
    {
        return Err(PkiError::new("expected [0] EXPLICIT version"));
    }
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    let inner = parse_integer(&input[start..end])?;
    if inner.value.is_empty() {
        return Err(PkiError::new("version INTEGER empty"));
    }
    let mut value = 0i32;
    for byte in inner.value {
        value = (value << 8) | i32::from(byte);
    }
    if !(0..=2).contains(&value) {
        return Err(PkiError::new("version out of range"));
    }
    Ok(Asn1Read::new(value + 1, end))
}

pub fn parse_name_full(input: &[u8]) -> PkiResult<Asn1Read<DistinguishedName>> {
    let seq = parse_sequence(input)?;
    let encoded = input[..seq.bytes_consumed].to_vec();
    Ok(Asn1Read::new(
        DistinguishedName::from_der(encoded)?,
        seq.bytes_consumed,
    ))
}

pub fn copy_bytes(span: &[u8]) -> Vec<u8> {
    span.to_vec()
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Validity {
    pub not_before: DerTime,
    pub not_after: DerTime,
}

pub type ValidityRange = Validity;

impl Validity {
    pub fn contains(&self, time: &DerTime) -> bool {
        der_time_cmp(time, &self.not_before).is_ge() && der_time_cmp(time, &self.not_after).is_le()
    }
}

fn der_time_cmp(a: &DerTime, b: &DerTime) -> std::cmp::Ordering {
    (a.year, a.month, a.day, a.hour, a.minute, a.second)
        .cmp(&(b.year, b.month, b.day, b.hour, b.minute, b.second))
}

pub fn parse_time_choice(input: &[u8]) -> PkiResult<Asn1Read<DerTime>> {
    let Some(first) = input.first() else {
        return Err(PkiError::new("missing time field"));
    };
    let tag_class = match first & 0xc0 {
        0x00 => Asn1Class::Universal,
        0x40 => Asn1Class::Application,
        0x80 => Asn1Class::ContextSpecific,
        _ => Asn1Class::Private,
    };
    if tag_class != Asn1Class::Universal {
        return Err(PkiError::new("invalid time tag class"));
    }
    match u32::from(first & 0x1f) {
        x if x == Asn1Tag::UtcTime as u32 => parse_utc_time(input),
        x if x == Asn1Tag::GeneralizedTime as u32 => parse_generalized_time(input),
        _ => Err(PkiError::new("unsupported time tag")),
    }
}

pub fn parse_validity(input: &[u8]) -> PkiResult<Asn1Read<Validity>> {
    let seq = parse_sequence(input)?;
    let mut cursor = Cursor::new(&seq.value);
    let not_before = parse_time_choice(cursor.remaining())?;
    cursor.advance(not_before.bytes_consumed)?;
    let not_after = parse_time_choice(cursor.remaining())?;
    cursor.advance(not_after.bytes_consumed)?;
    if !cursor.empty() {
        return Err(PkiError::new("extra data in Validity"));
    }
    Ok(Asn1Read::new(
        Validity {
            not_before: not_before.value,
            not_after: not_after.value,
        },
        seq.bytes_consumed,
    ))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TbsCertificate {
    pub version: i32,
    pub serial_number: Vec<u8>,
    pub signature: AlgorithmIdentifier,
    pub issuer: DistinguishedName,
    pub validity: Validity,
    pub subject: DistinguishedName,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub extensions: Vec<RawExtension>,
}

pub type TBSCertificate = TbsCertificate;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CertificateContext {
    pub der: Vec<u8>,
    pub tbs_certificate: Vec<u8>,
    pub version: i32,
    pub serial_number: Vec<u8>,
    pub tbs_signature: AlgorithmIdentifier,
    pub issuer: DistinguishedName,
    pub subject: DistinguishedName,
    pub not_before: DerTime,
    pub not_after: DerTime,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub extensions: Vec<RawExtension>,
    pub outer_signature: AlgorithmIdentifier,
    pub signature_value: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParseResult {
    pub success: bool,
    pub certificate: CertificateContext,
    pub error: String,
}

impl ParseResult {
    pub fn ok(certificate: CertificateContext) -> Self {
        Self {
            success: true,
            certificate,
            error: String::new(),
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            certificate: CertificateContext::default(),
            error: error.into(),
        }
    }

    pub fn into_result(self) -> PkiResult<CertificateContext> {
        if self.success {
            Ok(self.certificate)
        } else {
            Err(PkiError::new(self.error))
        }
    }
}

pub fn make_error(message: impl Into<String>) -> ParseResult {
    ParseResult::failure(message)
}

pub fn parse_certificate(input: &[u8], relaxed: bool) -> ParseResult {
    match parse_certificate_context(input, relaxed) {
        Ok(context) => ParseResult::ok(context),
        Err(error) => make_error(error.message),
    }
}

pub fn parse_x509_cert(input: &[u8]) -> PkiResult<CertificateContext> {
    parse_certificate_context(input, false)
}

pub fn parse_x509_cert_relaxed(input: &[u8]) -> PkiResult<CertificateContext> {
    parse_certificate_context(input, true)
}

pub fn parse_x509_cert_result(input: &[u8]) -> ParseResult {
    parse_certificate(input, false)
}

pub fn parse_x509_cert_relaxed_result(input: &[u8]) -> ParseResult {
    parse_certificate(input, true)
}

pub(crate) fn parse_certificate_context(
    input: &[u8],
    relaxed: bool,
) -> PkiResult<CertificateContext> {
    if input.is_empty() {
        return Err(PkiError::new("empty certificate buffer"));
    }
    let top = parse_sequence(input)?;
    if top.bytes_consumed != input.len() && !relaxed {
        return Err(PkiError::new("extra data after certificate"));
    }
    let mut context = CertificateContext {
        der: input.to_vec(),
        version: 1,
        ..CertificateContext::default()
    };
    let mut cert_cursor = Cursor::new(&top.value);

    let tbs_sequence = parse_sequence(cert_cursor.remaining())?;
    context.tbs_certificate = cert_cursor.remaining()[..tbs_sequence.bytes_consumed].to_vec();
    cert_cursor.advance(tbs_sequence.bytes_consumed)?;

    let outer_signature = parse_algorithm_identifier_full(cert_cursor.remaining())?;
    context.outer_signature = outer_signature.value;
    cert_cursor.advance(outer_signature.bytes_consumed)?;

    let signature_value = parse_bit_string(cert_cursor.remaining())?;
    if signature_value.value.unused_bits != 0 && !relaxed {
        return Err(PkiError::new("signature BIT STRING has unused bits"));
    }
    context.signature_value = signature_value.value.bytes;
    cert_cursor.advance(signature_value.bytes_consumed)?;
    if !cert_cursor.empty() && !relaxed {
        return Err(PkiError::new("extra fields after signatureValue"));
    }

    let mut tbs_cursor = Cursor::new(&tbs_sequence.value);
    if !tbs_cursor.empty() {
        let version_check = parse_id_len(tbs_cursor.remaining())?;
        if version_check.value.identifier.tag_class == Asn1Class::ContextSpecific
            && version_check.value.identifier.tag_number == 0
        {
            let version = parse_version(tbs_cursor.remaining())?;
            context.version = version.value;
            tbs_cursor.advance(version.bytes_consumed)?;
        }
    }
    let serial_number = parse_integer(tbs_cursor.remaining())?;
    context.serial_number = serial_number.value;
    tbs_cursor.advance(serial_number.bytes_consumed)?;

    let tbs_signature = parse_algorithm_identifier_full(tbs_cursor.remaining())?;
    context.tbs_signature = tbs_signature.value;
    tbs_cursor.advance(tbs_signature.bytes_consumed)?;

    let issuer = parse_name_full(tbs_cursor.remaining())?;
    context.issuer = issuer.value;
    tbs_cursor.advance(issuer.bytes_consumed)?;

    let validity = parse_validity(tbs_cursor.remaining())?;
    context.not_before = validity.value.not_before;
    context.not_after = validity.value.not_after;
    tbs_cursor.advance(validity.bytes_consumed)?;

    let subject = parse_name_full(tbs_cursor.remaining())?;
    context.subject = subject.value;
    tbs_cursor.advance(subject.bytes_consumed)?;

    let spki = parse_subject_public_key_info(tbs_cursor.remaining())?;
    context.subject_public_key_info = spki.value;
    tbs_cursor.advance(spki.bytes_consumed)?;

    while !tbs_cursor.empty() {
        let next = parse_id_len(tbs_cursor.remaining())?;
        let id = &next.value.identifier;
        if id.tag_class == Asn1Class::ContextSpecific {
            if id.tag_number == 3 && context.version < 3 && !relaxed {
                return Err(PkiError::new("extensions present but version < 3"));
            }
            if id.tag_number == 3 {
                let extensions = parse_extensions_explicit(tbs_cursor.remaining())?;
                context.extensions = extensions.value;
                tbs_cursor.advance(extensions.bytes_consumed)?;
                continue;
            }
            if id.tag_number == 1 || id.tag_number == 2 {
                // Unique IDs are IMPLICIT context-specific BIT STRINGs in X.509;
                // validate the context field's bounds and skip it.
                tbs_cursor.advance(next.value.header_bytes + next.value.length)?;
                continue;
            }
        }
        if !relaxed {
            return Err(PkiError::new("unexpected field in TBSCertificate"));
        }
        break;
    }

    Ok(context)
}
