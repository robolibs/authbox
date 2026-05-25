use super::{
    AlgorithmIdentifier, Asn1Class, Asn1Read, Asn1Tag, DerTime, DistinguishedName, PkiError,
    PkiResult, RawExtension, SubjectPublicKeyInfo, find_extension_by_oid, find_hash_by_oid,
    find_sig_alg_by_oid, parse_bit_string, parse_boolean, parse_generalized_time, parse_id_len,
    parse_name_full, parse_octet_string, parse_oid, parse_sequence, parse_utc_time,
};

#[derive(Clone, Debug)]
pub struct DerCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> DerCursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }

    pub fn empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    pub fn advance(&mut self, count: usize) -> bool {
        if self.offset + count > self.data.len() {
            return false;
        }
        self.offset += count;
        true
    }
}

pub fn copy_span(span: &[u8]) -> Vec<u8> {
    span.to_vec()
}

pub fn parse_name(input: &[u8]) -> PkiResult<Asn1Read<DistinguishedName>> {
    parse_name_full(input)
}

pub fn parse_algorithm_identifier(input: &[u8]) -> PkiResult<Asn1Read<AlgorithmIdentifier>> {
    let seq = parse_sequence(input)?;
    let mut cursor = DerCursor::new(&seq.value);
    let oid = parse_oid(cursor.remaining())?;
    cursor.advance(oid.bytes_consumed);

    let mut identifier = AlgorithmIdentifier {
        signature: find_sig_alg_by_oid(&oid.value),
        ..AlgorithmIdentifier::default()
    };
    if let Some(hash_alg) = find_hash_by_oid(&oid.value) {
        identifier.hash = hash_alg;
    }

    Ok(Asn1Read::new(identifier, seq.bytes_consumed))
}

pub fn parse_subject_public_key_info(input: &[u8]) -> PkiResult<Asn1Read<SubjectPublicKeyInfo>> {
    let seq = parse_sequence(input)?;
    let mut cursor = DerCursor::new(&seq.value);
    let alg = parse_algorithm_identifier(cursor.remaining())?;
    cursor.advance(alg.bytes_consumed);

    let bit_string = parse_bit_string(cursor.remaining())?;
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
    let mut extensions = Vec::new();
    let mut cursor = DerCursor::new(&seq.value);
    while !cursor.empty() {
        let Ok(ext_seq) = parse_sequence(cursor.remaining()) else {
            break;
        };
        let mut ext_cursor = DerCursor::new(&ext_seq.value);
        let Ok(oid) = parse_oid(ext_cursor.remaining()) else {
            break;
        };
        ext_cursor.advance(oid.bytes_consumed);
        let mut critical = false;
        if let Ok(maybe_bool) = parse_boolean(ext_cursor.remaining()) {
            critical = maybe_bool.value;
            ext_cursor.advance(maybe_bool.bytes_consumed);
        }
        let Ok(value) = parse_octet_string(ext_cursor.remaining()) else {
            break;
        };
        extensions.push(RawExtension {
            id: find_extension_by_oid(&oid.value),
            oid: oid.value,
            critical,
            value: value.value,
        });
        cursor.advance(ext_seq.bytes_consumed);
    }

    Ok(Asn1Read::new(
        extensions,
        header.value.header_bytes + header.value.length,
    ))
}

pub fn parse_time_choice(input: &[u8]) -> PkiResult<Asn1Read<DerTime>> {
    let Some(first) = input.first() else {
        return Err(PkiError::new("empty time"));
    };
    let tag = first & 0x1f;
    if tag == Asn1Tag::UtcTime as u8 {
        return parse_utc_time(input);
    }
    if tag == Asn1Tag::GeneralizedTime as u8 {
        return parse_generalized_time(input);
    }
    Err(PkiError::new("invalid time tag"))
}

pub fn parse_spki(input: &[u8]) -> PkiResult<Asn1Read<SubjectPublicKeyInfo>> {
    parse_subject_public_key_info(input)
}

pub fn parse_explicit_extensions(input: &[u8]) -> PkiResult<Asn1Read<Vec<RawExtension>>> {
    parse_extensions(input)
}

pub fn parse_certificate_time_choice(input: &[u8]) -> PkiResult<Asn1Read<DerTime>> {
    parse_time_choice(input)
}
