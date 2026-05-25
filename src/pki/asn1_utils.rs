use super::{
    ASN1_MAX_TAG_NUMBER, Asn1Class, Asn1Identifier, Asn1Read, Asn1Result, Asn1Tag, BitString, Oid,
    ParsedHeader, PkiError, PkiResult,
};

fn asn1_result<T: Default>(result: PkiResult<Asn1Read<T>>) -> Asn1Result<T> {
    match result {
        Ok(read) => Asn1Result::ok(read.value, read.bytes_consumed),
        Err(err) => Asn1Result::failure(err.message),
    }
}

pub fn get_length(input: &[u8]) -> PkiResult<Asn1Read<usize>> {
    let Some(&first) = input.first() else {
        return Err(PkiError::new("missing length field"));
    };
    if first & 0x80 == 0 {
        return Ok(Asn1Read::new(first as usize, 1));
    }
    let octet_count = usize::from(first & 0x7f);
    if octet_count == 0 {
        return Err(PkiError::new("indefinite lengths are not supported in DER"));
    }
    if octet_count > std::mem::size_of::<usize>() {
        return Err(PkiError::new("length uses more bytes than supported"));
    }
    if input.len() < 1 + octet_count {
        return Err(PkiError::new("insufficient data for long-form length"));
    }
    let mut length = 0usize;
    for byte in &input[1..1 + octet_count] {
        length = (length << 8) | usize::from(*byte);
    }
    Ok(Asn1Read::new(length, 1 + octet_count))
}

pub fn get_length_result(input: &[u8]) -> Asn1Result<usize> {
    asn1_result(get_length(input))
}

pub fn parse_id_len(input: &[u8]) -> PkiResult<Asn1Read<ParsedHeader>> {
    let Some(&first_octet) = input.first() else {
        return Err(PkiError::new("input too small for ASN.1 header"));
    };
    let mut offset = 1usize;
    let tag_class = match first_octet & 0xc0 {
        0x00 => Asn1Class::Universal,
        0x40 => Asn1Class::Application,
        0x80 => Asn1Class::ContextSpecific,
        _ => Asn1Class::Private,
    };
    let constructed = first_octet & 0x20 != 0;
    let mut tag_number = u32::from(first_octet & 0x1f);
    if tag_number == 0x1f {
        tag_number = 0;
        let mut iterations = 0usize;
        loop {
            let Some(&byte) = input.get(offset) else {
                return Err(PkiError::new("unterminated long-form tag number"));
            };
            offset += 1;
            tag_number = (tag_number << 7) | u32::from(byte & 0x7f);
            iterations += 1;
            if iterations > 4 || tag_number > ASN1_MAX_TAG_NUMBER {
                return Err(PkiError::new("tag number exceeds supported range"));
            }
            if byte & 0x80 == 0 {
                break;
            }
        }
    }
    let length = get_length(&input[offset..])?;
    let header_bytes = offset + length.bytes_consumed;
    let Some(total) = header_bytes.checked_add(length.value) else {
        return Err(PkiError::new("value length overflows"));
    };
    if total > input.len() {
        return Err(PkiError::new("value length exceeds buffer"));
    }
    let header = ParsedHeader {
        identifier: Asn1Identifier {
            tag_class,
            constructed,
            tag_number,
        },
        length: length.value,
        header_bytes,
    };
    Ok(Asn1Read::new(header, total))
}

pub fn parse_id_len_result(input: &[u8]) -> Asn1Result<ParsedHeader> {
    asn1_result(parse_id_len(input))
}

fn expect_universal(
    input: &[u8],
    tag: Asn1Tag,
    constructed: Option<bool>,
    tag_name: &str,
) -> PkiResult<Asn1Read<ParsedHeader>> {
    let header = parse_id_len(input)?;
    let id = &header.value.identifier;
    if id.tag_class != Asn1Class::Universal || id.tag_number != tag as u32 {
        return Err(PkiError::new(format!("expected {tag_name}")));
    }
    if let Some(expected_constructed) = constructed
        && id.constructed != expected_constructed
    {
        return Err(PkiError::new(format!(
            "{tag_name} must be {}",
            if expected_constructed {
                "constructed"
            } else {
                "primitive"
            }
        )));
    }
    Ok(header)
}

pub fn parse_integer(input: &[u8]) -> PkiResult<Asn1Read<Vec<u8>>> {
    let header = expect_universal(input, Asn1Tag::Integer, Some(false), "INTEGER")?;
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    Ok(Asn1Read::new(input[start..end].to_vec(), end))
}

pub fn parse_integer_result(input: &[u8]) -> Asn1Result<Vec<u8>> {
    asn1_result(parse_integer(input))
}

pub fn parse_bit_string(input: &[u8]) -> PkiResult<Asn1Read<BitString>> {
    let header = expect_universal(input, Asn1Tag::BitString, Some(false), "BIT STRING")?;
    if header.value.length == 0 {
        return Err(PkiError::new("BIT STRING missing unused-bits byte"));
    }
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    let unused_bits = input[start];
    if unused_bits > 7 {
        return Err(PkiError::new("invalid unused bits"));
    }
    Ok(Asn1Read::new(
        BitString {
            unused_bits,
            bytes: input[start + 1..end].to_vec(),
        },
        end,
    ))
}

pub fn parse_bit_string_result(input: &[u8]) -> Asn1Result<BitString> {
    asn1_result(parse_bit_string(input))
}

pub fn parse_octet_string(input: &[u8]) -> PkiResult<Asn1Read<Vec<u8>>> {
    let header = expect_universal(input, Asn1Tag::OctetString, Some(false), "OCTET STRING")?;
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    Ok(Asn1Read::new(input[start..end].to_vec(), end))
}

pub fn parse_octet_string_result(input: &[u8]) -> Asn1Result<Vec<u8>> {
    asn1_result(parse_octet_string(input))
}

pub fn parse_oid(input: &[u8]) -> PkiResult<Asn1Read<Oid>> {
    let header = expect_universal(
        input,
        Asn1Tag::ObjectIdentifier,
        Some(false),
        "OBJECT IDENTIFIER",
    )?;
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    let content = &input[start..end];
    if content.is_empty() {
        return Err(PkiError::new("OBJECT IDENTIFIER has empty body"));
    }
    let first = u32::from(content[0]);
    let first_arc = (first / 40).min(2);
    let second_arc = first - (first_arc * 40);
    let mut nodes = vec![first_arc, second_arc];
    let mut offset = 1usize;
    while offset < content.len() {
        let mut value = 0u32;
        loop {
            let byte = content[offset];
            offset += 1;
            if value > (u32::MAX >> 7) {
                return Err(PkiError::new("OBJECT IDENTIFIER arc overflow"));
            }
            value = (value << 7) | u32::from(byte & 0x7f);
            if byte & 0x80 == 0 {
                break;
            }
            if offset >= content.len() {
                return Err(PkiError::new("truncated OBJECT IDENTIFIER arc"));
            }
        }
        nodes.push(value);
    }
    Ok(Asn1Read::new(Oid { nodes }, end))
}

pub fn parse_oid_result(input: &[u8]) -> Asn1Result<Oid> {
    asn1_result(parse_oid(input))
}

pub fn parse_sequence(input: &[u8]) -> PkiResult<Asn1Read<Vec<u8>>> {
    let header = expect_universal(input, Asn1Tag::Sequence, Some(true), "SEQUENCE")?;
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    Ok(Asn1Read::new(input[start..end].to_vec(), end))
}

pub fn parse_sequence_result(input: &[u8]) -> Asn1Result<Vec<u8>> {
    asn1_result(parse_sequence(input))
}

pub fn parse_set(input: &[u8]) -> PkiResult<Asn1Read<Vec<u8>>> {
    let header = expect_universal(input, Asn1Tag::Set, Some(true), "SET")?;
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    Ok(Asn1Read::new(input[start..end].to_vec(), end))
}

pub fn parse_set_result(input: &[u8]) -> Asn1Result<Vec<u8>> {
    asn1_result(parse_set(input))
}

pub fn parse_boolean(input: &[u8]) -> PkiResult<Asn1Read<bool>> {
    let header = expect_universal(input, Asn1Tag::Boolean, Some(false), "BOOLEAN")?;
    if header.value.length != 1 {
        return Err(PkiError::new("BOOLEAN length must be 1"));
    }
    Ok(Asn1Read::new(
        input[header.value.header_bytes] != 0,
        header.value.header_bytes + header.value.length,
    ))
}

pub fn parse_boolean_result(input: &[u8]) -> Asn1Result<bool> {
    asn1_result(parse_boolean(input))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DerTime {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

fn parse_decimal(view: &[u8]) -> PkiResult<i32> {
    if view.is_empty() || !view.iter().all(u8::is_ascii_digit) {
        return Err(PkiError::new("invalid time digits"));
    }
    let mut value = 0i32;
    for byte in view {
        value = (value * 10) + i32::from(byte - b'0');
    }
    Ok(value)
}

fn validate_time(
    year: i32,
    month: i32,
    day: i32,
    hour: i32,
    minute: i32,
    second: i32,
) -> PkiResult<DerTime> {
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return Err(PkiError::new("invalid time component"));
    }
    let max_day = days_in_month(year, month as u8);
    if day as u8 > max_day {
        return Err(PkiError::new("invalid calendar date"));
    }
    Ok(DerTime {
        year,
        month: month as u8,
        day: day as u8,
        hour: hour as u8,
        minute: minute as u8,
        second: second as u8,
    })
}

fn days_in_month(year: i32, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

pub fn parse_utc_time(input: &[u8]) -> PkiResult<Asn1Read<DerTime>> {
    let header = expect_universal(input, Asn1Tag::UtcTime, Some(false), "UTCTime")?;
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    let content = &input[start..end];
    if content.len() < 11 {
        return Err(PkiError::new("UTCTime too short"));
    }
    if content.last() != Some(&b'Z') {
        return Err(PkiError::new("UTCTime must end with Z"));
    }
    let digits = content.len() - 1;
    if digits != 10 && digits != 12 {
        return Err(PkiError::new("UTCTime must have 10 or 12 digits"));
    }
    let year = parse_decimal(&content[0..2])?;
    let month = parse_decimal(&content[2..4])?;
    let day = parse_decimal(&content[4..6])?;
    let hour = parse_decimal(&content[6..8])?;
    let minute = parse_decimal(&content[8..10])?;
    let second = if digits == 12 {
        parse_decimal(&content[10..12])?
    } else {
        0
    };
    let full_year = if year >= 50 { 1900 + year } else { 2000 + year };
    Ok(Asn1Read::new(
        validate_time(full_year, month, day, hour, minute, second)?,
        end,
    ))
}

pub fn parse_utc_time_result(input: &[u8]) -> Asn1Result<DerTime> {
    asn1_result(parse_utc_time(input))
}

pub fn parse_generalized_time(input: &[u8]) -> PkiResult<Asn1Read<DerTime>> {
    let header = expect_universal(
        input,
        Asn1Tag::GeneralizedTime,
        Some(false),
        "GeneralizedTime",
    )?;
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    let content = &input[start..end];
    if content.len() < 13 {
        return Err(PkiError::new("GeneralizedTime too short"));
    }
    if content.last() != Some(&b'Z') {
        return Err(PkiError::new("GeneralizedTime must end with Z"));
    }
    let digits = content.len() - 1;
    if digits != 12 && digits != 14 {
        return Err(PkiError::new("GeneralizedTime must have 12 or 14 digits"));
    }
    let year = parse_decimal(&content[0..4])?;
    let month = parse_decimal(&content[4..6])?;
    let day = parse_decimal(&content[6..8])?;
    let hour = parse_decimal(&content[8..10])?;
    let minute = parse_decimal(&content[10..12])?;
    let second = if digits == 14 {
        parse_decimal(&content[12..14])?
    } else {
        0
    };
    Ok(Asn1Read::new(
        validate_time(year, month, day, hour, minute, second)?,
        end,
    ))
}

pub fn parse_generalized_time_result(input: &[u8]) -> Asn1Result<DerTime> {
    asn1_result(parse_generalized_time(input))
}

pub fn parse_directory_string(input: &[u8]) -> PkiResult<Asn1Read<String>> {
    let header = parse_id_len(input)?;
    let id = &header.value.identifier;
    if id.tag_class != Asn1Class::Universal {
        return Err(PkiError::new("directory string invalid tag class"));
    }
    let start = header.value.header_bytes;
    let end = start + header.value.length;
    let content = &input[start..end];
    let text = match id.tag_number {
        x if x == Asn1Tag::PrintableString as u32
            || x == Asn1Tag::Ia5String as u32
            || x == Asn1Tag::Utf8String as u32
            || x == Asn1Tag::T61String as u32 =>
        {
            String::from_utf8(content.to_vec())
                .map_err(|_| PkiError::new("directory string is not UTF-8"))?
        }
        x if x == Asn1Tag::BmpString as u32 => {
            if !content.len().is_multiple_of(2) {
                return Err(PkiError::new("BMPString must have even length"));
            }
            let mut out = String::new();
            for chunk in content.chunks_exact(2) {
                let codepoint = (u16::from(chunk[0]) << 8) | u16::from(chunk[1]);
                let Some(ch) = char::from_u32(u32::from(codepoint)) else {
                    return Err(PkiError::new("invalid BMPString codepoint"));
                };
                out.push(ch);
            }
            out
        }
        _ => return Err(PkiError::new("unsupported directory string tag")),
    };
    Ok(Asn1Read::new(text, end))
}

pub fn parse_directory_string_result(input: &[u8]) -> Asn1Result<String> {
    asn1_result(parse_directory_string(input))
}

pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }

    pub(crate) fn empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    pub(crate) fn advance(&mut self, count: usize) -> PkiResult<()> {
        if self.offset + count > self.data.len() {
            return Err(PkiError::new("cursor advance exceeds buffer"));
        }
        self.offset += count;
        Ok(())
    }
}
