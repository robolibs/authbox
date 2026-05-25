use super::{
    Cursor, Oid, PkiError, PkiResult, der, parse_directory_string, parse_oid, parse_sequence,
    parse_set,
};
use std::fmt;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DistinguishedNameAttribute {
    #[default]
    Unknown,
    CommonName,
    CountryName,
    OrganizationName,
    OrganizationalUnitName,
    StateOrProvinceName,
    LocalityName,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AttributeTypeAndValue {
    pub oid: Oid,
    pub attribute: DistinguishedNameAttribute,
    pub value: String,
}

pub type RelativeDistinguishedName = Vec<AttributeTypeAndValue>;

pub fn attribute_from_oid(oid: &Oid) -> DistinguishedNameAttribute {
    match oid.nodes.as_slice() {
        [2, 5, 4, 3] => DistinguishedNameAttribute::CommonName,
        [2, 5, 4, 6] => DistinguishedNameAttribute::CountryName,
        [2, 5, 4, 10] => DistinguishedNameAttribute::OrganizationName,
        [2, 5, 4, 11] => DistinguishedNameAttribute::OrganizationalUnitName,
        [2, 5, 4, 8] => DistinguishedNameAttribute::StateOrProvinceName,
        [2, 5, 4, 7] => DistinguishedNameAttribute::LocalityName,
        _ => DistinguishedNameAttribute::Unknown,
    }
}

pub fn oid_from_attribute(attribute: DistinguishedNameAttribute) -> PkiResult<Oid> {
    match attribute {
        DistinguishedNameAttribute::CommonName => Ok(Oid::new([2, 5, 4, 3])),
        DistinguishedNameAttribute::CountryName => Ok(Oid::new([2, 5, 4, 6])),
        DistinguishedNameAttribute::OrganizationName => Ok(Oid::new([2, 5, 4, 10])),
        DistinguishedNameAttribute::OrganizationalUnitName => Ok(Oid::new([2, 5, 4, 11])),
        DistinguishedNameAttribute::StateOrProvinceName => Ok(Oid::new([2, 5, 4, 8])),
        DistinguishedNameAttribute::LocalityName => Ok(Oid::new([2, 5, 4, 7])),
        DistinguishedNameAttribute::Unknown => Err(PkiError::new(
            "Cannot convert Unknown or invalid DistinguishedNameAttribute to OID",
        )),
    }
}

pub fn is_printable_string(text: &str) -> bool {
    text.chars().all(|ch| {
        ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                ' ' | '\'' | '(' | ')' | '+' | ',' | '-' | '.' | '/' | ':' | '=' | '?'
            )
    })
}

pub fn encode_directory_string(attr: &AttributeTypeAndValue) -> Vec<u8> {
    if attr.attribute == DistinguishedNameAttribute::CountryName
        && attr.value.len() == 2
        && attr.value.chars().all(|c| c.is_ascii_alphabetic())
    {
        return der::encode_printable_string(&attr.value.to_ascii_uppercase());
    }
    if is_printable_string(&attr.value) {
        der::encode_printable_string(&attr.value)
    } else {
        der::encode_utf8_string(&attr.value)
    }
}

pub fn dn_trim(mut view: &str) -> &str {
    while view.as_bytes().first().is_some_and(u8::is_ascii_whitespace) {
        view = &view[1..];
    }
    while view.as_bytes().last().is_some_and(u8::is_ascii_whitespace) {
        view = &view[..view.len() - 1];
    }
    view
}

pub fn attribute_from_string(token: &str) -> Option<DistinguishedNameAttribute> {
    match token {
        "CN" => Some(DistinguishedNameAttribute::CommonName),
        "C" => Some(DistinguishedNameAttribute::CountryName),
        "O" => Some(DistinguishedNameAttribute::OrganizationName),
        "OU" => Some(DistinguishedNameAttribute::OrganizationalUnitName),
        "ST" | "S" => Some(DistinguishedNameAttribute::StateOrProvinceName),
        "L" => Some(DistinguishedNameAttribute::LocalityName),
        _ => None,
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ParsedDn {
    pub success: bool,
    pub rdns: Vec<RelativeDistinguishedName>,
    pub error: String,
}

pub fn parse_dn_string(input: &str) -> ParsedDn {
    let mut rdns = Vec::new();
    for component in input.split(',').map(dn_trim) {
        if component.is_empty() {
            continue;
        }
        let mut rdn = Vec::new();
        for pair in component.split('+').map(dn_trim) {
            let Some((attr, value)) = pair.split_once('=') else {
                return ParsedDn {
                    success: false,
                    rdns: Vec::new(),
                    error: "invalid DN component".to_string(),
                };
            };
            let attr = dn_trim(attr);
            let value = dn_trim(value);
            let Some(attribute) = attribute_from_string(attr) else {
                return ParsedDn {
                    success: false,
                    rdns: Vec::new(),
                    error: "unsupported DN attribute".to_string(),
                };
            };
            let Ok(oid) = oid_from_attribute(attribute) else {
                return ParsedDn {
                    success: false,
                    rdns: Vec::new(),
                    error: "unsupported DN attribute".to_string(),
                };
            };
            rdn.push(AttributeTypeAndValue {
                oid,
                attribute,
                value: value.to_string(),
            });
        }
        rdns.push(rdn);
    }
    if rdns.is_empty() {
        return ParsedDn {
            success: false,
            rdns: Vec::new(),
            error: "DN string empty".to_string(),
        };
    }
    ParsedDn {
        success: true,
        rdns,
        error: String::new(),
    }
}

fn attr_name(attribute: DistinguishedNameAttribute) -> &'static str {
    match attribute {
        DistinguishedNameAttribute::CommonName => "CN",
        DistinguishedNameAttribute::CountryName => "C",
        DistinguishedNameAttribute::OrganizationName => "O",
        DistinguishedNameAttribute::OrganizationalUnitName => "OU",
        DistinguishedNameAttribute::StateOrProvinceName => "ST",
        DistinguishedNameAttribute::LocalityName => "L",
        DistinguishedNameAttribute::Unknown => "OID",
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DistinguishedName {
    der: Vec<u8>,
    rdns: Vec<RelativeDistinguishedName>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DistinguishedNameResult {
    pub success: bool,
    pub value: DistinguishedName,
    pub error: String,
}

impl DistinguishedNameResult {
    pub fn ok(value: DistinguishedName) -> Self {
        Self {
            success: true,
            value,
            error: String::new(),
        }
    }

    pub fn failure(error: impl Into<String>) -> Self {
        Self {
            success: false,
            value: DistinguishedName::default(),
            error: error.into(),
        }
    }

    pub fn into_result(self) -> PkiResult<DistinguishedName> {
        if self.success {
            Ok(self.value)
        } else {
            Err(PkiError::new(self.error))
        }
    }
}

impl DistinguishedName {
    pub fn from_der(der: impl Into<Vec<u8>>) -> PkiResult<Self> {
        let der = der.into();
        let rdns = parse_name_der(&der)?;
        Ok(Self { der, rdns })
    }

    pub fn from_string(input: &str) -> PkiResult<Self> {
        let parsed = parse_dn_string(input);
        if !parsed.success {
            return Err(PkiError::new(parsed.error));
        }
        let rdns = parsed.rdns;
        let der = encode_name(&rdns);
        Ok(Self { der, rdns })
    }

    pub fn from_string_result(input: &str) -> DistinguishedNameResult {
        match Self::from_string(input) {
            Ok(value) => DistinguishedNameResult::ok(value),
            Err(err) => DistinguishedNameResult::failure(err.message),
        }
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn rdns(&self) -> &[RelativeDistinguishedName] {
        &self.rdns
    }

    pub fn first(&self, attribute: DistinguishedNameAttribute) -> Option<&str> {
        self.rdns
            .iter()
            .flat_map(|rdn| rdn.iter())
            .find(|entry| entry.attribute == attribute)
            .map(|entry| entry.value.as_str())
    }
}

impl fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for entry in self.rdns.iter().flat_map(|rdn| rdn.iter()) {
            if !first {
                f.write_str(", ")?;
            }
            first = false;
            write!(f, "{}={}", attr_name(entry.attribute), entry.value)?;
        }
        Ok(())
    }
}

pub fn encode_name(rdns: &[RelativeDistinguishedName]) -> Vec<u8> {
    let rdn_blocks = rdns
        .iter()
        .map(|rdn| {
            let atvs = rdn
                .iter()
                .map(|atv| {
                    der::encode_sequence(&der::concat(&[
                        der::encode_oid(&atv.oid),
                        encode_directory_string(atv),
                    ]))
                })
                .collect::<Vec<_>>();
            der::encode_set(&der::concat(&atvs))
        })
        .collect::<Vec<_>>();
    der::encode_sequence(&der::concat(&rdn_blocks))
}

fn parse_name_der(der_bytes: &[u8]) -> PkiResult<Vec<RelativeDistinguishedName>> {
    let seq = parse_sequence(der_bytes)?;
    let mut rdns = Vec::new();
    let mut cursor = Cursor::new(&seq.value);
    while !cursor.empty() {
        let set = parse_set(cursor.remaining())?;
        let mut set_cursor = Cursor::new(&set.value);
        let mut rdn = Vec::new();
        while !set_cursor.empty() {
            let atv_seq = parse_sequence(set_cursor.remaining())?;
            let mut atv_cursor = Cursor::new(&atv_seq.value);
            let oid = parse_oid(atv_cursor.remaining())?;
            atv_cursor.advance(oid.bytes_consumed)?;
            let value = parse_directory_string(atv_cursor.remaining())?;
            atv_cursor.advance(value.bytes_consumed)?;
            if !atv_cursor.empty() {
                return Err(PkiError::new("trailing data in DN attribute"));
            }
            rdn.push(AttributeTypeAndValue {
                attribute: attribute_from_oid(&oid.value),
                oid: oid.value,
                value: value.value,
            });
            set_cursor.advance(atv_seq.bytes_consumed)?;
        }
        rdns.push(rdn);
        cursor.advance(set.bytes_consumed)?;
    }
    Ok(rdns)
}
