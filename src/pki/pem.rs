use base64ct::{Base64, Encoding as _};

use super::{PkiError, PkiResult};

pub fn encode_base64(data: &[u8]) -> String {
    Base64::encode_string(data)
}

pub fn decode_base64(input: &str) -> PkiResult<Vec<u8>> {
    Base64::decode_vec(input).map_err(|_| PkiError::new("invalid base64 content"))
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PemBlock {
    pub label: String,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PemResult {
    pub success: bool,
    pub block: PemBlock,
    pub error: String,
}

impl PemResult {
    pub fn ok(block: PemBlock) -> Self {
        Self {
            success: true,
            block,
            error: String::new(),
        }
    }

    pub fn err(error: impl Into<String>) -> Self {
        Self {
            success: false,
            block: PemBlock::default(),
            error: error.into(),
        }
    }

    pub fn into_result(self) -> PkiResult<PemBlock> {
        if self.success {
            Ok(self.block)
        } else {
            Err(PkiError::new(self.error))
        }
    }
}

pub fn pem_decode_block(pem: &str) -> PkiResult<PemBlock> {
    pem_decode_block_with_expected_label(pem, None)
}

pub fn pem_decode_block_with_expected_label(
    pem: &str,
    expected_label: Option<&str>,
) -> PkiResult<PemBlock> {
    let begin_marker = "-----BEGIN ";
    let end_marker = "-----END ";
    let trailer = "-----";
    let begin_pos = pem
        .find(begin_marker)
        .ok_or_else(|| PkiError::new("missing PEM BEGIN marker"))?;
    let label_start = begin_pos + begin_marker.len();
    let label_end = pem[label_start..]
        .find(trailer)
        .map(|idx| idx + label_start)
        .ok_or_else(|| PkiError::new("unterminated PEM header"))?;
    let label = &pem[label_start..label_end];
    if expected_label.is_some_and(|expected| expected != label) {
        return Err(PkiError::new("unexpected PEM label"));
    }
    let after_header = label_end + trailer.len();
    let mut content_start = pem[after_header..]
        .find(['\r', '\n'])
        .map(|idx| idx + after_header)
        .ok_or_else(|| PkiError::new("PEM header missing newline"))?;
    while matches!(pem.as_bytes().get(content_start), Some(b'\r' | b'\n')) {
        content_start += 1;
    }
    let footer = format!("{end_marker}{label}{trailer}");
    let footer_pos = pem[content_start..]
        .find(&footer)
        .map(|idx| idx + content_start)
        .ok_or_else(|| PkiError::new("missing PEM END marker"))?;
    let base64_data: String = pem[content_start..footer_pos]
        .chars()
        .filter(|ch| !matches!(ch, '\r' | '\n' | ' ' | '\t'))
        .collect();
    if base64_data.is_empty() {
        return Err(PkiError::new("empty PEM body"));
    }
    Ok(PemBlock {
        label: label.to_string(),
        data: decode_base64(&base64_data)?,
    })
}

pub fn pem_decode(pem: &str) -> PemResult {
    pem_decode_with_expected_label(pem, None)
}

pub fn pem_decode_with_expected_label(pem: &str, expected_label: Option<&str>) -> PemResult {
    match pem_decode_block_with_expected_label(pem, expected_label) {
        Ok(block) => PemResult::ok(block),
        Err(err) => PemResult::err(err.message),
    }
}

pub fn pem_decode_result(pem: &str) -> PemResult {
    pem_decode(pem)
}

pub fn pem_decode_result_with_expected_label(pem: &str, expected_label: Option<&str>) -> PemResult {
    pem_decode_with_expected_label(pem, expected_label)
}

pub fn pem_encode_with_line_length(der: &[u8], label: &str, line_length: usize) -> String {
    let body = encode_base64(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    if line_length == 0 {
        out.push_str(&body);
        out.push('\n');
    } else {
        for chunk in body.as_bytes().chunks(line_length) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            out.push('\n');
        }
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

pub fn pem_encode(der: &[u8], label: &str) -> String {
    pem_encode_with_line_length(der, label, 64)
}

pub fn pem_decode_certificate_block(pem: &str) -> PkiResult<PemBlock> {
    pem_decode_block_with_expected_label(pem, Some("CERTIFICATE"))
}

pub fn pem_decode_certificate(pem: &str) -> PemResult {
    pem_decode_with_expected_label(pem, Some("CERTIFICATE"))
}

pub fn pem_decode_certificate_result(pem: &str) -> PemResult {
    pem_decode_certificate(pem)
}

pub fn pem_decode_private_key_block(pem: &str) -> PkiResult<PemBlock> {
    pem_decode_block_with_expected_label(pem, Some("PRIVATE KEY"))
}

pub fn pem_decode_private_key(pem: &str) -> PemResult {
    pem_decode_with_expected_label(pem, Some("PRIVATE KEY"))
}

pub fn pem_decode_private_key_result(pem: &str) -> PemResult {
    pem_decode_private_key(pem)
}

pub fn pem_encode_certificate(der: &[u8]) -> String {
    pem_encode(der, "CERTIFICATE")
}

pub fn pem_encode_private_key(der: &[u8]) -> String {
    pem_encode(der, "PRIVATE KEY")
}

pub fn pem_decode_encrypted_private_key_block(pem: &str) -> PkiResult<PemBlock> {
    pem_decode_block_with_expected_label(pem, Some("ENCRYPTED PRIVATE KEY"))
}

pub fn pem_decode_encrypted_private_key(pem: &str) -> PemResult {
    pem_decode_with_expected_label(pem, Some("ENCRYPTED PRIVATE KEY"))
}

pub fn pem_encode_encrypted_private_key(der: &[u8]) -> String {
    pem_encode(der, "ENCRYPTED PRIVATE KEY")
}
