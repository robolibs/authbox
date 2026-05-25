use super::{PemBlock, PkiError, PkiResult, pem_decode_block_with_expected_label};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BinaryReadResult {
    pub success: bool,
    pub data: Vec<u8>,
    pub error_message: String,
}

impl BinaryReadResult {
    pub fn ok(data: Vec<u8>) -> Self {
        Self {
            success: true,
            data,
            error_message: String::new(),
        }
    }

    pub fn err(error_message: impl Into<String>) -> Self {
        Self {
            success: false,
            data: Vec::new(),
            error_message: error_message.into(),
        }
    }

    pub fn into_result(self) -> PkiResult<Vec<u8>> {
        if self.success {
            Ok(self.data)
        } else {
            Err(PkiError::new(self.error_message))
        }
    }
}

pub fn read_binary(path: impl AsRef<Path>) -> BinaryReadResult {
    let path = path.as_ref();
    match fs::read(path) {
        Ok(data) => BinaryReadResult::ok(data),
        Err(_) => BinaryReadResult::err(format!("Failed to open file: {}", path.display())),
    }
}

pub fn read_binary_result(path: impl AsRef<Path>) -> BinaryReadResult {
    read_binary(path)
}

pub fn read_binary_bytes(path: impl AsRef<Path>) -> PkiResult<Vec<u8>> {
    read_binary(path).into_result()
}

pub fn write_binary_result(bytes: &[u8], path: impl AsRef<Path>) -> PkiResult<()> {
    fs::write(path, bytes).map_err(|err| PkiError::new(format!("failed to write file: {err}")))
}

pub fn write_binary(bytes: &[u8], path: impl AsRef<Path>) -> bool {
    fs::write(path, bytes).is_ok()
}

pub fn write_binary_bool(bytes: &[u8], path: impl AsRef<Path>) -> bool {
    write_binary(bytes, path)
}

pub fn read_pem_or_der(
    path: impl AsRef<Path>,
    expected_label: Option<&str>,
) -> PkiResult<PemOrDer> {
    let bytes = read_binary_bytes(path)?;
    if bytes.starts_with(b"-----BEGIN")
        || bytes
            .windows(b"-----BEGIN".len())
            .any(|w| w == b"-----BEGIN")
    {
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| PkiError::new("PEM file is not valid UTF-8"))?;
        Ok(PemOrDer::Pem(pem_decode_block_with_expected_label(
            text,
            expected_label,
        )?))
    } else {
        Ok(PemOrDer::Der(bytes))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PemOrDer {
    Pem(PemBlock),
    Der(Vec<u8>),
}

impl PemOrDer {
    pub fn der_bytes(&self) -> &[u8] {
        match self {
            PemOrDer::Pem(block) => &block.data,
            PemOrDer::Der(bytes) => bytes,
        }
    }
}
