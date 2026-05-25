use std::fmt;

pub type PkiResult<T> = Result<T, PkiError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkiError {
    pub message: String,
}

impl PkiError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PkiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PkiError {}
