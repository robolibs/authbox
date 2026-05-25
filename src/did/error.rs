use std::fmt;
pub type DidResult<T> = Result<T, DidError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DidErrorCode {
    InvalidDidUri,
    InvalidMethodName,
    InvalidMethodId,
    InvalidPercentEncoding,
    MalformedDidUrl,
    UnsupportedMethod,
    MethodNotRegistered,
    MethodNotAllowed,
    InvalidMethodSpecificId,
    InvalidDocumentJson,
    DocumentMissingRequiredField,
    DocumentIdMismatch,
    DocumentTooLarge,
    NoVerificationMethods,
    NoVerificationRelationships,
    InvalidVerificationMethod,
    ResolutionFailed,
    NetworkError,
    FetchFailed,
    HttpsRequired,
    FetcherNotConfigured,
    FragmentNotFound,
    InvalidReference,
    InvalidKeyFormat,
    InvalidKeyLength,
    UnsupportedKeyType,
    UnsupportedCurve,
    InternalError,
    NotImplemented,
}

#[allow(non_upper_case_globals)]
impl DidErrorCode {
    pub const INVALID_DID_URI: Self = Self::InvalidDidUri;
    pub const INVALID_METHOD_NAME: Self = Self::InvalidMethodName;
    pub const INVALID_METHOD_ID: Self = Self::InvalidMethodId;
    pub const INVALID_PERCENT_ENCODING: Self = Self::InvalidPercentEncoding;
    pub const MALFORMED_DID_URL: Self = Self::MalformedDidUrl;
    pub const UNSUPPORTED_METHOD: Self = Self::UnsupportedMethod;
    pub const METHOD_NOT_REGISTERED: Self = Self::MethodNotRegistered;
    pub const METHOD_NOT_ALLOWED: Self = Self::MethodNotAllowed;
    pub const INVALID_METHOD_SPECIFIC_ID: Self = Self::InvalidMethodSpecificId;
    pub const INVALID_DOCUMENT_JSON: Self = Self::InvalidDocumentJson;
    pub const DOCUMENT_MISSING_REQUIRED_FIELD: Self = Self::DocumentMissingRequiredField;
    pub const DOCUMENT_ID_MISMATCH: Self = Self::DocumentIdMismatch;
    pub const DOCUMENT_TOO_LARGE: Self = Self::DocumentTooLarge;
    pub const NO_VERIFICATION_METHODS: Self = Self::NoVerificationMethods;
    pub const NO_VERIFICATION_RELATIONSHIPS: Self = Self::NoVerificationRelationships;
    pub const INVALID_VERIFICATION_METHOD: Self = Self::InvalidVerificationMethod;
    pub const RESOLUTION_FAILED: Self = Self::ResolutionFailed;
    pub const NETWORK_ERROR: Self = Self::NetworkError;
    pub const FETCH_FAILED: Self = Self::FetchFailed;
    pub const HTTPS_REQUIRED: Self = Self::HttpsRequired;
    pub const FETCHER_NOT_CONFIGURED: Self = Self::FetcherNotConfigured;
    pub const FRAGMENT_NOT_FOUND: Self = Self::FragmentNotFound;
    pub const INVALID_REFERENCE: Self = Self::InvalidReference;
    pub const INVALID_KEY_FORMAT: Self = Self::InvalidKeyFormat;
    pub const INVALID_KEY_LENGTH: Self = Self::InvalidKeyLength;
    pub const UNSUPPORTED_KEY_TYPE: Self = Self::UnsupportedKeyType;
    pub const UNSUPPORTED_CURVE: Self = Self::UnsupportedCurve;
    pub const INTERNAL_ERROR: Self = Self::InternalError;
    pub const NOT_IMPLEMENTED: Self = Self::NotImplemented;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DidError {
    pub code: DidErrorCode,
    pub message: String,
}

impl DidError {
    pub fn new(code: DidErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for DidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DidError {}

pub fn to_dp_string(value: impl AsRef<str>) -> String {
    value.as_ref().to_string()
}

pub fn invalid_did_uri(details: impl AsRef<str>) -> DidError {
    let details = details.as_ref();
    let msg = if details.is_empty() {
        "Malformed DID URI".to_string()
    } else {
        format!("Malformed DID URI: {details}")
    };
    DidError::new(DidErrorCode::InvalidDidUri, msg)
}

pub fn invalid_method_name(method: impl AsRef<str>) -> DidError {
    DidError::new(
        DidErrorCode::InvalidMethodName,
        format!("Invalid DID method name: {}", method.as_ref()),
    )
}

pub fn invalid_method_id(details: impl AsRef<str>) -> DidError {
    let details = details.as_ref();
    let msg = if details.is_empty() {
        "Invalid DID method-specific-id".to_string()
    } else {
        format!("Invalid DID method-specific-id: {details}")
    };
    DidError::new(DidErrorCode::InvalidMethodSpecificId, msg)
}

pub fn invalid_percent_encoding() -> DidError {
    DidError::new(
        DidErrorCode::InvalidPercentEncoding,
        "Invalid percent encoding",
    )
}

pub fn unsupported_method(method: impl AsRef<str>) -> DidError {
    DidError::new(
        DidErrorCode::UnsupportedMethod,
        format!("Unsupported DID method: {}", method.as_ref()),
    )
}

pub fn method_not_registered(method: impl AsRef<str>) -> DidError {
    DidError::new(
        DidErrorCode::MethodNotRegistered,
        format!("DID method not registered: {}", method.as_ref()),
    )
}

pub fn method_not_allowed(method: impl AsRef<str>) -> DidError {
    DidError::new(
        DidErrorCode::MethodNotAllowed,
        format!("DID method not allowed by policy: {}", method.as_ref()),
    )
}

pub fn document_too_large(details: impl AsRef<str>) -> DidError {
    let details = details.as_ref();
    let msg = if details.is_empty() {
        "DID document exceeds maximum size".to_string()
    } else {
        format!("DID document too large: {details}")
    };
    DidError::new(DidErrorCode::DocumentTooLarge, msg)
}

pub fn invalid_document_json(details: impl AsRef<str>) -> DidError {
    let details = details.as_ref();
    let msg = if details.is_empty() {
        "Invalid DID document JSON".to_string()
    } else {
        format!("Invalid DID document JSON: {details}")
    };
    DidError::new(DidErrorCode::InvalidDocumentJson, msg)
}

pub fn missing_field(field: impl AsRef<str>) -> DidError {
    DidError::new(
        DidErrorCode::DocumentMissingRequiredField,
        format!("Missing required field: {}", field.as_ref()),
    )
}

pub fn field_not_string(field: impl AsRef<str>) -> DidError {
    DidError::new(
        DidErrorCode::InvalidDocumentJson,
        format!("Field is not a string: {}", field.as_ref()),
    )
}

pub fn document_id_mismatch(expected: impl AsRef<str>, actual: impl AsRef<str>) -> DidError {
    DidError::new(
        DidErrorCode::DocumentIdMismatch,
        format!(
            "DID document id mismatch: expected {}, got {}",
            expected.as_ref(),
            actual.as_ref()
        ),
    )
}

pub fn no_verification_methods() -> DidError {
    DidError::new(
        DidErrorCode::NoVerificationMethods,
        "DID document has no verificationMethod",
    )
}

pub fn no_verification_relationships() -> DidError {
    DidError::new(
        DidErrorCode::NoVerificationRelationships,
        "DID document requires authentication/assertionMethod/keyAgreement",
    )
}

pub fn invalid_verification_method(details: impl AsRef<str>) -> DidError {
    let details = details.as_ref();
    let msg = if details.is_empty() {
        "Invalid verificationMethod entry".to_string()
    } else {
        format!("Invalid verificationMethod: {details}")
    };
    DidError::new(DidErrorCode::InvalidVerificationMethod, msg)
}

pub fn https_required() -> DidError {
    DidError::new(
        DidErrorCode::HttpsRequired,
        "HTTPS is required for this operation",
    )
}

pub fn fetcher_not_configured() -> DidError {
    DidError::new(
        DidErrorCode::FetcherNotConfigured,
        "Document fetcher is not configured",
    )
}

pub fn network_error(details: impl AsRef<str>) -> DidError {
    let details = details.as_ref();
    let msg = format!("Network error: {details}");
    DidError::new(DidErrorCode::NetworkError, msg)
}

pub fn fragment_not_found(fragment: impl AsRef<str>) -> DidError {
    DidError::new(
        DidErrorCode::FragmentNotFound,
        format!("Fragment not found: #{}", fragment.as_ref()),
    )
}

pub fn invalid_reference(details: impl AsRef<str>) -> DidError {
    let details = details.as_ref();
    let msg = if details.is_empty() {
        "Invalid DID reference".to_string()
    } else {
        format!("Invalid DID reference: {details}")
    };
    DidError::new(DidErrorCode::InvalidReference, msg)
}

pub fn invalid_key_format(details: impl AsRef<str>) -> DidError {
    let details = details.as_ref();
    let msg = if details.is_empty() {
        "Invalid key format".to_string()
    } else {
        format!("Invalid key format: {details}")
    };
    DidError::new(DidErrorCode::InvalidKeyFormat, msg)
}

pub fn invalid_key_length(expected: usize, actual: usize) -> DidError {
    DidError::new(
        DidErrorCode::InvalidKeyLength,
        format!("Invalid key length: expected {expected} bytes, got {actual} bytes"),
    )
}

pub fn unsupported_key_type(kind: impl AsRef<str>) -> DidError {
    DidError::new(
        DidErrorCode::UnsupportedKeyType,
        format!("Unsupported key type: {}", kind.as_ref()),
    )
}

pub fn unsupported_curve(curve: impl AsRef<str>) -> DidError {
    DidError::new(
        DidErrorCode::UnsupportedCurve,
        format!("Unsupported curve: {}", curve.as_ref()),
    )
}

pub fn not_implemented(feature: impl AsRef<str>) -> DidError {
    DidError::new(
        DidErrorCode::NotImplemented,
        format!("Not implemented: {}", feature.as_ref()),
    )
}

pub fn is_supported_method(method: impl AsRef<str>) -> bool {
    matches!(method.as_ref(), "key" | "web")
}
