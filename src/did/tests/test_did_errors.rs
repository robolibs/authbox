use super::*;

fn assert_cpp_error(err: DidError, code: DidErrorCode, message: &str) {
    assert_eq!(err.code, code);
    assert_eq!(err.message, message);
}

#[test]
fn did_errors_match_cpp_helper_messages() {
    assert_eq!(to_dp_string("did:error-helper"), "did:error-helper");
    assert_eq!(error::to_dp_string("did:error-module"), "did:error-module");
    assert_eq!(
        errors::to_dp_string("did:errors-module"),
        "did:errors-module"
    );

    assert_cpp_error(
        error::invalid_did_uri(""),
        DidErrorCode::InvalidDidUri,
        "Malformed DID URI",
    );
    assert_cpp_error(
        error::invalid_did_uri("bad scheme"),
        DidErrorCode::InvalidDidUri,
        "Malformed DID URI: bad scheme",
    );
    assert_cpp_error(
        error::invalid_method_name("UPPER"),
        DidErrorCode::InvalidMethodName,
        "Invalid DID method name: UPPER",
    );
    assert_cpp_error(
        error::invalid_method_id(""),
        DidErrorCode::InvalidMethodSpecificId,
        "Invalid DID method-specific-id",
    );
    assert_cpp_error(
        error::invalid_method_id("bad syntax"),
        DidErrorCode::InvalidMethodSpecificId,
        "Invalid DID method-specific-id: bad syntax",
    );
    assert_cpp_error(
        error::invalid_percent_encoding(),
        DidErrorCode::InvalidPercentEncoding,
        "Invalid percent encoding",
    );
    assert_cpp_error(
        error::unsupported_method("example"),
        DidErrorCode::UnsupportedMethod,
        "Unsupported DID method: example",
    );
    assert_cpp_error(
        error::method_not_registered("peer"),
        DidErrorCode::MethodNotRegistered,
        "DID method not registered: peer",
    );
    assert_cpp_error(
        error::method_not_allowed("web"),
        DidErrorCode::MethodNotAllowed,
        "DID method not allowed by policy: web",
    );
    assert_cpp_error(
        error::document_too_large(""),
        DidErrorCode::DocumentTooLarge,
        "DID document exceeds maximum size",
    );
    assert_cpp_error(
        error::document_too_large("limit"),
        DidErrorCode::DocumentTooLarge,
        "DID document too large: limit",
    );
    assert_cpp_error(
        error::invalid_document_json(""),
        DidErrorCode::InvalidDocumentJson,
        "Invalid DID document JSON",
    );
    assert_cpp_error(
        error::invalid_document_json("bad"),
        DidErrorCode::InvalidDocumentJson,
        "Invalid DID document JSON: bad",
    );
    assert_cpp_error(
        error::missing_field("id"),
        DidErrorCode::DocumentMissingRequiredField,
        "Missing required field: id",
    );
    assert_cpp_error(
        error::field_not_string("id"),
        DidErrorCode::InvalidDocumentJson,
        "Field is not a string: id",
    );
    assert_cpp_error(
        error::document_id_mismatch("did:example:1", "did:example:2"),
        DidErrorCode::DocumentIdMismatch,
        "DID document id mismatch: expected did:example:1, got did:example:2",
    );
    assert_cpp_error(
        error::no_verification_methods(),
        DidErrorCode::NoVerificationMethods,
        "DID document has no verificationMethod",
    );
    assert_cpp_error(
        error::no_verification_relationships(),
        DidErrorCode::NoVerificationRelationships,
        "DID document requires authentication/assertionMethod/keyAgreement",
    );
    assert_cpp_error(
        error::invalid_verification_method(""),
        DidErrorCode::InvalidVerificationMethod,
        "Invalid verificationMethod entry",
    );
    assert_cpp_error(
        error::invalid_verification_method("bad"),
        DidErrorCode::InvalidVerificationMethod,
        "Invalid verificationMethod: bad",
    );
    assert_cpp_error(
        error::https_required(),
        DidErrorCode::HttpsRequired,
        "HTTPS is required for this operation",
    );
    assert_cpp_error(
        error::fetcher_not_configured(),
        DidErrorCode::FetcherNotConfigured,
        "Document fetcher is not configured",
    );
    assert_cpp_error(
        error::network_error("dns failed"),
        DidErrorCode::NetworkError,
        "Network error: dns failed",
    );
    assert_cpp_error(
        error::network_error(""),
        DidErrorCode::NetworkError,
        "Network error: ",
    );
    assert_cpp_error(
        error::fragment_not_found("key-1"),
        DidErrorCode::FragmentNotFound,
        "Fragment not found: #key-1",
    );
    assert_cpp_error(
        error::invalid_key_format(""),
        DidErrorCode::InvalidKeyFormat,
        "Invalid key format",
    );
    assert_cpp_error(
        error::invalid_key_format("bad"),
        DidErrorCode::InvalidKeyFormat,
        "Invalid key format: bad",
    );
    assert_cpp_error(
        error::invalid_key_length(32, 31),
        DidErrorCode::InvalidKeyLength,
        "Invalid key length: expected 32 bytes, got 31 bytes",
    );
    assert_cpp_error(
        error::unsupported_key_type("RSA"),
        DidErrorCode::UnsupportedKeyType,
        "Unsupported key type: RSA",
    );
    assert_cpp_error(
        error::unsupported_curve("P-384"),
        DidErrorCode::UnsupportedCurve,
        "Unsupported curve: P-384",
    );
    assert_cpp_error(
        error::not_implemented("did:example"),
        DidErrorCode::NotImplemented,
        "Not implemented: did:example",
    );
}

#[test]
fn did_errors_cpp_named_error_code_constants_match_rust_variants() {
    assert_eq!(DidErrorCode::INVALID_DID_URI, DidErrorCode::InvalidDidUri);
    assert_eq!(
        errors::DidErrorCode::INVALID_DID_URI,
        errors::DidErrorCode::InvalidDidUri
    );
    assert_eq!(
        DidErrorCode::INVALID_METHOD_NAME,
        DidErrorCode::InvalidMethodName
    );
    assert_eq!(
        DidErrorCode::INVALID_METHOD_ID,
        DidErrorCode::InvalidMethodId
    );
    assert_eq!(
        DidErrorCode::INVALID_PERCENT_ENCODING,
        DidErrorCode::InvalidPercentEncoding
    );
    assert_eq!(
        DidErrorCode::MALFORMED_DID_URL,
        DidErrorCode::MalformedDidUrl
    );
    assert_eq!(
        DidErrorCode::UNSUPPORTED_METHOD,
        DidErrorCode::UnsupportedMethod
    );
    assert_eq!(
        DidErrorCode::METHOD_NOT_REGISTERED,
        DidErrorCode::MethodNotRegistered
    );
    assert_eq!(
        DidErrorCode::METHOD_NOT_ALLOWED,
        DidErrorCode::MethodNotAllowed
    );
    assert_eq!(
        DidErrorCode::INVALID_METHOD_SPECIFIC_ID,
        DidErrorCode::InvalidMethodSpecificId
    );
    assert_eq!(
        DidErrorCode::INVALID_DOCUMENT_JSON,
        DidErrorCode::InvalidDocumentJson
    );
    assert_eq!(
        DidErrorCode::DOCUMENT_MISSING_REQUIRED_FIELD,
        DidErrorCode::DocumentMissingRequiredField
    );
    assert_eq!(
        DidErrorCode::DOCUMENT_ID_MISMATCH,
        DidErrorCode::DocumentIdMismatch
    );
    assert_eq!(
        DidErrorCode::DOCUMENT_TOO_LARGE,
        DidErrorCode::DocumentTooLarge
    );
    assert_eq!(
        DidErrorCode::NO_VERIFICATION_METHODS,
        DidErrorCode::NoVerificationMethods
    );
    assert_eq!(
        DidErrorCode::NO_VERIFICATION_RELATIONSHIPS,
        DidErrorCode::NoVerificationRelationships
    );
    assert_eq!(
        DidErrorCode::INVALID_VERIFICATION_METHOD,
        DidErrorCode::InvalidVerificationMethod
    );
    assert_eq!(
        DidErrorCode::RESOLUTION_FAILED,
        DidErrorCode::ResolutionFailed
    );
    assert_eq!(DidErrorCode::NETWORK_ERROR, DidErrorCode::NetworkError);
    assert_eq!(DidErrorCode::FETCH_FAILED, DidErrorCode::FetchFailed);
    assert_eq!(DidErrorCode::HTTPS_REQUIRED, DidErrorCode::HttpsRequired);
    assert_eq!(
        DidErrorCode::FETCHER_NOT_CONFIGURED,
        DidErrorCode::FetcherNotConfigured
    );
    assert_eq!(
        DidErrorCode::FRAGMENT_NOT_FOUND,
        DidErrorCode::FragmentNotFound
    );
    assert_eq!(
        DidErrorCode::INVALID_REFERENCE,
        DidErrorCode::InvalidReference
    );
    assert_eq!(
        DidErrorCode::INVALID_KEY_FORMAT,
        DidErrorCode::InvalidKeyFormat
    );
    assert_eq!(
        DidErrorCode::INVALID_KEY_LENGTH,
        DidErrorCode::InvalidKeyLength
    );
    assert_eq!(
        DidErrorCode::UNSUPPORTED_KEY_TYPE,
        DidErrorCode::UnsupportedKeyType
    );
    assert_eq!(
        DidErrorCode::UNSUPPORTED_CURVE,
        DidErrorCode::UnsupportedCurve
    );
    assert_eq!(DidErrorCode::INTERNAL_ERROR, DidErrorCode::InternalError);
    assert_eq!(DidErrorCode::NOT_IMPLEMENTED, DidErrorCode::NotImplemented);
}

#[test]
fn did_errors_legacy_supported_method_helper_matches_cpp_surface() {
    assert!(is_supported_method("key"));
    assert!(is_supported_method("web"));
    assert!(!is_supported_method("dns"));
    assert!(!is_supported_method("jwk"));
}
