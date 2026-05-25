use super::super::*;

const ED25519_JWK: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
const X25519_JWK: &str =
    r#"{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#;
const P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI","y":"hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU"}"#;

#[test]
fn did_jwk_parse_and_validate_ed25519_key() {
    let did = encode_did_jwk(ED25519_JWK).unwrap();
    assert!(did.starts_with("did:jwk:"));
    assert_eq!(
        parse_did_jwk(&did).unwrap(),
        canonicalize_jwk_json(ED25519_JWK).unwrap()
    );

    let document = parse_document(&resolve_did_jwk_document_json(&did).unwrap()).unwrap();
    assert_eq!(document.id, did);
    assert_eq!(document.verification_methods.len(), 1);
    assert_eq!(document.authentication.len(), 1);
    assert!(document.key_agreement.is_empty());
}

#[test]
fn did_jwk_parse_and_validate_x25519_key_agreement_key() {
    let did = encode_did_jwk(X25519_JWK).unwrap();
    let document = parse_document(&resolve_did_jwk_document_json(&did).unwrap()).unwrap();

    assert_eq!(document.id, did);
    assert_eq!(document.verification_methods.len(), 1);
    assert!(document.authentication.is_empty());
    assert_eq!(document.key_agreement.len(), 1);
}

#[test]
fn did_jwk_parse_and_validate_p256_authentication_key() {
    let did = encode_did_jwk(P256_JWK).unwrap();
    let document = parse_document(&resolve_did_jwk_document_json(&did).unwrap()).unwrap();

    assert_eq!(document.id, did);
    assert_eq!(document.verification_methods.len(), 1);
    assert_eq!(document.authentication.len(), 1);
    assert!(document.key_agreement.is_empty());
}

#[test]
fn did_jwk_rejects_malformed_base64url() {
    assert!(parse_did_jwk("did:jwk:not valid base64url!!!").is_err());
}

#[test]
fn did_jwk_rejects_invalid_json_and_missing_required_fields() {
    assert!(parse_did_jwk("did:jwk:bm90LWpzb24").is_err());
    assert!(
        encode_did_jwk(r#"{"crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#)
            .is_err()
    );
}

#[test]
fn did_jwk_roundtrip_canonicalization_matches_cpp_surface() {
    let jwk_original = r#"{
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "kty": "OKP",
        "crv": "Ed25519"
    }"#;
    let jwk_reordered =
        r#"{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

    assert_eq!(
        encode_did_jwk(jwk_original).unwrap(),
        encode_did_jwk(jwk_reordered).unwrap()
    );
}

#[test]
fn did_jwk_canonicalization_uses_json_string_escaping() {
    assert_eq!(
        canonicalize_jwk_json(r#"{"kty":"OKP","crv":"Ed25519","x":"A\"B\\C"}"#).unwrap(),
        r#"{"crv":"Ed25519","kty":"OKP","x":"A\"B\\C"}"#
    );
}

#[test]
fn did_jwk_integration_with_resolver() {
    let did = encode_did_jwk(ED25519_JWK).unwrap();
    let mut resolver = Resolver::new();
    resolver
        .registry_mut()
        .register_method("jwk", |did_uri, _| resolve_did_jwk_document_json(did_uri));

    let resolution = resolver.resolve(&did).unwrap();
    assert_eq!(resolution.document.id, did);
    assert_eq!(resolution.document.verification_methods.len(), 1);
    assert_eq!(resolution.source_url, "did:jwk:inline");
}
