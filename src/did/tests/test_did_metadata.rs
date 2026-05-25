use super::super::*;

const ED25519_JWK: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

fn did_jwk_resolution() -> Resolution {
    let did = encode_did_jwk(ED25519_JWK).unwrap();
    let resolver = Resolver::new();
    resolver.resolve(&did).unwrap()
}

#[test]
fn resolution_metadata_basic_resolution_includes_metadata() {
    let resolution = did_jwk_resolution();
    assert_eq!(
        resolution.resolution_metadata.content_type,
        "application/did+ld+json"
    );
}

#[test]
fn resolution_metadata_legacy_fields_still_work() {
    let resolution = did_jwk_resolution();

    assert_eq!(resolution.source_url, "did:jwk:inline");
    assert!(!resolution.raw_document_json.is_empty());
    assert_eq!(resolution.document.verification_methods.len(), 1);
}

#[test]
fn document_metadata_structure_exists_and_is_accessible() {
    let resolution = did_jwk_resolution();
    assert!(!resolution.document_metadata.deactivated);
    assert!(resolution.document_metadata.created.is_empty());
    assert!(resolution.document_metadata.updated.is_empty());
}

#[test]
fn resolution_metadata_can_be_populated_from_document() {
    let resolution = Resolver::resolve_from_document_with_source_url(
        "did:example:123",
        super::service_document_json(),
        "https://example.com/did.json",
    )
    .unwrap();

    assert_eq!(
        resolution.resolution_metadata.content_type,
        "application/did+ld+json"
    );
    assert_eq!(resolution.source_url, "https://example.com/did.json");
    assert_eq!(resolution.document.id, "did:example:123");
}

#[test]
fn resolution_metadata_error_field_remains_empty_on_success() {
    let resolution = did_jwk_resolution();
    assert!(resolution.resolution_metadata.error.is_empty());
}

#[test]
fn resolution_metadata_backward_compatibility_fields_are_populated() {
    let public_key = core::array::from_fn(|idx| idx as u8);
    let did = encode_ed25519_did_key(public_key).unwrap();
    let resolver = Resolver::new();
    let resolution = resolver.resolve(&did).unwrap();

    assert!(!resolution.did.uri.is_empty());
    assert_eq!(resolution.did.uri, did);
    assert!(!resolution.document.verification_methods.is_empty());
    assert_eq!(resolution.source_url, "did:key:inline");
    assert!(!resolution.raw_document_json.is_empty());
    assert!(!resolution.resolution_metadata.content_type.is_empty());
    assert!(!resolution.document_metadata.deactivated);
}
