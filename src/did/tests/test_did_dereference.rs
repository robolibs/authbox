use super::super::*;

const ED25519_JWK: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

fn jwk_did() -> String {
    encode_did_jwk(ED25519_JWK).unwrap()
}

#[test]
fn did_dereference_whole_document() {
    let did = jwk_did();
    let resolver = Resolver::new();

    let dereferenced = dereference(&did, &resolver).unwrap();

    assert!(is_document(&dereferenced));
    assert!(!is_verification_method(&dereferenced));
    assert_eq!(
        get_document(&dereferenced)
            .unwrap()
            .verification_methods
            .len(),
        1
    );
}

#[test]
fn did_dereference_verification_method_with_local_fragment() {
    let did = jwk_did();
    let resolver = Resolver::new();
    let did_url = format!("{did}#0");

    let dereferenced = dereference(&did_url, &resolver).unwrap();

    assert!(is_verification_method(&dereferenced));
    assert!(!is_document(&dereferenced));
    assert_eq!(
        get_verification_method(&dereferenced).unwrap().type_,
        "JsonWebKey2020"
    );
}

#[test]
fn did_dereference_verification_method_with_absolute_fragment_reference() {
    let did = jwk_did();
    let resolver = Resolver::new();
    let resolution = resolver.resolve(&did).unwrap();
    let fragment = resolution.document.verification_methods[0]
        .id
        .split_once('#')
        .unwrap()
        .1;
    let did_url = format!("{did}#{fragment}");

    let dereferenced = dereference(&did_url, &resolver).unwrap();

    assert!(is_verification_method(&dereferenced));
}

#[test]
fn did_dereference_missing_fragment_returns_error() {
    let did = jwk_did();
    let resolver = Resolver::new();
    let did_url = format!("{did}#nonexistent");

    assert!(dereference(&did_url, &resolver).is_err());
}

#[test]
fn did_dereference_parse_url_with_path_query_and_fragment() {
    let parsed =
        parse_url("did:example:123/path/to/resource?service=agent&relativeRef=/credentials#degree")
            .unwrap();

    assert_eq!(parsed.did.uri, "did:example:123");
    assert_eq!(parsed.path, "/path/to/resource");
    assert_eq!(parsed.query, "service=agent&relativeRef=/credentials");
    assert_eq!(parsed.fragment, "degree");
}

#[test]
fn did_dereference_works_with_did_key() {
    let public_key = core::array::from_fn(|idx| idx as u8);
    let did = encode_ed25519_did_key(public_key).unwrap();
    let resolver = Resolver::new();
    let resolution = resolver.resolve(&did).unwrap();
    let fragment = resolution.document.verification_methods[0]
        .id
        .split_once('#')
        .unwrap()
        .1;
    let did_url = format!("{did}#{fragment}");

    let dereferenced = dereference(&did_url, &resolver).unwrap();

    assert!(is_verification_method(&dereferenced));
}

#[test]
fn did_dereference_with_options_matches_cpp_explicit_surface() {
    let did = jwk_did();
    let resolver = Resolver::new();

    let dereferenced =
        dereference_with_options(&did, &resolver, &DereferenceOptions::default()).unwrap();

    assert!(is_document(&dereferenced));
    assert_eq!(dereferenced.content_type, "application/did+ld+json");
}
