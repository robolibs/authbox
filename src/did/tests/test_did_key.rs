use super::super::*;

#[test]
fn did_key_encodes_and_parses_ed25519_keys() {
    let keypair = crate::pki::generate_ed25519_keypair().unwrap();
    assert_eq!(keypair.public_key.len(), 32);

    let public_key: [u8; 32] = keypair.public_key.as_slice().try_into().unwrap();
    let did = encode_ed25519_did_key(public_key).unwrap();

    assert!(did.starts_with("did:key:z"));
    let parsed = parse_did_key(&did).unwrap();
    assert_eq!(parsed.type_, DidKeyType::Ed25519);
    assert_eq!(parsed.public_key, keypair.public_key);
}

#[test]
fn did_key_cpp_named_type_constants_match_rust_variants() {
    assert_eq!(DidKeyType::ED25519, DidKeyType::Ed25519);
    assert_eq!(DidKeyType::X25519, DidKeyType::X25519);
}

#[test]
fn did_key_info_default_matches_cpp_value_initialized_aggregate() {
    let info = DidKeyInfo::default();

    assert_eq!(info.type_, DidKeyType::ED25519);
    assert!(info.public_key.is_empty());
    assert!(info.prefixed_key.is_empty());
    assert_eq!(info.fingerprint, "");
    assert_eq!(info.did_uri, "");
}

#[test]
fn did_key_resolves_document_json() {
    let keypair = crate::pki::generate_ed25519_keypair().unwrap();
    let public_key: [u8; 32] = keypair.public_key.as_slice().try_into().unwrap();
    let did = encode_ed25519_did_key(public_key).unwrap();

    let json = resolve_did_key_document_json(&did).unwrap();
    let document = parse_document(&json).unwrap();

    assert_eq!(document.id, did);
    assert_eq!(document.verification_methods.len(), 1);
    assert_eq!(document.authentication.len(), 1);
}

#[test]
fn did_key_resolver_supports_inline_resolution_without_network_fetcher() {
    let keypair = crate::pki::generate_ed25519_keypair().unwrap();
    let public_key: [u8; 32] = keypair.public_key.as_slice().try_into().unwrap();
    let did = encode_ed25519_did_key(public_key).unwrap();

    let resolver = Resolver::new();
    let resolved = resolver.resolve(&did).unwrap();

    assert_eq!(resolved.source_url, "did:key:inline");
    assert_eq!(resolved.document.id, did);
}
