use super::super::*;

const PEER_VERIFICATION: &str = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const PEER_VERIFICATION_AND_ENCRYPTION: &str = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc";

#[test]
fn did_peer_element_default_matches_cpp_value_initialized_aggregate() {
    let element = PeerElement::default();

    assert_eq!(element.type_, PeerElementType::Verification);
    assert_eq!(element.encoded_value, "");
}

#[test]
fn did_peer_parses_simple_numalgo_2_with_one_verification_key() {
    let elements = parse_did_peer(PEER_VERIFICATION).unwrap();
    assert_eq!(elements.len(), 1);
    assert_eq!(elements[0].type_, PeerElementType::Verification);
}

#[test]
fn did_peer_parses_numalgo_2_with_multiple_keys() {
    let elements = parse_did_peer(PEER_VERIFICATION_AND_ENCRYPTION).unwrap();
    assert_eq!(elements.len(), 2);
    assert_eq!(elements[0].type_, PeerElementType::Verification);
    assert_eq!(elements[1].type_, PeerElementType::Encryption);
}

#[test]
fn did_peer_rejects_wrong_method_unsupported_numalgo_and_empty_method_id() {
    assert!(parse_did_peer("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_err());
    assert!(parse_did_peer("did:peer:0z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_err());
    assert!(parse_did_peer("did:peer:").is_err());
}

#[test]
fn did_peer_decodes_base58btc_multibase_key_and_rejects_other_multibase() {
    assert!(
        !decode_peer_key("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
            .unwrap()
            .is_empty()
    );
    assert!(decode_peer_key("u6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_err());
}

#[test]
fn did_peer_decode_empty_key_matches_cpp_error_branch() {
    let error = decode_peer_key("").unwrap_err();
    assert_eq!(error.code, DidErrorCode::InvalidKeyFormat);
    assert_eq!(error.message, "Invalid key format: empty encoded key");
}

#[test]
fn did_peer_resolves_verification_key_to_document() {
    let document =
        parse_document(&resolve_did_peer_document_json(PEER_VERIFICATION).unwrap()).unwrap();

    assert_eq!(document.id, PEER_VERIFICATION);
    assert_eq!(document.verification_methods.len(), 1);
    assert_eq!(document.authentication.len(), 1);
    assert!(document.key_agreement.is_empty());
}

#[test]
fn did_peer_resolves_verification_and_encryption_keys_to_document() {
    let document =
        parse_document(&resolve_did_peer_document_json(PEER_VERIFICATION_AND_ENCRYPTION).unwrap())
            .unwrap();

    assert_eq!(document.id, PEER_VERIFICATION_AND_ENCRYPTION);
    assert_eq!(document.verification_methods.len(), 2);
    assert_eq!(document.authentication.len(), 1);
    assert_eq!(document.key_agreement.len(), 1);
}

#[test]
fn did_peer_relationship_refs_follow_cpp_second_pass_even_for_skipped_keys() {
    let did_uri = "did:peer:2.VuNotBase58btc.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc";
    let doc_json = resolve_did_peer_document_json(did_uri).unwrap();

    assert!(doc_json.contains("\"id\": \"did:peer:2.VuNotBase58btc.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc#key-0\""));
    assert!(doc_json.contains("\"authentication\": [\n    \"did:peer:2.VuNotBase58btc.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc#key-0\""));
    assert!(doc_json.contains("\"keyAgreement\": [\n    \"did:peer:2.VuNotBase58btc.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc#key-1\""));
}

#[test]
fn did_peer_integration_with_resolver() {
    let mut resolver = Resolver::new();
    resolver
        .registry_mut()
        .register_method("peer", |did_uri, _| resolve_did_peer_document_json(did_uri));

    let resolution = resolver.resolve(PEER_VERIFICATION).unwrap();

    assert_eq!(resolution.document.id, PEER_VERIFICATION);
    assert_eq!(resolution.document.verification_methods.len(), 1);
    assert_eq!(resolution.source_url, "did:peer:inline");
}

#[test]
fn did_peer_parses_service_and_unknown_element_types() {
    let with_service = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.SeyJpZCI6IiNzZXJ2aWNlIiwidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQifQ";
    let elements = parse_did_peer(with_service).unwrap();
    assert_eq!(elements.len(), 3);
    assert_eq!(elements[0].type_, PeerElementType::Verification);
    assert_eq!(elements[1].type_, PeerElementType::Encryption);
    assert_eq!(elements[2].type_, PeerElementType::Service);

    let with_unknown =
        "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.XsomeUnknownElement";
    let elements = parse_did_peer(with_unknown).unwrap();
    assert_eq!(elements.len(), 2);
    assert_eq!(elements[0].type_, PeerElementType::Verification);
    assert_eq!(elements[1].type_, PeerElementType::Unknown);
}

#[test]
fn did_peer_resolves_service_element_to_document_service() {
    let did_uri = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.SeyJpZCI6IiNzZXJ2aWNlIiwidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQifQ";

    let doc_json = resolve_did_peer_document_json(did_uri).unwrap();
    assert!(doc_json.contains("\"service\""));
    assert!(doc_json.contains("https://example.com/endpoint"));

    let document = parse_document(&doc_json).unwrap();
    assert_eq!(document.services.len(), 1);
    assert_eq!(document.services[0].id, format!("{did_uri}#service"));
    assert_eq!(document.services[0].type_, "dm");
    assert_eq!(
        document.services[0].service_endpoint_json,
        "\"https://example.com/endpoint\""
    );
}

#[test]
fn did_peer_resolves_full_service_endpoint_json_without_flattening() {
    let service = r##"{"id":"#agent","type":"DIDCommMessaging","serviceEndpoint":{"uri":"https://agent.example","routingKeys":["did:example:mediator#key"]}}"##;
    let did_uri = format!(
        "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.S{}",
        base64url_encode(service.as_bytes())
    );

    let document = parse_document(&resolve_did_peer_document_json(&did_uri).unwrap()).unwrap();
    assert_eq!(document.services.len(), 1);
    assert_eq!(document.services[0].id, format!("{did_uri}#agent"));
    assert_eq!(document.services[0].type_, "DIDCommMessaging");
    assert!(
        document.services[0]
            .service_endpoint_json
            .contains("routingKeys")
    );
    assert!(
        document.services[0]
            .service_endpoint_json
            .contains("agent.example")
    );
}
