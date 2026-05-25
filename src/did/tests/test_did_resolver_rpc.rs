use super::super::*;

fn make_test_cert_with_did(
    did_uri: &str,
) -> (
    crate::pki::Certificate,
    crate::pki::KeyPair,
    x509::DidWebDocumentBundle,
) {
    let keypair = keylock::generate_ed25519_keypair().unwrap();
    let cert = crate::pki::CertificateBuilder::new()
        .set_serial_u64(0x720c)
        .set_subject_from_string("CN=example.com,O=Example")
        .unwrap()
        .set_issuer_from_string("CN=example.com,O=Example")
        .unwrap()
        .set_validity(
            crate::pki::DerTime {
                year: 2026,
                month: 5,
                day: 24,
                hour: 0,
                minute: 0,
                second: 0,
            },
            crate::pki::DerTime {
                year: 2027,
                month: 5,
                day: 24,
                hour: 0,
                minute: 0,
                second: 0,
            },
        )
        .set_subject_public_key_ed25519(keypair.public_key.clone())
        .set_basic_constraints_with_critical(false, None, false)
        .unwrap()
        .set_subject_alt_name(&[crate::pki::GeneralName {
            type_: crate::pki::GeneralNameType::Uri,
            value: did_uri.as_bytes().to_vec(),
        }])
        .unwrap()
        .build_ed25519_with_self_signed(&keypair, true)
        .unwrap();
    let bundle = x509::generate_did_web_document_from_certificate("example.com", &cert).unwrap();
    (cert, keypair, bundle)
}

#[test]
fn resolver_rpc_fetches_did_web_using_configured_fetcher() {
    let (_cert, _keypair, bundle) = make_test_cert_with_did("did:web:example.com");
    let did_document_json = bundle.did_document_json.clone();
    let resolver = Resolver::with_fetcher(move |url| {
        assert_eq!(url, "https://example.com/.well-known/did.json");
        Ok(did_document_json.clone())
    });

    let resolved = resolver.resolve("did:web:example.com").unwrap();

    assert_eq!(resolved.document.id, "did:web:example.com");
    assert_eq!(
        resolved.source_url,
        "https://example.com/.well-known/did.json"
    );
}

#[test]
fn resolver_rpc_client_resolves_and_verifies_binding_over_loopback() {
    let (cert, _keypair, bundle) = make_test_cert_with_did("did:web:example.com");
    let did_document_json = bundle.did_document_json.clone();
    let resolver = Resolver::with_fetcher(move |url| {
        assert_eq!(url, "https://example.com/.well-known/did.json");
        Ok(did_document_json.clone())
    });
    let service = rpc::Service::new(resolver);
    let client = rpc::Client::new(rpc::LoopbackRemote::new(service));

    let resolved = client.resolve("did:web:example.com").unwrap();
    assert_eq!(resolved.document.id, "did:web:example.com");
    assert_eq!(
        resolved.source_url,
        "https://example.com/.well-known/did.json"
    );

    assert!(
        client
            .verify_binding(
                "did:web:example.com",
                &bundle.did_document_json,
                &cert.to_pem()
            )
            .unwrap()
    );
}

#[test]
fn resolver_rpc_detail_namespace_matches_cpp_codec_helpers() {
    let message = rpc::detail::message_from_string("hello");
    assert_eq!(message, b"hello");
    assert_eq!(rpc::detail::string_from_message(&message), "hello");
    assert_eq!(rpc::detail::json_escape("a\"b\\c\n"), "a\\\"b\\\\c\\n");

    let payload = rpc::detail::message_from_string(
        r#"{"success":true,"error":"","did_uri":"did:example:123","source_url":"inline","did_document_json":"{\"id\":\"did:example:123\"}"}"#,
    );
    let object = rpc::detail::parse_json_object(&payload).unwrap();
    assert!(rpc::detail::get_bool_field(&object, "success"));
    assert_eq!(
        rpc::detail::get_string_field(&object, "did_uri"),
        "did:example:123"
    );
    assert_eq!(rpc::detail::get_string_field(&object, "missing"), "");
    assert!(!rpc::detail::get_bool_field(&object, "missing"));

    let response = rpc::ResolveResponse {
        success: true,
        error: String::new(),
        did_uri: "did:example:123".to_string(),
        source_url: "inline".to_string(),
        did_document_json: "{\"id\":\"did:example:123\"}".to_string(),
    };
    let encoded = rpc::detail::encode_resolve_response(&response);
    let decoded = rpc::detail::decode_resolve_response(&encoded).unwrap();
    assert_eq!(decoded, response);

    let verify = rpc::VerifyBindingResponse {
        success: true,
        valid: false,
        error: "binding failed".to_string(),
    };
    let encoded = rpc::detail::encode_verify_response(&verify);
    let decoded = rpc::detail::decode_verify_response(&encoded).unwrap();
    assert_eq!(decoded, verify);

    let invalid = rpc::detail::parse_json_object(b"not-json").unwrap_err();
    assert_eq!(
        invalid.message,
        "Invalid DID document JSON: invalid json payload"
    );
}
