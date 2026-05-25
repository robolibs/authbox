use super::super::*;

#[test]
fn did_document_web_url_conversion_matches_cpp_vectors() {
    assert_eq!(
        did_web_document_url("did:web:example.com").unwrap(),
        "https://example.com/.well-known/did.json"
    );
    assert_eq!(
        did_web_document_url("did:web:example.com:users:alice").unwrap(),
        "https://example.com/users/alice/did.json"
    );
    assert_eq!(
        did_web_document_url("did:web:example.com::alice").unwrap(),
        "https://example.com//alice/did.json"
    );
    assert_eq!(
        did_web_document_url("did:web:example.com:").unwrap(),
        "https://example.com//did.json"
    );
}

#[test]
fn did_document_parse_and_validate_json() {
    let doc_json = r#"{
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
      "id": "did:web:example.com",
      "verificationMethod": [
        {
          "id": "did:web:example.com#0",
          "type": "JsonWebKey2020",
          "controller": "did:web:example.com",
          "publicKeyJwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": "AA",
            "y": "BB"
          }
        }
      ],
      "authentication": ["did:web:example.com#0"],
      "assertionMethod": ["did:web:example.com#0"]
    }"#;

    let document = parse_document(doc_json).unwrap();
    assert_eq!(document.verification_methods.len(), 1);
    assert_eq!(document.assertion_method.len(), 1);
    assert!(validate_document(&document, "did:web:example.com").unwrap());
}

#[test]
fn did_document_parser_accepts_basic_dids_and_capability_relationships_like_cpp_tests() {
    let parsed = parse("did:web:example.com").unwrap();
    assert_eq!(parsed.method, "web");
    assert!(parse("https://example.com").is_err());

    let doc_json = r#"{
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:example:123",
        "verificationMethod": [{
            "id": "did:example:123#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:example:123",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }
        }],
        "authentication": ["did:example:123#key-1"],
        "capabilityInvocation": ["did:example:123#key-1"],
        "capabilityDelegation": ["did:example:123#key-1"]
    }"#;

    let document = parse_document(doc_json).unwrap();
    assert_eq!(document.authentication.len(), 1);
    assert_eq!(document.capability_invocation.len(), 1);
    assert_eq!(document.capability_delegation.len(), 1);
}

#[test]
fn did_document_parse_errors_match_cpp_surface() {
    let error = parse_document(r#"{"id": "did:example:123", "verificationMethod": ["#).unwrap_err();
    assert_eq!(error.code, DidErrorCode::InvalidDocumentJson);
    assert_eq!(error.message, "Invalid DID document JSON: parse failed");

    let error = parse_document(r#"{"id": "did:example:123"}"#).unwrap_err();
    assert_eq!(error.code, DidErrorCode::InvalidDocumentJson);
    assert_eq!(
        error.message,
        "Invalid DID document JSON: verificationMethod must be a non-empty array"
    );
}

#[test]
fn did_document_public_key_jwk_requires_cpp_fields() {
    let missing_crv = r#"{
      "id": "did:example:123",
      "verificationMethod": [{
        "id": "did:example:123#key-1",
        "type": "JsonWebKey2020",
        "controller": "did:example:123",
        "publicKeyJwk": {"kty": "OKP", "x": "AA"}
      }],
      "authentication": ["did:example:123#key-1"]
    }"#;
    let error = parse_document(missing_crv).unwrap_err();
    assert_eq!(error.code, DidErrorCode::DocumentMissingRequiredField);
    assert_eq!(error.message, "Missing required field: crv");

    let non_string_x = r#"{
      "id": "did:example:123",
      "verificationMethod": [{
        "id": "did:example:123#key-1",
        "type": "JsonWebKey2020",
        "controller": "did:example:123",
        "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": 1}
      }],
      "authentication": ["did:example:123#key-1"]
    }"#;
    let error = parse_document(non_string_x).unwrap_err();
    assert_eq!(error.code, DidErrorCode::InvalidDocumentJson);
    assert_eq!(error.message, "Field is not a string: x");
}

#[test]
fn did_document_generates_did_web_document_from_certificate_and_verifies_binding() {
    let keypair = crate::pki::generate_ed25519_keypair().unwrap();
    let did_uri = "did:web:example.com";
    let certificate = crate::pki::CertificateBuilder::new()
        .set_serial_u64(0x5d1d)
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

    let generated =
        x509::generate_did_web_document_from_certificate("example.com", &certificate).unwrap();
    let document = parse_document(&generated.did_document_json).unwrap();

    assert_eq!(generated.did_uri, did_uri);
    assert_eq!(document.id, did_uri);
    assert!(x509::verify_certificate_binding(&certificate, &document, did_uri).unwrap());
}

#[test]
fn did_document_x509_generation_defaults_fragment_like_cpp() {
    let key = [0x11; 32];

    let default_doc = x509::generate_did_web_document("example.com", &key).unwrap();
    assert_eq!(default_doc.verification_method_id, "did:web:example.com#0");

    let empty_fragment_doc =
        x509::generate_did_web_document_with_fragment("example.com", &key, "").unwrap();
    assert_eq!(empty_fragment_doc, default_doc);

    let named_fragment_doc =
        x509::generate_did_web_document_with_fragment("example.com", &key, "key-1").unwrap();
    assert_eq!(
        named_fragment_doc.verification_method_id,
        "did:web:example.com#key-1"
    );
}

#[test]
fn did_document_x509_helpers_preserve_cpp_raw_error_messages() {
    let empty_domain = x509::generate_did_web_document("", &[0x11; 32]).unwrap_err();
    assert_eq!(empty_domain.code, DidErrorCode::InvalidMethodSpecificId);
    assert_eq!(empty_domain.message, "Domain must not be empty");

    let unsupported_key = x509::generate_did_web_document("example.com", &[0x22; 31]).unwrap_err();
    assert_eq!(unsupported_key.code, DidErrorCode::UnsupportedKeyType);
    assert_eq!(
        unsupported_key.message,
        "Unsupported public key format for DID JWK"
    );

    let empty_key_cert = crate::pki::Certificate::default();
    let empty_key = x509::jwk_from_certificate_public_key(&empty_key_cert).unwrap_err();
    assert_eq!(empty_key.code, DidErrorCode::InvalidKeyFormat);
    assert_eq!(empty_key.message, "Certificate public key is empty");
}

#[test]
fn did_document_x509_binding_errors_preserve_cpp_raw_messages() {
    let keypair = crate::pki::generate_ed25519_keypair().unwrap();
    let cert_did_uri = "did:web:device.example";
    let requested_did_uri = "did:web:other.example";
    let certificate = crate::pki::CertificateBuilder::new()
        .set_serial_u64(0x5d1e)
        .set_subject_from_string("CN=device.example")
        .unwrap()
        .set_issuer_from_string("CN=device.example")
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
        .set_subject_alt_name(&[crate::pki::GeneralName {
            type_: crate::pki::GeneralNameType::Uri,
            value: cert_did_uri.as_bytes().to_vec(),
        }])
        .unwrap()
        .build_ed25519_with_self_signed(&keypair, true)
        .unwrap();

    let requested_doc = x509::generate_did_web_document(
        "other.example",
        &certificate.tbs.subject_public_key_info.public_key,
    )
    .unwrap();
    let document = parse_document(&requested_doc.did_document_json).unwrap();
    let san_error =
        x509::verify_certificate_binding(&certificate, &document, requested_did_uri).unwrap_err();
    assert_eq!(san_error.code, DidErrorCode::InvalidVerificationMethod);
    assert_eq!(
        san_error.message,
        "Certificate does not contain matching DID URI in SAN"
    );

    let other_key = crate::pki::generate_ed25519_keypair().unwrap();
    let cert_doc =
        x509::generate_did_web_document("device.example", &other_key.public_key).unwrap();
    let document = parse_document(&cert_doc.did_document_json).unwrap();
    let method_error =
        x509::verify_certificate_binding(&certificate, &document, cert_did_uri).unwrap_err();
    assert_eq!(method_error.code, DidErrorCode::InvalidVerificationMethod);
    assert_eq!(
        method_error.message,
        "No DID verificationMethod matches certificate public key"
    );
}
