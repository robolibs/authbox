use super::super::*;

#[test]
fn did_privacy_security_cpp_combined_file_smoke_cases() {
    let email_doc = DidDocument {
        id: "did:example:user@example.com".to_string(),
        ..DidDocument::default()
    };
    let email_concerns = privacy::scan_for_pii(&email_doc);
    assert!(!email_concerns.is_empty());
    assert_eq!(email_concerns[0].risk, privacy::PrivacyRisk::Critical);
    assert_eq!(email_concerns[0].category, "Email Address");

    let phone_doc = DidDocument {
        id: "did:example:555-123-4567".to_string(),
        ..DidDocument::default()
    };
    let phone_concerns = privacy::scan_for_pii(&phone_doc);
    assert!(!phone_concerns.is_empty());
    assert_eq!(phone_concerns[0].risk, privacy::PrivacyRisk::Critical);

    let safe_doc = DidDocument {
        id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        ..DidDocument::default()
    };
    assert!(privacy::scan_for_pii(&safe_doc).is_empty());
    assert!(privacy::is_safe_for_immutable_storage(&safe_doc));
}

#[test]
fn did_privacy_security_cpp_key_reuse_and_separate_key_cases() {
    let reused = DidDocument {
        id: "did:example:123".to_string(),
        authentication: vec!["did:example:123#key-1".to_string()],
        assertion_method: vec!["did:example:123#key-1".to_string()],
        key_agreement: vec!["did:example:123#key-1".to_string()],
        ..DidDocument::default()
    };
    let concerns = privacy::check_correlation_risks(&reused);
    assert!(!concerns.is_empty());
    assert_eq!(concerns[0].risk, privacy::PrivacyRisk::Medium);
    assert_eq!(concerns[0].category, "Key Reuse");

    let separate = DidDocument {
        id: "did:example:123".to_string(),
        authentication: vec!["did:example:123#key-1".to_string()],
        assertion_method: vec!["did:example:123#key-2".to_string()],
        key_agreement: vec!["did:example:123#key-3".to_string()],
        ..DidDocument::default()
    };
    assert!(privacy::check_correlation_risks(&separate).is_empty());
}

#[test]
fn did_privacy_security_cpp_crypto_strength_smoke_cases() {
    use security::CryptographicStrength::*;

    let ed25519 = VerificationMethod {
        type_: "Ed25519VerificationKey2020".to_string(),
        ..VerificationMethod::default()
    };
    assert_eq!(
        security::evaluate_verification_method(&ed25519, 0).strength,
        Recommended
    );

    let secp256k1 = VerificationMethod {
        type_: "EcdsaSecp256k1VerificationKey2019".to_string(),
        ..VerificationMethod::default()
    };
    let deprecated = security::evaluate_verification_method(&secp256k1, 0);
    assert_eq!(deprecated.strength, Deprecated);
    assert_eq!(deprecated.category, "Deprecated Cryptography");

    let p256 = VerificationMethod {
        type_: "JsonWebKey2020".to_string(),
        public_key_jwk: Some(JsonWebKey {
            kty: String::new(),
            crv: "P-256".to_string(),
            x: String::new(),
            y: String::new(),
        }),
        ..VerificationMethod::default()
    };
    assert_eq!(
        security::evaluate_verification_method(&p256, 0).strength,
        Acceptable
    );

    let mixed_doc = DidDocument {
        id: "did:example:123".to_string(),
        verification_methods: vec![ed25519, secp256k1],
        ..DidDocument::default()
    };
    let concerns = security::scan_document(&mixed_doc);
    assert_eq!(concerns.len(), 1);
    assert_eq!(concerns[0].strength, Deprecated);

    let recommended_doc = DidDocument {
        id: "did:example:123".to_string(),
        verification_methods: vec![VerificationMethod {
            type_: "Ed25519VerificationKey2020".to_string(),
            ..VerificationMethod::default()
        }],
        ..DidDocument::default()
    };
    assert!(security::uses_recommended_cryptography(&recommended_doc));
}

#[test]
fn did_privacy_security_cpp_format_and_capability_relationship_cases() {
    let email_doc = DidDocument {
        id: "did:example:user@example.com".to_string(),
        ..DidDocument::default()
    };
    let formatted_privacy = privacy::format_concerns(&privacy::scan_for_pii(&email_doc));
    assert!(formatted_privacy.contains("CRITICAL"));
    assert!(formatted_privacy.contains("Email Address"));

    let secp256k1 = VerificationMethod {
        type_: "EcdsaSecp256k1VerificationKey2019".to_string(),
        ..VerificationMethod::default()
    };
    let formatted_security =
        security::format_concerns(&[security::evaluate_verification_method(&secp256k1, 0)]);
    assert!(formatted_security.contains("DEPRECATED"));
    assert!(formatted_security.contains("secp256k1"));

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
    let doc = parse_document(doc_json).expect("C++ capability relationship fixture parses");
    assert_eq!(doc.authentication.len(), 1);
    assert_eq!(doc.capability_invocation.len(), 1);
    assert_eq!(doc.capability_delegation.len(), 1);
}
