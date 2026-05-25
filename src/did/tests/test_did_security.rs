use super::super::*;

fn method(id: &str, type_: &str, crv: Option<&str>) -> VerificationMethod {
    VerificationMethod {
        id: id.to_string(),
        type_: type_.to_string(),
        controller: "did:example:123".to_string(),
        public_key_jwk: crv.map(|crv| JsonWebKey {
            kty: "OKP".to_string(),
            crv: crv.to_string(),
            x: "AA".to_string(),
            y: String::new(),
        }),
        blockchain_account_id: None,
    }
}

#[test]
fn did_security_key_type_strength_matches_cpp_surface() {
    use security::CryptographicStrength::*;

    assert_eq!(
        security::evaluate_key_type("Ed25519VerificationKey2020"),
        Recommended
    );
    assert_eq!(security::evaluate_key_type("EdDSA"), Recommended);
    assert_eq!(
        security::evaluate_key_type("EcdsaSecp256k1RecoveryMethod2020"),
        Deprecated
    );
    assert_eq!(
        security::evaluate_key_type("JsonWebKey2020 ES256"),
        Acceptable
    );
    assert_eq!(security::evaluate_key_type("P-384"), Acceptable);
    assert_eq!(security::evaluate_key_type("secp521r1"), Acceptable);
    assert_eq!(security::evaluate_key_type("RS256"), Acceptable);
    assert_eq!(
        security::evaluate_key_type("X25519KeyAgreementKey2020"),
        Recommended
    );
    assert_eq!(
        security::evaluate_key_type("Bls12381G2Key2020"),
        Recommended
    );
    assert_eq!(security::evaluate_key_type("Dilithium3"), Experimental);
    assert_eq!(security::evaluate_key_type("UnknownKeyType"), Acceptable);
}

#[test]
fn did_security_jwk_curve_strength_matches_cpp_surface() {
    use security::CryptographicStrength::*;

    assert_eq!(security::evaluate_jwk_curve("Ed25519"), Recommended);
    assert_eq!(security::evaluate_jwk_curve("Ed448"), Recommended);
    assert_eq!(security::evaluate_jwk_curve("P-256"), Acceptable);
    assert_eq!(security::evaluate_jwk_curve("secp384r1"), Acceptable);
    assert_eq!(security::evaluate_jwk_curve("P-521"), Acceptable);
    assert_eq!(security::evaluate_jwk_curve("secp256k1"), Deprecated);
    assert_eq!(security::evaluate_jwk_curve("X448"), Recommended);
    assert_eq!(security::evaluate_jwk_curve("mystery"), Acceptable);
}

#[test]
fn did_security_evaluates_methods_and_document_summary_like_cpp() {
    use security::CryptographicStrength::*;

    let ed25519_type_only = VerificationMethod {
        type_: "Ed25519VerificationKey2020".to_string(),
        ..VerificationMethod::default()
    };
    assert_eq!(
        security::evaluate_verification_method(&ed25519_type_only, 0).strength,
        Recommended
    );

    let p256_jwk = VerificationMethod {
        type_: "JsonWebKey2020".to_string(),
        public_key_jwk: Some(JsonWebKey {
            kty: "EC".to_string(),
            crv: "P-256".to_string(),
            x: "AA".to_string(),
            y: "BB".to_string(),
        }),
        ..VerificationMethod::default()
    };
    assert_eq!(
        security::evaluate_verification_method(&p256_jwk, 0).strength,
        Acceptable
    );

    let doc = DidDocument {
        id: "did:example:123".to_string(),
        verification_methods: vec![
            method("did:example:123#ed", "JsonWebKey2020", Some("Ed25519")),
            method("did:example:123#p256", "JsonWebKey2020", Some("P-256")),
            method(
                "did:example:123#k1",
                "EcdsaSecp256k1RecoveryMethod2020",
                None,
            ),
            method("did:example:123#pq", "DilithiumVerificationKey2024", None),
        ],
        ..DidDocument::default()
    };

    let recommended = security::evaluate_verification_method(&doc.verification_methods[0], 0);
    assert_eq!(recommended.strength, Recommended);
    assert_eq!(recommended.category, "Recommended Cryptography");
    assert_eq!(recommended.location, "verificationMethod[0]");
    assert_eq!(recommended.method_id, "did:example:123#ed");
    assert!(
        recommended
            .recommendation
            .contains("This is a recommended algorithm")
    );

    let acceptable = security::evaluate_verification_method(&doc.verification_methods[1], 1);
    assert_eq!(acceptable.strength, Acceptable);
    assert_eq!(acceptable.category, "Acceptable Cryptography");
    assert_eq!(
        acceptable.description,
        "Uses acceptable but not recommended algorithm: JsonWebKey2020"
    );

    let deprecated = security::evaluate_verification_method(&doc.verification_methods[2], 2);
    assert_eq!(deprecated.strength, Deprecated);
    assert_eq!(deprecated.category, "Deprecated Cryptography");
    assert!(
        deprecated
            .recommendation
            .contains("W3C DID Implementation Guide advises against secp256k1")
    );

    let concerns = security::scan_document(&doc);
    assert_eq!(concerns.len(), 3);
    assert_eq!(concerns[0].location, "verificationMethod[1]");
    assert_eq!(concerns[1].location, "verificationMethod[2]");
    assert_eq!(concerns[2].location, "verificationMethod[3]");

    assert!(!security::uses_recommended_cryptography(&doc));
    let recommended_doc = DidDocument {
        id: "did:example:123".to_string(),
        verification_methods: vec![method(
            "did:example:123#ed",
            "Ed25519VerificationKey2020",
            None,
        )],
        ..DidDocument::default()
    };
    assert!(security::scan_document(&recommended_doc).is_empty());
    assert!(security::uses_recommended_cryptography(&recommended_doc));

    let acceptable_only_doc = DidDocument {
        verification_methods: vec![method(
            "did:example:123#p256",
            "JsonWebKey2020",
            Some("P-256"),
        )],
        ..DidDocument::default()
    };
    assert!(security::uses_recommended_cryptography(
        &acceptable_only_doc
    ));

    assert_eq!(
        security::get_cryptography_summary(&doc),
        "Cryptography Summary:\n  Recommended: 0\n  Acceptable: 2\n  Deprecated: 1\n  Experimental: 1\n"
    );
}

#[test]
fn did_security_format_concerns_matches_cpp_surface() {
    let vm = VerificationMethod {
        type_: "EcdsaSecp256k1VerificationKey2019".to_string(),
        ..VerificationMethod::default()
    };
    let concern = security::evaluate_verification_method(&vm, 0);
    let formatted = security::format_concerns(&[concern]);

    assert!(formatted.starts_with("Security Concerns:\n"));
    assert!(formatted.contains("[DEPRECATED] Deprecated Cryptography"));
    assert!(formatted.contains("Location: verificationMethod[0]"));
    assert!(formatted.contains("secp256k1"));
    assert_eq!(
        security::format_concerns(&[]),
        "No security concerns detected. All cryptography uses recommended algorithms."
    );
}
