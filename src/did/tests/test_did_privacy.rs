use super::super::*;

fn pii_doc() -> DidDocument {
    DidDocument {
        id: "did:example:Alice Smith alice@example.com".to_string(),
        verification_methods: vec![VerificationMethod {
            id: "did:example:123#Alice Smith".to_string(),
            type_: "JsonWebKey2020".to_string(),
            controller: "did:example:123".to_string(),
            public_key_jwk: Some(JsonWebKey {
                kty: "OKP".to_string(),
                crv: "Ed25519".to_string(),
                x: "AA".to_string(),
                y: String::new(),
            }),
            blockchain_account_id: None,
        }],
        services: vec![
            Service {
                id: "did:example:123#alice@example.com".to_string(),
                type_: "DIDCommMessaging".to_string(),
                service_endpoint_json: "\"https://agent.example.com\"".to_string(),
            },
            Service {
                id: "did:example:123#office".to_string(),
                type_: "Office".to_string(),
                service_endpoint_json: "\"123 Main Street\"".to_string(),
            },
        ],
        ..DidDocument::default()
    }
}

#[test]
fn did_privacy_pattern_helpers_match_cpp_surface() {
    assert!(privacy::contains_email_pattern("alice@example.com"));
    assert!(!privacy::contains_email_pattern("alice.example.com"));
    assert!(privacy::contains_phone_pattern("+1-555-123-4567"));
    assert!(privacy::contains_phone_pattern("(555) 123-4567"));
    assert!(privacy::contains_name_pattern("Alice Smith"));
    assert!(!privacy::contains_name_pattern("alice smith"));
    assert!(privacy::contains_address_pattern("123 Main Street"));
    assert!(privacy::contains_address_pattern("9 Oak Rd"));
}

#[test]
fn did_privacy_scan_for_pii_reports_cpp_locations_and_risks() {
    use privacy::PrivacyRisk::*;

    let email_doc = DidDocument {
        id: "did:example:user@example.com".to_string(),
        ..DidDocument::default()
    };
    let email_concerns = privacy::scan_for_pii(&email_doc);
    assert!(!email_concerns.is_empty());
    assert_eq!(email_concerns[0].risk, Critical);
    assert_eq!(email_concerns[0].category, "Email Address");

    let phone_doc = DidDocument {
        id: "did:example:555-123-4567".to_string(),
        ..DidDocument::default()
    };
    let phone_concerns = privacy::scan_for_pii(&phone_doc);
    assert!(!phone_concerns.is_empty());
    assert_eq!(phone_concerns[0].risk, Critical);

    let concerns = privacy::scan_for_pii(&pii_doc());
    assert_eq!(privacy::get_max_risk(&concerns), Critical);
    assert!(concerns.iter().any(|concern| {
        concern.risk == Critical && concern.category == "Email Address" && concern.location == "id"
    }));
    assert!(concerns.iter().any(|concern| {
        concern.risk == High && concern.category == "Personal Name" && concern.location == "id"
    }));
    assert!(concerns.iter().any(|concern| {
        concern.risk == High
            && concern.category == "PII in Verification Method"
            && concern.location == "verificationMethod[0].id"
    }));
    assert!(concerns.iter().any(|concern| {
        concern.risk == Critical
            && concern.category == "Email in Service"
            && concern.location == "service[0]"
    }));
    assert!(concerns.iter().any(|concern| {
        concern.risk == Critical
            && concern.category == "Physical Address"
            && concern.location == "service[1].serviceEndpoint"
    }));

    let formatted = privacy::format_concerns(&concerns);
    assert!(formatted.starts_with("Privacy Concerns Detected:\n"));
    assert!(formatted.contains("[CRITICAL] Email Address"));
    assert!(formatted.contains("Location: service[1].serviceEndpoint"));
    assert_eq!(
        privacy::format_concerns(&[]),
        "No privacy concerns detected."
    );
}

#[test]
fn did_privacy_correlation_and_immutable_storage_match_cpp_surface() {
    use privacy::PrivacyRisk::*;

    let reused = DidDocument {
        id: "did:example:123".to_string(),
        authentication: vec!["did:example:123#key-1".to_string()],
        assertion_method: vec!["did:example:123#key-1".to_string()],
        key_agreement: vec!["did:example:123#key-2".to_string()],
        ..DidDocument::default()
    };
    let concerns = privacy::check_correlation_risks(&reused);
    assert_eq!(concerns.len(), 1);
    assert_eq!(concerns[0].risk, Medium);
    assert_eq!(concerns[0].category, "Key Reuse");
    assert_eq!(concerns[0].location, "verification relationships");
    assert_eq!(privacy::get_max_risk(&concerns), Medium);

    assert_eq!(privacy::get_max_risk(&[]), None);

    let safe = DidDocument {
        id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
        ..DidDocument::default()
    };
    assert!(privacy::scan_for_pii(&safe).is_empty());
    assert!(privacy::is_safe_for_immutable_storage(&safe));

    assert!(privacy::is_safe_for_immutable_storage(&reused));
    assert!(!privacy::is_safe_for_immutable_storage(&pii_doc()));

    let separate_keys = DidDocument {
        id: "did:example:123".to_string(),
        authentication: vec!["did:example:123#key-1".to_string()],
        assertion_method: vec!["did:example:123#key-2".to_string()],
        key_agreement: vec!["did:example:123#key-3".to_string()],
        ..DidDocument::default()
    };
    assert!(privacy::check_correlation_risks(&separate_keys).is_empty());

    let combined = privacy::scan_document(&reused);
    assert_eq!(combined.len(), 1);
    assert_eq!(combined[0].category, "Key Reuse");
}
