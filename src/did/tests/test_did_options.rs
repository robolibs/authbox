use super::*;

fn document_with_counts() -> &'static str {
    r#"{
        "id": "did:example:options",
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://example.com/context"
        ],
        "verificationMethod": [
            {
                "id": "did:example:options#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:example:options",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
                }
            },
            {
                "id": "did:example:options#key-2",
                "type": "JsonWebKey2020",
                "controller": "did:example:options",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "22qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
                }
            }
        ],
        "authentication": ["did:example:options#key-1"],
        "service": [
            {
                "id": "did:example:options#agent",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://agent.example.com"
            },
            {
                "id": "did:example:options#hub",
                "type": "IdentityHub",
                "serviceEndpoint": "https://hub.example.com"
            }
        ]
    }"#
}

#[test]
fn did_resolve_options_defaults_and_method_policy_match_cpp_surface() {
    let defaults = ResolveOptions::default();

    assert!(defaults.require_https);
    assert!(defaults.require_matching_id);
    assert_eq!(defaults.max_document_size, 1_048_576);
    assert!(!defaults.strict_parsing);
    assert!(!defaults.allow_experimental);
    assert!(defaults.allowed_methods.is_empty());
    assert!(defaults.blocked_methods.is_empty());
    assert!(!defaults.validate_contexts);
    assert!(defaults.require_verification_method);
    assert_eq!(defaults.max_verification_methods, 100);
    assert_eq!(defaults.max_services, 50);
    assert_eq!(defaults.max_context_entries, 10);

    assert!(defaults.is_method_allowed("key"));
    assert!(defaults.is_method_allowed("experimental"));

    let mut allowlist = ResolveOptions::default();
    allowlist.allowed_methods.insert("key".to_string());
    assert!(allowlist.is_method_allowed("key"));
    assert!(!allowlist.is_method_allowed("web"));

    allowlist.blocked_methods.insert("key".to_string());
    assert!(!allowlist.is_method_allowed("key"));
}

#[test]
fn did_parse_document_with_options_enforces_cpp_policy_limits() {
    let document = document_with_counts();
    let parsed = parse_document_with_options(document, &ResolveOptions::default()).unwrap();

    assert_eq!(parsed.contexts.len(), 2);
    assert_eq!(parsed.verification_methods.len(), 2);
    assert_eq!(parsed.services.len(), 2);

    let too_many_methods = ResolveOptions {
        max_verification_methods: 1,
        ..ResolveOptions::default()
    };
    assert_eq!(
        parse_document_with_options(document, &too_many_methods)
            .unwrap_err()
            .message,
        "Invalid DID document JSON: too many verification methods: 2 (max: 1)"
    );

    let too_many_services = ResolveOptions {
        max_services: 1,
        ..ResolveOptions::default()
    };
    assert_eq!(
        parse_document_with_options(document, &too_many_services)
            .unwrap_err()
            .message,
        "Invalid DID document JSON: too many services: 2 (max: 1)"
    );

    let too_many_contexts = ResolveOptions {
        max_context_entries: 1,
        ..ResolveOptions::default()
    };
    assert_eq!(
        parse_document_with_options(document, &too_many_contexts)
            .unwrap_err()
            .message,
        "Invalid DID document JSON: too many @context entries: 2 (max: 1)"
    );
}
