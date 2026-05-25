use super::super::*;

fn minimal_document(did_uri: &str) -> String {
    format!(
        r#"{{
            "id": "{did_uri}",
            "verificationMethod": [{{
                "id": "{did_uri}#key-1",
                "type": "JsonWebKey2020",
                "controller": "{did_uri}",
                "publicKeyJwk": {{"kty":"OKP","crv":"Ed25519","x":"AA"}}
            }}],
            "authentication": ["{did_uri}#key-1"]
        }}"#
    )
}

fn service_document(did_uri: &str) -> String {
    format!(
        r#"{{
            "id": "{did_uri}",
            "verificationMethod": [{{
                "id": "{did_uri}#key-1",
                "type": "JsonWebKey2020",
                "controller": "{did_uri}",
                "publicKeyJwk": {{"kty":"OKP","crv":"Ed25519","x":"AA"}}
            }}],
            "authentication": ["{did_uri}#key-1"],
            "service": [
                {{"id":"{did_uri}#agent","type":"DIDCommMessaging","serviceEndpoint":"https://agent.example.com"}},
                {{"id":"{did_uri}#hub","type":"IdentityHub","serviceEndpoint":{{"instances":["https://hub.example.com"]}}}},
                {{"id":"{did_uri}#multi","type":"MultiEndpoint","serviceEndpoint":["https://one.example.com","https://two.example.com"]}}
            ]
        }}"#
    )
}

#[test]
fn did_method_registry_cpp_surface_aliases_and_global_registry_work() {
    let mut registry = MethodRegistry::new();
    let handler: MethodHandler = std::sync::Arc::new(|did_uri, _| Ok(minimal_document(did_uri)));
    registry.register_method("example", move |did_uri, options| handler(did_uri, options));
    assert!(registry.is_registered("example"));
    assert_eq!(registry.list_methods(), vec!["example".to_string()]);
    assert!(registry.resolve_to_document("did:example:123").is_ok());
    registry.clear();
    assert!(!registry.is_registered("example"));

    let global = MethodRegistry::get_global();
    let mut guard = global.lock().unwrap();
    guard.clear();
    guard.register_method("global", |did_uri, _| Ok(minimal_document(did_uri)));
    assert!(guard.is_registered("global"));
    guard.clear();
}

#[test]
fn did_method_registry_global_and_custom_registry_resolver_work() {
    {
        let mut global = MethodRegistry::global().lock().unwrap();
        global.clear();
        global.register_method("example", |did_uri, _| Ok(minimal_document(did_uri)));
        assert!(global.is_registered("example"));
        assert_eq!(global.list_methods(), vec!["example".to_string()]);
        let resolved = global.resolve_to_document("did:example:global").unwrap();
        assert!(resolved.contains("did:example:global"));
    }
    MethodRegistry::global().lock().unwrap().clear();

    let mut registry = MethodRegistry::new();
    registry.register_method("example", |did_uri, _| Ok(service_document(did_uri)));
    let resolver = Resolver::with_registry(None, registry);
    assert!(resolver.registry().is_registered("key"));
    assert!(resolver.registry().is_registered("example"));

    let resolution = resolver.resolve("did:example:123").unwrap();
    assert_eq!(resolution.source_url, "inline");
    assert_eq!(resolution.document.services.len(), 3);
}

#[test]
fn did_resolve_options_method_policy_matches_cpp_surface() {
    let mut options = ResolveOptions::default();
    assert!(options.is_method_allowed("web"));

    options.blocked_methods.insert("web".to_string());
    assert!(!options.is_method_allowed("web"));

    options.blocked_methods.clear();
    options.allowed_methods.insert("key".to_string());
    assert!(options.is_method_allowed("key"));
    assert!(!options.is_method_allowed("web"));

    options.blocked_methods.insert("key".to_string());
    assert!(!options.is_method_allowed("key"));
}

#[test]
fn did_method_registry_enforces_document_size_limit_like_cpp() {
    let mut registry = MethodRegistry::new();
    registry.register_method("example", |did_uri, _| Ok(minimal_document(did_uri)));

    let mut options = ResolveOptions {
        max_document_size: 8,
        ..ResolveOptions::default()
    };
    let error = registry
        .resolve_to_document_with_options("did:example:123", &options)
        .unwrap_err();
    assert_eq!(error.code, DidErrorCode::DocumentTooLarge);
    assert!(error.message.contains("document exceeds max size of 8"));

    options.max_document_size = 4096;
    assert!(
        registry
            .resolve_to_document_with_options("did:example:123", &options)
            .is_ok()
    );
}
