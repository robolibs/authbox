use super::super::*;

fn document_with_service(service_json: &str) -> String {
    format!(
        r#"{{
        "id": "did:example:123",
        "@context": "https://www.w3.org/ns/did/v1",
        "verificationMethod": [{{
            "id": "did:example:123#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:123",
            "publicKeyJwk": {{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }}
        }}],
        "authentication": ["did:example:123#key-1"],
        "service": [{service_json}]
    }}"#
    )
}

fn document_without_services() -> &'static str {
    r#"{
        "id": "did:example:123",
        "@context": "https://www.w3.org/ns/did/v1",
        "verificationMethod": [{
            "id": "did:example:123#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:123",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }
        }],
        "authentication": ["did:example:123#key-1"]
    }"#
}

fn service_document_json() -> &'static str {
    r#"{
        "id": "did:example:123",
        "@context": "https://www.w3.org/ns/did/v1",
        "verificationMethod": [{
            "id": "did:example:123#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:123",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }
        }],
        "authentication": ["did:example:123#key-1"],
        "service": [
            {
                "id": "did:example:123#agent",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://agent.example.com"
            },
            {
                "id": "did:example:123#hub",
                "type": "IdentityHub",
                "serviceEndpoint": {
                    "instances": ["https://hub.example.com"]
                }
            },
            {
                "id": "did:example:123#multi",
                "type": "MultiEndpoint",
                "serviceEndpoint": ["https://one.example.com", "https://two.example.com"]
            }
        ]
    }"#
}

#[test]
fn did_service_parses_string_endpoint() {
    let document = parse_document(&document_with_service(
        r##"{
            "id": "did:example:123#agent",
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint"
        }"##,
    ))
    .unwrap();

    assert_eq!(document.services.len(), 1);
    let service = &document.services[0];
    assert_eq!(service.id, "did:example:123#agent");
    assert_eq!(service.type_, "DIDCommMessaging");
    assert_eq!(
        service.service_endpoint_json,
        "\"https://example.com/endpoint\""
    );
}

#[test]
fn did_service_parses_object_endpoint() {
    let document = parse_document(&document_with_service(
        r##"{
            "id": "did:example:123#hub",
            "type": "IdentityHub",
            "serviceEndpoint": {
                "instances": ["https://hub.example.com"]
            }
        }"##,
    ))
    .unwrap();

    assert_eq!(document.services.len(), 1);
    let service = &document.services[0];
    assert_eq!(service.id, "did:example:123#hub");
    assert_eq!(service.type_, "IdentityHub");
    assert!(service.service_endpoint_json.starts_with('{'));
}

#[test]
fn did_service_parses_array_endpoint() {
    let document = parse_document(&document_with_service(
        r##"{
            "id": "did:example:123#multi",
            "type": "MultiEndpoint",
            "serviceEndpoint": ["https://endpoint1.example.com", "https://endpoint2.example.com"]
        }"##,
    ))
    .unwrap();

    assert_eq!(document.services.len(), 1);
    assert!(document.services[0].service_endpoint_json.starts_with('['));
}

#[test]
fn did_service_endpoint_scalar_values_use_real_json_serialization() {
    let document = parse_document(&document_with_service(
        r##"{
            "id": "did:example:123#numeric",
            "type": "ScalarEndpoint",
            "serviceEndpoint": 123
        }"##,
    ))
    .unwrap();
    assert_eq!(document.services[0].service_endpoint_json, "123");

    let document = parse_document(&document_with_service(
        r##"{
            "id": "did:example:123#bool",
            "type": "ScalarEndpoint",
            "serviceEndpoint": {"enabled": true, "fallback": ["https://example.com", false]}
        }"##,
    ))
    .unwrap();
    assert_eq!(
        document.services[0].service_endpoint_json,
        "{\"enabled\":true,\"fallback\":[\"https://example.com\",false]}"
    );
}

#[test]
fn did_service_endpoint_string_serialization_uses_json_escaping() {
    let document = parse_document(&document_with_service(
        r##"{
            "id": "did:example:123#quoted",
            "type": "QuotedEndpoint",
            "serviceEndpoint": "https://example.com/a\"b"
        }"##,
    ))
    .unwrap();

    assert_eq!(
        document.services[0].service_endpoint_json,
        "\"https://example.com/a\\\"b\""
    );
}

#[test]
fn did_service_parses_multiple_services_and_absent_services() {
    let document = parse_document(service_document_json()).unwrap();
    assert_eq!(document.services.len(), 3);
    assert_eq!(document.services[0].type_, "DIDCommMessaging");
    assert_eq!(document.services[1].type_, "IdentityHub");
    assert_eq!(document.services[2].type_, "MultiEndpoint");

    let no_services = parse_document(document_without_services()).unwrap();
    assert!(no_services.services.is_empty());
}

#[test]
fn did_service_dereferences_service_by_fragment() {
    let mut resolver = Resolver::new();
    resolver
        .registry_mut()
        .register_method("example", |_, _| Ok(service_document_json().to_string()));

    let dereferenced = dereference("did:example:123#agent", &resolver).unwrap();

    assert!(is_service(&dereferenced));
    assert!(!is_verification_method(&dereferenced));
    assert!(!is_document(&dereferenced));
    assert_eq!(
        get_service(&dereferenced).unwrap().type_,
        "DIDCommMessaging"
    );
}
