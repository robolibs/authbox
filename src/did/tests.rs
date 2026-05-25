use super::*;

mod test_did_dereference;
mod test_did_detail;
mod test_did_dns;
mod test_did_document;
mod test_did_errors;
mod test_did_jwk;
mod test_did_key;
mod test_did_metadata;
mod test_did_method_registry;
mod test_did_options;
mod test_did_peer;
mod test_did_pkh;
mod test_did_privacy;
mod test_did_privacy_security;
mod test_did_resolver_rpc;
mod test_did_security;
mod test_did_service;
mod test_did_web_fetch;

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
