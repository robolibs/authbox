#include <doctest/doctest.h>

#include <string>

#include "../include/authbox.hpp"

using namespace authbox::did;

TEST_CASE("DID Document services - parse document with string endpoint") {
    const std::string doc_json = R"({
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
        "service": [{
            "id": "did:example:123#agent",
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://example.com/endpoint"
        }]
    })";

    auto doc = parse_document(doc_json);
    REQUIRE(doc.is_ok());

    CHECK(doc.value().services.size() == 1);
    const auto &svc = doc.value().services[0];
    CHECK(std::string_view(svc.id.data(), svc.id.size()) == "did:example:123#agent");
    CHECK(std::string_view(svc.type.data(), svc.type.size()) == "DIDCommMessaging");
    CHECK(std::string_view(svc.service_endpoint_json.data(), svc.service_endpoint_json.size()) == "\"https://example.com/endpoint\"");
}

TEST_CASE("DID Document services - parse document with object endpoint") {
    const std::string doc_json = R"({
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
        "service": [{
            "id": "did:example:123#hub",
            "type": "IdentityHub",
            "serviceEndpoint": {
                "instances": ["https://hub.example.com"]
            }
        }]
    })";

    auto doc = parse_document(doc_json);
    REQUIRE(doc.is_ok());

    CHECK(doc.value().services.size() == 1);
    const auto &svc = doc.value().services[0];
    CHECK(std::string_view(svc.id.data(), svc.id.size()) == "did:example:123#hub");
    CHECK(std::string_view(svc.type.data(), svc.type.size()) == "IdentityHub");
    // Service endpoint should be a JSON object
    CHECK(std::string_view(svc.service_endpoint_json.data(), svc.service_endpoint_json.size()).starts_with("{"));
}

TEST_CASE("DID Document services - parse document with array endpoint") {
    const std::string doc_json = R"({
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
        "service": [{
            "id": "did:example:123#multi",
            "type": "MultiEndpoint",
            "serviceEndpoint": ["https://endpoint1.example.com", "https://endpoint2.example.com"]
        }]
    })";

    auto doc = parse_document(doc_json);
    REQUIRE(doc.is_ok());

    CHECK(doc.value().services.size() == 1);
    const auto &svc = doc.value().services[0];
    CHECK(std::string_view(svc.service_endpoint_json.data(), svc.service_endpoint_json.size()).starts_with("["));
}

TEST_CASE("DID Document services - parse document with multiple services") {
    const std::string doc_json = R"({
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
                "serviceEndpoint": "https://hub.example.com"
            }
        ]
    })";

    auto doc = parse_document(doc_json);
    REQUIRE(doc.is_ok());

    CHECK(doc.value().services.size() == 2);
    CHECK(std::string_view(doc.value().services[0].type.data(), doc.value().services[0].type.size()) == "DIDCommMessaging");
    CHECK(std::string_view(doc.value().services[1].type.data(), doc.value().services[1].type.size()) == "IdentityHub");
}

TEST_CASE("DID Document services - document without services is valid") {
    const std::string doc_json = R"({
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
    })";

    auto doc = parse_document(doc_json);
    REQUIRE(doc.is_ok());
    CHECK(doc.value().services.empty());
}

TEST_CASE("DID Document services - dereference service by fragment") {
    const std::string doc_json = R"({
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
        "service": [{
            "id": "did:example:123#agent",
            "type": "DIDCommMessaging",
            "serviceEndpoint": "https://agent.example.com"
        }]
    })";

    // Create a simple resolver that returns this document
    Resolver resolver;
    resolver.registry().register_method("example", [&](std::string_view, const ResolveOptions &) -> DidResult<std::string> {
        return DidResult<std::string>::ok(doc_json);
    });

    // Dereference the service
    auto deref = dereference("did:example:123#agent", resolver);
    REQUIRE(deref.is_ok());

    CHECK(is_service(deref.value()));
    CHECK(!is_verification_method(deref.value()));
    CHECK(!is_document(deref.value()));

    const auto &svc = get_service(deref.value());
    CHECK(std::string_view(svc.type.data(), svc.type.size()) == "DIDCommMessaging");
}
