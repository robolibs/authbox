#include <doctest/doctest.h>

#include <string>

#include "../include/authbox.hpp"

using namespace authbox::did;

TEST_CASE("Resolution metadata - basic resolution includes metadata") {
    // Create a did:jwk
    const std::string jwk_json = R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    // Create resolver
    Resolver resolver;
    resolver.registry().register_method("jwk", [](std::string_view did_uri, const ResolveOptions &) {
        return resolve_did_jwk_document_json(did_uri);
    });

    // Resolve the DID
    auto resolution = resolver.resolve(did_result.value());
    REQUIRE(resolution.is_ok());

    // Check that metadata structures exist
    CHECK(!resolution.value().resolution_metadata.content_type.empty());
    CHECK(std::string_view(resolution.value().resolution_metadata.content_type.data(),
                           resolution.value().resolution_metadata.content_type.size()) == "application/did+ld+json");
}

TEST_CASE("Resolution metadata - legacy fields still work") {
    // Create a did:jwk
    const std::string jwk_json = R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    // Create resolver
    Resolver resolver;
    resolver.registry().register_method("jwk", [](std::string_view did_uri, const ResolveOptions &) {
        return resolve_did_jwk_document_json(did_uri);
    });

    // Resolve the DID
    auto resolution = resolver.resolve(did_result.value());
    REQUIRE(resolution.is_ok());

    // Check that legacy fields still exist and are populated
    CHECK(!resolution.value().source_url.empty());
    CHECK(!resolution.value().raw_document_json.empty());

    // Verify the document is accessible
    CHECK(resolution.value().document.verification_methods.size() == 1);
}

TEST_CASE("Document metadata - structure exists and is accessible") {
    // Create a did:jwk
    const std::string jwk_json = R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    // Create resolver
    Resolver resolver;
    resolver.registry().register_method("jwk", [](std::string_view did_uri, const ResolveOptions &) {
        return resolve_did_jwk_document_json(did_uri);
    });

    // Resolve the DID
    auto resolution = resolver.resolve(did_result.value());
    REQUIRE(resolution.is_ok());

    // Check that document metadata structure is accessible
    CHECK(resolution.value().document_metadata.deactivated == false);
    // Other metadata fields will be empty since did:jwk doesn't populate them
}

TEST_CASE("Resolution metadata - can be populated by custom handlers") {
    // Create a custom document with metadata
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

    // Use resolve_from_document which is a static method
    auto resolution = Resolver::resolve_from_document("did:example:123", doc_json, "https://example.com/did.json");
    REQUIRE(resolution.is_ok());

    // Verify metadata is present
    CHECK(!resolution.value().resolution_metadata.content_type.empty());
    CHECK(std::string_view(resolution.value().source_url.data(), resolution.value().source_url.size()) ==
          "https://example.com/did.json");
}

TEST_CASE("Resolution metadata - error field remains empty on success") {
    // Create a did:jwk
    const std::string jwk_json = R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    // Create resolver
    Resolver resolver;
    resolver.registry().register_method("jwk", [](std::string_view did_uri, const ResolveOptions &) {
        return resolve_did_jwk_document_json(did_uri);
    });

    // Resolve the DID
    auto resolution = resolver.resolve(did_result.value());
    REQUIRE(resolution.is_ok());

    // Error field should be empty on successful resolution
    CHECK(resolution.value().resolution_metadata.error.empty());
}

TEST_CASE("Resolution metadata - backward compatibility") {
    // Ensure that code using the old Resolution structure still works

    // Create a did:key for testing
    std::array<uint8_t, 32> pub_key{};
    for (size_t i = 0; i < 32; ++i) {
        pub_key[i] = static_cast<uint8_t>(i);
    }
    auto did_result = encode_ed25519_did_key(pub_key);
    REQUIRE(did_result.is_ok());

    // Create resolver
    Resolver resolver;

    // Resolve using the standard method
    auto resolution = resolver.resolve(did_result.value());
    REQUIRE(resolution.is_ok());

    // Old code accessing legacy fields should still work
    const auto &did = resolution.value().did;
    const auto &document = resolution.value().document;
    const auto &source_url = resolution.value().source_url;
    const auto &raw_json = resolution.value().raw_document_json;

    CHECK(!did.uri.empty());
    CHECK(!document.verification_methods.empty());
    CHECK(!source_url.empty());
    CHECK(!raw_json.empty());

    // New metadata fields are also accessible
    const auto &res_meta = resolution.value().resolution_metadata;
    const auto &doc_meta = resolution.value().document_metadata;

    CHECK(!res_meta.content_type.empty());
    CHECK(doc_meta.deactivated == false);
}
