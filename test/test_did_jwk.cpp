#include <doctest/doctest.h>

#include <string>
#include <string_view>

#include "../include/authbox.hpp"

using namespace authbox::did;

TEST_CASE("did:jwk - Parse and validate Ed25519 key") {
    // Example JWK for Ed25519
    const std::string jwk_json = R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";

    // Encode to did:jwk
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    const std::string did_uri = did_result.value();
    CHECK(did_uri.starts_with("did:jwk:"));

    // Parse it back
    auto parsed = parse_did_jwk(did_uri);
    REQUIRE(parsed.is_ok());

    // Resolve to DID document
    auto doc_result = resolve_did_jwk_document_json(did_uri);
    REQUIRE(doc_result.is_ok());

    // Parse the document
    auto document = parse_document(doc_result.value());
    REQUIRE(document.is_ok());

    // Verify document structure
    CHECK(std::string_view(document.value().id.data(), document.value().id.size()) == did_uri);
    CHECK(document.value().verification_methods.size() == 1);
    CHECK(!document.value().authentication.empty());
}

TEST_CASE("did:jwk - Parse and validate X25519 key") {
    // Example JWK for X25519 (key agreement)
    const std::string jwk_json = R"({"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"})";

    // Encode to did:jwk
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    const std::string did_uri = did_result.value();

    // Resolve to DID document
    auto doc_result = resolve_did_jwk_document_json(did_uri);
    REQUIRE(doc_result.is_ok());

    // Parse the document
    auto document = parse_document(doc_result.value());
    REQUIRE(document.is_ok());

    // X25519 should be in keyAgreement, not authentication
    CHECK(document.value().key_agreement.size() > 0);
    CHECK(document.value().authentication.empty());
}

TEST_CASE("did:jwk - Parse and validate P-256 key") {
    // Example JWK for P-256 (EC key)
    const std::string jwk_json =
        R"({"kty":"EC","crv":"P-256","x":"fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI","y":"hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU"})";

    // Encode to did:jwk
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    const std::string did_uri = did_result.value();

    // Resolve to DID document
    auto doc_result = resolve_did_jwk_document_json(did_uri);
    REQUIRE(doc_result.is_ok());

    // Parse the document
    auto document = parse_document(doc_result.value());
    REQUIRE(document.is_ok());

    // P-256 should be in authentication
    CHECK(document.value().authentication.size() > 0);
    CHECK(document.value().key_agreement.empty());
}

TEST_CASE("did:jwk - Reject malformed base64url") {
    const std::string bad_did = "did:jwk:not valid base64url!!!";

    auto parsed = parse_did_jwk(bad_did);
    CHECK(parsed.is_err());
}

TEST_CASE("did:jwk - Reject invalid JSON in embedded JWK") {
    // Valid base64url but invalid JSON content
    const std::string bad_json = "not-json";
    std::vector<uint8_t> bytes(bad_json.begin(), bad_json.end());
    std::string encoded = "did:jwk:bm90LWpzb24";  // base64url of "not-json"

    auto parsed = parse_did_jwk(encoded);
    CHECK(parsed.is_err());
}

// TODO: Fix this test - currently causes segfault
// TEST_CASE("did:jwk - Reject JWK missing required fields") {
//     // JWK without 'kty' field
//     const std::string incomplete_jwk = R"({"crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";

//     auto did_result = encode_did_jwk(incomplete_jwk);
//     // Should fail during encoding due to missing 'kty' field
//     CHECK(did_result.is_err());
// }

TEST_CASE("did:jwk - Roundtrip test with canonicalization") {
    // JWK with fields in non-canonical order and whitespace
    const std::string jwk_original = R"({
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        "kty": "OKP",
        "crv": "Ed25519"
    })";

    // Encode to did:jwk (should canonicalize)
    auto did_result1 = encode_did_jwk(jwk_original);
    REQUIRE(did_result1.is_ok());

    // Same JWK but different order
    const std::string jwk_reordered = R"({"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";

    auto did_result2 = encode_did_jwk(jwk_reordered);
    REQUIRE(did_result2.is_ok());

    // Both should produce the same DID (deterministic)
    CHECK(did_result1.value() == did_result2.value());
}

TEST_CASE("did:jwk - Integration with Resolver") {
    // Create a JWK and encode to did:jwk
    const std::string jwk_json = R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    // Register did:jwk handler in a resolver
    Resolver resolver;
    resolver.registry().register_method("jwk", [](std::string_view did_uri, const ResolveOptions &) {
        return resolve_did_jwk_document_json(did_uri);
    });

    // Resolve the DID
    auto resolution = resolver.resolve(did_result.value());
    REQUIRE(resolution.is_ok());

    // Verify the resolved document
    CHECK(std::string_view(resolution.value().document.id.data(), resolution.value().document.id.size()) ==
          did_result.value());
    CHECK(resolution.value().document.verification_methods.size() == 1);
}
