#include <doctest/doctest.h>

#include <string>

#include "../include/authbox.hpp"

using namespace authbox::did;

TEST_CASE("DID URL dereferencing - dereference whole document") {
    // Create a did:key
    const std::string jwk_json = R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    // Create resolver and register did:jwk
    Resolver resolver;
    resolver.registry().register_method("jwk", [](std::string_view did_uri, const ResolveOptions &) {
        return resolve_did_jwk_document_json(did_uri);
    });

    // Dereference without fragment - should return whole document
    auto deref_result = dereference(did_result.value(), resolver);
    REQUIRE(deref_result.is_ok());

    CHECK(is_document(deref_result.value()));
    CHECK(!is_verification_method(deref_result.value()));

    const auto &doc = get_document(deref_result.value());
    CHECK(doc.verification_methods.size() == 1);
}

TEST_CASE("DID URL dereferencing - dereference verification method with local fragment") {
    // Create a did:jwk
    const std::string jwk_json = R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    // Create resolver
    Resolver resolver;
    resolver.registry().register_method("jwk", [](std::string_view did_uri, const ResolveOptions &) {
        return resolve_did_jwk_document_json(did_uri);
    });

    // Dereference with fragment - should return verification method
    std::string did_url = did_result.value() + "#0";
    auto deref_result = dereference(did_url, resolver);
    REQUIRE(deref_result.is_ok());

    CHECK(is_verification_method(deref_result.value()));
    CHECK(!is_document(deref_result.value()));

    const auto &vm = get_verification_method(deref_result.value());
    CHECK(std::string_view(vm.type.data(), vm.type.size()) == "JsonWebKey2020");
}

TEST_CASE("DID URL dereferencing - dereference with absolute fragment reference") {
    // Create a did:jwk
    const std::string jwk_json = R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    // Create resolver
    Resolver resolver;
    resolver.registry().register_method("jwk", [](std::string_view did_uri, const ResolveOptions &) {
        return resolve_did_jwk_document_json(did_uri);
    });

    // Get the full verification method ID
    auto resolution = resolver.resolve(did_result.value());
    REQUIRE(resolution.is_ok());

    const auto &vm_id = resolution.value().document.verification_methods[0].id;
    std::string vm_id_str(vm_id.data(), vm_id.size());

    // Extract just the fragment part from the full ID
    auto hash_pos = vm_id_str.find('#');
    REQUIRE(hash_pos != std::string::npos);
    std::string fragment = vm_id_str.substr(hash_pos + 1);

    // Dereference using the fragment
    std::string did_url = did_result.value() + "#" + fragment;
    auto deref_result = dereference(did_url, resolver);
    REQUIRE(deref_result.is_ok());

    CHECK(is_verification_method(deref_result.value()));
}

TEST_CASE("DID URL dereferencing - fragment not found") {
    // Create a did:jwk
    const std::string jwk_json = R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";
    auto did_result = encode_did_jwk(jwk_json);
    REQUIRE(did_result.is_ok());

    // Create resolver
    Resolver resolver;
    resolver.registry().register_method("jwk", [](std::string_view did_uri, const ResolveOptions &) {
        return resolve_did_jwk_document_json(did_uri);
    });

    // Dereference with non-existent fragment
    std::string did_url = did_result.value() + "#nonexistent";
    auto deref_result = dereference(did_url, resolver);

    CHECK(deref_result.is_err());
}

TEST_CASE("DID URL dereferencing - parse URL with path and query") {
    // Parse a DID URL with path, query, and fragment
    const std::string did_url = "did:example:123/path/to/resource?service=agent&relativeRef=/credentials#degree";

    auto parsed = parse_url(did_url);
    REQUIRE(parsed.is_ok());

    CHECK(std::string_view(parsed.value().did.uri.data(), parsed.value().did.uri.size()) == "did:example:123");
    CHECK(std::string_view(parsed.value().path.data(), parsed.value().path.size()) == "/path/to/resource");
    CHECK(std::string_view(parsed.value().query.data(), parsed.value().query.size()) == "service=agent&relativeRef=/credentials");
    CHECK(std::string_view(parsed.value().fragment.data(), parsed.value().fragment.size()) == "degree");
}

TEST_CASE("DID URL dereferencing - works with did:key") {
    // Use an existing did:key for testing
    std::array<uint8_t, 32> pub_key{};
    // Fill with test data
    for (size_t i = 0; i < 32; ++i) {
        pub_key[i] = static_cast<uint8_t>(i);
    }

    auto did_result = encode_ed25519_did_key(pub_key);
    REQUIRE(did_result.is_ok());

    // Create resolver with did:key handler
    Resolver resolver;

    // Dereference the verification method
    auto resolution = resolver.resolve(did_result.value());
    REQUIRE(resolution.is_ok());

    // Get the fragment from the first VM
    const auto &vm = resolution.value().document.verification_methods[0];
    std::string vm_id(vm.id.data(), vm.id.size());

    auto hash_pos = vm_id.find('#');
    REQUIRE(hash_pos != std::string::npos);
    std::string fragment = vm_id.substr(hash_pos + 1);

    // Dereference with fragment
    std::string did_url = did_result.value() + "#" + fragment;
    auto deref_result = dereference(did_url, resolver);
    REQUIRE(deref_result.is_ok());

    CHECK(is_verification_method(deref_result.value()));
}
