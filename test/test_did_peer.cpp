#include <doctest/doctest.h>

#include <string>

#include "../include/authbox.hpp"

using namespace authbox::did;

TEST_CASE("did:peer - parse simple did:peer:2 with one verification key") {
    // Example did:peer:2 with Ed25519 key
    const std::string did_uri = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    auto elements = parse_did_peer(did_uri);
    REQUIRE(elements.is_ok());
    CHECK(elements.value().size() == 1);
    CHECK(elements.value()[0].type == PeerElementType::Verification);
}

TEST_CASE("did:peer - parse did:peer:2 with multiple keys") {
    // did:peer:2 with verification and encryption keys
    const std::string did_uri = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc";

    auto elements = parse_did_peer(did_uri);
    REQUIRE(elements.is_ok());
    CHECK(elements.value().size() == 2);
    CHECK(elements.value()[0].type == PeerElementType::Verification);
    CHECK(elements.value()[1].type == PeerElementType::Encryption);
}

TEST_CASE("did:peer - reject non-peer method") {
    const std::string did_uri = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    auto elements = parse_did_peer(did_uri);
    CHECK(elements.is_err());
}

TEST_CASE("did:peer - reject unsupported numalgo") {
    // did:peer:0 and did:peer:1 are not supported yet
    const std::string did_uri = "did:peer:0z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    auto elements = parse_did_peer(did_uri);
    CHECK(elements.is_err());
}

TEST_CASE("did:peer - reject empty method-id") {
    const std::string did_uri = "did:peer:";

    auto elements = parse_did_peer(did_uri);
    CHECK(elements.is_err());
}

TEST_CASE("did:peer - decode base58btc multibase key") {
    // Valid base58btc encoded key (z prefix)
    const std::string encoded = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    auto decoded = decode_peer_key(encoded);
    REQUIRE(decoded.is_ok());
    CHECK(decoded.value().size() > 0);
}

TEST_CASE("did:peer - reject non-base58btc encoding") {
    // Multibase with different encoding (not z)
    const std::string encoded = "u6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    auto decoded = decode_peer_key(encoded);
    CHECK(decoded.is_err());
}

TEST_CASE("did:peer - resolve to DID document") {
    // did:peer:2 with Ed25519 verification key
    const std::string did_uri = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    auto doc_result = resolve_did_peer_document_json(did_uri);
    REQUIRE(doc_result.is_ok());

    // Parse the document to verify structure
    auto document = parse_document(doc_result.value());
    REQUIRE(document.is_ok());

    CHECK(std::string_view(document.value().id.data(), document.value().id.size()) == did_uri);
    CHECK(document.value().verification_methods.size() == 1);
    CHECK(document.value().authentication.size() == 1);
}

TEST_CASE("did:peer - resolve with verification and encryption keys") {
    // did:peer:2 with both verification (V) and encryption (E) keys
    const std::string did_uri = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc";

    auto doc_result = resolve_did_peer_document_json(did_uri);
    REQUIRE(doc_result.is_ok());

    // Parse the document
    auto document = parse_document(doc_result.value());
    REQUIRE(document.is_ok());

    CHECK(document.value().verification_methods.size() == 2);
    CHECK(document.value().authentication.size() == 1);  // V key
    CHECK(document.value().key_agreement.size() == 1);   // E key
}

TEST_CASE("did:peer - integration with resolver") {
    const std::string did_uri = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    // Create resolver and register did:peer handler
    Resolver resolver;
    resolver.registry().register_method("peer", [](std::string_view did_uri, const ResolveOptions &) {
        return resolve_did_peer_document_json(did_uri);
    });

    // Resolve the DID
    auto resolution = resolver.resolve(did_uri);
    REQUIRE(resolution.is_ok());

    CHECK(std::string_view(resolution.value().document.id.data(), resolution.value().document.id.size()) == did_uri);
    CHECK(resolution.value().document.verification_methods.size() == 1);
}

TEST_CASE("did:peer - element type parsing") {
    const std::string did_uri = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc.SeyJpZCI6IiNzZXJ2aWNlIiwidCI6ImRtIiwicyI6Imh0dHBzOi8vZXhhbXBsZS5jb20vZW5kcG9pbnQifQ";

    auto elements = parse_did_peer(did_uri);
    REQUIRE(elements.is_ok());
    CHECK(elements.value().size() == 3);
    CHECK(elements.value()[0].type == PeerElementType::Verification);
    CHECK(elements.value()[1].type == PeerElementType::Encryption);
    CHECK(elements.value()[2].type == PeerElementType::Service);
}

TEST_CASE("did:peer - parse handles unknown element types gracefully") {
    // Create a did:peer with an unknown element type 'X'
    const std::string did_uri = "did:peer:2.Vz6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK.XsomeUnknownElement";

    auto elements = parse_did_peer(did_uri);
    REQUIRE(elements.is_ok());
    CHECK(elements.value().size() == 2);
    CHECK(elements.value()[0].type == PeerElementType::Verification);
    CHECK(elements.value()[1].type == PeerElementType::Unknown);
}
