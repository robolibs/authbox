#include <doctest/doctest.h>

#include <string>

#include "../include/authbox.hpp"

using namespace authbox::did;

TEST_CASE("did:pkh - parse Ethereum mainnet DID") {
    const std::string did_uri = "did:pkh:eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb";

    auto components = parse_did_pkh(did_uri);
    REQUIRE(components.is_ok());
    CHECK(components.value().namespace_id == "eip155");
    CHECK(components.value().chain_id == "1");
    CHECK(components.value().address == "0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb");
}

TEST_CASE("did:pkh - parse Polygon DID") {
    const std::string did_uri = "did:pkh:eip155:137:0x1234567890123456789012345678901234567890";

    auto components = parse_did_pkh(did_uri);
    REQUIRE(components.is_ok());
    CHECK(components.value().namespace_id == "eip155");
    CHECK(components.value().chain_id == "137");
    CHECK(components.value().address == "0x1234567890123456789012345678901234567890");
}

TEST_CASE("did:pkh - parse Bitcoin DID") {
    const std::string did_uri = "did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3";

    auto components = parse_did_pkh(did_uri);
    REQUIRE(components.is_ok());
    CHECK(components.value().namespace_id == "bip122");
    CHECK(components.value().chain_id == "000000000019d6689c085ae165831e93");
    CHECK(components.value().address == "128Lkh3S7CkDTBZ8W7BbpsN3");
}

TEST_CASE("did:pkh - parse Cosmos DID") {
    const std::string did_uri = "did:pkh:cosmos:cosmoshub-3:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0";

    auto components = parse_did_pkh(did_uri);
    REQUIRE(components.is_ok());
    CHECK(components.value().namespace_id == "cosmos");
    CHECK(components.value().chain_id == "cosmoshub-3");
    CHECK(components.value().address == "cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0");
}

TEST_CASE("did:pkh - reject non-pkh method") {
    const std::string did_uri = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    auto components = parse_did_pkh(did_uri);
    CHECK(components.is_err());
}

TEST_CASE("did:pkh - reject empty method-id") {
    const std::string did_uri = "did:pkh:";

    auto components = parse_did_pkh(did_uri);
    CHECK(components.is_err());
}

TEST_CASE("did:pkh - reject missing colons") {
    const std::string did_uri = "did:pkh:eip155-1-0xabcd";

    auto components = parse_did_pkh(did_uri);
    CHECK(components.is_err());
}

TEST_CASE("did:pkh - reject invalid namespace (too short)") {
    const std::string did_uri = "did:pkh:ab:1:0xabcd";

    auto components = parse_did_pkh(did_uri);
    CHECK(components.is_err());
}

TEST_CASE("did:pkh - reject invalid namespace (uppercase)") {
    const std::string did_uri = "did:pkh:EIP155:1:0xabcd";

    auto components = parse_did_pkh(did_uri);
    CHECK(components.is_err());
}

TEST_CASE("did:pkh - reject invalid chain_id (too long)") {
    const std::string did_uri = "did:pkh:eip155:123456789012345678901234567890123:0xabcd";

    auto components = parse_did_pkh(did_uri);
    CHECK(components.is_err());
}

TEST_CASE("did:pkh - reject invalid address (too long)") {
    const std::string very_long_address(65, 'a');
    const std::string did_uri = "did:pkh:eip155:1:" + very_long_address;

    auto components = parse_did_pkh(did_uri);
    CHECK(components.is_err());
}

TEST_CASE("did:pkh - get blockchain account ID") {
    PkhComponents components;
    components.namespace_id = "eip155";
    components.chain_id = "1";
    components.address = "0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb";

    std::string account_id = get_blockchain_account_id(components);
    CHECK(account_id == "eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb");
}

TEST_CASE("did:pkh - get chain name for Ethereum mainnet") {
    PkhComponents components;
    components.namespace_id = "eip155";
    components.chain_id = "1";
    components.address = "0xabcd";

    std::string chain_name = get_chain_name(components);
    CHECK(chain_name == "Ethereum Mainnet");
}

TEST_CASE("did:pkh - get chain name for Polygon") {
    PkhComponents components;
    components.namespace_id = "eip155";
    components.chain_id = "137";
    components.address = "0xabcd";

    std::string chain_name = get_chain_name(components);
    CHECK(chain_name == "Polygon Mainnet");
}

TEST_CASE("did:pkh - get chain name for unknown chain") {
    PkhComponents components;
    components.namespace_id = "eip155";
    components.chain_id = "999";
    components.address = "0xabcd";

    std::string chain_name = get_chain_name(components);
    CHECK(chain_name == "Ethereum Chain 999");
}

TEST_CASE("did:pkh - resolve Ethereum DID to document") {
    const std::string did_uri = "did:pkh:eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb";

    auto doc_result = resolve_did_pkh_document_json(did_uri);
    REQUIRE(doc_result.is_ok());

    // Verify the JSON contains expected fields
    CHECK(doc_result.value().find("\"id\": \"" + did_uri + "\"") != std::string::npos);
    CHECK(doc_result.value().find("verificationMethod") != std::string::npos);
    CHECK(doc_result.value().find("authentication") != std::string::npos);
}

TEST_CASE("did:pkh - document contains blockchain account ID") {
    const std::string did_uri = "did:pkh:eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb";

    auto doc_result = resolve_did_pkh_document_json(did_uri);
    REQUIRE(doc_result.is_ok());

    // Check that document contains the blockchainAccountId
    CHECK(doc_result.value().find("blockchainAccountId") != std::string::npos);
    CHECK(doc_result.value().find("eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb") != std::string::npos);
}

TEST_CASE("did:pkh - document has correct verification method type") {
    const std::string did_uri = "did:pkh:eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb";

    auto doc_result = resolve_did_pkh_document_json(did_uri);
    REQUIRE(doc_result.is_ok());

    // Check for EcdsaSecp256k1RecoveryMethod2020 type
    CHECK(doc_result.value().find("EcdsaSecp256k1RecoveryMethod2020") != std::string::npos);
}

// TODO: Fix parse_document to handle blockchainAccountId before enabling this test
TEST_CASE("did:pkh - integration with resolver" * doctest::skip()) {
    const std::string did_uri = "did:pkh:eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb";

    // Create resolver and register did:pkh handler
    Resolver resolver;
    resolver.registry().register_method(
        "pkh", [](std::string_view did_uri, const ResolveOptions &) { return resolve_did_pkh_document_json(did_uri); });

    // Resolve the DID
    auto resolution = resolver.resolve(did_uri);
    REQUIRE(resolution.is_ok());

    // Verify document fields
    CHECK(std::string_view(resolution.value().document.id.data(), resolution.value().document.id.size()) == did_uri);
}

TEST_CASE("did:pkh - resolve Bitcoin DID") {
    const std::string did_uri = "did:pkh:bip122:000000000019d6689c085ae165831e93:128Lkh3S7CkDTBZ8W7BbpsN3";

    auto doc_result = resolve_did_pkh_document_json(did_uri);
    REQUIRE(doc_result.is_ok());

    // Verify the JSON contains expected fields
    CHECK(doc_result.value().find("\"id\": \"" + did_uri + "\"") != std::string::npos);
    CHECK(doc_result.value().find("blockchainAccountId") != std::string::npos);
}

TEST_CASE("did:pkh - resolve Cosmos DID") {
    const std::string did_uri = "did:pkh:cosmos:cosmoshub-3:cosmos1t2uflqwqe0fsj0shcfkrvpukewcw40yjj6hdc0";

    auto doc_result = resolve_did_pkh_document_json(did_uri);
    REQUIRE(doc_result.is_ok());

    // Verify the JSON contains expected fields
    CHECK(doc_result.value().find("\"id\": \"" + did_uri + "\"") != std::string::npos);
    CHECK(doc_result.value().find("cosmos") != std::string::npos);
}
