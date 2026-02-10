#include <doctest/doctest.h>

#include <string>
#include <vector>

#include "../include/authbox.hpp"

using namespace authbox::did;

TEST_CASE("did:dns - parse valid DID") {
    const std::string did_uri = "did:dns:example.com";

    auto domain = parse_did_dns(did_uri);
    REQUIRE(domain.is_ok());
    CHECK(domain.value() == "example.com");
}

TEST_CASE("did:dns - parse subdomain") {
    const std::string did_uri = "did:dns:identity.example.com";

    auto domain = parse_did_dns(did_uri);
    REQUIRE(domain.is_ok());
    CHECK(domain.value() == "identity.example.com");
}

TEST_CASE("did:dns - reject invalid method") {
    const std::string did_uri = "did:web:example.com";

    auto domain = parse_did_dns(did_uri);
    CHECK(domain.is_err());
}

TEST_CASE("did:dns - reject empty domain") {
    const std::string did_uri = "did:dns:";

    auto domain = parse_did_dns(did_uri);
    CHECK(domain.is_err());
}

TEST_CASE("did:dns - reject domain with spaces") {
    const std::string did_uri = "did:dns:example .com";

    auto domain = parse_did_dns(did_uri);
    CHECK(domain.is_err());
}

TEST_CASE("did:dns - reject domain without TLD") {
    const std::string did_uri = "did:dns:localhost";

    auto domain = parse_did_dns(did_uri);
    CHECK(domain.is_err());
}

TEST_CASE("did:dns - get DNS query domain") {
    const std::string domain = "example.com";
    const std::string query_domain = get_dns_query_domain(domain);

    CHECK(query_domain == "_did.example.com");
}

TEST_CASE("did:dns - resolve with mocked DNS returning JSON document") {
    const std::string did_uri = "did:dns:example.com";

    // Mock DID document
    const std::string mock_document = R"({
        "id": "did:dns:example.com",
        "@context": "https://www.w3.org/ns/did/v1",
        "verificationMethod": [{
            "id": "did:dns:example.com#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:dns:example.com",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }
        }],
        "authentication": ["did:dns:example.com#key-1"]
    })";

    // Create mock DNS lookup function
    DnsLookupFn mock_dns = [&](std::string_view domain) -> DidResult<std::vector<DnsTxtRecord>> {
        CHECK(domain == "_did.example.com");

        std::vector<DnsTxtRecord> records;
        DnsTxtRecord record;
        record.value = mock_document;
        record.dnssec_valid = true;
        records.push_back(record);

        return DidResult<std::vector<DnsTxtRecord>>::ok(std::move(records));
    };

    // Set up options with mock DNS
    DnsResolveOptions options;
    options.dns_lookup = mock_dns;

    // Resolve the DID
    auto doc_result = resolve_did_dns_document_json(did_uri, options);
    REQUIRE(doc_result.is_ok());
    CHECK(doc_result.value() == mock_document);
}

TEST_CASE("did:dns - resolve with no DNS lookup callback fails") {
    const std::string did_uri = "did:dns:example.com";

    DnsResolveOptions options;
    // No dns_lookup callback set

    auto doc_result = resolve_did_dns_document_json(did_uri, options);
    CHECK(doc_result.is_err());
}

TEST_CASE("did:dns - resolve with empty TXT records fails") {
    const std::string did_uri = "did:dns:example.com";

    // Mock DNS that returns no records
    DnsLookupFn mock_dns = [](std::string_view) -> DidResult<std::vector<DnsTxtRecord>> {
        return DidResult<std::vector<DnsTxtRecord>>::ok(std::vector<DnsTxtRecord>{});
    };

    DnsResolveOptions options;
    options.dns_lookup = mock_dns;

    auto doc_result = resolve_did_dns_document_json(did_uri, options);
    CHECK(doc_result.is_err());
}

TEST_CASE("did:dns - resolve with DNSSEC requirement") {
    const std::string did_uri = "did:dns:example.com";

    const std::string mock_document = R"({
        "id": "did:dns:example.com",
        "@context": "https://www.w3.org/ns/did/v1",
        "verificationMethod": [{
            "id": "did:dns:example.com#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:dns:example.com",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }
        }],
        "authentication": ["did:dns:example.com#key-1"]
    })";

    // Mock DNS with DNSSEC valid record
    DnsLookupFn mock_dns = [&](std::string_view) -> DidResult<std::vector<DnsTxtRecord>> {
        std::vector<DnsTxtRecord> records;
        DnsTxtRecord record;
        record.value = mock_document;
        record.dnssec_valid = true;
        records.push_back(record);
        return DidResult<std::vector<DnsTxtRecord>>::ok(std::move(records));
    };

    DnsResolveOptions options;
    options.dns_lookup = mock_dns;
    options.require_dnssec = true;

    auto doc_result = resolve_did_dns_document_json(did_uri, options);
    REQUIRE(doc_result.is_ok());
}

TEST_CASE("did:dns - resolve fails when DNSSEC required but not valid") {
    const std::string did_uri = "did:dns:example.com";

    const std::string mock_document = R"({"id": "did:dns:example.com"})";

    // Mock DNS with DNSSEC invalid record
    DnsLookupFn mock_dns = [&](std::string_view) -> DidResult<std::vector<DnsTxtRecord>> {
        std::vector<DnsTxtRecord> records;
        DnsTxtRecord record;
        record.value = mock_document;
        record.dnssec_valid = false;  // Not validated
        records.push_back(record);
        return DidResult<std::vector<DnsTxtRecord>>::ok(std::move(records));
    };

    DnsResolveOptions options;
    options.dns_lookup = mock_dns;
    options.require_dnssec = true;  // Require DNSSEC

    auto doc_result = resolve_did_dns_document_json(did_uri, options);
    CHECK(doc_result.is_err());
}

TEST_CASE("did:dns - integration with resolver") {
    const std::string did_uri = "did:dns:example.com";

    const std::string mock_document = R"({
        "id": "did:dns:example.com",
        "@context": "https://www.w3.org/ns/did/v1",
        "verificationMethod": [{
            "id": "did:dns:example.com#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:dns:example.com",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }
        }],
        "authentication": ["did:dns:example.com#key-1"]
    })";

    // Mock DNS lookup
    DnsLookupFn mock_dns = [&](std::string_view) -> DidResult<std::vector<DnsTxtRecord>> {
        std::vector<DnsTxtRecord> records;
        DnsTxtRecord record;
        record.value = mock_document;
        record.dnssec_valid = true;
        records.push_back(record);
        return DidResult<std::vector<DnsTxtRecord>>::ok(std::move(records));
    };

    // Set up options
    DnsResolveOptions dns_options;
    dns_options.dns_lookup = mock_dns;

    // Create resolver and register did:dns handler
    Resolver resolver;
    resolver.registry().register_method("dns", create_dns_handler(dns_options));

    // Resolve the DID
    auto resolution = resolver.resolve(did_uri);
    REQUIRE(resolution.is_ok());

    CHECK(std::string_view(resolution.value().document.id.data(), resolution.value().document.id.size()) ==
          "did:dns:example.com");
    CHECK(resolution.value().document.verification_methods.size() == 1);
}

TEST_CASE("did:dns - reject non-JSON TXT records") {
    const std::string did_uri = "did:dns:example.com";

    // Mock DNS returning invalid content
    DnsLookupFn mock_dns = [](std::string_view) -> DidResult<std::vector<DnsTxtRecord>> {
        std::vector<DnsTxtRecord> records;
        DnsTxtRecord record;
        record.value = "this is not json";
        record.dnssec_valid = true;
        records.push_back(record);
        return DidResult<std::vector<DnsTxtRecord>>::ok(std::move(records));
    };

    DnsResolveOptions options;
    options.dns_lookup = mock_dns;

    auto doc_result = resolve_did_dns_document_json(did_uri, options);
    CHECK(doc_result.is_err());
}
