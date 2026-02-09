#include <chrono>
#include <optional>

#include <doctest/doctest.h>

#include <authbox.hpp>
#include <pki/builder.hpp>
#include <pki/key_utils.hpp>

TEST_SUITE("did/document") {

    TEST_CASE("did:web url conversion") {
        auto url = authbox::did::did_web_document_url("did:web:example.com");
        REQUIRE(url.is_ok());
        CHECK(url.value() == "https://example.com/.well-known/did.json");

        auto url_with_path = authbox::did::did_web_document_url("did:web:example.com:users:alice");
        REQUIRE(url_with_path.is_ok());
        CHECK(url_with_path.value() == "https://example.com/users/alice/did.json");
    }

    TEST_CASE("parse did document json") {
        const char *doc = R"({
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
  "id": "did:web:example.com",
  "verificationMethod": [
    {
      "id": "did:web:example.com#0",
      "type": "JsonWebKey2020",
      "controller": "did:web:example.com",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "AA",
        "y": "BB"
      }
    }
  ],
  "authentication": ["did:web:example.com#0"],
  "assertionMethod": ["did:web:example.com#0"]
})";

        auto parsed = authbox::did::parse_document(doc);
        REQUIRE(parsed.is_ok());
        CHECK(parsed.value().verification_methods.size() == 1);
        CHECK(parsed.value().assertion_method.size() == 1);

        auto validation = authbox::did::validate_document(parsed.value(), "did:web:example.com");
        CHECK(validation.is_ok());
        CHECK(validation.value());
    }

    TEST_CASE("generate did:web document from certificate and verify binding") {
        auto keypair = authbox::pik::generate_ed25519_keypair();
        authbox::pik::CertificateBuilder builder;
        const auto now = std::chrono::system_clock::now();

        authbox::pik::SubjectAltNameExtension::GeneralName did_name{};
        did_name.type = authbox::pik::SubjectAltNameExtension::GeneralNameType::URI;
        did_name.value = "did:web:example.com";

        builder.set_subject_from_string("CN=example.com,O=Example")
            .set_issuer_from_string("CN=example.com,O=Example")
            .set_validity(now - std::chrono::hours(1), now + std::chrono::hours(24))
            .set_subject_public_key_ed25519(keypair.public_key)
            .set_basic_constraints(false, std::nullopt)
            .set_subject_alt_name({did_name});

        auto cert = builder.build_ed25519(keypair, true);
        REQUIRE(cert.success);

        auto generated = authbox::did::generate_did_web_document("example.com", cert.value);
        REQUIRE(generated.is_ok());

        auto parsed = authbox::did::parse_document(
            std::string_view(generated.value().did_document_json.data(), generated.value().did_document_json.size()));
        REQUIRE(parsed.is_ok());

        auto verified = authbox::did::verify_certificate_binding(cert.value, parsed.value(), "did:web:example.com");
        CHECK(verified.is_ok());
        CHECK(verified.value());
    }
}
