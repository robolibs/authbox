#include <array>

#include <doctest/doctest.h>

#include <authbox.hpp>
#include <pki/key_utils.hpp>

TEST_SUITE("did/key") {

    TEST_CASE("encode and parse did:key ed25519") {
        auto keypair = authbox::pik::generate_ed25519_keypair();
        REQUIRE(keypair.public_key.size() == 32);

        std::array<uint8_t, 32> pub{};
        std::copy_n(keypair.public_key.begin(), 32, pub.begin());

        auto did = authbox::did::encode_ed25519_did_key(pub);
        REQUIRE(did.is_ok());
        CHECK(std::string_view(did.value()).starts_with("did:key:z"));

        auto parsed = authbox::did::parse_did_key(did.value());
        REQUIRE(parsed.is_ok());
        CHECK(parsed.value().type == authbox::did::DidKeyType::ED25519);
        CHECK(parsed.value().public_key == keypair.public_key);
    }

    TEST_CASE("resolve did:key document") {
        auto keypair = authbox::pik::generate_ed25519_keypair();
        std::array<uint8_t, 32> pub{};
        std::copy_n(keypair.public_key.begin(), 32, pub.begin());

        auto did = authbox::did::encode_ed25519_did_key(pub);
        REQUIRE(did.is_ok());

        auto json = authbox::did::resolve_did_key_document_json(did.value());
        REQUIRE(json.is_ok());

        auto parsed_doc = authbox::did::parse_document(json.value());
        REQUIRE(parsed_doc.is_ok());
        CHECK(std::string_view(parsed_doc.value().id.data(), parsed_doc.value().id.size()) == did.value());
        CHECK(parsed_doc.value().verification_methods.size() == 1);
        CHECK(parsed_doc.value().authentication.size() == 1);
    }

    TEST_CASE("resolver supports did:key without network fetcher") {
        auto keypair = authbox::pik::generate_ed25519_keypair();
        std::array<uint8_t, 32> pub{};
        std::copy_n(keypair.public_key.begin(), 32, pub.begin());
        auto did = authbox::did::encode_ed25519_did_key(pub);
        REQUIRE(did.is_ok());

        authbox::did::Resolver resolver;
        auto resolved = resolver.resolve(did.value());
        REQUIRE(resolved.is_ok());
        CHECK(std::string_view(resolved.value().source_url.data(), resolved.value().source_url.size()) ==
              "did:key:inline");
        CHECK(std::string_view(resolved.value().document.id.data(), resolved.value().document.id.size()) ==
              did.value());
    }
}
