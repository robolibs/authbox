#include <chrono>
#include <optional>

#include <doctest/doctest.h>

#include <authbox.hpp>
#include <pki/builder.hpp>
#include <pki/key_utils.hpp>

namespace {

    authbox::pik::Certificate make_test_cert_with_did(const std::string &did_uri,
                                                      keylock::crypto::Context::KeyPair &keypair) {
        keypair = authbox::pik::generate_ed25519_keypair();

        authbox::pik::CertificateBuilder builder;
        const auto now = std::chrono::system_clock::now();

        authbox::pik::SubjectAltNameExtension::GeneralName did_name{};
        did_name.type = authbox::pik::SubjectAltNameExtension::GeneralNameType::URI;
        did_name.value = did_uri;

        auto cert = builder.set_subject_from_string("CN=example.com,O=Example")
                        .set_issuer_from_string("CN=example.com,O=Example")
                        .set_validity(now - std::chrono::hours(1), now + std::chrono::hours(24))
                        .set_subject_public_key_ed25519(keypair.public_key)
                        .set_basic_constraints(false, std::nullopt)
                        .set_subject_alt_name({did_name})
                        .build_ed25519(keypair, true);
        REQUIRE(cert.success);
        return cert.value;
    }

    struct LoopbackRemote {
        authbox::did::rpc::Service *service{nullptr};

        dp::Res<netpipe::Message> call(dp::u32 method_id, const netpipe::Message &request, dp::u32) {
            if (!service) {
                return dp::result::err(dp::Error::not_found("service not configured"));
            }
            return service->dispatch(method_id, request);
        }
    };

} // namespace

TEST_SUITE("did/resolver-rpc") {

    TEST_CASE("resolver fetches did:web using configured fetcher") {
        keylock::crypto::Context::KeyPair keypair;
        auto cert = make_test_cert_with_did("did:web:example.com", keypair);
        auto generated = authbox::did::generate_did_web_document("example.com", cert);
        REQUIRE(generated.is_ok());

        auto resolver = authbox::did::Resolver([](std::string_view url) -> authbox::did::DidResult<std::string> {
            return authbox::did::DidResult<std::string>::ok(std::string(url));
        });

        auto resolver_with_doc =
            authbox::did::Resolver([&generated](std::string_view url) -> authbox::did::DidResult<std::string> {
                if (url != "https://example.com/.well-known/did.json") {
                    return authbox::did::DidResult<std::string>::err(authbox::did::to_dp_string("Unexpected URL"));
                }
                return authbox::did::DidResult<std::string>::ok(std::string(
                    generated.value().did_document_json.data(), generated.value().did_document_json.size()));
            });

        auto resolved = resolver_with_doc.resolve("did:web:example.com");
        REQUIRE(resolved.is_ok());
        CHECK(std::string_view(resolved.value().source_url.data(), resolved.value().source_url.size()) ==
              "https://example.com/.well-known/did.json");
    }

    TEST_CASE("rpc client resolve and verify binding over loopback") {
        keylock::crypto::Context::KeyPair keypair;
        auto cert = make_test_cert_with_did("did:web:example.com", keypair);

        auto generated = authbox::did::generate_did_web_document("example.com", cert);
        REQUIRE(generated.is_ok());

        auto resolver =
            authbox::did::Resolver([&generated](std::string_view url) -> authbox::did::DidResult<std::string> {
                if (url != "https://example.com/.well-known/did.json") {
                    return authbox::did::DidResult<std::string>::err(authbox::did::to_dp_string("Unexpected URL"));
                }
                return authbox::did::DidResult<std::string>::ok(std::string(
                    generated.value().did_document_json.data(), generated.value().did_document_json.size()));
            });

        authbox::did::rpc::Service service(resolver);
        LoopbackRemote remote{&service};
        authbox::did::rpc::Client<LoopbackRemote> client(remote);

        auto resolved = client.resolve("did:web:example.com");
        REQUIRE(resolved.is_ok());

        auto verified = client.verify_binding(
            "did:web:example.com",
            std::string_view(generated.value().did_document_json.data(), generated.value().did_document_json.size()),
            cert.to_pem());
        REQUIRE(verified.is_ok());
        CHECK(verified.value());
    }
}
