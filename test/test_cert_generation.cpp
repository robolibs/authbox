#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

TEST_SUITE("cert/generation") {
    TEST_CASE("builder generates self-signed certificate") {
        using namespace authbox::pik;
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();
        auto dn = cert_test::dn_from_string("CN=BuilderTest");

        CertificateBuilder builder;
        builder.set_serial(42)
            .set_subject(dn)
            .set_issuer(dn)
            .set_validity(std::chrono::system_clock::now() - std::chrono::hours(1),
                          std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_basic_constraints(true, 0)
            .set_key_usage(KeyUsageExtension::KeyCertSign);

        auto result = builder.build_ed25519(key, true);
        REQUIRE(result.success);
        CHECK(result.value.match_subject(dn));
    }
}
