#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

TEST_SUITE("cert/extensions") {
    TEST_CASE("SAN and key usage verification") {
        using namespace authbox::pik;
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();
        auto dn = cert_test::dn_from_string("CN=example.com");

        CertificateBuilder builder;
        builder.set_serial(100)
            .set_subject(dn)
            .set_issuer(dn)
            .set_validity(std::chrono::system_clock::now() - std::chrono::hours(1),
                          std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_key_usage(KeyUsageExtension::DigitalSignature)
            .set_subject_alt_name({{SubjectAltNameExtension::GeneralNameType::DNSName, "example.com"}});

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);
        CHECK(cert.value.verify_key_usage(KeyUsageExtension::DigitalSignature));
        CHECK(cert.value.verify_extensions(CertificatePurpose::TLSServer));
        CHECK(cert.value.match_hostname("example.com"));
    }
}
