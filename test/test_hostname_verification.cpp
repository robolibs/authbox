#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

TEST_SUITE("cert/hostname_verification") {
    TEST_CASE("DNS SAN exact and wildcard matching") {
        using namespace authbox::pik;
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();
        auto dn = cert_test::dn_from_string("CN=www.example.com");

        CertificateBuilder builder;
        builder.set_serial(200)
            .set_subject(dn)
            .set_issuer(dn)
            .set_validity(std::chrono::system_clock::now() - std::chrono::hours(1),
                          std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_key_usage(KeyUsageExtension::DigitalSignature)
            .set_subject_alt_name({{SubjectAltNameExtension::GeneralNameType::DNSName, "*.example.com"}});

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);
        CHECK(cert.value.match_hostname("www.example.com"));
        CHECK_FALSE(cert.value.match_hostname("a.b.example.com"));
        CHECK_FALSE(cert.value.match_hostname("example.com"));
    }

    TEST_CASE("SAN precedence over CN and IPv4 SAN handling") {
        using namespace authbox::pik;
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();
        auto dn = cert_test::dn_from_string("CN=should-not-be-used.example.com");

        // Add both DNS and IP SANs
        CertificateBuilder builder;
        builder.set_serial(201)
            .set_subject(dn)
            .set_issuer(dn)
            .set_validity(std::chrono::system_clock::now() - std::chrono::hours(1),
                          std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_key_usage(KeyUsageExtension::DigitalSignature)
            .set_subject_alt_name({{SubjectAltNameExtension::GeneralNameType::DNSName, "app.example.com"},
                                   {SubjectAltNameExtension::GeneralNameType::IPAddress, "192.168.1.10"}});

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);

        // IPv4 literal must match only IP SANs, CN ignored
        CHECK(cert.value.match_hostname("192.168.1.10"));
        CHECK_FALSE(cert.value.match_hostname("192.168.1.11"));

        // With SAN present, hostname must match a DNS SAN; CN should be ignored
        CHECK(cert.value.match_hostname("app.example.com"));
        CHECK_FALSE(cert.value.match_hostname("should-not-be-used.example.com"));
    }
}
