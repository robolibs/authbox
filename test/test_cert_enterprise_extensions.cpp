#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

TEST_SUITE("cert/enterprise_extensions") {

    TEST_CASE("Enterprise Extension APIs exist and don't crash") {
        using namespace authbox::pik;

        // Create a simple self-signed certificate for testing
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();
        auto dn = cert_test::dn_from_string("CN=EnterpriseTest");

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

        const auto &cert = result.value;

        // Test that enterprise extension methods exist and don't crash when called
        // on a certificate without these extensions (should return empty/nullopt)

        // Issuer Alternative Name
        auto ian = cert.issuer_alt_names();
        CHECK(ian.empty()); // No IAN extension in this cert

        // Policy Mappings
        auto pm = cert.policy_mappings();
        CHECK(pm.empty()); // No policy mappings in this cert

        // Policy Constraints
        auto pc = cert.policy_constraints();
        CHECK(!pc.has_value()); // No policy constraints in this cert

        // Inhibit Any Policy
        auto iap = cert.inhibit_any_policy();
        CHECK(!iap.has_value()); // No inhibit any policy in this cert
    }

} // TEST_SUITE
