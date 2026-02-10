#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <pki/builder.hpp>
#include <pki/trust_store.hpp>

TEST_SUITE("cert/chain") {
    TEST_CASE("chain validation with trust store") {
        using namespace authbox::pik;
        keylock::crypto::Context::KeyPair root_key, intermediate_key, leaf_key;
        auto [root_cert, intermediate_cert, leaf_cert] = cert_test::make_chain(root_key, intermediate_key, leaf_key);
        auto leaf_dn = leaf_cert.tbs().subject;

        TrustStore store;
        store.add(root_cert);

        auto result = leaf_cert.validate_chain({intermediate_cert}, store);
        if (!result.success) {
            MESSAGE("Chain validation failed with error: ", result.error);
        } else if (!result.value) {
            MESSAGE("Chain validation returned false");
        }
        CHECK(result.success);
        CHECK(result.value);
        CHECK(leaf_cert.match_subject(leaf_dn));
    }

    TEST_CASE("chain validation accepts unordered intermediates") {
        using namespace authbox::pik;
        keylock::crypto::Context::KeyPair root_key, intermediate_key, leaf_key;
        auto [root_cert, intermediate_cert, leaf_cert] = cert_test::make_chain(root_key, intermediate_key, leaf_key);

        TrustStore store;
        store.add(root_cert);

        // Supply chain with unrelated order/noise to ensure builder picks by issuer relation.
        auto result = leaf_cert.validate_chain({intermediate_cert, root_cert}, store);
        CHECK(result.success);
        CHECK(result.value);
    }

    TEST_CASE("chain validation succeeds when issuer is directly trusted") {
        using namespace authbox::pik;
        keylock::crypto::Context::KeyPair root_key, intermediate_key, leaf_key;
        auto [root_cert, intermediate_cert, leaf_cert] = cert_test::make_chain(root_key, intermediate_key, leaf_key);

        TrustStore store;
        store.add(intermediate_cert);

        auto result = leaf_cert.validate_chain({}, store);
        CHECK(result.success);
        CHECK(result.value);
    }

    TEST_CASE("detailed validation reports unknown critical extension") {
        using namespace authbox::pik;

        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();
        auto dn = cert_test::dn_from_string("CN=StrictRoot");

        RawExtension unknown_critical{};
        unknown_critical.id = ExtensionId::Unknown;
        unknown_critical.oid = Oid{{1, 2, 3, 4, 5, 6}};
        unknown_critical.critical = true;
        unknown_critical.value = {0x05, 0x00};

        CertificateBuilder builder;
        builder.set_serial(700)
            .set_subject(dn)
            .set_issuer(dn)
            .set_validity(std::chrono::system_clock::now() - std::chrono::hours(1),
                          std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_basic_constraints(true, 0, true)
            .set_key_usage(KeyUsageExtension::KeyCertSign | KeyUsageExtension::CRLSign, true)
            .add_extension(unknown_critical);

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);

        TrustStore store;
        store.add(cert.value);

        ChainValidationOptions options;
        options.reject_unknown_critical_extensions = true;

        auto report = validate_chain_detailed(cert.value, {}, store, options);
        REQUIRE(report.success);
        CHECK(report.value.valid == false);
        CHECK(report.value.code == ChainValidationCode::UnknownCriticalExtension);
    }

    TEST_CASE("detailed validation supports revocation policy modes") {
        using namespace authbox::pik;
        keylock::crypto::Context::KeyPair root_key, intermediate_key, leaf_key;
        auto [root_cert, intermediate_cert, leaf_cert] = cert_test::make_chain(root_key, intermediate_key, leaf_key);

        TrustStore store;
        store.add(root_cert);

        ChainValidationOptions strict_unknown;
        strict_unknown.revocation_policy = RevocationPolicy::Strict;
        strict_unknown.revocation_checker = [](const Certificate &) -> std::optional<bool> { return std::nullopt; };

        auto unknown_report = validate_chain_detailed(leaf_cert, {intermediate_cert}, store, strict_unknown);
        REQUIRE(unknown_report.success);
        CHECK(unknown_report.value.valid == false);
        CHECK(unknown_report.value.code == ChainValidationCode::RevocationStatusUnknown);

        ChainValidationOptions best_effort_unknown;
        best_effort_unknown.revocation_policy = RevocationPolicy::BestEffort;
        best_effort_unknown.revocation_checker = [](const Certificate &) -> std::optional<bool> {
            return std::nullopt;
        };

        auto best_effort_report = validate_chain_detailed(leaf_cert, {intermediate_cert}, store, best_effort_unknown);
        REQUIRE(best_effort_report.success);
        CHECK(best_effort_report.value.valid == true);

        ChainValidationOptions revoked;
        revoked.revocation_policy = RevocationPolicy::BestEffort;
        revoked.revocation_checker = [&leaf_cert](const Certificate &cert) -> std::optional<bool> {
            return cert.tbs().serial_number == leaf_cert.tbs().serial_number;
        };

        auto revoked_report = validate_chain_detailed(leaf_cert, {intermediate_cert}, store, revoked);
        REQUIRE(revoked_report.success);
        CHECK(revoked_report.value.valid == false);
        CHECK(revoked_report.value.code == ChainValidationCode::Revoked);
    }
}
