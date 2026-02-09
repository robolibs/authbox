#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <pki/crl_builder.hpp>

TEST_SUITE("cert/crl") {
    TEST_CASE("crl builder and revocation") {
        using namespace authbox::pik;
        keylock::crypto::Context::KeyPair root_key;
        auto root_cert = cert_test::make_self_signed_certificate("Root CA", root_key);

        auto leaf_key = keylock::crypto::Context(keylock::crypto::Context::Algorithm::Ed25519).generate_keypair();
        auto leaf_dn = cert_test::dn_from_string("CN=revoked");
        auto leaf_cert = cert_test::make_certificate(root_cert.tbs().subject, leaf_dn, root_key, leaf_key, false,
                                                     KeyUsageExtension::DigitalSignature);

        CrlBuilder builder;
        builder.set_issuer(root_cert.tbs().subject)
            .set_this_update(std::chrono::system_clock::now())
            .add_revoked(leaf_cert.tbs().serial_number, std::chrono::system_clock::now(), CrlReason::KeyCompromise);
        auto crl_result = builder.build_ed25519(root_key);
        REQUIRE(crl_result.success);

        auto parsed = parse_crl(ByteSpan(crl_result.value.der.data(), crl_result.value.der.size()));
        if (!parsed.success) {
            MESSAGE("CRL parse error: ", parsed.error);
        }
        REQUIRE(parsed.success);

        CHECK(leaf_cert.is_revoked(parsed.value));
    }
}
