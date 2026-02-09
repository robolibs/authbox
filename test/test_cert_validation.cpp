#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

TEST_SUITE("cert/validation") {
    TEST_CASE("verify signature against issuer") {
        using namespace authbox::pik;
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto root_key = ctx.generate_keypair();
        auto leaf_key = ctx.generate_keypair();
        auto root_dn = cert_test::dn_from_string("CN=Root");
        auto leaf_dn = cert_test::dn_from_string("CN=Leaf");
        auto root_cert =
            cert_test::make_certificate(root_dn, root_dn, root_key, root_key, true, KeyUsageExtension::KeyCertSign);
        auto leaf_cert =
            cert_test::make_certificate(root_dn, leaf_dn, root_key, leaf_key, false, KeyUsageExtension::DigitalSignature);

        auto result = leaf_cert.verify_signature(root_cert);
        CHECK(result.success);
        CHECK(result.value);
    }
}
