#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <pki/crl_builder.hpp>
#include <pki/csr_builder.hpp>
#include <pki/trust_store.hpp>

TEST_SUITE("cert/vectors") {
    TEST_CASE("deterministic fingerprint for root cert") {
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();
        auto dn = cert_test::dn_from_string("CN=VectorRoot");
        auto cert1 = cert_test::make_self_signed_certificate_with_key(dn, key, 123);
        auto cert2 = cert_test::make_self_signed_certificate_with_key(dn, key, 123);
        CHECK(cert1.der() == cert2.der());
        CHECK(cert1.fingerprint(::keylock::hash::Algorithm::SHA256) == cert2.fingerprint(::keylock::hash::Algorithm::SHA256));
    }

    TEST_CASE("chain/csr/crl vector generation") {
        using namespace authbox::pik;
        keylock::crypto::Context::KeyPair root_key, intermediate_key, leaf_key;
        auto [root, intermediate, leaf] = cert_test::make_chain(root_key, intermediate_key, leaf_key);
        // Validation should succeed but return false (not valid) with empty trust store
        auto validation = leaf.validate_chain({intermediate}, TrustStore{});
        CHECK(validation.success == true);
        CHECK(validation.value == false);

        CsrBuilder csr_builder;
        csr_builder.set_subject(leaf.tbs().subject)
            .set_subject_public_key_ed25519(leaf.tbs().subject_public_key_info.public_key);
        auto csr = csr_builder.build_ed25519(leaf_key);
        REQUIRE(csr.success);

        CrlBuilder crl_builder;
        crl_builder.set_issuer(root.tbs().subject)
            .set_this_update(cert_test::fixed_time())
            .add_revoked(leaf.tbs().serial_number, cert_test::fixed_time(), CrlReason::Superseded);
        auto crl = crl_builder.build_ed25519(root_key);
        REQUIRE(crl.success);
    }
}
