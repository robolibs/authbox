#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

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
}
