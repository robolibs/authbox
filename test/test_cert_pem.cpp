#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <pki/pem.hpp>

TEST_SUITE("cert/pem") {
    TEST_CASE("certificate pem encode/decode") {
        using namespace authbox::pik;
        keylock::crypto::Context::KeyPair key;
        auto cert = cert_test::make_self_signed_certificate("PEMTest", key);
        auto pem = cert.to_pem();
        auto decoded = pem_decode(pem, "CERTIFICATE");
        REQUIRE(decoded.success);
        CHECK(decoded.block.data == cert.der());
    }
}
