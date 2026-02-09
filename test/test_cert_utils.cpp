#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <sstream>

TEST_SUITE("cert/utils") {
    TEST_CASE("print_info and to_json") {
        using namespace authbox::pik;
        keylock::crypto::Context::KeyPair key;
        auto cert = cert_test::make_self_signed_certificate("Print Test", key);
        std::ostringstream oss;
        cert.print_info(oss);
        CHECK(oss.str().find("Print Test") != std::string::npos);
        auto json = cert.to_json();
        CHECK(json.find("Print Test") != std::string::npos);
    }

    TEST_CASE("identity equality") {
        using namespace authbox::pik;
        keylock::crypto::Context::KeyPair key_a;
        auto cert_a = cert_test::make_self_signed_certificate("Identity", key_a);
        keylock::crypto::Context::KeyPair key_b;
        auto cert_b = cert_test::make_self_signed_certificate("Identity", key_b);
        CHECK(!(cert_a == cert_b));
        CHECK(cert_a.equals_identity(cert_a));
    }
}
