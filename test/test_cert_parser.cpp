#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <pki/parser.hpp>
#include <pki/pem.hpp>

using namespace authbox::pik;

TEST_SUITE("cert/parser") {
    TEST_CASE("parse self-signed certificate") {
        keylock::crypto::Context::KeyPair root_key;
        auto cert = cert_test::make_self_signed_certificate("Root CA", root_key);
        auto der = cert.der();
        auto parse = parse_x509_cert(ByteSpan(der.data(), der.size()));
        REQUIRE(parse.success);
        CHECK(parse.certificate.subject.to_string().find("Root CA") != std::string::npos);
    }

    TEST_CASE("PEM encode/decode roundtrip") {
        keylock::crypto::Context::KeyPair root_key;
        auto cert = cert_test::make_self_signed_certificate("Root CA", root_key);
        auto pem = cert.to_pem();
        auto decoded = pem_decode(pem, "CERTIFICATE");
        REQUIRE(decoded.success);
        CHECK(decoded.block.data == cert.der());
    }
}
