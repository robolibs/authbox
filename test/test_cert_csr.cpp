#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <pki/csr_builder.hpp>

TEST_SUITE("cert/csr") {
    TEST_CASE("csr build and parse") {
        using namespace authbox::pik;
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();

        CsrBuilder builder;
        builder.set_subject_from_string("CN=csr.example")
            .set_subject_public_key_ed25519(key.public_key);

        auto csr_result = builder.build_ed25519(key);
        REQUIRE(csr_result.success);

        auto parsed = parse_csr(ByteSpan(csr_result.value.der.data(), csr_result.value.der.size()));
        REQUIRE(parsed.success);
        CHECK(parsed.value.info.subject.to_string().find("csr.example") != std::string::npos);
    }
}
