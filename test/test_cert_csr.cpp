#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <pki/csr_builder.hpp>

TEST_SUITE("cert/csr") {
    TEST_CASE("csr build and parse") {
        using namespace authbox::pik;
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();

        CsrBuilder builder;
        builder.set_subject_from_string("CN=csr.example").set_subject_public_key_ed25519(key.public_key);

        auto csr_result = builder.build_ed25519(key);
        REQUIRE(csr_result.success);

        auto parsed = parse_csr(ByteSpan(csr_result.value.der.data(), csr_result.value.der.size()));
        REQUIRE(parsed.success);
        CHECK(parsed.value.info.subject.to_string().find("csr.example") != std::string::npos);
    }

    TEST_CASE("csr builder supports RSA and ECDSA signature algorithms") {
        using namespace authbox::pik;

        keylock::crypto::Context rsa_ctx(keylock::crypto::Context::Algorithm::RSA_PKCS1v15_SHA256);
        auto rsa_key = rsa_ctx.generate_keypair();

        SubjectPublicKeyInfo rsa_spki{};
        rsa_spki.algorithm.signature = SignatureAlgorithmId::RsaPkcs1Sha256;
        rsa_spki.public_key = rsa_key.public_key;

        CsrBuilder rsa_builder;
        rsa_builder.set_subject_from_string("CN=csr-rsa.example")
            .set_subject_public_key(rsa_spki)
            .set_signature_algorithm(SignatureAlgorithmId::RsaPkcs1Sha256);

        auto rsa_csr_result = rsa_builder.build(rsa_key);
        REQUIRE(rsa_csr_result.success);
        auto rsa_parsed = parse_csr(ByteSpan(rsa_csr_result.value.der.data(), rsa_csr_result.value.der.size()));
        REQUIRE(rsa_parsed.success);
        CHECK(rsa_parsed.value.signature_algorithm.signature == SignatureAlgorithmId::RsaPkcs1Sha256);

        keylock::crypto::Context ecdsa_ctx(keylock::crypto::Context::Algorithm::ECDSA_P256_SHA256);
        auto ecdsa_key = ecdsa_ctx.generate_keypair();

        SubjectPublicKeyInfo ecdsa_spki{};
        ecdsa_spki.algorithm.signature = SignatureAlgorithmId::EcdsaSha256;
        ecdsa_spki.algorithm.curve = CurveId::Secp256r1;
        ecdsa_spki.public_key = ecdsa_key.public_key;

        CsrBuilder ecdsa_builder;
        ecdsa_builder.set_subject_from_string("CN=csr-ecdsa.example")
            .set_subject_public_key(ecdsa_spki)
            .set_signature_algorithm(SignatureAlgorithmId::EcdsaSha256);

        auto ecdsa_csr_result = ecdsa_builder.build(ecdsa_key);
        REQUIRE(ecdsa_csr_result.success);
        auto ecdsa_parsed = parse_csr(ByteSpan(ecdsa_csr_result.value.der.data(), ecdsa_csr_result.value.der.size()));
        REQUIRE(ecdsa_parsed.success);
        CHECK(ecdsa_parsed.value.signature_algorithm.signature == SignatureAlgorithmId::EcdsaSha256);
        CHECK(!ecdsa_parsed.value.signature.empty());
        CHECK(ecdsa_parsed.value.signature[0] == 0x30); // DER-encoded ECDSA signature sequence
    }
}
