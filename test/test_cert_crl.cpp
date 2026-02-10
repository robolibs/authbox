#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <pki/crl_builder.hpp>

namespace {
    authbox::pik::Certificate make_issuer_certificate_with_public_key(const std::vector<uint8_t> &public_key,
                                                                      authbox::pik::SignatureAlgorithmId sig_alg) {
        authbox::pik::TBSCertificate tbs{};
        tbs.subject = cert_test::dn_from_string("CN=issuer");
        tbs.subject_public_key_info.algorithm.signature = sig_alg;
        tbs.subject_public_key_info.public_key = public_key;
        return authbox::pik::Certificate(tbs, authbox::pik::AlgorithmIdentifier{}, {}, {}, {});
    }
} // namespace

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

    TEST_CASE("crl signing and verification supports RSA and ECDSA") {
        using namespace authbox::pik;

        CrlBuilder rsa_builder;
        rsa_builder.set_issuer_from_string("CN=issuer")
            .set_this_update(std::chrono::system_clock::now())
            .add_revoked({0x01}, std::chrono::system_clock::now(), CrlReason::KeyCompromise)
            .set_signature_algorithm(SignatureAlgorithmId::RsaPkcs1Sha256);

        keylock::crypto::Context rsa_ctx(keylock::crypto::Context::Algorithm::RSA_PKCS1v15_SHA256);
        auto rsa_key = rsa_ctx.generate_keypair();
        auto rsa_crl = rsa_builder.build(rsa_key);
        REQUIRE(rsa_crl.success);
        auto rsa_issuer =
            make_issuer_certificate_with_public_key(rsa_key.public_key, SignatureAlgorithmId::RsaPkcs1Sha256);
        auto rsa_verify = rsa_crl.value.verify_signature(rsa_issuer);
        CHECK(rsa_verify.success);
        CHECK(rsa_verify.value);

        CrlBuilder ecdsa_builder;
        ecdsa_builder.set_issuer_from_string("CN=issuer")
            .set_this_update(std::chrono::system_clock::now())
            .add_revoked({0x02}, std::chrono::system_clock::now(), CrlReason::Superseded)
            .set_signature_algorithm(SignatureAlgorithmId::EcdsaSha256);

        keylock::crypto::Context ecdsa_ctx(keylock::crypto::Context::Algorithm::ECDSA_P256_SHA256);
        auto ecdsa_key = ecdsa_ctx.generate_keypair();
        auto ecdsa_crl = ecdsa_builder.build(ecdsa_key);
        REQUIRE(ecdsa_crl.success);

        std::vector<uint8_t> uncompressed;
        uncompressed.reserve(65);
        uncompressed.push_back(0x04);
        uncompressed.insert(uncompressed.end(), ecdsa_key.public_key.begin(), ecdsa_key.public_key.end());

        auto ecdsa_issuer = make_issuer_certificate_with_public_key(uncompressed, SignatureAlgorithmId::EcdsaSha256);
        auto ecdsa_verify = ecdsa_crl.value.verify_signature(ecdsa_issuer);
        CHECK(ecdsa_verify.success);
        CHECK(ecdsa_verify.value);
    }
}
