#include <cstdint>

#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <pki/asn1_writer.hpp>

namespace {

    bool decode_rsa_public_blob(const std::vector<uint8_t> &blob, std::vector<uint8_t> &modulus,
                                std::vector<uint8_t> &exponent) {
        auto read_u32_be = [&](size_t &offset, uint32_t &value) -> bool {
            if (offset + 4 > blob.size()) {
                return false;
            }
            value = (static_cast<uint32_t>(blob[offset]) << 24U) | (static_cast<uint32_t>(blob[offset + 1]) << 16U) |
                    (static_cast<uint32_t>(blob[offset + 2]) << 8U) | static_cast<uint32_t>(blob[offset + 3]);
            offset += 4;
            return true;
        };

        size_t offset = 0;
        uint32_t n_len = 0;
        uint32_t e_len = 0;
        if (!read_u32_be(offset, n_len) || n_len == 0 || offset + n_len > blob.size()) {
            return false;
        }
        modulus.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                       blob.begin() + static_cast<std::ptrdiff_t>(offset + n_len));
        offset += n_len;

        if (!read_u32_be(offset, e_len) || e_len == 0 || offset + e_len > blob.size()) {
            return false;
        }
        exponent.assign(blob.begin() + static_cast<std::ptrdiff_t>(offset),
                        blob.begin() + static_cast<std::ptrdiff_t>(offset + e_len));
        offset += e_len;
        return offset == blob.size();
    }

    authbox::pik::Certificate make_signature_target(authbox::pik::SignatureAlgorithmId algorithm,
                                                    const std::vector<uint8_t> &signature,
                                                    const std::vector<uint8_t> &tbs_der) {
        authbox::pik::TBSCertificate tbs{};
        tbs.subject = cert_test::dn_from_string("CN=Leaf");
        tbs.issuer = cert_test::dn_from_string("CN=Issuer");

        authbox::pik::AlgorithmIdentifier sig_alg{};
        sig_alg.signature = algorithm;

        return authbox::pik::Certificate(tbs, sig_alg, signature, tbs_der, tbs_der);
    }

    authbox::pik::Certificate make_issuer_certificate(const std::vector<uint8_t> &public_key_blob) {
        authbox::pik::TBSCertificate issuer_tbs{};
        issuer_tbs.subject = cert_test::dn_from_string("CN=Issuer");
        issuer_tbs.subject_public_key_info.public_key = public_key_blob;

        return authbox::pik::Certificate(issuer_tbs, authbox::pik::AlgorithmIdentifier{}, {}, {}, {});
    }

} // namespace

TEST_SUITE("cert/signature_algorithms") {

    TEST_CASE("verify_signature supports RSA PKCS1v15 SHA256") {
        using namespace authbox::pik;
        keylock::crypto::Context signer(keylock::crypto::Context::Algorithm::RSA_PKCS1v15_SHA256);
        auto issuer_key = signer.generate_keypair();

        const std::vector<uint8_t> tbs_der = {'r', 's', 'a', '-', 'p', 'k', 'c', 's', '1'};
        auto sig = signer.sign(tbs_der, issuer_key.private_key);
        REQUIRE(sig.success);

        auto target = make_signature_target(SignatureAlgorithmId::RsaPkcs1Sha256, sig.data, tbs_der);
        auto issuer = make_issuer_certificate(issuer_key.public_key);

        auto verify = target.verify_signature(issuer);
        CHECK(verify.success);
        CHECK(verify.value);
    }

    TEST_CASE("verify_signature supports RSA-PSS SHA256") {
        using namespace authbox::pik;
        keylock::crypto::Context signer(keylock::crypto::Context::Algorithm::RSA_PSS_SHA256);
        auto issuer_key = signer.generate_keypair();

        const std::vector<uint8_t> tbs_der = {'r', 's', 'a', '-', 'p', 's', 's'};
        auto sig = signer.sign(tbs_der, issuer_key.private_key);
        REQUIRE(sig.success);

        auto target = make_signature_target(SignatureAlgorithmId::RsaPssSha256, sig.data, tbs_der);
        auto issuer = make_issuer_certificate(issuer_key.public_key);

        auto verify = target.verify_signature(issuer);
        CHECK(verify.success);
        CHECK(verify.value);
    }

    TEST_CASE("verify_signature supports RSA public key DER decoding") {
        using namespace authbox::pik;
        keylock::crypto::Context signer(keylock::crypto::Context::Algorithm::RSA_PKCS1v15_SHA256);
        auto issuer_key = signer.generate_keypair();

        std::vector<uint8_t> modulus;
        std::vector<uint8_t> exponent;
        REQUIRE(decode_rsa_public_blob(issuer_key.public_key, modulus, exponent));

        auto rsa_pk_der =
            der::encode_sequence(der::concat({der::encode_integer(modulus), der::encode_integer(exponent)}));

        const std::vector<uint8_t> tbs_der = {'r', 's', 'a', '-', 'd', 'e', 'r'};
        auto sig = signer.sign(tbs_der, issuer_key.private_key);
        REQUIRE(sig.success);

        auto target = make_signature_target(SignatureAlgorithmId::RsaPkcs1Sha256, sig.data, tbs_der);
        auto issuer = make_issuer_certificate(rsa_pk_der);

        auto verify = target.verify_signature(issuer);
        CHECK(verify.success);
        CHECK(verify.value);
    }

    TEST_CASE("verify_signature supports ECDSA P-256 with DER signature and uncompressed key") {
        using namespace authbox::pik;
        keylock::crypto::Context signer(keylock::crypto::Context::Algorithm::ECDSA_P256_SHA256);
        auto issuer_key = signer.generate_keypair();
        REQUIRE(issuer_key.public_key.size() == 64);

        const std::vector<uint8_t> tbs_der = {'e', 'c', 'd', 's', 'a'};
        auto raw_sig = signer.sign(tbs_der, issuer_key.private_key);
        REQUIRE(raw_sig.success);
        REQUIRE(raw_sig.data.size() == 64);

        auto der_sig = keylock::crypto::Context::encode_ecdsa_p256_signature_der(raw_sig.data);
        REQUIRE(der_sig.success);

        std::vector<uint8_t> uncompressed_key;
        uncompressed_key.reserve(65);
        uncompressed_key.push_back(0x04);
        uncompressed_key.insert(uncompressed_key.end(), issuer_key.public_key.begin(), issuer_key.public_key.end());

        auto target = make_signature_target(SignatureAlgorithmId::EcdsaSha256, der_sig.data, tbs_der);
        auto issuer = make_issuer_certificate(uncompressed_key);

        auto verify = target.verify_signature(issuer);
        CHECK(verify.success);
        CHECK(verify.value);
    }
}
