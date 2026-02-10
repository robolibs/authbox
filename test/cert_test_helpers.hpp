#pragma once

#include <chrono>
#include <tuple>

#include <doctest/doctest.h>

#include <pki/builder.hpp>
#include <pki/key_utils.hpp>

namespace cert_test {

    inline std::chrono::system_clock::time_point fixed_time() {
        // Return a fixed time for deterministic tests (2024-01-01 00:00:00 UTC)
        return std::chrono::system_clock::from_time_t(1704067200);
    }

    inline authbox::pik::DistinguishedName dn_from_string(std::string_view str) {
        auto parsed = authbox::pik::DistinguishedName::from_string(str);
        REQUIRE(parsed.success);
        return parsed.value;
    }

    inline authbox::pik::Certificate make_certificate(const authbox::pik::DistinguishedName &issuer_dn,
                                                      const authbox::pik::DistinguishedName &subject_dn,
                                                      const keylock::crypto::Context::KeyPair &issuer_key,
                                                      const keylock::crypto::Context::KeyPair &subject_key, bool is_ca,
                                                      uint16_t key_usage, uint64_t serial = 1) {
        using namespace std::chrono;
        authbox::pik::CertificateBuilder builder;
        builder.set_serial(serial)
            .set_subject(subject_dn)
            .set_issuer(issuer_dn)
            .set_validity(system_clock::now() - hours(1), system_clock::now() + hours(24))
            .set_subject_public_key_ed25519(subject_key.public_key)
            .set_key_usage(key_usage)
            .set_basic_constraints(is_ca, std::nullopt, true);
        auto result = builder.build_ed25519(issuer_key, issuer_dn.der() == subject_dn.der());
        REQUIRE(result.success);
        return result.value;
    }

    inline authbox::pik::Certificate make_self_signed_certificate(const std::string &subject_cn,
                                                                  keylock::crypto::Context::KeyPair &key_out,
                                                                  uint64_t serial = 1) {
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        key_out = ctx.generate_keypair();
        auto dn = dn_from_string("CN=" + subject_cn);
        return make_certificate(dn, dn, key_out, key_out, true, authbox::pik::KeyUsageExtension::KeyCertSign, serial);
    }

    inline authbox::pik::Certificate make_self_signed_certificate_with_key(const authbox::pik::DistinguishedName &dn,
                                                                           const keylock::crypto::Context::KeyPair &key,
                                                                           uint64_t serial) {
        using namespace std::chrono;
        authbox::pik::CertificateBuilder builder;
        const auto base_time = fixed_time();
        builder.set_serial(serial)
            .set_subject(dn)
            .set_issuer(dn)
            .set_validity(base_time - hours(1), base_time + hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_key_usage(authbox::pik::KeyUsageExtension::KeyCertSign)
            .set_basic_constraints(true, std::nullopt, true);
        auto result = builder.build_ed25519(key, true);
        REQUIRE(result.success);
        return result.value;
    }

    inline std::tuple<authbox::pik::Certificate, authbox::pik::Certificate, authbox::pik::Certificate>
    make_chain(keylock::crypto::Context::KeyPair &root_key, keylock::crypto::Context::KeyPair &intermediate_key,
               keylock::crypto::Context::KeyPair &leaf_key) {
        auto root = make_self_signed_certificate("Test Root", root_key, 10);
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        intermediate_key = ctx.generate_keypair();
        auto intermediate_dn = dn_from_string("CN=Test Intermediate");
        auto intermediate = make_certificate(root.tbs().subject, intermediate_dn, root_key, intermediate_key, true,
                                             authbox::pik::KeyUsageExtension::KeyCertSign, 11);
        leaf_key = ctx.generate_keypair();
        auto leaf_dn = dn_from_string("CN=Test Leaf");
        auto leaf = make_certificate(intermediate_dn, leaf_dn, intermediate_key, leaf_key, false,
                                     authbox::pik::KeyUsageExtension::DigitalSignature, 12);
        return {root, intermediate, leaf};
    }

} // namespace cert_test
