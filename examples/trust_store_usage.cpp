#include <chrono>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "pki/builder.hpp"
#include "pki/certificate.hpp"
#include "pki/key_utils.hpp"
#include "pki/trust_store.hpp"

namespace {

using namespace std::chrono_literals;

authbox::pik::Certificate build_anchor(keylock::crypto::Context::KeyPair &keypair) {
    authbox::pik::CertificateBuilder builder;
    const auto now = std::chrono::system_clock::now();
    builder.set_subject_from_string("CN=keylock Anchor,O=keylock")
        .set_subject_public_key_ed25519(keypair.public_key)
        .set_validity(now - 1h, now + 3 * 365 * 24h)
        .set_basic_constraints(true, 1)
        .set_key_usage(authbox::pik::KeyUsageExtension::KeyCertSign |
                       authbox::pik::KeyUsageExtension::CRLSign);
    auto cert = builder.build_ed25519(keypair, true);
    if (!cert.success) {
        throw std::runtime_error(cert.error);
    }
    return cert.value;
}

authbox::pik::Certificate build_leaf(const authbox::pik::Certificate &issuer,
                                     keylock::crypto::Context::KeyPair &issuer_key) {
    auto leaf_key = authbox::pik::generate_ed25519_keypair();
    authbox::pik::CertificateBuilder builder;
    const auto now = std::chrono::system_clock::now();
    builder.set_subject_from_string("CN=Trusted Client,O=keylock")
        .set_subject_public_key_ed25519(leaf_key.public_key)
        .set_validity(now - 1h, now + 180 * 24h)
        .set_basic_constraints(false, std::nullopt)
        .set_key_usage(authbox::pik::KeyUsageExtension::DigitalSignature)
        .set_issuer(issuer.tbs().subject);
    auto cert = builder.build_ed25519(issuer_key, false);
    if (!cert.success) {
        throw std::runtime_error(cert.error);
    }
    return cert.value;
}

} // namespace

int main() {
    authbox::pik::TrustStore store;

    auto anchor_key = authbox::pik::generate_ed25519_keypair();
    auto anchor = build_anchor(anchor_key);
    store.add(anchor);
    std::cout << "Anchors loaded: " << store.anchors().size() << "\n";

    auto leaf = build_leaf(anchor, anchor_key);
    auto issuer = store.find_issuer(leaf);
    if (issuer) {
        std::cout << "Issuer match: " << issuer->tbs().subject.to_string() << "\n";
    }

    store.remove_by_subject(anchor.tbs().subject);
    std::cout << "Anchors after removal: " << store.anchors().size() << "\n";
    return 0;
}
