#include <chrono>
#include <iostream>
#include <string>
#include <vector>

#include "keylock/crypto/common.hpp"
#include "pki/builder.hpp"
#include "pki/certificate.hpp"
#include "pki/key_utils.hpp"

int main(int argc, char **argv) {
    using namespace std::chrono_literals;

    authbox::pik::Certificate certificate;
    if (argc > 1) {
        auto loaded = authbox::pik::Certificate::load(argv[1]);
        if (!loaded.success) {
            std::cerr << "Failed to load certificate: " << loaded.error << "\n";
            return 1;
        }
        certificate = loaded.value.front();
    } else {
        auto keypair = authbox::pik::generate_ed25519_keypair();
        authbox::pik::CertificateBuilder builder;
        const auto now = std::chrono::system_clock::now();
        builder.set_subject_from_string("CN=On-The-Fly Cert,O=keylock")
            .set_subject_public_key_ed25519(keypair.public_key)
            .set_validity(now - 1h, now + 90 * 24h)
            .set_basic_constraints(false, std::nullopt)
            .set_key_usage(authbox::pik::KeyUsageExtension::DigitalSignature);
        auto cert = builder.build_ed25519(keypair, true);
        if (!cert.success) {
            std::cerr << "Unable to generate fallback certificate: " << cert.error << "\n";
            return 1;
        }
        certificate = cert.value;
    }

    certificate.print_info(std::cout);
    auto sans = certificate.subject_alt_names();
    std::cout << "SubjectAltName count: " << sans.size() << "\n";
    const auto fingerprint = certificate.fingerprint(::keylock::hash::Algorithm::SHA256);
    std::cout << "Fingerprint (SHA-256): " << keylock::crypto::to_hex(fingerprint) << "\n";
    return 0;
}
