#include <chrono>
#include <iostream>
#include <string>

#include "pki/builder.hpp"
#include "pki/key_utils.hpp"

int main() {
    using namespace std::chrono_literals;
    using authbox::pik::CertificateBuilder;

    const auto ca_key = authbox::pik::generate_ed25519_keypair();
    CertificateBuilder builder;
    const auto now = std::chrono::system_clock::now();

    builder.set_subject_from_string("CN=keylock Dev CA,O=keylock Labs,C=US")
        .set_subject_public_key_ed25519(ca_key.public_key)
        .set_validity(now - 24h, now + 2 * 365 * 24h)
        .set_basic_constraints(true, 1)
        .set_key_usage(authbox::pik::KeyUsageExtension::KeyCertSign |
                       authbox::pik::KeyUsageExtension::CRLSign)
        .set_subject_key_identifier(ca_key.public_key);

    auto certificate = builder.build_ed25519(ca_key, true);
    if (!certificate.success) {
        std::cerr << "Failed to create CA certificate: " << certificate.error << "\n";
        return 1;
    }

    const std::string pem_path = "dev_ca.pem";
    if (!certificate.value.save(pem_path)) {
        std::cerr << "Unable to write " << pem_path << "\n";
        return 1;
    }

    std::cout << "CA certificate saved to " << pem_path << "\n";
    return 0;
}
