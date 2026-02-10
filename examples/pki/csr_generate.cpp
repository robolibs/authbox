#include <chrono>
#include <fstream>
#include <iostream>
#include <string>

#include "pki/csr_builder.hpp"
#include "pki/key_utils.hpp"
#include "pki/pem.hpp"

int main() {
    using authbox::pik::CsrBuilder;

    const auto subject_key = authbox::pik::generate_ed25519_keypair();

    CsrBuilder builder;
    builder.set_subject_from_string("CN=keylock Client,O=keylock")
        .set_subject_public_key_ed25519(subject_key.public_key);

    auto csr = builder.build_ed25519(subject_key);
    if (!csr.success) {
        std::cerr << "Failed to build CSR: " << csr.error << "\n";
        return 1;
    }

    const std::string path = "client_request.csr.pem";
    std::ofstream out(path, std::ios::binary);
    const auto pem = authbox::pik::pem_encode(authbox::pik::ByteSpan(csr.value.der.data(), csr.value.der.size()),
                                              "CERTIFICATE REQUEST");
    out << pem;
    if (!out.good()) {
        std::cerr << "Unable to write CSR file\n";
        return 1;
    }

    std::cout << "CSR saved to " << path << "\n";
    return 0;
}
