/**
 * Example: Certificate revocation checking using local verification
 *
 * This example demonstrates how to use the keylock Verification Protocol (LVP)
 * to check certificate revocation status using local/in-process verification.
 *
 * Build with: cmake -Dkeylock_BUILD_EXAMPLES=ON
 */

#include <iostream>
#include <keylock/keylock.hpp>
#include <pki/verify/direct_transport.hpp>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <certificate.pem>\n";
        std::cerr << "Example: " << argv[0] << " cert.pem\n";
        return 1;
    }

    std::string cert_path = argv[1];

    std::cout << "keylock Certificate Revocation Check Example\n";
    std::cout << "===========================================\n\n";

    // Load certificate
    std::cout << "Loading certificate from: " << cert_path << "\n";
    auto cert_result = authbox::pik::Certificate::load(cert_path);
    if (!cert_result.success || cert_result.value.empty()) {
        std::cerr << "Failed to load certificate: " << cert_result.error << "\n";
        return 1;
    }

    auto cert = cert_result.value[0];
    std::cout << "Certificate loaded successfully\n";
    std::cout << "Subject: " << cert.tbs().subject.to_string() << "\n\n";

    // Create a local verifier (no networking)
    std::cout << "Creating local verifier...\n";
    authbox::pik::verify::Verifier verifier;

    // Add some revoked certificates to the list (for demonstration)
    auto *revocation_handler = verifier.as_revocation_handler();
    if (revocation_handler) {
        revocation_handler->add_revoked_certificate({0x01, 0x02, 0x03, 0x04, 0x05}, "Key compromise",
                                                    std::chrono::system_clock::now() - std::chrono::hours(48));
        std::cout << "Added example revoked certificate to the list\n";
    }

    // Health check
    std::cout << "\nChecking verifier health...\n";
    auto health = verifier.health_check();
    if (!health.success || !health.value) {
        std::cerr << "Health check failed: " << health.error << "\n";
        return 1;
    }
    std::cout << "Verifier is healthy\n\n";

    // Verify certificate revocation status
    std::cout << "Checking certificate revocation status...\n";
    std::vector<authbox::pik::Certificate> chain = {cert};
    auto result = verifier.verify_chain(chain);

    if (!result.success) {
        std::cerr << "Verification failed: " << result.error << "\n";
        return 1;
    }

    const auto &response = result.value;

    std::cout << "\nVerification Result:\n";
    std::cout << "-------------------\n";

    switch (response.status) {
    case authbox::pik::verify::wire::VerifyStatus::GOOD:
        std::cout << "Status: GOOD\n";
        std::cout << "The certificate is valid and not revoked\n";
        break;

    case authbox::pik::verify::wire::VerifyStatus::REVOKED:
        std::cout << "Status: REVOKED\n";
        std::cout << "Reason: " << response.reason << "\n";
        if (response.revocation_time != std::chrono::system_clock::time_point{}) {
            auto rev_time = std::chrono::system_clock::to_time_t(response.revocation_time);
            std::cout << "Revoked at: " << std::ctime(&rev_time);
        }
        break;

    case authbox::pik::verify::wire::VerifyStatus::UNKNOWN:
        std::cout << "Status: UNKNOWN\n";
        std::cout << "The verifier doesn't have information about this certificate\n";
        if (!response.reason.empty()) {
            std::cout << "Reason: " << response.reason << "\n";
        }
        break;
    }

    std::cout << "\nResponse Details:\n";
    auto this_update = std::chrono::system_clock::to_time_t(response.this_update);
    auto next_update = std::chrono::system_clock::to_time_t(response.next_update);
    std::cout << "This update: " << std::ctime(&this_update);
    std::cout << "Next update: " << std::ctime(&next_update);
    std::cout << "Nonce: " << (response.nonce.size() == 32 ? "Valid" : "Invalid") << "\n";

    return 0;
}
