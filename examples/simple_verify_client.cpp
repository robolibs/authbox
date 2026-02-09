/**
 * Simple Verification Example
 *
 * This example demonstrates how to use the authbox::pik::verify::Verifier to check
 * certificate revocation status using local/in-process verification.
 *
 * Build with: cmake -Dkeylock_BUILD_EXAMPLES=ON
 * Run: ./simple_verify_client
 */

#include <iostream>
#include <pki/builder.hpp>
#include <keylock/keylock.hpp>
#include <pki/verify/direct_transport.hpp>

int main() {
    std::cout << "keylock Simple Verification Example\n";
    std::cout << "===================================\n\n";

    // Create a local verifier (no networking)
    std::cout << "Creating local verifier...\n";
    authbox::pik::verify::Verifier verifier;

    // Setup revocation list
    auto *revocation_handler = verifier.as_revocation_handler();
    if (revocation_handler) {
        // Add some revoked certificates for demonstration
        revocation_handler->add_revoked_certificate({0x01, 0x02, 0x03, 0x04, 0x05}, "Key compromise",
                                                    std::chrono::system_clock::now() - std::chrono::hours(48));
        revocation_handler->add_revoked_certificate({0xDE, 0xAD, 0xBE, 0xEF}, "Certificate hold",
                                                    std::chrono::system_clock::now() - std::chrono::hours(24));
        std::cout << "Added 2 revoked certificates to the list\n\n";
    }

    // Create a test certificate to verify
    std::cout << "Creating test certificate...\n";
    keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
    auto keys = ctx.generate_keypair();

    auto dn_result = authbox::pik::DistinguishedName::from_string("CN=Test User,O=Example Organization,C=US");
    if (!dn_result.success) {
        std::cerr << "Failed to create DN: " << dn_result.error << "\n";
        return 1;
    }

    auto not_before = std::chrono::system_clock::now();
    auto not_after = not_before + std::chrono::hours(24 * 365); // 1 year

    authbox::pik::CertificateBuilder builder;
    builder.set_version(3)     // v3 required for extensions
        .set_serial(12345)     // Use a serial that's not in the revocation list
        .set_subject(dn_result.value)
        .set_issuer(dn_result.value)
        .set_validity(not_before, not_after)
        .set_subject_public_key_ed25519(keys.public_key)
        .set_basic_constraints(false, std::nullopt, true);

    auto cert_result = builder.build_ed25519(keys, true);
    if (!cert_result.success) {
        std::cerr << "Failed to create certificate: " << cert_result.error << "\n";
        return 1;
    }

    auto test_cert = cert_result.value;
    std::cout << "Certificate created successfully\n";
    std::cout << "Subject: " << test_cert.tbs().subject.to_string() << "\n";
    std::cout << "Serial: 12345\n\n";

    // Health check
    std::cout << "Performing health check...\n";
    auto health = verifier.health_check();
    if (!health.success || !health.value) {
        std::cerr << "Health check failed: " << health.error << "\n";
        return 1;
    }
    std::cout << "Verifier is healthy\n\n";

    // Verify certificate
    std::cout << "Verifying certificate...\n";
    std::vector<authbox::pik::Certificate> chain = {test_cert};
    auto result = verifier.verify_chain(chain);

    if (!result.success) {
        std::cerr << "Verification request failed: " << result.error << "\n";
        return 1;
    }

    const auto &response = result.value;

    std::cout << "\n=== Verification Result ===\n";

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

    std::cout << "\n=== Response Details ===\n";
    if (response.this_update != std::chrono::system_clock::time_point{}) {
        auto this_update = std::chrono::system_clock::to_time_t(response.this_update);
        std::cout << "This update: " << std::ctime(&this_update);
    }
    if (response.next_update != std::chrono::system_clock::time_point{}) {
        auto next_update = std::chrono::system_clock::to_time_t(response.next_update);
        std::cout << "Next update: " << std::ctime(&next_update);
    }
    std::cout << "Nonce: " << (response.nonce.size() == 32 ? "Valid (32 bytes)" : "Invalid") << "\n";

    // Test with a revoked certificate
    std::cout << "\n\n=== Testing with Revoked Certificate ===\n";
    std::cout << "Creating certificate with serial number in revocation list...\n";

    authbox::pik::CertificateBuilder revoked_builder;
    revoked_builder.set_version(3)                              // v3 required for extensions
        .set_serial({0x01, 0x02, 0x03, 0x04, 0x05})             // This serial is revoked
        .set_subject(dn_result.value)
        .set_issuer(dn_result.value)
        .set_validity(not_before, not_after)
        .set_subject_public_key_ed25519(keys.public_key)
        .set_basic_constraints(false, std::nullopt, true);

    auto revoked_cert_result = revoked_builder.build_ed25519(keys, true);
    if (!revoked_cert_result.success) {
        std::cerr << "Failed to create revoked certificate: " << revoked_cert_result.error << "\n";
        return 1;
    }

    std::cout << "Verifying revoked certificate...\n";
    std::vector<authbox::pik::Certificate> revoked_chain = {revoked_cert_result.value};
    auto revoked_result = verifier.verify_chain(revoked_chain);

    if (!revoked_result.success) {
        std::cerr << "Verification request failed: " << revoked_result.error << "\n";
        return 1;
    }

    const auto &revoked_response = revoked_result.value;

    std::cout << "\n=== Verification Result ===\n";

    switch (revoked_response.status) {
    case authbox::pik::verify::wire::VerifyStatus::GOOD:
        std::cout << "Status: GOOD (unexpected!)\n";
        break;

    case authbox::pik::verify::wire::VerifyStatus::REVOKED:
        std::cout << "Status: REVOKED (as expected)\n";
        std::cout << "Reason: " << revoked_response.reason << "\n";
        if (revoked_response.revocation_time != std::chrono::system_clock::time_point{}) {
            auto rev_time = std::chrono::system_clock::to_time_t(revoked_response.revocation_time);
            std::cout << "Revoked at: " << std::ctime(&rev_time);
        }
        break;

    case authbox::pik::verify::wire::VerifyStatus::UNKNOWN:
        std::cout << "Status: UNKNOWN\n";
        break;
    }

    std::cout << "\nDemo completed successfully!\n";
    return 0;
}
