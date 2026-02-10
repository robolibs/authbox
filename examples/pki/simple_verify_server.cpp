/**
 * Request Processor Example
 *
 * This example demonstrates how to use the authbox::pik::verify::RequestProcessor
 * to handle verification requests. The RequestProcessor can be used to build
 * custom transport layers (e.g., over Unix sockets, shared memory, message queues).
 *
 * For simple in-process verification, use authbox::pik::verify::Verifier instead.
 *
 * Build with: cmake -Dkeylock_BUILD_EXAMPLES=ON
 * Run: ./simple_verify_server
 */

#include <iostream>
#include <keylock/crypto/ed25519/ed25519.hpp>
#include <keylock/crypto/rng/randombytes.hpp>
#include <keylock/keylock.hpp>
#include <pki/builder.hpp>
#include <pki/verify/server.hpp>

int main() {
    std::cout << "keylock Request Processor Example\n";
    std::cout << "=================================\n\n";

    // Create a simple revocation handler
    auto handler = std::make_shared<authbox::pik::verify::SimpleRevocationHandler>();

    // Add some revoked certificates for demonstration
    std::cout << "Initializing revocation list...\n";
    handler->add_revoked_certificate({0x01, 0x02, 0x03, 0x04, 0x05}, "Key compromise",
                                     std::chrono::system_clock::now() - std::chrono::hours(48));
    handler->add_revoked_certificate({0xDE, 0xAD, 0xBE, 0xEF}, "Certificate hold",
                                     std::chrono::system_clock::now() - std::chrono::hours(24));
    std::cout << "Added 2 revoked certificates to the list\n\n";

    // Create request processor
    std::cout << "Creating request processor...\n";
    authbox::pik::verify::RequestProcessor processor(handler);

    // Optional: Generate and set signing key for response signatures
    std::cout << "Generating Ed25519 signing key...\n";
    std::vector<uint8_t> pk(keylock::crypto::ed25519::PUBLICKEYBYTES);
    std::vector<uint8_t> sk(keylock::crypto::ed25519::SECRETKEYBYTES);
    keylock::crypto::ed25519::keypair(pk.data(), sk.data());
    processor.set_signing_key(sk);

    // Create a test certificate
    std::cout << "\nCreating test certificate...\n";
    keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
    auto keys = ctx.generate_keypair();

    auto dn_result = authbox::pik::DistinguishedName::from_string("CN=Test Certificate,O=Example Organization");
    if (!dn_result.success) {
        std::cerr << "Failed to create DN: " << dn_result.error << "\n";
        return 1;
    }

    auto not_before = std::chrono::system_clock::now();
    auto not_after = not_before + std::chrono::hours(24 * 365);

    authbox::pik::CertificateBuilder builder;
    builder.set_version(3)
        .set_serial(99999) // Not in revocation list
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
    std::cout << "Certificate created with serial: 99999\n\n";

    // Build a wire format request manually
    std::cout << "=== Testing Request Processor ===\n\n";

    // 1. Test health check
    std::cout << "1. Testing health check...\n";
    authbox::pik::verify::wire::HealthCheckRequest health_req;
    auto health_req_data = authbox::pik::verify::wire::Serializer::serialize(health_req);
    auto health_resp_data = processor.process(authbox::pik::verify::methods::HEALTH_CHECK, health_req_data);

    authbox::pik::verify::wire::HealthCheckResponse health_resp;
    if (authbox::pik::verify::wire::Serializer::deserialize(health_resp_data, health_resp)) {
        std::cout << "   Health status: "
                  << (health_resp.status == authbox::pik::verify::wire::HealthCheckResponse::ServingStatus::SERVING
                          ? "SERVING"
                          : "NOT_SERVING")
                  << "\n\n";
    }

    // 2. Test certificate verification (valid cert)
    std::cout << "2. Testing valid certificate verification...\n";
    authbox::pik::verify::wire::VerifyRequest verify_req;
    authbox::pik::verify::wire::CertificateData cert_data;
    cert_data.der_bytes = test_cert.to_der();
    verify_req.certificate_chain.push_back(std::move(cert_data));
    verify_req.validation_timestamp = std::chrono::system_clock::now();
    verify_req.flags = authbox::pik::verify::wire::RequestFlags::NONE;
    verify_req.nonce.resize(32);
    keylock::crypto::rng::randombytes_buf(verify_req.nonce.data(), verify_req.nonce.size());

    auto verify_req_data = authbox::pik::verify::wire::Serializer::serialize(verify_req);
    auto verify_resp_data = processor.process(authbox::pik::verify::methods::CHECK_CERTIFICATE, verify_req_data);

    authbox::pik::verify::wire::VerifyResponse verify_resp;
    if (authbox::pik::verify::wire::Serializer::deserialize(verify_resp_data, verify_resp)) {
        std::cout << "   Status: ";
        switch (verify_resp.status) {
        case authbox::pik::verify::wire::VerifyStatus::GOOD:
            std::cout << "GOOD\n";
            break;
        case authbox::pik::verify::wire::VerifyStatus::REVOKED:
            std::cout << "REVOKED\n";
            break;
        case authbox::pik::verify::wire::VerifyStatus::UNKNOWN:
            std::cout << "UNKNOWN\n";
            break;
        }
        std::cout << "   Reason: " << verify_resp.reason << "\n";
        std::cout << "   Signature present: " << (verify_resp.signature.size() == 64 ? "Yes" : "No") << "\n\n";
    }

    // 3. Test certificate verification (revoked cert)
    std::cout << "3. Testing revoked certificate verification...\n";
    authbox::pik::CertificateBuilder revoked_builder;
    revoked_builder.set_version(3)
        .set_serial({0x01, 0x02, 0x03, 0x04, 0x05}) // This serial is revoked
        .set_subject(dn_result.value)
        .set_issuer(dn_result.value)
        .set_validity(not_before, not_after)
        .set_subject_public_key_ed25519(keys.public_key)
        .set_basic_constraints(false, std::nullopt, true);

    auto revoked_cert_result = revoked_builder.build_ed25519(keys, true);
    if (!revoked_cert_result.success) {
        std::cerr << "Failed to create revoked certificate\n";
        return 1;
    }

    authbox::pik::verify::wire::VerifyRequest revoked_verify_req;
    authbox::pik::verify::wire::CertificateData revoked_cert_data;
    revoked_cert_data.der_bytes = revoked_cert_result.value.to_der();
    revoked_verify_req.certificate_chain.push_back(std::move(revoked_cert_data));
    revoked_verify_req.validation_timestamp = std::chrono::system_clock::now();
    revoked_verify_req.flags = authbox::pik::verify::wire::RequestFlags::NONE;
    revoked_verify_req.nonce.resize(32);
    keylock::crypto::rng::randombytes_buf(revoked_verify_req.nonce.data(), revoked_verify_req.nonce.size());

    auto revoked_verify_req_data = authbox::pik::verify::wire::Serializer::serialize(revoked_verify_req);
    auto revoked_verify_resp_data =
        processor.process(authbox::pik::verify::methods::CHECK_CERTIFICATE, revoked_verify_req_data);

    authbox::pik::verify::wire::VerifyResponse revoked_verify_resp;
    if (authbox::pik::verify::wire::Serializer::deserialize(revoked_verify_resp_data, revoked_verify_resp)) {
        std::cout << "   Status: ";
        switch (revoked_verify_resp.status) {
        case authbox::pik::verify::wire::VerifyStatus::GOOD:
            std::cout << "GOOD\n";
            break;
        case authbox::pik::verify::wire::VerifyStatus::REVOKED:
            std::cout << "REVOKED\n";
            break;
        case authbox::pik::verify::wire::VerifyStatus::UNKNOWN:
            std::cout << "UNKNOWN\n";
            break;
        }
        std::cout << "   Reason: " << revoked_verify_resp.reason << "\n\n";
    }

    // Print statistics
    auto stats = processor.get_stats();
    std::cout << "=== Processor Statistics ===\n";
    std::cout << "Total requests: " << stats.total_requests << "\n";
    std::cout << "Health checks: " << stats.total_health_checks << "\n";
    std::cout << "GOOD responses: " << stats.good_responses << "\n";
    std::cout << "REVOKED responses: " << stats.revoked_responses << "\n";

    std::cout << "\nDemo completed successfully!\n";
    std::cout << "\nNote: To implement a custom transport layer, use RequestProcessor::process()\n";
    std::cout << "with your own transport mechanism (sockets, shared memory, etc.)\n";

    return 0;
}
