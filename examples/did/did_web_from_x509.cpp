#include <chrono>
#include <iostream>
#include <optional>

#include <authbox.hpp>
#include <keylock/crypto/context.hpp>
#include <pki/builder.hpp>

int main() {
    const std::string did_uri = "did:web:example.com";

    keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
    auto keypair = ctx.generate_keypair();
    authbox::pik::CertificateBuilder builder;
    const auto now = std::chrono::system_clock::now();

    authbox::pik::SubjectAltNameExtension::GeneralName did_name{};
    did_name.type = authbox::pik::SubjectAltNameExtension::GeneralNameType::URI;
    did_name.value = did_uri;

    auto cert = builder.set_subject_from_string("CN=example.com,O=Example")
                    .set_issuer_from_string("CN=example.com,O=Example")
                    .set_validity(now - std::chrono::hours(1), now + std::chrono::hours(24))
                    .set_subject_public_key_ed25519(keypair.public_key)
                    .set_basic_constraints(false, std::nullopt)
                    .set_subject_alt_name({did_name})
                    .build_ed25519(keypair, true);

    if (!cert.success) {
        std::cerr << "Failed to create cert: " << cert.error << "\n";
        return 1;
    }

    auto doc = authbox::did::generate_did_web_document("example.com", cert.value);
    if (doc.is_err()) {
        std::cerr << "Failed to generate did:web document: " << doc.error().c_str() << "\n";
        return 1;
    }

    auto verify = authbox::did::verify_certificate_binding(
        std::string_view(doc.value().did_document_json.data(), doc.value().did_document_json.size()), cert.value,
        did_uri);
    if (verify.is_err() || !verify.value()) {
        std::cerr << "Binding verification failed: " << (verify.is_err() ? verify.error().c_str() : "invalid") << "\n";
        return 1;
    }

    auto url = authbox::did::did_web_document_url(did_uri);
    std::cout << "did:web URL: " << (url.is_ok() ? url.value() : "<invalid>") << "\n";
    std::cout << "Generated did.json:\n" << doc.value().did_document_json.c_str() << "\n";
    std::cout << "Binding verification: OK\n";
    return 0;
}
