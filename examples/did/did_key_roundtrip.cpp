#include <array>
#include <iostream>

#include <authbox.hpp>
#include <keylock/crypto/context.hpp>

int main() {
    keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
    auto keypair = ctx.generate_keypair();
    if (keypair.public_key.size() != 32U) {
        std::cerr << "Unexpected Ed25519 public key size\n";
        return 1;
    }

    std::array<uint8_t, 32> public_key{};
    std::copy_n(keypair.public_key.begin(), 32, public_key.begin());

    auto did_result = authbox::did::encode_ed25519_did_key(public_key);
    if (did_result.is_err()) {
        std::cerr << "Failed to encode did:key: " << did_result.error().c_str() << "\n";
        return 1;
    }

    auto parsed = authbox::did::parse_did_key(did_result.value());
    if (parsed.is_err()) {
        std::cerr << "Failed to parse did:key: " << parsed.error().c_str() << "\n";
        return 1;
    }

    auto doc_json = authbox::did::resolve_did_key_document_json(did_result.value());
    if (doc_json.is_err()) {
        std::cerr << "Failed to resolve did:key document: " << doc_json.error().c_str() << "\n";
        return 1;
    }

    std::cout << "did:key: " << did_result.value() << "\n";
    std::cout << "fingerprint: " << parsed.value().fingerprint.c_str() << "\n";
    std::cout << "did:key document:\n" << doc_json.value() << "\n";
    return 0;
}
