#pragma once

#include <keylock/crypto/context.hpp>
#include <pki/asn1_writer.hpp>
#include <pki/certificate.hpp>
#include <pki/oid_registry.hpp>

namespace authbox::pik {

    inline keylock::crypto::Context::KeyPair generate_ed25519_keypair() {
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        return ctx.generate_keypair();
    }

    inline std::vector<uint8_t> spki_from_ed25519_public(const std::vector<uint8_t> &public_key) {
        auto oid = oid_for_signature(SignatureAlgorithmId::Ed25519);
        if (!oid) {
            throw std::runtime_error("Failed to get OID for Ed25519 signature algorithm");
        }
        std::vector<std::vector<uint8_t>> fields;
        fields.push_back(der::encode_sequence(der::encode_oid(*oid)));
        fields.push_back(der::encode_bit_string(ByteSpan(public_key.data(), public_key.size())));
        return der::encode_sequence(der::concat(fields));
    }

} // namespace authbox::pik
