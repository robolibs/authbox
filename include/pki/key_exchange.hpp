#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include "keylock/crypto/box_seal_x25519/seal.hpp"
#include "keylock/crypto/context.hpp"
#include "keylock/hash/blake2b/blake2b.hpp"

namespace keylock::io::key_exchange {

    using CryptoResult = keylock::crypto::Context::CryptoResult;

    namespace detail {

        constexpr uint32_t MAGIC = 0x4c4b5847; // "LKXG"
        constexpr uint8_t VERSION = 1;
        constexpr size_t DIGEST_SIZE = 32; // BLAKE2b output size

        inline void append_u32(std::vector<uint8_t> &out, uint32_t value) {
            out.push_back(static_cast<uint8_t>(value & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        }

        inline uint32_t read_u32(const uint8_t *data) {
            return static_cast<uint32_t>(data[0]) | (static_cast<uint32_t>(data[1]) << 8) |
                   (static_cast<uint32_t>(data[2]) << 16) | (static_cast<uint32_t>(data[3]) << 24);
        }

        struct Envelope {
            std::vector<uint8_t> associated_data;
            std::vector<uint8_t> ciphertext;

            std::vector<uint8_t> serialize() const {
                std::vector<uint8_t> body;
                body.reserve(associated_data.size() + ciphertext.size());
                body.insert(body.end(), associated_data.begin(), associated_data.end());
                body.insert(body.end(), ciphertext.begin(), ciphertext.end());

                std::vector<uint8_t> digest(DIGEST_SIZE);
                keylock::hash::blake2b::hash(digest.data(), digest.size(), body.data(), body.size());

                std::vector<uint8_t> serialized;
                serialized.reserve(4 + 1 + 1 + 2 + 4 + 4 + DIGEST_SIZE + body.size());

                append_u32(serialized, MAGIC);
                serialized.push_back(VERSION);
                serialized.push_back(0); // flags
                serialized.push_back(0); // reserved
                serialized.push_back(0); // reserved
                append_u32(serialized, static_cast<uint32_t>(associated_data.size()));
                append_u32(serialized, static_cast<uint32_t>(ciphertext.size()));
                serialized.insert(serialized.end(), digest.begin(), digest.end());
                serialized.insert(serialized.end(), body.begin(), body.end());
                return serialized;
            }

            static std::optional<Envelope> deserialize(const std::vector<uint8_t> &buffer) {
                if (buffer.size() < 4 + 1 + 1 + 2 + 4 + 4 + DIGEST_SIZE) {
                    return std::nullopt;
                }

                const uint8_t *ptr = buffer.data();
                uint32_t magic = read_u32(ptr);
                ptr += 4;

                if (magic != MAGIC) {
                    return std::nullopt;
                }
                uint8_t version = *ptr++;
                if (version != VERSION) {
                    return std::nullopt;
                }
                ptr += 3; // flags + reserved

                uint32_t aad_len = read_u32(ptr);
                ptr += 4;
                uint32_t cipher_len = read_u32(ptr);
                ptr += 4;

                if (buffer.size() != 4 + 1 + 1 + 2 + 4 + 4 + DIGEST_SIZE + aad_len + cipher_len) {
                    return std::nullopt;
                }

                const uint8_t *stored_digest = ptr;
                ptr += DIGEST_SIZE;

                std::vector<uint8_t> body(ptr, buffer.data() + buffer.size());
                std::vector<uint8_t> computed(DIGEST_SIZE);
                keylock::hash::blake2b::hash(computed.data(), computed.size(), body.data(), body.size());

                if (!std::equal(computed.begin(), computed.end(), stored_digest)) {
                    return std::nullopt;
                }

                Envelope env;
                env.associated_data.assign(body.begin(), body.begin() + aad_len);
                env.ciphertext.assign(body.begin() + aad_len, body.end());
                return env;
            }
        };

    } // namespace detail

    inline CryptoResult create_envelope(const std::vector<uint8_t> &payload,
                                        const std::vector<uint8_t> &recipient_public_key,
                                        const std::vector<uint8_t> &associated_data = {}) {
        if (recipient_public_key.size() != keylock::crypto::box_seal::PUBLICKEYBYTES) {
            return {false, {}, "Recipient public key must be PUBLICKEYBYTES bytes"};
        }

        std::vector<uint8_t> ciphertext(payload.size() + keylock::crypto::box_seal::SEALBYTES);
        if (keylock::crypto::box_seal::seal(ciphertext.data(), payload.data(), payload.size(),
                                            recipient_public_key.data()) != 0) {
            return {false, {}, "seal failed"};
        }

        detail::Envelope env;
        env.associated_data = associated_data;
        env.ciphertext = std::move(ciphertext);
        return {true, env.serialize(), ""};
    }

    inline CryptoResult consume_envelope(const uint8_t *buffer, size_t size,
                                         const std::vector<uint8_t> &recipient_private_key,
                                         std::vector<uint8_t> *associated_data_out = nullptr) {
        if (!buffer || size == 0) {
            return {false, {}, "Invalid envelope buffer"};
        }

        std::vector<uint8_t> bytes(buffer, buffer + size);
        auto env = detail::Envelope::deserialize(bytes);
        if (!env) {
            return {false, {}, "Invalid key exchange envelope"};
        }

        if (recipient_private_key.size() !=
            keylock::crypto::box_seal::PUBLICKEYBYTES + keylock::crypto::box_seal::SECRETKEYBYTES) {
            return {false, {}, "Recipient private key must contain public and secret material"};
        }

        if (env->ciphertext.size() < keylock::crypto::box_seal::SEALBYTES) {
            return {false, {}, "Ciphertext too short"};
        }

        std::vector<uint8_t> plaintext(env->ciphertext.size() - keylock::crypto::box_seal::SEALBYTES);
        const uint8_t *pub = recipient_private_key.data();
        const uint8_t *sec = recipient_private_key.data() + keylock::crypto::box_seal::PUBLICKEYBYTES;
        if (keylock::crypto::box_seal::seal_open(plaintext.data(), env->ciphertext.data(), env->ciphertext.size(), pub,
                                                 sec) != 0) {
            return {false, {}, "Failed to decrypt key exchange envelope"};
        }

        if (associated_data_out) {
            *associated_data_out = env->associated_data;
        }

        return {true, std::move(plaintext), ""};
    }

    inline CryptoResult consume_envelope(const std::vector<uint8_t> &buffer,
                                         const std::vector<uint8_t> &recipient_private_key,
                                         std::vector<uint8_t> *associated_data_out = nullptr) {
        return consume_envelope(buffer.data(), buffer.size(), recipient_private_key, associated_data_out);
    }

    inline CryptoResult write_envelope_to_file(const std::vector<uint8_t> &payload,
                                               const std::vector<uint8_t> &recipient_public_key,
                                               const std::string &path,
                                               const std::vector<uint8_t> &associated_data = {}) {
        auto env = create_envelope(payload, recipient_public_key, associated_data);
        if (!env.success) {
            return env;
        }

        std::ofstream file(path, std::ios::binary);
        if (!file) {
            return {false, {}, "Unable to open envelope file for writing"};
        }
        file.write(reinterpret_cast<const char *>(env.data.data()), static_cast<std::streamsize>(env.data.size()));
        if (!file.good()) {
            return {false, {}, "Failed to write envelope file"};
        }
        return {true, {}, ""};
    }

    inline CryptoResult read_envelope_from_file(const std::string &path,
                                                const std::vector<uint8_t> &recipient_private_key,
                                                std::vector<uint8_t> *associated_data_out = nullptr) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return {false, {}, "Unable to open envelope file for reading"};
        }
        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        if (buffer.empty()) {
            return {false, {}, "Envelope file empty"};
        }
        return consume_envelope(buffer, recipient_private_key, associated_data_out);
    }

    inline CryptoResult write_envelope_to_memory(uint8_t *dest, size_t capacity, size_t &written,
                                                 const std::vector<uint8_t> &payload,
                                                 const std::vector<uint8_t> &recipient_public_key,
                                                 const std::vector<uint8_t> &associated_data = {}) {
        auto env = create_envelope(payload, recipient_public_key, associated_data);
        if (!env.success) {
            return env;
        }

        if (env.data.size() > capacity) {
            return {false, {}, "Shared memory region too small for envelope"};
        }

        std::memcpy(dest, env.data.data(), env.data.size());
        written = env.data.size();
        return {true, {}, ""};
    }

    inline CryptoResult read_envelope_from_memory(const uint8_t *src, size_t size,
                                                  const std::vector<uint8_t> &recipient_private_key,
                                                  std::vector<uint8_t> *associated_data_out = nullptr) {
        return consume_envelope(src, size, recipient_private_key, associated_data_out);
    }

} // namespace keylock::io::key_exchange
