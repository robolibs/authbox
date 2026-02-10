#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "../pki/pem.hpp"

#include "did.hpp"

namespace authbox::did {

    enum class DidKeyType {
        ED25519,
        X25519,
    };

    struct DidKeyInfo {
        DidKeyType type;
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> prefixed_key;
        dp::String fingerprint;
        dp::String did_uri;
    };

    namespace detail {

        constexpr uint8_t MULTICODEC_ED25519_PUB[2] = {0xED, 0x01};
        constexpr uint8_t MULTICODEC_X25519_PUB[2] = {0xEC, 0x01};

        inline int base58_value(char ch) {
            if (ch >= '1' && ch <= '9') {
                return ch - '1';
            }
            if (ch >= 'A' && ch <= 'H') {
                return 9 + (ch - 'A');
            }
            if (ch >= 'J' && ch <= 'N') {
                return 17 + (ch - 'J');
            }
            if (ch >= 'P' && ch <= 'Z') {
                return 22 + (ch - 'P');
            }
            if (ch >= 'a' && ch <= 'k') {
                return 33 + (ch - 'a');
            }
            if (ch >= 'm' && ch <= 'z') {
                return 44 + (ch - 'm');
            }
            return -1;
        }

        inline DidResult<std::vector<uint8_t>> base58btc_decode(std::string_view input) {
            if (input.empty()) {
                return DidResult<std::vector<uint8_t>>::err(error::invalid_key_format("empty base58 string"));
            }

            size_t leading_ones = 0;
            while (leading_ones < input.size() && input[leading_ones] == '1') {
                ++leading_ones;
            }

            std::vector<uint8_t> bytes_le;
            bytes_le.reserve(input.size());

            for (char ch : input) {
                const int val = base58_value(ch);
                if (val < 0) {
                    return DidResult<std::vector<uint8_t>>::err(error::invalid_key_format("invalid base58 character"));
                }

                int carry = val;
                for (size_t i = 0; i < bytes_le.size(); ++i) {
                    const int x = static_cast<int>(bytes_le[i]) * 58 + carry;
                    bytes_le[i] = static_cast<uint8_t>(x & 0xFF);
                    carry = x >> 8;
                }

                while (carry > 0) {
                    bytes_le.push_back(static_cast<uint8_t>(carry & 0xFF));
                    carry >>= 8;
                }
            }

            std::vector<uint8_t> out;
            out.reserve(leading_ones + bytes_le.size());
            out.insert(out.end(), leading_ones, 0);
            for (auto it = bytes_le.rbegin(); it != bytes_le.rend(); ++it) {
                out.push_back(*it);
            }

            return DidResult<std::vector<uint8_t>>::ok(std::move(out));
        }

        inline std::string base58btc_encode(const std::vector<uint8_t> &bytes) {
            static constexpr char ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

            size_t leading_zeros = 0;
            while (leading_zeros < bytes.size() && bytes[leading_zeros] == 0) {
                ++leading_zeros;
            }

            std::vector<uint8_t> digits_le;
            digits_le.reserve(bytes.size() * 2);

            for (size_t idx = leading_zeros; idx < bytes.size(); ++idx) {
                int carry = bytes[idx];
                for (size_t i = 0; i < digits_le.size(); ++i) {
                    const int x = (static_cast<int>(digits_le[i]) << 8) + carry;
                    digits_le[i] = static_cast<uint8_t>(x % 58);
                    carry = x / 58;
                }
                while (carry > 0) {
                    digits_le.push_back(static_cast<uint8_t>(carry % 58));
                    carry /= 58;
                }
            }

            std::string out;
            out.reserve(leading_zeros + digits_le.size());
            out.append(leading_zeros, '1');
            for (auto it = digits_le.rbegin(); it != digits_le.rend(); ++it) {
                out.push_back(ALPHABET[*it]);
            }

            if (out.empty()) {
                out = "1";
            }
            return out;
        }

        inline std::string base64url_encode_key(const std::vector<uint8_t> &bytes) {
            const auto base64 = authbox::pik::detail::encode_base64(authbox::pik::ByteSpan(bytes.data(), bytes.size()));
            std::string out;
            out.reserve(base64.size());
            for (char ch : base64) {
                if (ch == '=') {
                    continue;
                }
                if (ch == '+') {
                    out.push_back('-');
                } else if (ch == '/') {
                    out.push_back('_');
                } else {
                    out.push_back(ch);
                }
            }
            return out;
        }

    } // namespace detail

    inline DidResult<DidKeyInfo> parse_did_key(std::string_view did_uri) {
        auto parsed = parse(did_uri);
        if (parsed.is_err()) {
            return DidResult<DidKeyInfo>::err(parsed.error());
        }
        if (parsed.value().method != "key") {
            return DidResult<DidKeyInfo>::err(error::invalid_method_id("method must be 'key'"));
        }

        const std::string_view method_id(parsed.value().method_id.data(), parsed.value().method_id.size());
        if (method_id.size() < 2 || method_id[0] != 'z') {
            return DidResult<DidKeyInfo>::err(
                error::invalid_key_format("did:key fingerprint must use multibase base58btc (z...)"));
        }

        auto decoded = detail::base58btc_decode(method_id.substr(1));
        if (decoded.is_err()) {
            return DidResult<DidKeyInfo>::err(decoded.error());
        }
        if (decoded.value().size() < 34) {
            return DidResult<DidKeyInfo>::err(error::invalid_key_format("multicodec payload too short"));
        }

        DidKeyInfo out{};
        out.prefixed_key = decoded.value();
        out.fingerprint = to_dp_string(method_id);
        out.did_uri = to_dp_string(did_uri);

        const auto &payload = out.prefixed_key;
        if (payload[0] == detail::MULTICODEC_ED25519_PUB[0] && payload[1] == detail::MULTICODEC_ED25519_PUB[1]) {
            out.type = DidKeyType::ED25519;
        } else if (payload[0] == detail::MULTICODEC_X25519_PUB[0] && payload[1] == detail::MULTICODEC_X25519_PUB[1]) {
            out.type = DidKeyType::X25519;
        } else {
            return DidResult<DidKeyInfo>::err(error::unsupported_key_type("unsupported multicodec prefix"));
        }

        out.public_key.assign(payload.begin() + 2, payload.end());
        if (out.public_key.size() != 32U) {
            return DidResult<DidKeyInfo>::err(error::invalid_key_length(32, out.public_key.size()));
        }

        return DidResult<DidKeyInfo>::ok(std::move(out));
    }

    inline DidResult<std::string> encode_ed25519_did_key(const std::array<uint8_t, 32> &public_key) {
        std::vector<uint8_t> payload;
        payload.reserve(34);
        payload.push_back(detail::MULTICODEC_ED25519_PUB[0]);
        payload.push_back(detail::MULTICODEC_ED25519_PUB[1]);
        payload.insert(payload.end(), public_key.begin(), public_key.end());

        std::string fingerprint = "z" + detail::base58btc_encode(payload);
        return DidResult<std::string>::ok("did:key:" + fingerprint);
    }

    inline DidResult<std::string> resolve_did_key_document_json(std::string_view did_uri) {
        auto info = parse_did_key(did_uri);
        if (info.is_err()) {
            return DidResult<std::string>::err(info.error());
        }

        const std::string did(did_uri);
        const std::string vm_id =
            did + "#" + std::string(info.value().fingerprint.data(), info.value().fingerprint.size());
        const std::string x = detail::base64url_encode_key(info.value().public_key);

        std::string kty;
        std::string crv;
        std::string vm_type;
        std::string relationship_key;
        if (info.value().type == DidKeyType::ED25519) {
            kty = "OKP";
            crv = "Ed25519";
            vm_type = "JsonWebKey2020";
            relationship_key = "authentication";
        } else {
            kty = "OKP";
            crv = "X25519";
            vm_type = "JsonWebKey2020";
            relationship_key = "keyAgreement";
        }

        std::string json;
        json.reserve(768);
        json += "{\n";
        json += "  \"@context\": [\n";
        json += "    \"https://www.w3.org/ns/did/v1\",\n";
        json += "    \"https://w3id.org/security/suites/jws-2020/v1\"\n";
        json += "  ],\n";
        json += "  \"id\": \"" + did + "\",\n";
        json += "  \"verificationMethod\": [\n";
        json += "    {\n";
        json += "      \"id\": \"" + vm_id + "\",\n";
        json += "      \"type\": \"" + vm_type + "\",\n";
        json += "      \"controller\": \"" + did + "\",\n";
        json += "      \"publicKeyJwk\": {\n";
        json += "        \"kty\": \"" + kty + "\",\n";
        json += "        \"crv\": \"" + crv + "\",\n";
        json += "        \"x\": \"" + x + "\"\n";
        json += "      }\n";
        json += "    }\n";
        json += "  ],\n";
        json += "  \"" + relationship_key + "\": [\n";
        json += "    \"" + vm_id + "\"\n";
        json += "  ]\n";
        json += "}\n";

        return DidResult<std::string>::ok(std::move(json));
    }

} // namespace authbox::did
