#pragma once

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

#include "../json.hpp"
#include "../pki/pem.hpp"

#include "did.hpp"
#include "errors.hpp"
#include "x509.hpp"

namespace authbox::did {

    namespace detail {

        // Base64URL decode (URL-safe base64 without padding)
        inline DidResult<std::vector<uint8_t>> base64url_decode(std::string_view input) {
            if (input.empty()) {
                return DidResult<std::vector<uint8_t>>::err(error::invalid_key_format("empty base64url string"));
            }

            // Convert base64url to standard base64
            std::string base64_str(input);
            for (char &ch : base64_str) {
                if (ch == '-') {
                    ch = '+';
                } else if (ch == '_') {
                    ch = '/';
                }
            }

            // Add padding if needed
            const size_t padding = (4 - (base64_str.size() % 4)) % 4;
            base64_str.append(padding, '=');

            // Use existing base64 decoder from pem.hpp
            std::vector<uint8_t> decoded;
            if (!authbox::pik::detail::decode_base64(base64_str, decoded)) {
                return DidResult<std::vector<uint8_t>>::err(error::invalid_key_format("invalid base64url encoding"));
            }

            return DidResult<std::vector<uint8_t>>::ok(std::move(decoded));
        }

        // Canonicalize JWK JSON: sorted keys, no whitespace, compact form
        inline DidResult<std::string> canonicalize_jwk_json(std::string_view jwk_json) {
            json_parse_result_t parse_result{};
            json_value_t *root = json_parse_ex(jwk_json.data(), jwk_json.size(), json_parse_flags_default, nullptr,
                                               nullptr, &parse_result);
            if (!root) {
                return DidResult<std::string>::err(error::invalid_key_format("invalid JWK JSON"));
            }

            const auto cleanup = [&]() { std::free(root); };

            const auto *root_obj = json_value_as_object(root);
            if (!root_obj) {
                cleanup();
                return DidResult<std::string>::err(error::invalid_key_format("JWK must be a JSON object"));
            }

            // Collect all fields
            std::vector<std::pair<std::string, std::string>> fields;
            for (json_object_element_t *elem = root_obj->start; elem != nullptr; elem = elem->next) {
                const auto key = json_string_view(elem->name);
                const auto *value_str = json_value_as_string(elem->value);
                if (value_str) {
                    fields.emplace_back(std::string(key), std::string(json_string_view(value_str)));
                }
            }

            cleanup();

            // Sort fields lexicographically
            std::sort(fields.begin(), fields.end(), [](const auto &a, const auto &b) { return a.first < b.first; });

            // Build canonical JSON (compact, sorted)
            std::string canonical = "{";
            for (size_t i = 0; i < fields.size(); ++i) {
                if (i > 0) {
                    canonical += ",";
                }
                canonical += "\"" + fields[i].first + "\":\"" + fields[i].second + "\"";
            }
            canonical += "}";

            return DidResult<std::string>::ok(std::move(canonical));
        }

    } // namespace detail

    // Parse and validate a did:jwk DID
    inline DidResult<std::string> parse_did_jwk(std::string_view did_uri) {
        auto parsed = parse(did_uri);
        if (parsed.is_err()) {
            return DidResult<std::string>::err(parsed.error());
        }

        if (parsed.value().method != "jwk") {
            return DidResult<std::string>::err(error::invalid_method_id("method must be 'jwk'"));
        }

        const std::string_view method_id(parsed.value().method_id.data(), parsed.value().method_id.size());
        if (method_id.empty()) {
            return DidResult<std::string>::err(error::invalid_method_id("did:jwk method-id is empty"));
        }

        // Decode the base64url-encoded JWK
        auto decoded = detail::base64url_decode(method_id);
        if (decoded.is_err()) {
            return DidResult<std::string>::err(decoded.error());
        }

        // Convert to string and validate as JSON
        std::string jwk_json(decoded.value().begin(), decoded.value().end());

        // Parse and validate JWK structure
        json_parse_result_t parse_result{};
        json_value_t *root =
            json_parse_ex(jwk_json.data(), jwk_json.size(), json_parse_flags_default, nullptr, nullptr, &parse_result);
        if (!root) {
            return DidResult<std::string>::err(error::invalid_key_format("embedded JWK is not valid JSON"));
        }

        const auto cleanup = [&]() { std::free(root); };

        const auto *root_obj = json_value_as_object(root);
        if (!root_obj) {
            cleanup();
            return DidResult<std::string>::err(error::invalid_key_format("embedded JWK must be a JSON object"));
        }

        // Validate required JWK fields
        auto *kty = json_value_as_string(detail::find_object_field(root_obj, "kty"));
        if (!kty) {
            cleanup();
            return DidResult<std::string>::err(error::invalid_key_format("JWK missing required field: kty"));
        }

        cleanup();

        return DidResult<std::string>::ok(std::move(jwk_json));
    }

    // Create a did:jwk DID from a JWK JSON object
    inline DidResult<std::string> encode_did_jwk(std::string_view jwk_json) {
        // First validate that it's valid JSON and has required fields
        json_parse_result_t parse_result{};
        json_value_t *root =
            json_parse_ex(jwk_json.data(), jwk_json.size(), json_parse_flags_default, nullptr, nullptr, &parse_result);
        if (!root) {
            return DidResult<std::string>::err(error::invalid_key_format("invalid JWK JSON"));
        }

        const auto cleanup = [&]() { std::free(root); };
        const auto *root_obj = json_value_as_object(root);
        if (!root_obj) {
            cleanup();
            return DidResult<std::string>::err(error::invalid_key_format("JWK must be a JSON object"));
        }

        // Validate required 'kty' field
        auto *kty = json_value_as_string(detail::find_object_field(root_obj, "kty"));
        if (!kty) {
            cleanup();
            return DidResult<std::string>::err(error::invalid_key_format("JWK missing required field: kty"));
        }
        cleanup();

        // Canonicalize the JWK
        auto canonical = detail::canonicalize_jwk_json(jwk_json);
        if (canonical.is_err()) {
            return DidResult<std::string>::err(canonical.error());
        }

        // Base64url encode (use function from x509.hpp detail namespace)
        std::vector<uint8_t> jwk_bytes(canonical.value().begin(), canonical.value().end());
        std::string encoded = detail::base64url_encode(jwk_bytes); // This is from x509.hpp

        return DidResult<std::string>::ok("did:jwk:" + encoded);
    }

    // Resolve a did:jwk to a DID document JSON
    inline DidResult<std::string> resolve_did_jwk_document_json(std::string_view did_uri) {
        // Parse and extract JWK
        auto jwk_json_result = parse_did_jwk(did_uri);
        if (jwk_json_result.is_err()) {
            return DidResult<std::string>::err(jwk_json_result.error());
        }

        const std::string jwk_json = jwk_json_result.value();

        // Parse JWK to extract fields
        json_parse_result_t parse_result{};
        json_value_t *root =
            json_parse_ex(jwk_json.data(), jwk_json.size(), json_parse_flags_default, nullptr, nullptr, &parse_result);
        if (!root) {
            return DidResult<std::string>::err(error::invalid_key_format("invalid JWK JSON"));
        }

        const auto cleanup = [&]() { std::free(root); };

        const auto *root_obj = json_value_as_object(root);
        if (!root_obj) {
            cleanup();
            return DidResult<std::string>::err(error::invalid_key_format("JWK must be an object"));
        }

        // Extract required fields
        const auto *kty = json_value_as_string(detail::find_object_field(root_obj, "kty"));
        const auto *crv = json_value_as_string(detail::find_object_field(root_obj, "crv"));
        const auto *x_val = json_value_as_string(detail::find_object_field(root_obj, "x"));

        if (!kty) {
            cleanup();
            return DidResult<std::string>::err(error::invalid_key_format("JWK missing 'kty'"));
        }

        const std::string kty_str(detail::json_string_view(kty));
        const std::string did_str(did_uri);
        const std::string vm_id = did_str + "#0";

        // Determine verification relationship based on key type
        std::string relationship_key;
        if (kty_str == "OKP" || kty_str == "EC") {
            if (crv) {
                const std::string crv_str(detail::json_string_view(crv));
                if (crv_str == "X25519" || crv_str == "X448") {
                    relationship_key = "keyAgreement";
                } else {
                    relationship_key = "authentication";
                }
            } else {
                relationship_key = "authentication";
            }
        } else if (kty_str == "RSA") {
            relationship_key = "authentication";
        } else {
            cleanup();
            return DidResult<std::string>::err(error::unsupported_key_type(kty_str));
        }

        cleanup();

        // Build DID document
        std::string doc;
        doc.reserve(768);
        doc += "{\n";
        doc += "  \"@context\": [\n";
        doc += "    \"https://www.w3.org/ns/did/v1\",\n";
        doc += "    \"https://w3id.org/security/suites/jws-2020/v1\"\n";
        doc += "  ],\n";
        doc += "  \"id\": \"" + did_str + "\",\n";
        doc += "  \"verificationMethod\": [\n";
        doc += "    {\n";
        doc += "      \"id\": \"" + vm_id + "\",\n";
        doc += "      \"type\": \"JsonWebKey2020\",\n";
        doc += "      \"controller\": \"" + did_str + "\",\n";
        doc += "      \"publicKeyJwk\": " + jwk_json + "\n";
        doc += "    }\n";
        doc += "  ],\n";
        doc += "  \"" + relationship_key + "\": [\n";
        doc += "    \"" + vm_id + "\"\n";
        doc += "  ]\n";
        doc += "}\n";

        return DidResult<std::string>::ok(std::move(doc));
    }

} // namespace authbox::did
