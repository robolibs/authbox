#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "did.hpp"
#include "errors.hpp"
#include "key.hpp"

namespace authbox::did {

    // did:peer element types (numalgo 2)
    enum class PeerElementType {
        Verification, // V - verification method (authentication)
        Encryption,   // E - encryption key (key agreement)
        Service,      // S - service endpoint
        Unknown
    };

    struct PeerElement {
        PeerElementType type;
        std::string encoded_value; // Multibase-encoded value
    };

    // Parse a did:peer:2 DID and extract elements
    inline DidResult<std::vector<PeerElement>> parse_did_peer(std::string_view did_uri) {
        auto parsed = parse(did_uri);
        if (parsed.is_err()) {
            return DidResult<std::vector<PeerElement>>::err(parsed.error());
        }

        if (parsed.value().method != "peer") {
            return DidResult<std::vector<PeerElement>>::err(error::invalid_method_id("method must be 'peer'"));
        }

        const std::string_view method_id(parsed.value().method_id.data(), parsed.value().method_id.size());
        if (method_id.empty()) {
            return DidResult<std::vector<PeerElement>>::err(error::invalid_method_id("did:peer method-id is empty"));
        }

        // Check for numalgo 2 (only supported variant for now)
        if (!method_id.starts_with("2.")) {
            return DidResult<std::vector<PeerElement>>::err(error::not_implemented("only did:peer:2 is supported"));
        }

        // Extract elements (format: 2.Element1.Element2.Element3...)
        std::vector<PeerElement> elements;
        size_t pos = 2; // Skip "2."

        while (pos < method_id.size()) {
            if (method_id[pos] == '.') {
                pos++;
                continue;
            }

            // Find the next dot or end
            size_t next_dot = method_id.find('.', pos);
            if (next_dot == std::string_view::npos) {
                next_dot = method_id.size();
            }

            std::string_view element_str = method_id.substr(pos, next_dot - pos);
            if (element_str.empty()) {
                pos = next_dot;
                continue;
            }

            // Parse element type (first character) and value (rest)
            char type_char = element_str[0];
            std::string encoded_value(element_str.substr(1));

            PeerElement element;
            element.encoded_value = encoded_value;

            switch (type_char) {
            case 'V':
                element.type = PeerElementType::Verification;
                break;
            case 'E':
                element.type = PeerElementType::Encryption;
                break;
            case 'S':
                element.type = PeerElementType::Service;
                break;
            default:
                element.type = PeerElementType::Unknown;
                break;
            }

            elements.push_back(std::move(element));
            pos = next_dot;
        }

        if (elements.empty()) {
            return DidResult<std::vector<PeerElement>>::err(
                error::invalid_method_id("did:peer:2 must have at least one element"));
        }

        return DidResult<std::vector<PeerElement>>::ok(std::move(elements));
    }

    // Decode a multibase-encoded key from a peer element
    // For did:peer:2, keys are typically base58btc encoded (z prefix)
    inline DidResult<std::vector<uint8_t>> decode_peer_key(std::string_view encoded) {
        if (encoded.empty()) {
            return DidResult<std::vector<uint8_t>>::err(error::invalid_key_format("empty encoded key"));
        }

        // Check for multibase prefix
        if (encoded[0] != 'z') {
            return DidResult<std::vector<uint8_t>>::err(
                error::invalid_key_format("only base58btc (z) encoding is supported"));
        }

        // Decode base58btc (reuse did:key decoder)
        return detail::base58btc_decode(encoded.substr(1));
    }

    // Resolve a did:peer:2 DID to a DID document JSON
    inline DidResult<std::string> resolve_did_peer_document_json(std::string_view did_uri) {
        // Parse the DID
        auto elements_result = parse_did_peer(did_uri);
        if (elements_result.is_err()) {
            return DidResult<std::string>::err(elements_result.error());
        }

        const auto &elements = elements_result.value();
        const std::string did_str(did_uri);

        // Build DID document
        std::string doc;
        doc.reserve(1024);
        doc += "{\n";
        doc += "  \"@context\": [\n";
        doc += "    \"https://www.w3.org/ns/did/v1\",\n";
        doc += "    \"https://w3id.org/security/suites/jws-2020/v1\"\n";
        doc += "  ],\n";
        doc += "  \"id\": \"" + did_str + "\",\n";
        doc += "  \"verificationMethod\": [\n";

        // Process verification and encryption elements
        bool first_vm = true;
        int vm_index = 0;

        for (const auto &elem : elements) {
            if (elem.type != PeerElementType::Verification && elem.type != PeerElementType::Encryption) {
                continue;
            }

            // Decode the key
            auto key_bytes = decode_peer_key(elem.encoded_value);
            if (key_bytes.is_err()) {
                continue; // Skip invalid keys
            }

            // Determine key type from the decoded bytes (multicodec prefix)
            if (key_bytes.value().size() < 34) {
                continue; // Too short
            }

            const auto &payload = key_bytes.value();
            std::string kty;
            std::string crv;
            std::string vm_type;

            // Check multicodec prefix
            if (payload[0] == 0xED && payload[1] == 0x01) {
                // Ed25519
                kty = "OKP";
                crv = "Ed25519";
                vm_type = "JsonWebKey2020";
            } else if (payload[0] == 0xEC && payload[1] == 0x01) {
                // X25519
                kty = "OKP";
                crv = "X25519";
                vm_type = "JsonWebKey2020";
            } else {
                continue; // Unsupported key type
            }

            // Extract the raw key (skip 2-byte multicodec prefix)
            std::vector<uint8_t> raw_key(payload.begin() + 2, payload.end());
            if (raw_key.size() != 32) {
                continue; // Invalid key length
            }

            std::string x = detail::base64url_encode_key(raw_key);

            if (!first_vm) {
                doc += ",\n";
            }
            first_vm = false;

            std::string vm_id = did_str + "#key-" + std::to_string(vm_index++);

            doc += "    {\n";
            doc += "      \"id\": \"" + vm_id + "\",\n";
            doc += "      \"type\": \"" + vm_type + "\",\n";
            doc += "      \"controller\": \"" + did_str + "\",\n";
            doc += "      \"publicKeyJwk\": {\n";
            doc += "        \"kty\": \"" + kty + "\",\n";
            doc += "        \"crv\": \"" + crv + "\",\n";
            doc += "        \"x\": \"" + x + "\"\n";
            doc += "      }\n";
            doc += "    }";
        }

        doc += "\n  ]";

        // Add verification relationships
        vm_index = 0;
        std::vector<std::string> auth_refs;
        std::vector<std::string> ka_refs;

        for (const auto &elem : elements) {
            if (elem.type == PeerElementType::Verification) {
                auth_refs.push_back(did_str + "#key-" + std::to_string(vm_index++));
            } else if (elem.type == PeerElementType::Encryption) {
                ka_refs.push_back(did_str + "#key-" + std::to_string(vm_index++));
            }
        }

        if (!auth_refs.empty()) {
            doc += ",\n  \"authentication\": [\n";
            for (size_t i = 0; i < auth_refs.size(); ++i) {
                if (i > 0)
                    doc += ",\n";
                doc += "    \"" + auth_refs[i] + "\"";
            }
            doc += "\n  ]";
        }

        if (!ka_refs.empty()) {
            doc += ",\n  \"keyAgreement\": [\n";
            for (size_t i = 0; i < ka_refs.size(); ++i) {
                if (i > 0)
                    doc += ",\n";
                doc += "    \"" + ka_refs[i] + "\"";
            }
            doc += "\n  ]";
        }

        // TODO: Process service elements (S type) - not implemented yet

        doc += "\n}\n";

        return DidResult<std::string>::ok(std::move(doc));
    }

} // namespace authbox::did
