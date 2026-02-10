#pragma once

#include <regex>
#include <string>
#include <string_view>

#include "did.hpp"
#include "errors.hpp"

namespace authbox::did {

    // Parsed components of a did:pkh identifier
    // Format: did:pkh:<namespace>:<chain_id>:<address>
    // Based on CAIP-10 Account ID Specification
    struct PkhComponents {
        std::string namespace_id; // e.g., "eip155", "bip122", "cosmos"
        std::string chain_id;     // Chain-specific identifier
        std::string address;      // Account address
    };

    // Parse a did:pkh DID and extract CAIP-10 components
    inline DidResult<PkhComponents> parse_did_pkh(std::string_view did_uri) {
        auto parsed = parse(did_uri);
        if (parsed.is_err()) {
            return DidResult<PkhComponents>::err(parsed.error());
        }

        if (parsed.value().method != "pkh") {
            return DidResult<PkhComponents>::err(error::invalid_method_id("method must be 'pkh'"));
        }

        const std::string_view method_id(parsed.value().method_id.data(), parsed.value().method_id.size());
        if (method_id.empty()) {
            return DidResult<PkhComponents>::err(error::invalid_method_id("did:pkh method-id is empty"));
        }

        // Parse CAIP-10 format: <namespace>:<chain_id>:<address>
        // namespace: lowercase alphanumeric, 3-8 chars
        // chain_id: alphanumeric with dots/dashes, 1-32 chars
        // address: alphanumeric with additional chars, 1-64 chars

        size_t first_colon = method_id.find(':');
        if (first_colon == std::string_view::npos) {
            return DidResult<PkhComponents>::err(
                error::invalid_method_id("did:pkh method-id must contain at least two colons"));
        }

        size_t second_colon = method_id.find(':', first_colon + 1);
        if (second_colon == std::string_view::npos) {
            return DidResult<PkhComponents>::err(
                error::invalid_method_id("did:pkh method-id must contain at least two colons"));
        }

        std::string namespace_id(method_id.substr(0, first_colon));
        std::string chain_id(method_id.substr(first_colon + 1, second_colon - first_colon - 1));
        std::string address(method_id.substr(second_colon + 1));

        // Validate namespace (3-8 lowercase alphanumeric)
        if (namespace_id.size() < 3 || namespace_id.size() > 8) {
            return DidResult<PkhComponents>::err(error::invalid_method_id("namespace must be 3-8 characters"));
        }
        for (char c : namespace_id) {
            if (!std::islower(c) && !std::isdigit(c)) {
                return DidResult<PkhComponents>::err(
                    error::invalid_method_id("namespace must be lowercase alphanumeric"));
            }
        }

        // Validate chain_id (1-32 chars, alphanumeric with . and -)
        if (chain_id.empty() || chain_id.size() > 32) {
            return DidResult<PkhComponents>::err(error::invalid_method_id("chain_id must be 1-32 characters"));
        }
        for (char c : chain_id) {
            if (!std::isalnum(c) && c != '.' && c != '-') {
                return DidResult<PkhComponents>::err(
                    error::invalid_method_id("chain_id must be alphanumeric with . or -"));
            }
        }

        // Validate address (1-64 chars, alphanumeric with some special chars)
        if (address.empty() || address.size() > 64) {
            return DidResult<PkhComponents>::err(error::invalid_method_id("address must be 1-64 characters"));
        }
        // Allow alphanumeric plus common address characters
        for (char c : address) {
            if (!std::isalnum(c) && c != '_' && c != '-' && c != '.') {
                // For hex addresses (0x prefix), allow lowercase hex chars
                if (!(std::isxdigit(c) || c == 'x')) {
                    return DidResult<PkhComponents>::err(
                        error::invalid_method_id("address contains invalid characters"));
                }
            }
        }

        PkhComponents components;
        components.namespace_id = namespace_id;
        components.chain_id = chain_id;
        components.address = address;

        return DidResult<PkhComponents>::ok(std::move(components));
    }

    // Get the blockchain account ID in CAIP-10 format
    // Example: eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb
    inline std::string get_blockchain_account_id(const PkhComponents &components) {
        return components.namespace_id + ":" + components.chain_id + ":" + components.address;
    }

    // Get a human-readable chain name (for known chains)
    inline std::string get_chain_name(const PkhComponents &components) {
        // EIP-155 (Ethereum) chains
        if (components.namespace_id == "eip155") {
            if (components.chain_id == "1")
                return "Ethereum Mainnet";
            if (components.chain_id == "5")
                return "Ethereum Goerli";
            if (components.chain_id == "137")
                return "Polygon Mainnet";
            if (components.chain_id == "8453")
                return "Base";
            return "Ethereum Chain " + components.chain_id;
        }

        // BIP-122 (Bitcoin)
        if (components.namespace_id == "bip122") {
            return "Bitcoin";
        }

        // Cosmos
        if (components.namespace_id == "cosmos") {
            return "Cosmos " + components.chain_id;
        }

        return components.namespace_id + ":" + components.chain_id;
    }

    // Resolve a did:pkh DID to a DID document JSON
    inline DidResult<std::string> resolve_did_pkh_document_json(std::string_view did_uri) {
        // Parse the DID
        auto components_result = parse_did_pkh(did_uri);
        if (components_result.is_err()) {
            return DidResult<std::string>::err(components_result.error());
        }

        const auto &components = components_result.value();
        const std::string did_str(did_uri);
        const std::string account_id = get_blockchain_account_id(components);

        // Build DID document
        // did:pkh documents are minimal and follow a standard pattern
        std::string doc;
        doc.reserve(512);
        doc += "{\n";
        doc += "  \"@context\": [\n";
        doc += "    \"https://www.w3.org/ns/did/v1\",\n";
        doc += "    \"https://w3id.org/security/suites/secp256k1-2019/v1\"\n";
        doc += "  ],\n";
        doc += "  \"id\": \"" + did_str + "\",\n";
        doc += "  \"verificationMethod\": [\n";
        doc += "    {\n";
        doc += "      \"id\": \"" + did_str + "#blockchainAccountId\",\n";
        doc += "      \"type\": \"EcdsaSecp256k1RecoveryMethod2020\",\n";
        doc += "      \"controller\": \"" + did_str + "\",\n";
        doc += "      \"blockchainAccountId\": \"" + account_id + "\"\n";
        doc += "    }\n";
        doc += "  ],\n";
        doc += "  \"authentication\": [\"" + did_str + "#blockchainAccountId\"],\n";
        doc += "  \"assertionMethod\": [\"" + did_str + "#blockchainAccountId\"]\n";
        doc += "}\n";

        return DidResult<std::string>::ok(std::move(doc));
    }

    // Verify an Ethereum signature (EIP-191 personal_sign format)
    // This is a placeholder - actual implementation would require crypto library integration
    inline DidResult<bool> verify_ethereum_signature(std::string_view address, std::string_view message,
                                                     std::string_view signature) {
        // TODO: Implement actual signature verification
        // Would need:
        // 1. Hash message with Ethereum prefix: "\x19Ethereum Signed Message:\n" + len(message) + message
        // 2. Recover public key from signature using secp256k1
        // 3. Derive address from public key
        // 4. Compare with expected address

        (void)address;
        (void)message;
        (void)signature;

        return DidResult<bool>::err(error::not_implemented("Ethereum signature verification not yet implemented"));
    }

} // namespace authbox::did
