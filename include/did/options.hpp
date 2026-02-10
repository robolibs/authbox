#pragma once

#include <cstddef>
#include <set>
#include <string>

namespace authbox::did {

    // Options for DID resolution
    struct ResolveOptions {
        // Security options
        bool require_https{true};       // Require HTTPS for did:web and external fetches
        bool require_matching_id{true}; // Require DID document ID to match requested DID

        // Production hardening options
        size_t max_document_size{1048576}; // Maximum DID document size in bytes (default: 1MB)
        bool strict_parsing{false};        // Enable strict spec compliance checks
        bool allow_experimental{false};    // Allow experimental/draft DID methods

        // Method filtering (empty = allow all)
        std::set<std::string> allowed_methods; // Allowlist of DID methods (e.g., {"key", "web"})
        std::set<std::string> blocked_methods; // Blocklist of DID methods (blocklist takes precedence)

        // Validation options
        bool validate_contexts{false};          // Validate @context URLs
        bool require_verification_method{true}; // Require at least one verification method

        // Performance limits
        size_t max_verification_methods{100}; // Maximum number of verification methods
        size_t max_services{50};              // Maximum number of services
        size_t max_context_entries{10};       // Maximum number of @context entries

        // Check if a DID method is allowed by policy
        inline bool is_method_allowed(const std::string &method) const {
            // Blocklist takes precedence
            if (!blocked_methods.empty() && blocked_methods.count(method) > 0) {
                return false;
            }
            // If allowlist is empty, allow all (except blocked)
            if (allowed_methods.empty()) {
                return true;
            }
            // Otherwise, check allowlist
            return allowed_methods.count(method) > 0;
        }
    };

} // namespace authbox::did
