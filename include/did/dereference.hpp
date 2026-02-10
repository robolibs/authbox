#pragma once

#include <string_view>
#include <variant>

#include "did.hpp"
#include "document.hpp"
#include "errors.hpp"
#include "resolver.hpp"

namespace authbox::did {

    // Dereferenced resource types
    struct DereferencedVerificationMethod {
        VerificationMethod method;
    };

    struct DereferencedService {
        // TODO: Will be implemented in Phase 4
        dp::String id;
    };

    struct DereferencedDocument {
        DidDocument document;
    };

    // Result of dereferencing - can be one of several resource types
    using DereferencedResource =
        std::variant<DereferencedVerificationMethod, DereferencedService, DereferencedDocument>;

    struct DereferenceResult {
        DereferencedResource resource;
        dp::String content_type;
        Did did;
    };

    // Options for dereferencing
    struct DereferenceOptions {
        ResolveOptions resolve_options;
    };

    // Dereference a DID URL to a specific resource
    // Supports:
    // - DID without fragment/path/query -> returns the DID document
    // - DID with fragment (e.g., did:example:123#key-1) -> returns verification method or service
    // - DID with path/query -> returns the DID document (path/query not yet supported)
    inline DidResult<DereferenceResult> dereference(std::string_view did_url, const Resolver &resolver,
                                                    const DereferenceOptions &options = {}) {
        // Parse the DID URL
        auto parsed_url = parse_url(did_url);
        if (parsed_url.is_err()) {
            return DidResult<DereferenceResult>::err(parsed_url.error());
        }

        const auto &url = parsed_url.value();
        const std::string did_uri(url.did.uri.data(), url.did.uri.size());

        // Resolve the DID to get the document
        auto resolution = resolver.resolve(did_uri, options.resolve_options);
        if (resolution.is_err()) {
            return DidResult<DereferenceResult>::err(resolution.error());
        }

        const auto &doc = resolution.value().document;

        // If no fragment, return the entire document
        if (url.fragment.empty()) {
            DereferenceResult result{};
            result.resource = DereferencedDocument{doc};
            result.content_type = to_dp_string("application/did+ld+json");
            result.did = url.did;
            return DidResult<DereferenceResult>::ok(std::move(result));
        }

        // Dereference the fragment to a specific resource
        const std::string_view fragment(url.fragment.data(), url.fragment.size());

        // Try to find verification method with matching ID
        for (const auto &vm : doc.verification_methods) {
            const std::string_view vm_id(vm.id.data(), vm.id.size());

            // Support both local fragments (#key-1) and absolute IDs (did:example:123#key-1)
            bool matches = false;

            // Check if it's a local fragment reference
            if (vm_id.ends_with(fragment) && vm_id.size() > fragment.size() &&
                vm_id[vm_id.size() - fragment.size() - 1] == '#') {
                matches = true;
            }

            // Check if it's an exact match (absolute ID)
            if (vm_id == fragment) {
                matches = true;
            }

            // Check if the full DID URL matches
            std::string full_ref = did_uri + "#" + std::string(fragment);
            if (vm_id == full_ref) {
                matches = true;
            }

            if (matches) {
                DereferenceResult result{};
                result.resource = DereferencedVerificationMethod{vm};
                result.content_type = to_dp_string("application/did+json");
                result.did = url.did;
                return DidResult<DereferenceResult>::ok(std::move(result));
            }
        }

        // TODO: Phase 4 - Search in services when implemented

        // Fragment not found
        return DidResult<DereferenceResult>::err(error::fragment_not_found(fragment));
    }

    // Helper to check if a dereferenced result is a verification method
    inline bool is_verification_method(const DereferenceResult &result) {
        return std::holds_alternative<DereferencedVerificationMethod>(result.resource);
    }

    // Helper to check if a dereferenced result is a service
    inline bool is_service(const DereferenceResult &result) {
        return std::holds_alternative<DereferencedService>(result.resource);
    }

    // Helper to check if a dereferenced result is a document
    inline bool is_document(const DereferenceResult &result) {
        return std::holds_alternative<DereferencedDocument>(result.resource);
    }

    // Helper to get verification method (throws if wrong type)
    inline const VerificationMethod &get_verification_method(const DereferenceResult &result) {
        return std::get<DereferencedVerificationMethod>(result.resource).method;
    }

    // Helper to get document (throws if wrong type)
    inline const DidDocument &get_document(const DereferenceResult &result) {
        return std::get<DereferencedDocument>(result.resource).document;
    }

} // namespace authbox::did
