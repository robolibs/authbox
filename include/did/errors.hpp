#pragma once

#include <string>
#include <string_view>

#include <datapod/datapod.hpp>

namespace authbox::did {

    // Semantic error codes for DID operations
    enum class DidErrorCode {
        // Parsing errors
        INVALID_DID_URI,
        INVALID_METHOD_NAME,
        INVALID_METHOD_ID,
        INVALID_PERCENT_ENCODING,
        MALFORMED_DID_URL,

        // Method-specific errors
        UNSUPPORTED_METHOD,
        METHOD_NOT_REGISTERED,
        INVALID_METHOD_SPECIFIC_ID,

        // Document errors
        INVALID_DOCUMENT_JSON,
        DOCUMENT_MISSING_REQUIRED_FIELD,
        DOCUMENT_ID_MISMATCH,
        NO_VERIFICATION_METHODS,
        NO_VERIFICATION_RELATIONSHIPS,
        INVALID_VERIFICATION_METHOD,

        // Resolution errors
        RESOLUTION_FAILED,
        NETWORK_ERROR,
        FETCH_FAILED,
        HTTPS_REQUIRED,
        FETCHER_NOT_CONFIGURED,

        // Dereferencing errors
        FRAGMENT_NOT_FOUND,
        INVALID_REFERENCE,

        // Cryptographic errors
        INVALID_KEY_FORMAT,
        INVALID_KEY_LENGTH,
        UNSUPPORTED_KEY_TYPE,
        UNSUPPORTED_CURVE,

        // General errors
        INTERNAL_ERROR,
        NOT_IMPLEMENTED,
    };

    using DidError = dp::String;
    template <typename T> using DidResult = dp::Result<T, DidError>;

    // Helper to convert string_view to dp::String
    inline dp::String to_dp_string(std::string_view value) { return dp::String(value.data(), value.size()); }

    // Structured error factory functions
    namespace error {

        inline DidError invalid_did_uri(std::string_view details = "") {
            if (details.empty()) {
                return to_dp_string("Malformed DID URI");
            }
            return to_dp_string(std::string("Malformed DID URI: ") + std::string(details));
        }

        inline DidError invalid_method_name(std::string_view method) {
            return to_dp_string(std::string("Invalid DID method name: ") + std::string(method));
        }

        inline DidError invalid_method_id(std::string_view details = "") {
            if (details.empty()) {
                return to_dp_string("Invalid DID method-specific-id");
            }
            return to_dp_string(std::string("Invalid DID method-specific-id: ") + std::string(details));
        }

        inline DidError invalid_percent_encoding() { return to_dp_string("Invalid percent encoding"); }

        inline DidError unsupported_method(std::string_view method) {
            return to_dp_string(std::string("Unsupported DID method: ") + std::string(method));
        }

        inline DidError method_not_registered(std::string_view method) {
            return to_dp_string(std::string("DID method not registered: ") + std::string(method));
        }

        inline DidError invalid_document_json(std::string_view details = "") {
            if (details.empty()) {
                return to_dp_string("Invalid DID document JSON");
            }
            return to_dp_string(std::string("Invalid DID document JSON: ") + std::string(details));
        }

        inline DidError missing_field(std::string_view field) {
            return to_dp_string(std::string("Missing required field: ") + std::string(field));
        }

        inline DidError field_not_string(std::string_view field) {
            return to_dp_string(std::string("Field is not a string: ") + std::string(field));
        }

        inline DidError document_id_mismatch(std::string_view expected, std::string_view actual) {
            return to_dp_string(std::string("DID document id mismatch: expected ") + std::string(expected) + ", got " +
                                std::string(actual));
        }

        inline DidError no_verification_methods() { return to_dp_string("DID document has no verificationMethod"); }

        inline DidError no_verification_relationships() {
            return to_dp_string("DID document requires authentication/assertionMethod/keyAgreement");
        }

        inline DidError invalid_verification_method(std::string_view details = "") {
            if (details.empty()) {
                return to_dp_string("Invalid verificationMethod entry");
            }
            return to_dp_string(std::string("Invalid verificationMethod: ") + std::string(details));
        }

        inline DidError https_required() { return to_dp_string("HTTPS is required for this operation"); }

        inline DidError fetcher_not_configured() { return to_dp_string("Document fetcher is not configured"); }

        inline DidError network_error(std::string_view details) {
            return to_dp_string(std::string("Network error: ") + std::string(details));
        }

        inline DidError fragment_not_found(std::string_view fragment) {
            return to_dp_string(std::string("Fragment not found: #") + std::string(fragment));
        }

        inline DidError invalid_key_format(std::string_view details = "") {
            if (details.empty()) {
                return to_dp_string("Invalid key format");
            }
            return to_dp_string(std::string("Invalid key format: ") + std::string(details));
        }

        inline DidError invalid_key_length(size_t expected, size_t actual) {
            return to_dp_string(std::string("Invalid key length: expected ") + std::to_string(expected) +
                                " bytes, got " + std::to_string(actual) + " bytes");
        }

        inline DidError unsupported_key_type(std::string_view type) {
            return to_dp_string(std::string("Unsupported key type: ") + std::string(type));
        }

        inline DidError unsupported_curve(std::string_view curve) {
            return to_dp_string(std::string("Unsupported curve: ") + std::string(curve));
        }

        inline DidError not_implemented(std::string_view feature) {
            return to_dp_string(std::string("Not implemented: ") + std::string(feature));
        }

    } // namespace error

    // Check if a method is supported (legacy function for backward compatibility)
    inline bool is_supported_method(std::string_view method) { return method == "key" || method == "web"; }

} // namespace authbox::did
