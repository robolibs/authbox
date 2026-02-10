#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "did.hpp"
#include "errors.hpp"

namespace authbox::did {

    // DNS TXT record result
    struct DnsTxtRecord {
        std::string value;
        bool dnssec_valid{false}; // Whether DNSSEC validation succeeded
    };

    // Callback interface for DNS lookups
    // The caller must provide this function to perform actual DNS queries
    using DnsLookupFn = std::function<DidResult<std::vector<DnsTxtRecord>>(std::string_view domain)>;

    // Options for did:dns resolution
    struct DnsResolveOptions {
        bool require_dnssec{false}; // Require DNSSEC validation
        DnsLookupFn dns_lookup;     // DNS lookup callback (required)
    };

    // Parse and validate a did:dns DID
    inline DidResult<std::string> parse_did_dns(std::string_view did_uri) {
        auto parsed = parse(did_uri);
        if (parsed.is_err()) {
            return DidResult<std::string>::err(parsed.error());
        }

        if (parsed.value().method != "dns") {
            return DidResult<std::string>::err(error::invalid_method_id("method must be 'dns'"));
        }

        const std::string_view method_id(parsed.value().method_id.data(), parsed.value().method_id.size());
        if (method_id.empty()) {
            return DidResult<std::string>::err(error::invalid_method_id("did:dns method-id is empty"));
        }

        // Validate that method_id is a valid domain name
        // Basic validation: no spaces, contains at least one dot (for TLD)
        if (method_id.find(' ') != std::string_view::npos) {
            return DidResult<std::string>::err(error::invalid_method_id("domain cannot contain spaces"));
        }

        // Domain should have at least one dot (e.g., example.com)
        if (method_id.find('.') == std::string_view::npos) {
            return DidResult<std::string>::err(error::invalid_method_id("domain must contain at least one dot"));
        }

        return DidResult<std::string>::ok(std::string(method_id));
    }

    // Construct the DNS query domain for a did:dns DID
    // For did:dns:example.com, this returns _did.example.com
    inline std::string get_dns_query_domain(std::string_view domain) { return "_did." + std::string(domain); }

    // Resolve a did:dns DID to a DID document JSON
    inline DidResult<std::string> resolve_did_dns_document_json(std::string_view did_uri,
                                                                const DnsResolveOptions &options) {
        // Parse the DID
        auto domain_result = parse_did_dns(did_uri);
        if (domain_result.is_err()) {
            return DidResult<std::string>::err(domain_result.error());
        }

        const std::string &domain = domain_result.value();

        // Check that DNS lookup callback is provided
        if (!options.dns_lookup) {
            return DidResult<std::string>::err(error::fetcher_not_configured());
        }

        // Construct the query domain (_did.<domain>)
        std::string query_domain = get_dns_query_domain(domain);

        // Perform DNS lookup
        auto dns_result = options.dns_lookup(query_domain);
        if (dns_result.is_err()) {
            return DidResult<std::string>::err(dns_result.error());
        }

        const auto &records = dns_result.value();
        if (records.empty()) {
            return DidResult<std::string>::err(error::network_error("no TXT records found at " + query_domain));
        }

        // If DNSSEC is required, verify at least one record has valid DNSSEC
        if (options.require_dnssec) {
            bool has_valid_dnssec = false;
            for (const auto &record : records) {
                if (record.dnssec_valid) {
                    has_valid_dnssec = true;
                    break;
                }
            }
            if (!has_valid_dnssec) {
                return DidResult<std::string>::err(error::network_error("DNSSEC validation failed"));
            }
        }

        // Look for a TXT record that starts with "did=" or is valid JSON
        for (const auto &record : records) {
            const std::string &value = record.value;

            // Skip if DNSSEC is required and this record isn't validated
            if (options.require_dnssec && !record.dnssec_valid) {
                continue;
            }

            // Check if it's a reference to another location (did=<url>)
            if (value.starts_with("did=")) {
                // This is a URL reference - would need HTTP fetch (not implemented here)
                return DidResult<std::string>::err(error::not_implemented("DID document URL references"));
            }

            // Try to parse as JSON (direct document embedding)
            json_parse_result_t parse_result{};
            json_value_t *root =
                json_parse_ex(value.data(), value.size(), json_parse_flags_default, nullptr, nullptr, &parse_result);
            if (root) {
                std::free(root);
                // Valid JSON - return as-is
                return DidResult<std::string>::ok(value);
            }
        }

        // No valid DID document found
        return DidResult<std::string>::err(error::network_error("no valid DID document in TXT records"));
    }

    // Create a method handler for did:dns with specified options
    inline MethodHandler create_dns_handler(const DnsResolveOptions &dns_options) {
        return [dns_options](std::string_view did_uri, const ResolveOptions &) -> DidResult<std::string> {
            return resolve_did_dns_document_json(did_uri, dns_options);
        };
    }

} // namespace authbox::did
