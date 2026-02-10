#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include "document.hpp"
#include "key.hpp"
#include "method_registry.hpp"
#include "options.hpp"

namespace authbox::did {

    struct Resolution {
        Did did;
        DidDocument document;
        dp::String source_url;
        dp::String raw_document_json;
    };

    using FetchDidDocumentFn = std::function<DidResult<std::string>(std::string_view url)>;

    class Resolver {
      public:
        explicit Resolver(FetchDidDocumentFn fetcher = {})
            : fetcher_(std::move(fetcher)), registry_(new MethodRegistry()) {
            register_builtin_methods();
        }

        // Constructor with custom registry
        explicit Resolver(FetchDidDocumentFn fetcher, std::shared_ptr<MethodRegistry> registry)
            : fetcher_(std::move(fetcher)), registry_(std::move(registry)) {
            register_builtin_methods();
        }

        // Get the method registry for this resolver
        MethodRegistry &registry() { return *registry_; }
        const MethodRegistry &registry() const { return *registry_; }

        DidResult<Resolution> resolve(std::string_view did_uri, const ResolveOptions &options = {}) const {
            // Use the registry to resolve to document JSON
            auto doc_result = registry_->resolve_to_document(did_uri, options);
            if (doc_result.is_err()) {
                return DidResult<Resolution>::err(doc_result.error());
            }

            // Determine source URL based on method
            auto parsed = parse(did_uri);
            std::string source_url = "inline";
            if (parsed.is_ok() && parsed.value().method == "web") {
                auto url_result = did_web_document_url(did_uri);
                if (url_result.is_ok()) {
                    source_url = url_result.value();
                }
            } else if (parsed.is_ok() && parsed.value().method == "key") {
                source_url = "did:key:inline";
            }

            // Convert document JSON to Resolution structure
            return resolve_from_document(did_uri, doc_result.value(), source_url, options);
        }

        static DidResult<Resolution> resolve_from_document(std::string_view did_uri, std::string_view document_json,
                                                           std::string_view source_url = "inline",
                                                           const ResolveOptions &options = {}) {
            auto parsed_did = parse(did_uri);
            if (parsed_did.is_err()) {
                return DidResult<Resolution>::err(parsed_did.error());
            }

            auto document = parse_document(document_json);
            if (document.is_err()) {
                return DidResult<Resolution>::err(document.error());
            }

            if (options.require_matching_id) {
                auto valid = validate_document(document.value(), did_uri);
                if (valid.is_err()) {
                    return DidResult<Resolution>::err(valid.error());
                }
            }

            Resolution out{};
            out.did = parsed_did.value();
            out.document = std::move(document.value());
            out.source_url = to_dp_string(source_url);
            out.raw_document_json = to_dp_string(document_json);
            return DidResult<Resolution>::ok(std::move(out));
        }

      private:
        void register_builtin_methods() {
            // Register did:key handler (offline, deterministic)
            registry_->register_method("key",
                                       [](std::string_view did_uri, const ResolveOptions &) -> DidResult<std::string> {
                                           return resolve_did_key_document_json(did_uri);
                                       });

            // Register did:web handler (requires fetcher)
            registry_->register_method(
                "web", [this](std::string_view did_uri, const ResolveOptions &options) -> DidResult<std::string> {
                    auto doc_url = did_web_document_url(did_uri);
                    if (doc_url.is_err()) {
                        return DidResult<std::string>::err(doc_url.error());
                    }

                    if (options.require_https && !std::string_view(doc_url.value()).starts_with("https://")) {
                        return DidResult<std::string>::err(error::https_required());
                    }

                    if (!fetcher_) {
                        return DidResult<std::string>::err(error::fetcher_not_configured());
                    }

                    return fetcher_(doc_url.value());
                });
        }

        FetchDidDocumentFn fetcher_;
        std::shared_ptr<MethodRegistry> registry_;
    };

} // namespace authbox::did
