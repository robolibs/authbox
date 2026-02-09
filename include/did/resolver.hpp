#pragma once

#include <functional>
#include <string>
#include <string_view>

#include "document.hpp"
#include "key.hpp"

namespace authbox::did {

    struct ResolveOptions {
        bool require_https{true};
        bool require_matching_id{true};
    };

    struct Resolution {
        Did did;
        DidDocument document;
        dp::String source_url;
        dp::String raw_document_json;
    };

    using FetchDidDocumentFn = std::function<DidResult<std::string>(std::string_view url)>;

    class Resolver {
      public:
        explicit Resolver(FetchDidDocumentFn fetcher = {}) : fetcher_(std::move(fetcher)) {}

        DidResult<Resolution> resolve(std::string_view did_uri, const ResolveOptions &options = {}) const {
            auto parsed = parse(did_uri);
            if (parsed.is_err()) {
                return DidResult<Resolution>::err(parsed.error());
            }

            if (parsed.value().method != "web") {
                if (parsed.value().method == "key") {
                    auto key_doc = resolve_did_key_document_json(did_uri);
                    if (key_doc.is_err()) {
                        return DidResult<Resolution>::err(key_doc.error());
                    }
                    return resolve_from_document(did_uri, key_doc.value(), "did:key:inline", options);
                }
                return DidResult<Resolution>::err(to_dp_string("Only did:web and did:key are supported by Resolver"));
            }

            auto doc_url = did_web_document_url(did_uri);
            if (doc_url.is_err()) {
                return DidResult<Resolution>::err(doc_url.error());
            }

            if (options.require_https && !std::string_view(doc_url.value()).starts_with("https://")) {
                return DidResult<Resolution>::err(to_dp_string("did:web document URL must use https"));
            }

            if (!fetcher_) {
                return DidResult<Resolution>::err(to_dp_string("Resolver fetcher is not configured"));
            }

            auto fetched = fetcher_(doc_url.value());
            if (fetched.is_err()) {
                return DidResult<Resolution>::err(fetched.error());
            }

            return resolve_from_document(did_uri, fetched.value(), doc_url.value(), options);
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
        FetchDidDocumentFn fetcher_;
    };

} // namespace authbox::did
