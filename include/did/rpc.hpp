#pragma once

#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include <netpipe/protocol/rpc.hpp>

#include "../json.hpp"
#include "resolver.hpp"
#include "x509.hpp"

namespace authbox::did::rpc {

    constexpr uint32_t METHOD_RESOLVE_DID = 0x44524401;    // DRD\1
    constexpr uint32_t METHOD_VERIFY_BINDING = 0x44564201; // DVB\1

    struct ResolveRequest {
        dp::String did_uri;
        dp::String did_document_json;
    };

    struct ResolveResponse {
        bool success{false};
        dp::String error;
        dp::String did_uri;
        dp::String source_url;
        dp::String did_document_json;
    };

    struct VerifyBindingRequest {
        dp::String did_uri;
        dp::String did_document_json;
        dp::String certificate_pem;
    };

    struct VerifyBindingResponse {
        bool success{false};
        bool valid{false};
        dp::String error;
    };

    namespace detail {

        inline netpipe::Message message_from_string(std::string_view value) {
            return netpipe::Message(value.begin(), value.end());
        }

        inline std::string string_from_message(const netpipe::Message &message) {
            return std::string(reinterpret_cast<const char *>(message.data()), message.size());
        }

        inline std::string_view json_string_view(const json_string_t *value) {
            if (!value || !value->string) {
                return {};
            }
            return std::string_view(value->string, value->string_size);
        }

        inline json_value_t *find_field(const json_object_t *obj, std::string_view key) {
            if (!obj) {
                return nullptr;
            }
            for (json_object_element_t *elem = obj->start; elem != nullptr; elem = elem->next) {
                if (json_string_view(elem->name) == key) {
                    return elem->value;
                }
            }
            return nullptr;
        }

        inline std::string get_string_field(const json_object_t *obj, std::string_view key) {
            auto *value = find_field(obj, key);
            if (!value) {
                return {};
            }
            auto *text = json_value_as_string(value);
            if (!text) {
                return {};
            }
            return std::string(json_string_view(text));
        }

        inline bool get_bool_field(const json_object_t *obj, std::string_view key) {
            auto *value = find_field(obj, key);
            if (!value) {
                return false;
            }
            return json_value_is_true(value) != 0;
        }

        inline dp::Res<json_object_t *> parse_json_object(const netpipe::Message &payload, json_value_t **root_out) {
            if (!root_out) {
                return dp::result::err(dp::Error::invalid_argument("root_out must not be null"));
            }

            json_parse_result_t parse_result{};
            const auto text = string_from_message(payload);
            json_value_t *root =
                json_parse_ex(text.data(), text.size(), json_parse_flags_default, nullptr, nullptr, &parse_result);
            if (!root) {
                return dp::result::err(dp::Error::invalid_argument("invalid json payload"));
            }

            auto *obj = json_value_as_object(root);
            if (!obj) {
                std::free(root);
                return dp::result::err(dp::Error::invalid_argument("json payload must be object"));
            }

            *root_out = root;
            return dp::result::ok(obj);
        }

        inline std::string json_escape(std::string_view value) {
            std::string out;
            out.reserve(value.size() + 8);
            for (char ch : value) {
                switch (ch) {
                case '\\':
                    out += "\\\\";
                    break;
                case '"':
                    out += "\\\"";
                    break;
                case '\n':
                    out += "\\n";
                    break;
                case '\r':
                    out += "\\r";
                    break;
                case '\t':
                    out += "\\t";
                    break;
                default:
                    out.push_back(ch);
                    break;
                }
            }
            return out;
        }

        inline netpipe::Message encode_resolve_response(const ResolveResponse &response) {
            std::string json = "{";
            json += "\"success\":";
            json += response.success ? "true" : "false";
            json += ",\"error\":\"" + json_escape(std::string(response.error.data(), response.error.size())) + "\"";
            json +=
                ",\"did_uri\":\"" + json_escape(std::string(response.did_uri.data(), response.did_uri.size())) + "\"";
            json += ",\"source_url\":\"" +
                    json_escape(std::string(response.source_url.data(), response.source_url.size())) + "\"";
            json += ",\"did_document_json\":\"" +
                    json_escape(std::string(response.did_document_json.data(), response.did_document_json.size())) +
                    "\"";
            json += "}";
            return message_from_string(json);
        }

        inline ResolveResponse decode_resolve_response(const netpipe::Message &payload) {
            ResolveResponse out{};
            json_value_t *root = nullptr;
            auto parsed = parse_json_object(payload, &root);
            if (parsed.is_err()) {
                out.error = to_dp_string(parsed.error().message.c_str());
                return out;
            }

            out.success = get_bool_field(parsed.value(), "success");
            out.error = to_dp_string(get_string_field(parsed.value(), "error"));
            out.did_uri = to_dp_string(get_string_field(parsed.value(), "did_uri"));
            out.source_url = to_dp_string(get_string_field(parsed.value(), "source_url"));
            out.did_document_json = to_dp_string(get_string_field(parsed.value(), "did_document_json"));
            std::free(root);
            return out;
        }

        inline netpipe::Message encode_verify_response(const VerifyBindingResponse &response) {
            std::string json = "{";
            json += "\"success\":";
            json += response.success ? "true" : "false";
            json += ",\"valid\":";
            json += response.valid ? "true" : "false";
            json += ",\"error\":\"" + json_escape(std::string(response.error.data(), response.error.size())) + "\"";
            json += "}";
            return message_from_string(json);
        }

        inline VerifyBindingResponse decode_verify_response(const netpipe::Message &payload) {
            VerifyBindingResponse out{};
            json_value_t *root = nullptr;
            auto parsed = parse_json_object(payload, &root);
            if (parsed.is_err()) {
                out.error = to_dp_string(parsed.error().message.c_str());
                return out;
            }

            out.success = get_bool_field(parsed.value(), "success");
            out.valid = get_bool_field(parsed.value(), "valid");
            out.error = to_dp_string(get_string_field(parsed.value(), "error"));
            std::free(root);
            return out;
        }

    } // namespace detail

    class Service {
      public:
        explicit Service(Resolver resolver) : resolver_(std::move(resolver)) {}

        template <typename RemoteType> dp::Res<void> bind(RemoteType &remote) {
            auto resolve_handler = [this](const netpipe::Message &request) -> dp::Res<netpipe::Message> {
                return handle_resolve_request(request);
            };
            auto verify_handler = [this](const netpipe::Message &request) -> dp::Res<netpipe::Message> {
                return handle_verify_binding_request(request);
            };

            auto reg_resolve = remote.register_method(METHOD_RESOLVE_DID, resolve_handler);
            if (reg_resolve.is_err()) {
                return reg_resolve;
            }
            return remote.register_method(METHOD_VERIFY_BINDING, verify_handler);
        }

        dp::Res<netpipe::Message> dispatch(uint32_t method_id, const netpipe::Message &request) {
            if (method_id == METHOD_RESOLVE_DID) {
                return handle_resolve_request(request);
            }
            if (method_id == METHOD_VERIFY_BINDING) {
                return handle_verify_binding_request(request);
            }
            return dp::result::err(dp::Error::not_found("unknown DID RPC method"));
        }

        dp::Res<netpipe::Message> handle_resolve_request(const netpipe::Message &payload) {
            json_value_t *root = nullptr;
            auto parsed = detail::parse_json_object(payload, &root);
            if (parsed.is_err()) {
                return dp::result::err(parsed.error());
            }

            ResolveRequest request{};
            request.did_uri = to_dp_string(detail::get_string_field(parsed.value(), "did_uri"));
            request.did_document_json = to_dp_string(detail::get_string_field(parsed.value(), "did_document_json"));
            std::free(root);

            ResolveResponse response{};
            const std::string did_uri(request.did_uri.data(), request.did_uri.size());

            DidResult<Resolution> resolved =
                request.did_document_json.empty()
                    ? resolver_.resolve(did_uri)
                    : Resolver::resolve_from_document(did_uri, std::string_view(request.did_document_json.data(),
                                                                                request.did_document_json.size()));

            if (resolved.is_err()) {
                response.success = false;
                response.error = resolved.error();
                return dp::result::ok(detail::encode_resolve_response(response));
            }

            response.success = true;
            response.did_uri = resolved.value().did.uri;
            response.source_url = resolved.value().source_url;
            response.did_document_json = resolved.value().raw_document_json;
            return dp::result::ok(detail::encode_resolve_response(response));
        }

        dp::Res<netpipe::Message> handle_verify_binding_request(const netpipe::Message &payload) {
            json_value_t *root = nullptr;
            auto parsed = detail::parse_json_object(payload, &root);
            if (parsed.is_err()) {
                return dp::result::err(parsed.error());
            }

            VerifyBindingRequest request{};
            request.did_uri = to_dp_string(detail::get_string_field(parsed.value(), "did_uri"));
            request.did_document_json = to_dp_string(detail::get_string_field(parsed.value(), "did_document_json"));
            request.certificate_pem = to_dp_string(detail::get_string_field(parsed.value(), "certificate_pem"));
            std::free(root);

            VerifyBindingResponse response{};

            auto parsed_chain = authbox::pik::Certificate::parse_pem_chain(
                std::string_view(request.certificate_pem.data(), request.certificate_pem.size()));
            if (!parsed_chain.success || parsed_chain.value.empty()) {
                response.success = false;
                response.error =
                    to_dp_string(parsed_chain.error.empty() ? "Failed to parse certificate PEM" : parsed_chain.error);
                return dp::result::ok(detail::encode_verify_response(response));
            }

            auto verified = verify_certificate_binding(
                std::string_view(request.did_document_json.data(), request.did_document_json.size()),
                parsed_chain.value[0], std::string_view(request.did_uri.data(), request.did_uri.size()));

            response.success = verified.is_ok();
            response.valid = verified.is_ok() && verified.value();
            if (verified.is_err()) {
                response.error = verified.error();
            }
            return dp::result::ok(detail::encode_verify_response(response));
        }

      private:
        Resolver resolver_;
    };

    template <typename RemoteType> class Client {
      public:
        explicit Client(RemoteType &remote) : remote_(remote) {}

        DidResult<Resolution> resolve(std::string_view did_uri, std::string_view did_document_json = {},
                                      uint32_t timeout_ms = 5000) {
            std::string payload = "{";
            payload += "\"did_uri\":\"" + detail::json_escape(did_uri) + "\"";
            payload += ",\"did_document_json\":\"" + detail::json_escape(did_document_json) + "\"";
            payload += "}";

            auto call_result = remote_.call(METHOD_RESOLVE_DID, detail::message_from_string(payload), timeout_ms);
            if (call_result.is_err()) {
                return DidResult<Resolution>::err(to_dp_string(call_result.error().message.c_str()));
            }

            auto response = detail::decode_resolve_response(call_result.value());
            if (!response.success) {
                return DidResult<Resolution>::err(response.error);
            }

            return Resolver::resolve_from_document(
                std::string_view(response.did_uri.data(), response.did_uri.size()),
                std::string_view(response.did_document_json.data(), response.did_document_json.size()),
                std::string_view(response.source_url.data(), response.source_url.size()));
        }

        DidResult<bool> verify_binding(std::string_view did_uri, std::string_view did_document_json,
                                       std::string_view certificate_pem, uint32_t timeout_ms = 5000) {
            std::string payload = "{";
            payload += "\"did_uri\":\"" + detail::json_escape(did_uri) + "\"";
            payload += ",\"did_document_json\":\"" + detail::json_escape(did_document_json) + "\"";
            payload += ",\"certificate_pem\":\"" + detail::json_escape(certificate_pem) + "\"";
            payload += "}";

            auto call_result = remote_.call(METHOD_VERIFY_BINDING, detail::message_from_string(payload), timeout_ms);
            if (call_result.is_err()) {
                return DidResult<bool>::err(to_dp_string(call_result.error().message.c_str()));
            }

            auto response = detail::decode_verify_response(call_result.value());
            if (!response.success) {
                return DidResult<bool>::err(response.error);
            }
            return DidResult<bool>::ok(response.valid);
        }

      private:
        RemoteType &remote_;
    };

} // namespace authbox::did::rpc
