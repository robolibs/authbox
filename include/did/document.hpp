#pragma once

#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include <datapod/datapod.hpp>

#include "../json.hpp"

#include "did.hpp"

namespace authbox::did {

    struct JsonWebKey {
        dp::String kty;
        dp::String crv;
        dp::String x;
        dp::String y;
    };

    struct VerificationMethod {
        dp::String id;
        dp::String type;
        dp::String controller;
        JsonWebKey public_key_jwk;
    };

    struct DidDocument {
        dp::String id;
        std::vector<dp::String> contexts;
        std::vector<VerificationMethod> verification_methods;
        std::vector<dp::String> authentication;
        std::vector<dp::String> assertion_method;
        std::vector<dp::String> key_agreement;
    };

    namespace detail {

        inline std::string_view json_string_view(const json_string_t *value) {
            if (!value || !value->string) {
                return {};
            }
            return std::string_view(value->string, value->string_size);
        }

        inline json_value_t *find_object_field(const json_object_t *obj, std::string_view key) {
            if (!obj) {
                return nullptr;
            }
            for (json_object_element_t *elem = obj->start; elem != nullptr; elem = elem->next) {
                const auto name = json_string_view(elem->name);
                if (name == key) {
                    return elem->value;
                }
            }
            return nullptr;
        }

        inline DidResult<dp::String> parse_required_string_field(const json_object_t *obj, std::string_view key) {
            json_value_t *value = find_object_field(obj, key);
            if (!value) {
                return DidResult<dp::String>::err(to_dp_string(std::string("Missing field: ") + std::string(key)));
            }
            const auto *text = json_value_as_string(value);
            if (!text) {
                return DidResult<dp::String>::err(
                    to_dp_string(std::string("Field is not a string: ") + std::string(key)));
            }
            return DidResult<dp::String>::ok(to_dp_string(json_string_view(text)));
        }

        inline std::vector<dp::String> parse_string_array(json_value_t *value) {
            std::vector<dp::String> out;
            if (!value) {
                return out;
            }
            const auto *array = json_value_as_array(value);
            if (!array) {
                return out;
            }
            out.reserve(array->length);
            for (json_array_element_t *elem = array->start; elem != nullptr; elem = elem->next) {
                const auto *text = json_value_as_string(elem->value);
                if (!text) {
                    continue;
                }
                out.push_back(to_dp_string(json_string_view(text)));
            }
            return out;
        }

        inline DidResult<JsonWebKey> parse_jwk(const json_object_t *obj) {
            JsonWebKey jwk{};
            auto kty = parse_required_string_field(obj, "kty");
            if (kty.is_err()) {
                return DidResult<JsonWebKey>::err(kty.error());
            }
            auto crv = parse_required_string_field(obj, "crv");
            if (crv.is_err()) {
                return DidResult<JsonWebKey>::err(crv.error());
            }
            auto x = parse_required_string_field(obj, "x");
            if (x.is_err()) {
                return DidResult<JsonWebKey>::err(x.error());
            }

            jwk.kty = kty.value();
            jwk.crv = crv.value();
            jwk.x = x.value();

            json_value_t *y_field = find_object_field(obj, "y");
            if (y_field) {
                const auto *text = json_value_as_string(y_field);
                if (text) {
                    jwk.y = to_dp_string(json_string_view(text));
                }
            }

            return DidResult<JsonWebKey>::ok(std::move(jwk));
        }

    } // namespace detail

    inline DidResult<DidDocument> parse_document(std::string_view json_text) {
        json_parse_result_t result{};
        json_value_t *root =
            json_parse_ex(json_text.data(), json_text.size(), json_parse_flags_default, nullptr, nullptr, &result);
        if (!root) {
            return DidResult<DidDocument>::err(to_dp_string("Invalid DID document JSON"));
        }

        const auto cleanup = [&]() { std::free(root); };

        const auto *root_obj = json_value_as_object(root);
        if (!root_obj) {
            cleanup();
            return DidResult<DidDocument>::err(to_dp_string("DID document root must be an object"));
        }

        DidDocument out{};
        auto id = detail::parse_required_string_field(root_obj, "id");
        if (id.is_err()) {
            cleanup();
            return DidResult<DidDocument>::err(id.error());
        }
        out.id = id.value();

        if (auto *ctx = detail::find_object_field(root_obj, "@context")) {
            const auto *ctx_string = json_value_as_string(ctx);
            if (ctx_string) {
                out.contexts.push_back(to_dp_string(detail::json_string_view(ctx_string)));
            } else {
                out.contexts = detail::parse_string_array(ctx);
            }
        }

        json_value_t *vm_value = detail::find_object_field(root_obj, "verificationMethod");
        const auto *vm_array = json_value_as_array(vm_value);
        if (!vm_array || vm_array->length == 0U) {
            cleanup();
            return DidResult<DidDocument>::err(to_dp_string("verificationMethod must be a non-empty array"));
        }

        out.verification_methods.reserve(vm_array->length);
        for (json_array_element_t *elem = vm_array->start; elem != nullptr; elem = elem->next) {
            const auto *vm_obj = json_value_as_object(elem->value);
            if (!vm_obj) {
                cleanup();
                return DidResult<DidDocument>::err(to_dp_string("verificationMethod entries must be objects"));
            }

            VerificationMethod vm{};
            auto vm_id = detail::parse_required_string_field(vm_obj, "id");
            auto vm_type = detail::parse_required_string_field(vm_obj, "type");
            auto vm_controller = detail::parse_required_string_field(vm_obj, "controller");
            if (vm_id.is_err() || vm_type.is_err() || vm_controller.is_err()) {
                cleanup();
                return DidResult<DidDocument>::err(to_dp_string("Invalid verificationMethod entry"));
            }

            vm.id = vm_id.value();
            vm.type = vm_type.value();
            vm.controller = vm_controller.value();

            const auto *jwk_obj = json_value_as_object(detail::find_object_field(vm_obj, "publicKeyJwk"));
            if (!jwk_obj) {
                cleanup();
                return DidResult<DidDocument>::err(to_dp_string("verificationMethod.publicKeyJwk is required"));
            }
            auto jwk = detail::parse_jwk(jwk_obj);
            if (jwk.is_err()) {
                cleanup();
                return DidResult<DidDocument>::err(jwk.error());
            }
            vm.public_key_jwk = jwk.value();
            out.verification_methods.push_back(std::move(vm));
        }

        out.authentication = detail::parse_string_array(detail::find_object_field(root_obj, "authentication"));
        out.assertion_method = detail::parse_string_array(detail::find_object_field(root_obj, "assertionMethod"));
        out.key_agreement = detail::parse_string_array(detail::find_object_field(root_obj, "keyAgreement"));

        cleanup();
        return DidResult<DidDocument>::ok(std::move(out));
    }

    inline DidResult<bool> validate_document(const DidDocument &document, std::string_view expected_did_uri) {
        if (std::string_view(document.id.data(), document.id.size()) != expected_did_uri) {
            return DidResult<bool>::err(to_dp_string("DID document id mismatch"));
        }

        if (document.verification_methods.empty()) {
            return DidResult<bool>::err(to_dp_string("DID document has no verificationMethod"));
        }

        bool has_relationship =
            !document.authentication.empty() || !document.assertion_method.empty() || !document.key_agreement.empty();
        if (!has_relationship) {
            return DidResult<bool>::err(
                to_dp_string("DID document requires authentication/assertionMethod/keyAgreement"));
        }

        return DidResult<bool>::ok(true);
    }

} // namespace authbox::did
