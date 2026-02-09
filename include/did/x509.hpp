#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "document.hpp"
#include <pki/pem.hpp>
#include <pki/pki.hpp>

namespace authbox::did {

    struct DidWebDocumentBundle {
        dp::String did_uri;
        dp::String verification_method_id;
        dp::String did_document_json;
    };

    namespace detail {

        inline std::string base64url_encode(const std::vector<uint8_t> &bytes) {
            const auto base64 = authbox::pik::detail::encode_base64(authbox::pik::ByteSpan(bytes.data(), bytes.size()));

            std::string out;
            out.reserve(base64.size());
            for (char ch : base64) {
                if (ch == '=') {
                    continue;
                }
                if (ch == '+') {
                    out.push_back('-');
                } else if (ch == '/') {
                    out.push_back('_');
                } else {
                    out.push_back(ch);
                }
            }
            return out;
        }

        inline bool has_reference(const std::vector<dp::String> &refs, std::string_view id) {
            for (const auto &ref : refs) {
                if (std::string_view(ref.data(), ref.size()) == id) {
                    return true;
                }
            }
            return false;
        }

    } // namespace detail

    inline DidResult<JsonWebKey> jwk_from_certificate_public_key(const authbox::pik::Certificate &certificate) {
        const auto &public_key = certificate.tbs().subject_public_key_info.public_key;
        if (public_key.empty()) {
            return DidResult<JsonWebKey>::err(to_dp_string("Certificate public key is empty"));
        }

        JsonWebKey out{};
        if (public_key.size() == 32U) {
            out.kty = to_dp_string("OKP");
            out.crv = to_dp_string("Ed25519");
            out.x = to_dp_string(detail::base64url_encode(public_key));
            return DidResult<JsonWebKey>::ok(std::move(out));
        }

        if (public_key.size() == 65U && public_key[0] == 0x04U) {
            std::vector<uint8_t> x(public_key.begin() + 1, public_key.begin() + 33);
            std::vector<uint8_t> y(public_key.begin() + 33, public_key.end());
            out.kty = to_dp_string("EC");
            out.crv = to_dp_string("P-256");
            out.x = to_dp_string(detail::base64url_encode(x));
            out.y = to_dp_string(detail::base64url_encode(y));
            return DidResult<JsonWebKey>::ok(std::move(out));
        }

        return DidResult<JsonWebKey>::err(to_dp_string("Unsupported public key format for DID JWK"));
    }

    inline DidResult<DidWebDocumentBundle> generate_did_web_document(std::string_view domain,
                                                                     const authbox::pik::Certificate &certificate,
                                                                     std::string_view key_fragment = "#0") {
        if (domain.empty()) {
            return DidResult<DidWebDocumentBundle>::err(to_dp_string("Domain must not be empty"));
        }

        auto jwk = jwk_from_certificate_public_key(certificate);
        if (jwk.is_err()) {
            return DidResult<DidWebDocumentBundle>::err(jwk.error());
        }

        std::string did_uri = "did:web:";
        did_uri += domain;

        std::string fragment = key_fragment.empty() ? "#0" : std::string(key_fragment);
        if (fragment[0] != '#') {
            fragment.insert(fragment.begin(), '#');
        }

        std::string vm_id = did_uri + fragment;

        std::string json;
        json.reserve(1024);
        json += "{\n";
        json += "  \"@context\": [\n";
        json += "    \"https://www.w3.org/ns/did/v1\",\n";
        json += "    \"https://w3id.org/security/suites/jws-2020/v1\"\n";
        json += "  ],\n";
        json += "  \"id\": \"" + did_uri + "\",\n";
        json += "  \"verificationMethod\": [\n";
        json += "    {\n";
        json += "      \"id\": \"" + vm_id + "\",\n";
        json += "      \"type\": \"JsonWebKey2020\",\n";
        json += "      \"controller\": \"" + did_uri + "\",\n";
        json += "      \"publicKeyJwk\": {\n";
        json += "        \"kty\": \"" + std::string(jwk.value().kty.data(), jwk.value().kty.size()) + "\",\n";
        json += "        \"crv\": \"" + std::string(jwk.value().crv.data(), jwk.value().crv.size()) + "\",\n";
        json += "        \"x\": \"" + std::string(jwk.value().x.data(), jwk.value().x.size()) + "\"";
        if (!jwk.value().y.empty()) {
            json += ",\n        \"y\": \"" + std::string(jwk.value().y.data(), jwk.value().y.size()) + "\"\n";
        } else {
            json += "\n";
        }
        json += "      }\n";
        json += "    }\n";
        json += "  ],\n";
        json += "  \"authentication\": [\n";
        json += "    \"" + vm_id + "\"\n";
        json += "  ],\n";
        json += "  \"assertionMethod\": [\n";
        json += "    \"" + vm_id + "\"\n";
        json += "  ]\n";
        json += "}\n";

        DidWebDocumentBundle bundle{};
        bundle.did_uri = to_dp_string(did_uri);
        bundle.verification_method_id = to_dp_string(vm_id);
        bundle.did_document_json = to_dp_string(json);
        return DidResult<DidWebDocumentBundle>::ok(std::move(bundle));
    }

    inline DidResult<bool> verify_certificate_binding(const authbox::pik::Certificate &certificate,
                                                      const DidDocument &document, std::string_view expected_did_uri) {
        auto document_ok = validate_document(document, expected_did_uri);
        if (document_ok.is_err()) {
            return DidResult<bool>::err(document_ok.error());
        }

        if (!authbox::pik::has_did_binding(certificate, expected_did_uri)) {
            return DidResult<bool>::err(to_dp_string("Certificate does not contain matching DID URI in SAN"));
        }

        auto cert_jwk = jwk_from_certificate_public_key(certificate);
        if (cert_jwk.is_err()) {
            return DidResult<bool>::err(cert_jwk.error());
        }

        for (const auto &method : document.verification_methods) {
            const bool same_kty = method.public_key_jwk.kty == cert_jwk.value().kty;
            const bool same_crv = method.public_key_jwk.crv == cert_jwk.value().crv;
            const bool same_x = method.public_key_jwk.x == cert_jwk.value().x;
            const bool same_y = method.public_key_jwk.y == cert_jwk.value().y;
            if (!(same_kty && same_crv && same_x && same_y)) {
                continue;
            }

            const std::string method_id(method.id.data(), method.id.size());
            if (detail::has_reference(document.authentication, method_id) ||
                detail::has_reference(document.assertion_method, method_id)) {
                return DidResult<bool>::ok(true);
            }
        }

        return DidResult<bool>::err(to_dp_string("No DID verificationMethod matches certificate public key"));
    }

    inline DidResult<bool> verify_certificate_binding(std::string_view did_document_json,
                                                      const authbox::pik::Certificate &certificate,
                                                      std::string_view expected_did_uri) {
        auto parsed = parse_document(did_document_json);
        if (parsed.is_err()) {
            return DidResult<bool>::err(parsed.error());
        }
        return verify_certificate_binding(certificate, parsed.value(), expected_did_uri);
    }

} // namespace authbox::did
