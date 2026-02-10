#pragma once

#include <string_view>
#include <vector>

#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

#include <pki/certificate.hpp>
#include <pki/trust_store.hpp>

#include <did/did.hpp>

namespace authbox::pik {

    using PkiError = dp::String;
    template <typename T> using PkiResult = dp::Result<T, PkiError>;

    struct CertificateRecord {
        authbox::pik::Certificate certificate;
        dp::Vector<dp::String> did_uris;
    };

    inline dp::String to_dp_string(std::string_view value) { return dp::String(value.data(), value.size()); }

    inline dp::Vector<dp::String> collect_did_uris(const authbox::pik::Certificate &certificate) {
        dp::Vector<dp::String> uris;
        const auto sans = certificate.subject_alt_names();

        for (const auto &name : sans) {
            if (name.type != authbox::pik::SubjectAltNameExtension::GeneralNameType::URI) {
                continue;
            }

            const std::string_view value(name.value);
            if (!did::is_did_uri(value)) {
                continue;
            }

            uris.push_back(to_dp_string(value));
        }

        echo::debug("pki::collect_did_uris found ", uris.size(), " DID SAN entries");
        return uris;
    }

    inline PkiResult<CertificateRecord> parse_pem_certificate(const dp::String &pem, bool relaxed = false) {
        echo::info("pki::parse_pem_certificate called");

        auto parsed_chain =
            authbox::pik::Certificate::parse_pem_chain(std::string_view(pem.data(), pem.size()), relaxed);
        if (!parsed_chain.success) {
            echo::error("pki::parse_pem_certificate failed: ", parsed_chain.error);
            return PkiResult<CertificateRecord>::err(to_dp_string(parsed_chain.error));
        }

        if (parsed_chain.value.empty()) {
            echo::warn("pki::parse_pem_certificate returned empty chain");
            return PkiResult<CertificateRecord>::err(to_dp_string("Certificate chain is empty"));
        }

        CertificateRecord out{};
        out.certificate = parsed_chain.value.front();
        out.did_uris = collect_did_uris(out.certificate);
        return PkiResult<CertificateRecord>::ok(std::move(out));
    }

    inline bool has_did_binding(const authbox::pik::Certificate &certificate, std::string_view did_uri) {
        const auto did_sans = collect_did_uris(certificate);
        for (const auto &candidate : did_sans) {
            if (std::string_view(candidate.data(), candidate.size()) == did_uri) {
                echo::info("pki::has_did_binding matched DID in SAN");
                return true;
            }
        }

        echo::warn("pki::has_did_binding no DID SAN match");
        return false;
    }

    inline PkiResult<bool> validate_with_system_trust(const authbox::pik::Certificate &leaf) {
        echo::info("pki::validate_with_system_trust loading system trust store");

        auto trust = authbox::pik::TrustStore::load_from_system();
        if (!trust.success) {
            echo::error("pki::validate_with_system_trust trust store load failed: ", trust.error);
            return PkiResult<bool>::err(to_dp_string(trust.error));
        }

        const std::vector<authbox::pik::Certificate> chain;
        auto validation = leaf.validate_chain(chain, trust.value);
        if (!validation.success) {
            echo::error("pki::validate_with_system_trust validation failure: ", validation.error);
            return PkiResult<bool>::err(to_dp_string(validation.error));
        }

        echo::info("pki::validate_with_system_trust validation result=", validation.value ? "true" : "false");
        return PkiResult<bool>::ok(validation.value);
    }

} // namespace authbox::pik

namespace authbox {
    namespace pki = pik;
}
