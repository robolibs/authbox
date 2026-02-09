#pragma once

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <pki/certificate.hpp>
#include <pki/files.hpp>
#include <pki/pem.hpp>

namespace authbox::pik {

    enum class ChainValidationCode {
        Ok,
        ChainConstructionFailed,
        SignatureVerificationError,
        SignatureMismatch,
        CertificateNotYetValidOrExpired,
        IssuerNotCa,
        IssuerMissingKeyCertSign,
        PathLenConstraintViolated,
        TrustAnchorNotFound,
        UnknownCriticalExtension,
        Revoked,
        RevocationStatusUnknown,
    };

    struct ChainValidationReport {
        bool valid{false};
        ChainValidationCode code{ChainValidationCode::Ok};
        std::string message;
        size_t cert_index{0};
    };

    enum class RevocationPolicy {
        Off,
        BestEffort,
        Strict,
    };

    struct ChainValidationOptions {
        bool reject_unknown_critical_extensions{false};
        RevocationPolicy revocation_policy{RevocationPolicy::Off};
        std::function<std::optional<bool>(const Certificate &)> revocation_checker{};
    };

    namespace detail {
        inline bool has_unknown_critical_extension(const Certificate &cert) {
            for (const auto &ext : cert.tbs().extensions) {
                if (ext.id == ExtensionId::Unknown && ext.critical) {
                    return true;
                }
            }
            return false;
        }

        inline CertificateResult<ChainValidationReport> run_revocation_check(const Certificate &cert, size_t cert_index,
                                                                             const ChainValidationOptions &options) {
            if (options.revocation_policy == RevocationPolicy::Off) {
                return CertificateResult<ChainValidationReport>::ok({true, ChainValidationCode::Ok, "", cert_index});
            }
            if (!options.revocation_checker) {
                if (options.revocation_policy == RevocationPolicy::Strict) {
                    return CertificateResult<ChainValidationReport>::ok(
                        {false, ChainValidationCode::RevocationStatusUnknown, "No revocation checker configured",
                         cert_index});
                }
                return CertificateResult<ChainValidationReport>::ok({true, ChainValidationCode::Ok, "", cert_index});
            }

            auto revocation = options.revocation_checker(cert);
            if (!revocation.has_value()) {
                if (options.revocation_policy == RevocationPolicy::Strict) {
                    return CertificateResult<ChainValidationReport>::ok(
                        {false, ChainValidationCode::RevocationStatusUnknown, "Revocation status unknown", cert_index});
                }
                return CertificateResult<ChainValidationReport>::ok({true, ChainValidationCode::Ok, "", cert_index});
            }

            if (revocation.value()) {
                return CertificateResult<ChainValidationReport>::ok(
                    {false, ChainValidationCode::Revoked, "Certificate is revoked", cert_index});
            }
            return CertificateResult<ChainValidationReport>::ok({true, ChainValidationCode::Ok, "", cert_index});
        }
    } // namespace detail

    class TrustStore {
      public:
        TrustStore() = default;

        inline bool add(const Certificate &cert) {
            anchors_.push_back(cert);
            return true;
        }

        inline bool remove_by_subject(const DistinguishedName &subject) {
            auto original = anchors_.size();
            anchors_.erase(
                std::remove_if(anchors_.begin(), anchors_.end(),
                               [&](const Certificate &cert) { return cert.tbs().subject.der() == subject.der(); }),
                anchors_.end());
            return anchors_.size() != original;
        }

        inline std::optional<Certificate> find_issuer(const Certificate &cert) const {
            for (const auto &anchor : anchors_) {
                if (anchor.tbs().subject.der() == cert.tbs().issuer.der()) {
                    return anchor;
                }
            }
            return std::nullopt;
        }

        inline bool contains_subject(const DistinguishedName &subject) const {
            for (const auto &anchor : anchors_) {
                if (anchor.tbs().subject.der() == subject.der()) {
                    return true;
                }
            }
            return false;
        }

        const std::vector<Certificate> &anchors() const { return anchors_; }

        static inline CertificateResult<TrustStore> load_from_pem(const std::string &path) {
            auto chain = Certificate::load(path, true);
            if (!chain.success) {
                return CertificateResult<TrustStore>::failure(chain.error);
            }
            TrustStore store;
            for (const auto &cert : chain.value) {
                store.add(cert);
            }
            return CertificateResult<TrustStore>::ok(std::move(store));
        }

        static inline CertificateResult<TrustStore> load_from_der(const std::string &path) {
            auto chain = Certificate::load(path, true);
            if (!chain.success) {
                return CertificateResult<TrustStore>::failure(chain.error);
            }
            TrustStore store;
            for (const auto &cert : chain.value) {
                store.add(cert);
            }
            return CertificateResult<TrustStore>::ok(std::move(store));
        }

        static inline CertificateResult<TrustStore> load_from_file(const std::string &path) {
            auto file = authbox::io::read_binary(path);
            if (!file.success) {
                return CertificateResult<TrustStore>::failure(file.error_message);
            }
            const std::string_view contents(reinterpret_cast<const char *>(file.data.data()), file.data.size());
            if (contents.find("-----BEGIN") != std::string_view::npos) {
                return load_from_pem(path);
            }
            return load_from_der(path);
        }

        static inline CertificateResult<TrustStore> load_from_system() {
            // 1) Explicit file via environment - if set, use it exclusively (no fallback)
            if (const char *env_file = std::getenv("SSL_CERT_FILE"); env_file && env_file[0] != '\0') {
                auto store = load_from_file(env_file);
                if (store.success) {
                    return store;
                }
                return CertificateResult<TrustStore>::failure("SSL_CERT_FILE set but failed to load: " + store.error);
            }

            // 2) Directory of CA files (hashed or flat), take first readable cert bundle inside
            if (const char *env_dir = std::getenv("SSL_CERT_DIR"); env_dir && env_dir[0] != '\0') {
                // Common hashed dir layout: many individual PEMs or symlinks; we can try well-known distro bundle names
                // in it
                const std::string dir(env_dir);
                const std::string candidates[] = {
                    dir + "/ca-certificates.crt",
                    dir + "/ca-bundle.crt",
                    dir + "/cert.pem",
                };
                for (const auto &candidate_path : candidates) {
                    if (auto store = load_from_file(candidate_path); store.success) {
                        return store;
                    }
                }
            }

            // 3) OS defaults
            constexpr const char *default_paths[] = {
                "/etc/ssl/certs/ca-certificates.crt",    // Debian/Ubuntu
                "/etc/pki/tls/certs/ca-bundle.crt",      // CentOS/RHEL
                "/usr/local/share/certs/ca-root-nss.crt" // FreeBSD
            };
            for (const auto *default_path : default_paths) {
                if (auto store = load_from_file(default_path); store.success) {
                    return store;
                }
            }

            return CertificateResult<TrustStore>::failure("unable to locate system trust store");
        }

      private:
        std::vector<Certificate> anchors_;
    };

    inline CertificateResult<ChainValidationReport>
    validate_chain_detailed(const Certificate &leaf, const std::vector<Certificate> &chain, const TrustStore &trust,
                            const ChainValidationOptions &options = {}) {
        std::vector<const Certificate *> order;
        order.push_back(&leaf);

        std::vector<const Certificate *> remaining;
        remaining.reserve(chain.size());
        for (const auto &cert : chain) {
            remaining.push_back(&cert);
        }

        const Certificate *current = &leaf;
        while (!remaining.empty()) {
            auto it = std::find_if(remaining.begin(), remaining.end(), [&](const Certificate *candidate) {
                return candidate->tbs().subject.der() == current->tbs().issuer.der();
            });
            if (it == remaining.end()) {
                break;
            }
            current = *it;
            order.push_back(current);
            remaining.erase(it);
        }

        if (!remaining.empty()) {
            return CertificateResult<ChainValidationReport>::ok(
                {false, ChainValidationCode::ChainConstructionFailed, "Provided chain cannot be linked by issuer", 0});
        }

        std::vector<bool> is_ca(order.size(), false);
        for (size_t idx = 0; idx < order.size(); ++idx) {
            is_ca[idx] = order[idx]->basic_constraints_ca().value_or(false);
            if (options.reject_unknown_critical_extensions && detail::has_unknown_critical_extension(*order[idx])) {
                return CertificateResult<ChainValidationReport>::ok(
                    {false, ChainValidationCode::UnknownCriticalExtension, "Unknown critical extension present", idx});
            }

            auto rev = detail::run_revocation_check(*order[idx], idx, options);
            if (!rev.success) {
                return rev;
            }
            if (!rev.value.valid) {
                return rev;
            }
        }

        auto intermediate_ca_count = [&](size_t subject_idx, size_t issuer_idx) -> size_t {
            size_t count = 0;
            for (size_t i = subject_idx + 1; i < issuer_idx; ++i) {
                if (is_ca[i]) {
                    ++count;
                }
            }
            return count;
        };

        auto validate_link = [&](size_t child_idx, size_t issuer_idx, const Certificate &child,
                                 const Certificate &issuer) -> CertificateResult<ChainValidationReport> {
            auto sig = child.verify_signature(issuer);
            if (!sig.success) {
                return CertificateResult<ChainValidationReport>::ok(
                    {false, ChainValidationCode::SignatureVerificationError, sig.error, child_idx});
            }
            if (!sig.value) {
                return CertificateResult<ChainValidationReport>::ok(
                    {false, ChainValidationCode::SignatureMismatch, "Certificate signature mismatch", child_idx});
            }
            if (!child.check_validity()) {
                return CertificateResult<ChainValidationReport>::ok(
                    {false, ChainValidationCode::CertificateNotYetValidOrExpired,
                     "Certificate validity period check failed", child_idx});
            }
            if (!issuer.check_validity()) {
                return CertificateResult<ChainValidationReport>::ok(
                    {false, ChainValidationCode::CertificateNotYetValidOrExpired, "Issuer validity period check failed",
                     issuer_idx});
            }
            if (!issuer.basic_constraints_ca().value_or(false)) {
                return CertificateResult<ChainValidationReport>::ok(
                    {false, ChainValidationCode::IssuerNotCa, "Issuer is not a CA", issuer_idx});
            }
            if (auto ku = issuer.key_usage_bits()) {
                if (static_cast<uint16_t>(*ku & KeyUsageExtension::KeyCertSign) == 0) {
                    return CertificateResult<ChainValidationReport>::ok(
                        {false, ChainValidationCode::IssuerMissingKeyCertSign,
                         "Issuer keyUsage does not allow certificate signing", issuer_idx});
                }
            }
            auto path_len = issuer.basic_constraints_path_length();
            if (path_len.has_value()) {
                const auto intermediates = intermediate_ca_count(child_idx, issuer_idx);
                if (intermediates > path_len.value()) {
                    return CertificateResult<ChainValidationReport>::ok(
                        {false, ChainValidationCode::PathLenConstraintViolated,
                         "pathLenConstraint violated by certification path", issuer_idx});
                }
            }
            return CertificateResult<ChainValidationReport>::ok({true, ChainValidationCode::Ok, "", child_idx});
        };

        for (size_t i = 0; i + 1 < order.size(); ++i) {
            auto result = validate_link(i, i + 1, *order[i], *order[i + 1]);
            if (!result.success || !result.value.valid) {
                return result;
            }
        }

        const Certificate &last = *order.back();
        if (trust.contains_subject(last.tbs().subject)) {
            if (options.reject_unknown_critical_extensions && detail::has_unknown_critical_extension(last)) {
                return CertificateResult<ChainValidationReport>::ok(
                    {false, ChainValidationCode::UnknownCriticalExtension,
                     "Unknown critical extension present on trust anchor", order.size() - 1});
            }

            if (!last.check_validity()) {
                return CertificateResult<ChainValidationReport>::ok(
                    {false, ChainValidationCode::CertificateNotYetValidOrExpired, "Trust anchor validity check failed",
                     order.size() - 1});
            }
            if (!last.basic_constraints_ca().value_or(false)) {
                return CertificateResult<ChainValidationReport>::ok(
                    {false, ChainValidationCode::IssuerNotCa, "Trust anchor is not a CA", order.size() - 1});
            }
            if (auto ku = last.key_usage_bits()) {
                if (static_cast<uint16_t>(*ku & KeyUsageExtension::KeyCertSign) == 0) {
                    return CertificateResult<ChainValidationReport>::ok(
                        {false, ChainValidationCode::IssuerMissingKeyCertSign,
                         "Trust anchor keyUsage does not allow certificate signing", order.size() - 1});
                }
            }

            if (last.tbs().subject.der() == last.tbs().issuer.der()) {
                auto self_sig = last.verify_signature(last);
                if (!self_sig.success) {
                    return CertificateResult<ChainValidationReport>::ok(
                        {false, ChainValidationCode::SignatureVerificationError, self_sig.error, order.size() - 1});
                }
                if (!self_sig.value) {
                    return CertificateResult<ChainValidationReport>::ok({false, ChainValidationCode::SignatureMismatch,
                                                                         "Trust anchor self-signature mismatch",
                                                                         order.size() - 1});
                }
            }

            auto rev = detail::run_revocation_check(last, order.size() - 1, options);
            if (!rev.success || !rev.value.valid) {
                return rev;
            }

            return CertificateResult<ChainValidationReport>::ok({true, ChainValidationCode::Ok, "", order.size() - 1});
        }

        auto anchor = trust.find_issuer(last);
        if (!anchor.has_value()) {
            return CertificateResult<ChainValidationReport>::ok(
                {false, ChainValidationCode::TrustAnchorNotFound, "Trust anchor not found", order.size()});
        }

        if (options.reject_unknown_critical_extensions && detail::has_unknown_critical_extension(*anchor)) {
            return CertificateResult<ChainValidationReport>::ok({false, ChainValidationCode::UnknownCriticalExtension,
                                                                 "Unknown critical extension present on trust anchor",
                                                                 order.size()});
        }

        auto anchor_result = validate_link(order.size() - 1, order.size(), last, *anchor);
        if (!anchor_result.success || !anchor_result.value.valid) {
            return anchor_result;
        }

        auto rev = detail::run_revocation_check(*anchor, order.size(), options);
        if (!rev.success || !rev.value.valid) {
            return rev;
        }

        return CertificateResult<ChainValidationReport>::ok({true, ChainValidationCode::Ok, "", order.size()});
    }

    // Implementation of Certificate::validate_chain requires complete TrustStore type
    inline CertificateBoolResult Certificate::validate_chain(const std::vector<Certificate> &chain,
                                                             const TrustStore &trust) const {
        auto detailed = validate_chain_detailed(*this, chain, trust);
        if (!detailed.success) {
            return CertificateBoolResult::failure(detailed.error);
        }
        return CertificateBoolResult::ok(detailed.value.valid);
    }

} // namespace authbox::pik
