#pragma once

#include <algorithm>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <pki/certificate.hpp>
#include <pki/files.hpp>
#include <pki/pem.hpp>

namespace authbox::pik {

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
            auto file = keylock::io::read_binary(path);
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

    // Implementation of Certificate::validate_chain requires complete TrustStore type
    inline CertificateBoolResult Certificate::validate_chain(const std::vector<Certificate> &chain,
                                                             const TrustStore &trust) const {
        std::vector<const Certificate *> order;
        order.push_back(this);
        for (const auto &cert : chain) {
            order.push_back(&cert);
        }

        std::vector<bool> is_ca(order.size(), false);
        for (size_t idx = 0; idx < order.size(); ++idx) {
            is_ca[idx] = order[idx]->basic_constraints_ca().value_or(false);
        }

        // Count intermediate CAs between subject and issuer (not including issuer itself)
        // This is used to check pathLenConstraint
        auto intermediate_ca_count = [&](size_t subject_idx, size_t issuer_idx) -> size_t {
            size_t count = 0;
            // Count CAs between subject and issuer (exclusive on both ends)
            for (size_t i = subject_idx + 1; i < issuer_idx; ++i) {
                if (is_ca[i]) {
                    ++count;
                }
            }
            return count;
        };

        auto validate_link = [&](size_t child_idx, size_t issuer_idx, const Certificate &child,
                                 const Certificate &issuer) -> CertificateBoolResult {
            auto sig = child.verify_signature(issuer);
            if (!sig.success) {
                return sig;
            }
            if (!sig.value) {
                return CertificateBoolResult::ok(false);
            }
            if (!child.check_validity()) {
                return CertificateBoolResult::ok(false);
            }
            // Issuer certificate must also be within its validity period
            if (!issuer.check_validity()) {
                return CertificateBoolResult::ok(false);
            }
            if (!issuer.basic_constraints_ca().value_or(false)) {
                return CertificateBoolResult::ok(false);
            }
            // If KeyUsage is present on the issuer, it must include keyCertSign
            if (auto ku = issuer.key_usage_bits()) {
                if (static_cast<uint16_t>(*ku & KeyUsageExtension::KeyCertSign) == 0) {
                    return CertificateBoolResult::ok(false);
                }
            }
            auto path_len = issuer.basic_constraints_path_length();
            if (path_len.has_value()) {
                // pathLenConstraint specifies the maximum number of intermediate CAs
                // that can follow this CA in the certification path
                const auto intermediates = intermediate_ca_count(child_idx, issuer_idx);
                if (intermediates > path_len.value()) {
                    return CertificateBoolResult::ok(false);
                }
            }
            return CertificateBoolResult::ok(true);
        };

        for (size_t i = 0; i + 1 < order.size(); ++i) {
            auto result = validate_link(i, i + 1, *order[i], *order[i + 1]);
            if (!result.success || !result.value) {
                return result;
            }
        }

        const Certificate &last = *order.back();
        auto anchor = trust.find_issuer(last);
        if (!anchor.has_value()) {
            return CertificateBoolResult::ok(false);
        }
        auto anchor_result = validate_link(order.size() - 1, order.size(), last, *anchor);
        if (!anchor_result.success || !anchor_result.value) {
            return anchor_result;
        }

        return CertificateBoolResult::ok(true);
    }

} // namespace authbox::pik
