#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <keylock/crypto/context.hpp>
#include <keylock/hash/context.hpp>
#include <pki/asn1_common.hpp>
#include <pki/asn1_utils.hpp>
#include <pki/asn1_writer.hpp>
#include <pki/distinguished_name.hpp>
#include <pki/files.hpp>
#include <pki/oid_registry.hpp>
#include <pki/pem.hpp>

// Forward declarations for verify module
namespace authbox::pik::verify {
    class Client;
}

namespace authbox::pik {

    // Forward declarations
    class Crl;
    class TrustStore;

    struct Validity {
        std::chrono::system_clock::time_point not_before{};
        std::chrono::system_clock::time_point not_after{};

        [[nodiscard]] bool contains(std::chrono::system_clock::time_point time) const noexcept {
            return time >= not_before && time <= not_after;
        }
    };

    // SubjectPublicKeyInfo and RawExtension are defined in asn1_common.hpp

    enum class CertificateFormat { DER, PEM };

    template <typename T> struct CertificateResult {
        bool success{};
        T value{};
        std::string error{};

        static CertificateResult<T> failure(std::string message) {
            return CertificateResult<T>{false, {}, std::move(message)};
        }

        static CertificateResult<T> ok(T value) { return CertificateResult<T>{true, std::move(value), {}}; }
    };

    class Certificate;

    using CertificateParseResult = CertificateResult<Certificate>;
    using CertificateChainResult = CertificateResult<std::vector<Certificate>>;
    using CertificateSignatureResult = CertificateResult<std::vector<uint8_t>>;
    using CertificateBoolResult = CertificateResult<bool>;

    enum class CertificatePurpose { TLSServer, TLSClient, CodeSigning };

    class Extension {
      public:
        Extension(ExtensionId id, bool critical) : id_(id), critical_(critical) {}
        virtual ~Extension() = default;

        [[nodiscard]] ExtensionId id() const noexcept { return id_; }

        [[nodiscard]] bool critical() const noexcept { return critical_; }

      private:
        ExtensionId id_;
        bool critical_;
    };

    class BasicConstraintsExtension : public Extension {
      public:
        BasicConstraintsExtension(bool critical, bool ca_flag, std::optional<uint32_t> path_length)
            : Extension(ExtensionId::BasicConstraints, critical), ca_(ca_flag), path_length_(path_length) {}

        [[nodiscard]] bool is_ca() const noexcept { return ca_; }

        [[nodiscard]] const std::optional<uint32_t> &path_length() const noexcept { return path_length_; }

      private:
        bool ca_{false};
        std::optional<uint32_t> path_length_{};
    };

    class KeyUsageExtension : public Extension {
      public:
        enum : uint16_t {
            DigitalSignature = 0x8000,
            NonRepudiation = 0x4000,
            KeyEncipherment = 0x2000,
            DataEncipherment = 0x1000,
            KeyAgreement = 0x0800,
            KeyCertSign = 0x0400,
            CRLSign = 0x0200,
            EncipherOnly = 0x0100,
            DecipherOnly = 0x0080
        };

        KeyUsageExtension(bool critical, uint16_t bits) : Extension(ExtensionId::KeyUsage, critical), bits_(bits) {}

        [[nodiscard]] bool has(uint16_t flag) const noexcept { return (bits_ & flag) != 0; }

        [[nodiscard]] uint16_t bits() const noexcept { return bits_; }

      private:
        uint16_t bits_{0};
    };

    class SubjectKeyIdentifierExtension : public Extension {
      public:
        SubjectKeyIdentifierExtension(bool critical, std::vector<uint8_t> identifier)
            : Extension(ExtensionId::SubjectKeyIdentifier, critical), identifier_(std::move(identifier)) {}

        [[nodiscard]] const std::vector<uint8_t> &identifier() const noexcept { return identifier_; }

      private:
        std::vector<uint8_t> identifier_;
    };

    class AuthorityKeyIdentifierExtension : public Extension {
      public:
        AuthorityKeyIdentifierExtension(bool critical, std::vector<uint8_t> key_id)
            : Extension(ExtensionId::AuthorityKeyIdentifier, critical), key_identifier_(std::move(key_id)) {}

        [[nodiscard]] const std::vector<uint8_t> &key_identifier() const noexcept { return key_identifier_; }

      private:
        std::vector<uint8_t> key_identifier_;
    };

    class SubjectAltNameExtension : public Extension {
      public:
        enum class GeneralNameType { DNSName, URI, IPAddress, Email, Other };

        struct GeneralName {
            GeneralNameType type;
            std::string value;
        };

        SubjectAltNameExtension(bool critical, std::vector<GeneralName> names)
            : Extension(ExtensionId::SubjectAltName, critical), names_(std::move(names)) {}

        [[nodiscard]] const std::vector<GeneralName> &names() const noexcept { return names_; }

      private:
        std::vector<GeneralName> names_;
    };

    class ExtendedKeyUsageExtension : public Extension {
      public:
        // RFC 5280 standard Extended Key Usage OIDs
        enum class KeyPurposeId {
            Unknown,
            ServerAuth,         // TLS Web Server Authentication (1.3.6.1.5.5.7.3.1)
            ClientAuth,         // TLS Web Client Authentication (1.3.6.1.5.5.7.3.2)
            CodeSigning,        // Code Signing (1.3.6.1.5.5.7.3.3)
            EmailProtection,    // E-mail Protection (1.3.6.1.5.5.7.3.4)
            TimeStamping,       // Time Stamping (1.3.6.1.5.5.7.3.8)
            OCSPSigning,        // OCSP Signing (1.3.6.1.5.5.7.3.9)
            AnyExtendedKeyUsage // anyExtendedKeyUsage (2.5.29.37.0)
        };

        ExtendedKeyUsageExtension(bool critical, std::vector<Oid> purpose_oids)
            : Extension(ExtensionId::ExtendedKeyUsage, critical), purpose_oids_(std::move(purpose_oids)) {}

        [[nodiscard]] const std::vector<Oid> &purpose_oids() const noexcept { return purpose_oids_; }

        [[nodiscard]] bool has_purpose(KeyPurposeId purpose) const noexcept;
        [[nodiscard]] bool has_purpose(const Oid &purpose_oid) const noexcept;
        [[nodiscard]] std::vector<KeyPurposeId> recognized_purposes() const noexcept;

        // Helper methods for common purposes
        [[nodiscard]] bool allows_server_auth() const noexcept { return has_purpose(KeyPurposeId::ServerAuth); }
        [[nodiscard]] bool allows_client_auth() const noexcept { return has_purpose(KeyPurposeId::ClientAuth); }
        [[nodiscard]] bool allows_code_signing() const noexcept { return has_purpose(KeyPurposeId::CodeSigning); }
        [[nodiscard]] bool allows_email_protection() const noexcept {
            return has_purpose(KeyPurposeId::EmailProtection);
        }
        [[nodiscard]] bool allows_any() const noexcept { return has_purpose(KeyPurposeId::AnyExtendedKeyUsage); }

        // Static helper to convert KeyPurposeId to OID
        static Oid purpose_to_oid(KeyPurposeId purpose);
        static KeyPurposeId oid_to_purpose(const Oid &oid);

      private:
        std::vector<Oid> purpose_oids_;
    };

    // Phase 13: Enterprise Extensions

    class IssuerAltNameExtension : public Extension {
      public:
        using GeneralNameType = SubjectAltNameExtension::GeneralNameType;
        using GeneralName = SubjectAltNameExtension::GeneralName;

        IssuerAltNameExtension(bool critical, std::vector<GeneralName> names)
            : Extension(ExtensionId::IssuerAltName, critical), names_(std::move(names)) {}

        [[nodiscard]] const std::vector<GeneralName> &names() const noexcept { return names_; }

      private:
        std::vector<GeneralName> names_;
    };

    class PolicyMappingsExtension : public Extension {
      public:
        struct PolicyMapping {
            std::vector<uint32_t> issuer_domain_policy;
            std::vector<uint32_t> subject_domain_policy;
        };

        PolicyMappingsExtension(bool critical, std::vector<PolicyMapping> mappings)
            : Extension(ExtensionId::PolicyMappings, critical), mappings_(std::move(mappings)) {}

        [[nodiscard]] const std::vector<PolicyMapping> &mappings() const noexcept { return mappings_; }

      private:
        std::vector<PolicyMapping> mappings_;
    };

    class PolicyConstraintsExtension : public Extension {
      public:
        PolicyConstraintsExtension(bool critical, std::optional<uint32_t> require_explicit_policy,
                                   std::optional<uint32_t> inhibit_policy_mapping)
            : Extension(ExtensionId::PolicyConstraints, critical), require_explicit_policy_(require_explicit_policy),
              inhibit_policy_mapping_(inhibit_policy_mapping) {}

        [[nodiscard]] std::optional<uint32_t> require_explicit_policy() const noexcept {
            return require_explicit_policy_;
        }

        [[nodiscard]] std::optional<uint32_t> inhibit_policy_mapping() const noexcept {
            return inhibit_policy_mapping_;
        }

      private:
        std::optional<uint32_t> require_explicit_policy_;
        std::optional<uint32_t> inhibit_policy_mapping_;
    };

    class InhibitAnyPolicyExtension : public Extension {
      public:
        InhibitAnyPolicyExtension(bool critical, uint32_t skip_certs)
            : Extension(ExtensionId::InhibitAnyPolicy, critical), skip_certs_(skip_certs) {}

        [[nodiscard]] uint32_t skip_certs() const noexcept { return skip_certs_; }

      private:
        uint32_t skip_certs_;
    };

    struct TBSCertificate {
        int version{1};
        std::vector<uint8_t> serial_number;
        AlgorithmIdentifier signature{};
        DistinguishedName issuer{};
        Validity validity{};
        DistinguishedName subject{};
        SubjectPublicKeyInfo subject_public_key_info{};
        std::vector<RawExtension> extensions;
    };

} // namespace authbox::pik

// Include parser header after types are defined to avoid circular dependency
#include <pki/parser.hpp>

namespace authbox::pik {

    namespace detail {

        inline Certificate make_certificate_from_context(CertificateContext &&ctx);

        inline bool contains_pem_marker(std::string_view view) {
            return view.find("-----BEGIN") != std::string_view::npos;
        }

        inline bool contains_pem_marker(const std::vector<uint8_t> &data) {
            if (data.empty()) {
                return false;
            }
            const auto view = std::string_view(reinterpret_cast<const char *>(data.data()), data.size());
            return contains_pem_marker(view);
        }

        inline bool equals_case_insensitive(std::string_view a, std::string_view b) {
            if (a.size() != b.size()) {
                return false;
            }
            for (size_t i = 0; i < a.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
                    return false;
                }
            }
            return true;
        }

        inline std::vector<Oid> parse_extended_key_usage(const RawExtension &ext) {
            std::vector<Oid> oids;
            auto seq = parse_sequence(ByteSpan(ext.value.data(), ext.value.size()));
            if (!seq.success) {
                return oids;
            }
            size_t offset = 0;
            while (offset < seq.value.size()) {
                auto oid_res = parse_oid(seq.value.subspan(offset));
                if (!oid_res.success) {
                    break;
                }
                oids.push_back(oid_res.value);
                offset += oid_res.bytes_consumed;
            }
            return oids;
        }

        // Count dot-separated labels in a hostname
        inline size_t label_count(std::string_view name) {
            if (name.empty())
                return 0;
            size_t count = 1;
            for (char c : name) {
                if (c == '.')
                    count++;
            }
            return count;
        }

        inline bool parse_ipv4(std::string_view s, std::array<uint8_t, 4> &out) {
            int parts = 0;
            uint32_t acc = 0;
            int acc_len = 0;
            std::array<uint8_t, 4> bytes{};
            for (size_t i = 0; i <= s.size(); ++i) {
                char c = (i < s.size()) ? s[i] : '.'; // force flush at end
                if (c >= '0' && c <= '9') {
                    acc = acc * 10 + static_cast<uint32_t>(c - '0');
                    if (++acc_len > 3)
                        return false;
                    if (acc > 255)
                        return false;
                } else if (c == '.') {
                    if (acc_len == 0)
                        return false;
                    if (parts >= 4)
                        return false;
                    bytes[parts++] = static_cast<uint8_t>(acc);
                    acc = 0;
                    acc_len = 0;
                } else {
                    return false;
                }
            }
            if (parts != 4)
                return false;
            out = bytes;
            return true;
        }

        inline bool is_ipv4_literal(std::string_view s) {
            std::array<uint8_t, 4> tmp{};
            return parse_ipv4(s, tmp);
        }

        inline bool ipv4_equal_bytes(std::string_view bytes_str, const std::array<uint8_t, 4> &ip) {
            if (bytes_str.size() != 4)
                return false;
            const unsigned char *p = reinterpret_cast<const unsigned char *>(bytes_str.data());
            for (size_t i = 0; i < 4; ++i) {
                if (p[i] != ip[i])
                    return false;
            }
            return true;
        }

        // RFC 6125-style wildcard: only "*.example.com"-like patterns allowed
        inline bool wildcard_match(std::string_view pattern, std::string_view hostname) {
            // Lowercase copies for case-insensitive compare
            std::string p(pattern);
            std::string h(hostname);
            std::transform(p.begin(), p.end(), p.begin(), [](unsigned char c) { return std::tolower(c); });
            std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c) { return std::tolower(c); });

            auto star = p.find('*');
            if (star == std::string::npos) {
                return p == h;
            }

            // Only allow a single '*' at start of left-most label ("*.")
            if (star != 0)
                return false;
            if (p.size() < 3 || p[1] != '.')
                return false; // must be "*."
            if (p.find('*', 1) != std::string::npos)
                return false; // only one '*'

            std::string suffix = p.substr(2); // after '*.'
            if (suffix.empty())
                return false;

            // Wildcard covers exactly one label
            if (label_count(h) != label_count(p))
                return false;

            if (h.size() < suffix.size() + 1)
                return false; // need at least one label for '*'
            std::string host_suffix = h.substr(h.size() - suffix.size());
            if (host_suffix != suffix)
                return false;

            // Ensure the left-most portion is a single label (no dot)
            size_t prefix_len = h.size() - suffix.size();
            if (prefix_len == 0)
                return false;
            if (h[prefix_len - 1] != '.')
                return false;
            std::string left = h.substr(0, prefix_len - 1);
            return !left.empty() && left.find('.') == std::string::npos;
        }

    } // namespace detail

    class Certificate {
      public:
        Certificate() = default;
        Certificate(TBSCertificate tbs, AlgorithmIdentifier signature_algorithm, std::vector<uint8_t> signature_value,
                    std::vector<uint8_t> der, std::vector<uint8_t> tbs_der)
            : tbs_(std::move(tbs)), signature_algorithm_(signature_algorithm),
              signature_value_(std::move(signature_value)), der_(std::move(der)), tbs_der_(std::move(tbs_der)) {}

        [[nodiscard]] const TBSCertificate &tbs() const noexcept { return tbs_; }

        [[nodiscard]] const AlgorithmIdentifier &signature_algorithm() const noexcept { return signature_algorithm_; }

        [[nodiscard]] const std::vector<uint8_t> &signature_value() const noexcept { return signature_value_; }

        [[nodiscard]] const std::vector<uint8_t> &der() const noexcept { return der_; }

        [[nodiscard]] const std::vector<uint8_t> &tbs_der() const noexcept { return tbs_der_; }

        [[nodiscard]] std::vector<uint8_t> to_der() const { return der_; }

        [[nodiscard]] std::string to_pem(size_t line_length = 64) const;

        [[nodiscard]] bool save(const std::string &path, CertificateFormat format = CertificateFormat::PEM) const;
        CertificateSignatureResult sign(const keylock::crypto::Context::KeyPair &issuer_key,
                                        keylock::hash::Algorithm hash_alg = keylock::hash::Algorithm::SHA256) const;
        CertificateBoolResult verify_signature(const Certificate &issuer) const;
        bool check_validity(std::optional<std::chrono::system_clock::time_point> check_time = std::nullopt) const;

        static CertificateParseResult parse(ByteSpan der, bool relaxed = false);
        static CertificateParseResult parse(const std::vector<uint8_t> &der, bool relaxed = false);
        static CertificateChainResult parse_pem_chain(std::string_view pem, bool relaxed = false);
        static CertificateChainResult parse_der_chain(ByteSpan der, bool relaxed = false);
        static CertificateChainResult load(const std::string &path, bool relaxed = false);
        [[nodiscard]] std::optional<RawExtension> find_extension(ExtensionId id) const;
        [[nodiscard]] std::optional<bool> basic_constraints_ca() const;
        [[nodiscard]] std::optional<uint32_t> basic_constraints_path_length() const;
        [[nodiscard]] std::optional<uint16_t> key_usage_bits() const;
        [[nodiscard]] std::vector<SubjectAltNameExtension::GeneralName> subject_alt_names() const;
        [[nodiscard]] std::optional<ExtendedKeyUsageExtension> extended_key_usage() const;
        // Phase 13: Enterprise extensions
        [[nodiscard]] std::vector<IssuerAltNameExtension::GeneralName> issuer_alt_names() const;
        [[nodiscard]] std::vector<PolicyMappingsExtension::PolicyMapping> policy_mappings() const;
        [[nodiscard]] std::optional<PolicyConstraintsExtension> policy_constraints() const;
        [[nodiscard]] std::optional<uint32_t> inhibit_any_policy() const;
        bool verify_key_usage(uint16_t required_bits) const;
        bool verify_extensions(CertificatePurpose purpose) const;
        bool match_hostname(std::string_view hostname) const;
        bool match_subject(const DistinguishedName &dn) const;
        bool is_revoked(const Crl &crl) const;

        // Check revocation status via verification service
        CertificateBoolResult check_revocation(verify::Client &client) const;

        CertificateBoolResult validate_chain(const std::vector<Certificate> &chain, const TrustStore &trust) const;

        std::vector<uint8_t> public_key_der() const;
        std::vector<uint8_t> fingerprint(::keylock::hash::Algorithm algo) const;
        void print_info(std::ostream &os) const;
        std::string to_json() const;
        bool operator==(const Certificate &other) const noexcept { return der_ == other.der_; }
        bool equals_identity(const Certificate &other) const;

      private:
        TBSCertificate tbs_{};
        AlgorithmIdentifier signature_algorithm_{};
        std::vector<uint8_t> signature_value_{};
        std::vector<uint8_t> der_{};
        std::vector<uint8_t> tbs_der_{};
    };

    namespace detail {
        inline Certificate make_certificate_from_context(CertificateContext &&ctx) {
            TBSCertificate tbs{};
            tbs.version = ctx.version;
            tbs.serial_number = std::move(ctx.serial_number);
            tbs.signature = ctx.tbs_signature;
            tbs.issuer = std::move(ctx.issuer);
            tbs.subject = std::move(ctx.subject);
            tbs.validity = Validity{ctx.not_before, ctx.not_after};
            tbs.subject_public_key_info = std::move(ctx.subject_public_key_info);
            tbs.extensions = std::move(ctx.extensions);

            return Certificate(std::move(tbs), ctx.outer_signature, std::move(ctx.signature_value), std::move(ctx.der),
                               std::move(ctx.tbs_certificate));
        }
    } // namespace detail

    // Certificate static method implementations

    inline CertificateParseResult Certificate::parse(ByteSpan der, bool relaxed) {
        if (der.empty()) {
            return CertificateParseResult::failure("empty DER buffer");
        }

        ParseResult parsed = relaxed ? parse_x509_cert_relaxed(der) : parse_x509_cert(der);
        if (!parsed.success) {
            return CertificateParseResult::failure(parsed.error);
        }
        return CertificateParseResult::ok(detail::make_certificate_from_context(std::move(parsed.certificate)));
    }

    inline CertificateParseResult Certificate::parse(const std::vector<uint8_t> &der, bool relaxed) {
        return parse(ByteSpan(der.data(), der.size()), relaxed);
    }

    inline CertificateChainResult Certificate::parse_pem_chain(std::string_view pem, bool relaxed) {
        constexpr std::string_view kLabel = "CERTIFICATE";
        std::vector<Certificate> certificates;
        size_t cursor = 0;

        while (cursor < pem.size()) {
            const auto begin = pem.find("-----BEGIN", cursor);
            if (begin == std::string_view::npos) {
                break;
            }

            const size_t label_start = begin + std::string_view("-----BEGIN ").size();
            const auto label_end = pem.find("-----", label_start);
            if (label_end == std::string_view::npos) {
                break;
            }

            const auto found_label = pem.substr(label_start, label_end - label_start);
            if (found_label != kLabel) {
                cursor = label_end + std::string_view("-----").size();
                continue;
            }

            const auto block_view = pem.substr(begin);
            auto pem_res = pem_decode(block_view, kLabel);
            if (!pem_res.success) {
                return CertificateChainResult::failure(pem_res.error);
            }

            auto cert_res = Certificate::parse(pem_res.block.data, relaxed);
            if (!cert_res.success) {
                return CertificateChainResult::failure(cert_res.error);
            }
            certificates.push_back(std::move(cert_res.value));

            const std::string end_marker = "-----END " + std::string(kLabel) + "-----";
            const auto end_pos = pem.find(end_marker, begin);
            if (end_pos == std::string_view::npos) {
                cursor = begin + block_view.size();
                break;
            }
            cursor = end_pos + end_marker.size();
        }

        if (certificates.empty()) {
            return CertificateChainResult::failure("no certificates found in PEM data");
        }
        return CertificateChainResult::ok(std::move(certificates));
    }

    inline CertificateChainResult Certificate::parse_der_chain(ByteSpan der, bool relaxed) {
        std::vector<Certificate> certificates;
        size_t offset = 0;
        while (offset < der.size()) {
            const auto seq_result = parse_sequence(der.subspan(offset));
            if (!seq_result.success) {
                if (certificates.empty()) {
                    return CertificateChainResult::failure(seq_result.error);
                }
                break;
            }
            const size_t length = seq_result.bytes_consumed;
            if (length == 0 || offset + length > der.size()) {
                return CertificateChainResult::failure("truncated DER certificate");
            }

            auto cert_res = Certificate::parse(der.subspan(offset, length), relaxed);
            if (!cert_res.success) {
                return CertificateChainResult::failure(cert_res.error);
            }
            certificates.push_back(std::move(cert_res.value));
            offset += length;
        }

        if (certificates.empty()) {
            return CertificateChainResult::failure("no DER certificates found");
        }
        return CertificateChainResult::ok(std::move(certificates));
    }

    inline CertificateChainResult Certificate::load(const std::string &path, bool relaxed) {
        auto file = authbox::io::read_binary(path);
        if (!file.success) {
            return CertificateChainResult::failure(file.error_message);
        }
        if (file.data.empty()) {
            return CertificateChainResult::failure("certificate file is empty");
        }

        if (detail::contains_pem_marker(file.data)) {
            std::string pem_text(reinterpret_cast<const char *>(file.data.data()), file.data.size());
            return parse_pem_chain(pem_text, relaxed);
        }

        return parse_der_chain(ByteSpan(file.data.data(), file.data.size()), relaxed);
    }

    inline std::string Certificate::to_pem(size_t line_length) const {
        return pem_encode(ByteSpan(der_.data(), der_.size()), "CERTIFICATE", line_length);
    }

    inline bool Certificate::save(const std::string &path, CertificateFormat format) const {
        if (format == CertificateFormat::DER) {
            return authbox::io::write_binary(der_, path);
        }

        const auto pem = to_pem();
        std::vector<uint8_t> pem_bytes(pem.begin(), pem.end());
        return authbox::io::write_binary(pem_bytes, path);
    }

    inline CertificateSignatureResult Certificate::sign(const keylock::crypto::Context::KeyPair &issuer_key,
                                                        keylock::hash::Algorithm) const {
        if (signature_algorithm_.signature != SignatureAlgorithmId::Ed25519) {
            return CertificateSignatureResult::failure("Unsupported signature algorithm");
        }
        keylock::crypto::Context signer(keylock::crypto::Context::Algorithm::Ed25519);
        auto result = signer.sign(tbs_der_, issuer_key.private_key);
        if (!result.success) {
            return CertificateSignatureResult::failure(result.error_message);
        }
        return CertificateSignatureResult::ok(result.data);
    }

    inline CertificateBoolResult Certificate::verify_signature(const Certificate &issuer) const {
        if (signature_algorithm_.signature != SignatureAlgorithmId::Ed25519 ||
            issuer.tbs_.subject_public_key_info.algorithm.signature != SignatureAlgorithmId::Ed25519) {
            return CertificateBoolResult::failure("Unsupported signature algorithm for verification");
        }

        keylock::crypto::Context verifier(keylock::crypto::Context::Algorithm::Ed25519);
        auto verify_result =
            verifier.verify(tbs_der_, signature_value_, issuer.tbs_.subject_public_key_info.public_key);
        if (!verify_result.success) {
            if (verify_result.error_message == "Ed25519 signature verification failed") {
                return CertificateBoolResult::ok(false);
            }
            return CertificateBoolResult::failure(verify_result.error_message);
        }
        return CertificateBoolResult::ok(true);
    }

    inline bool Certificate::check_validity(std::optional<std::chrono::system_clock::time_point> check_time) const {
        auto time = check_time.value_or(std::chrono::system_clock::now());
        return tbs_.validity.contains(time);
    }

    inline std::optional<RawExtension> Certificate::find_extension(ExtensionId id) const {
        auto it = std::find_if(tbs_.extensions.begin(), tbs_.extensions.end(),
                               [&](const RawExtension &ext) { return ext.id == id; });
        if (it == tbs_.extensions.end()) {
            return std::nullopt;
        }
        return *it;
    }

    inline std::optional<bool> Certificate::basic_constraints_ca() const {
        auto ext = find_extension(ExtensionId::BasicConstraints);
        if (!ext) {
            return std::nullopt;
        }
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return std::nullopt;
        }
        detail::DerCursor cursor(seq.value);
        if (cursor.empty()) {
            return false;
        }
        auto bool_res = parse_boolean(cursor.remaining());
        if (!bool_res.success) {
            return std::nullopt;
        }
        return bool_res.value;
    }

    inline std::optional<uint32_t> Certificate::basic_constraints_path_length() const {
        auto ext = find_extension(ExtensionId::BasicConstraints);
        if (!ext) {
            return std::nullopt;
        }
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return std::nullopt;
        }
        detail::DerCursor cursor(seq.value);
        auto bool_res = parse_boolean(cursor.remaining());
        if (bool_res.success) {
            cursor.advance(bool_res.bytes_consumed);
        }
        if (cursor.empty()) {
            return std::nullopt;
        }
        auto int_res = parse_integer(cursor.remaining());
        if (!int_res.success) {
            return std::nullopt;
        }
        uint32_t value = 0;
        for (auto byte : int_res.value) {
            value = (value << 8U) | byte;
        }
        return value;
    }

    inline std::optional<uint16_t> Certificate::key_usage_bits() const {
        auto ext = find_extension(ExtensionId::KeyUsage);
        if (!ext) {
            return std::nullopt;
        }
        auto bit = parse_bit_string(ByteSpan(ext->value.data(), ext->value.size()));
        if (!bit.success) {
            return std::nullopt;
        }
        uint16_t value = 0;
        for (auto byte : bit.value.bytes) {
            value = static_cast<uint16_t>((value << 8U) | byte);
        }
        return value;
    }

    inline std::vector<SubjectAltNameExtension::GeneralName> Certificate::subject_alt_names() const {
        std::vector<SubjectAltNameExtension::GeneralName> names;
        auto ext = find_extension(ExtensionId::SubjectAltName);
        if (!ext) {
            return names;
        }
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return names;
        }
        size_t offset = 0;
        auto view = seq.value;
        while (offset < view.size()) {
            auto header = parse_id_len(view.subspan(offset));
            if (!header.success) {
                break;
            }
            const auto &id = header.value.identifier;
            if (id.tag_class != ASN1Class::ContextSpecific) {
                break;
            }
            auto content = view.subspan(offset + header.value.header_bytes, header.value.length);
            SubjectAltNameExtension::GeneralName name{};
            switch (id.tag_number) {
            case 1:
                name.type = SubjectAltNameExtension::GeneralNameType::Email;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 2:
                name.type = SubjectAltNameExtension::GeneralNameType::DNSName;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 6:
                name.type = SubjectAltNameExtension::GeneralNameType::URI;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 7:
                name.type = SubjectAltNameExtension::GeneralNameType::IPAddress;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            default:
                name.type = SubjectAltNameExtension::GeneralNameType::Other;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            }
            names.push_back(std::move(name));
            offset += header.bytes_consumed;
        }
        return names;
    }

    inline std::optional<ExtendedKeyUsageExtension> Certificate::extended_key_usage() const {
        auto ext = find_extension(ExtensionId::ExtendedKeyUsage);
        if (!ext) {
            return std::nullopt;
        }
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return std::nullopt;
        }
        std::vector<Oid> oids;
        size_t offset = 0;
        while (offset < seq.value.size()) {
            auto oid_res = parse_oid(seq.value.subspan(offset));
            if (!oid_res.success) {
                break;
            }
            oids.push_back(oid_res.value);
            offset += oid_res.bytes_consumed;
        }
        return ExtendedKeyUsageExtension(ext->critical, std::move(oids));
    }

    // Phase 13: Enterprise Extensions Implementation

    inline std::vector<IssuerAltNameExtension::GeneralName> Certificate::issuer_alt_names() const {
        std::vector<IssuerAltNameExtension::GeneralName> names;
        auto ext = find_extension(ExtensionId::IssuerAltName);
        if (!ext) {
            return names;
        }

        // IAN has same structure as SAN (GeneralNames SEQUENCE)
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return names;
        }

        size_t offset = 0;
        auto view = seq.value;
        while (offset < view.size()) {
            auto header = parse_id_len(view.subspan(offset));
            if (!header.success) {
                break;
            }
            const auto &id = header.value.identifier;
            if (id.tag_class != ASN1Class::ContextSpecific) {
                break;
            }
            auto content = view.subspan(offset + header.value.header_bytes, header.value.length);
            IssuerAltNameExtension::GeneralName name{};
            switch (id.tag_number) {
            case 1: // rfc822Name
                name.type = IssuerAltNameExtension::GeneralNameType::Email;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 2: // dNSName
                name.type = IssuerAltNameExtension::GeneralNameType::DNSName;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 6: // uniformResourceIdentifier
                name.type = IssuerAltNameExtension::GeneralNameType::URI;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            case 7: // iPAddress
                name.type = IssuerAltNameExtension::GeneralNameType::IPAddress;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            default: // otherName, x400Address, directoryName, ediPartyName, registeredID
                name.type = IssuerAltNameExtension::GeneralNameType::Other;
                name.value.assign(reinterpret_cast<const char *>(content.data()), content.size());
                break;
            }
            names.push_back(std::move(name));
            offset += header.bytes_consumed;
        }
        return names;
    }

    inline std::vector<PolicyMappingsExtension::PolicyMapping> Certificate::policy_mappings() const {
        std::vector<PolicyMappingsExtension::PolicyMapping> mappings;
        auto ext = find_extension(ExtensionId::PolicyMappings);
        if (!ext) {
            return mappings;
        }

        // MUST be critical per RFC 5280 (but we're lenient)
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return mappings;
        }

        size_t offset = 0;
        auto view = seq.value;
        while (offset < view.size()) {
            // Each mapping is a SEQUENCE { issuerDomainPolicy, subjectDomainPolicy }
            auto mapping_seq = parse_sequence(view.subspan(offset));
            if (!mapping_seq.success) {
                break;
            }

            size_t mapping_offset = 0;
            auto mapping_view = mapping_seq.value;

            // Parse issuerDomainPolicy (OID)
            auto issuer_oid = parse_oid(mapping_view.subspan(mapping_offset));
            if (!issuer_oid.success) {
                break;
            }
            mapping_offset += issuer_oid.bytes_consumed;

            // Parse subjectDomainPolicy (OID)
            auto subject_oid = parse_oid(mapping_view.subspan(mapping_offset));
            if (!subject_oid.success) {
                break;
            }

            PolicyMappingsExtension::PolicyMapping mapping{};
            mapping.issuer_domain_policy = issuer_oid.value.nodes;
            mapping.subject_domain_policy = subject_oid.value.nodes;
            mappings.push_back(std::move(mapping));

            offset += mapping_seq.bytes_consumed;
        }
        return mappings;
    }

    inline std::optional<PolicyConstraintsExtension> Certificate::policy_constraints() const {
        auto ext = find_extension(ExtensionId::PolicyConstraints);
        if (!ext) {
            return std::nullopt;
        }

        // MUST be critical per RFC 5280
        auto seq = parse_sequence(ByteSpan(ext->value.data(), ext->value.size()));
        if (!seq.success) {
            return std::nullopt;
        }

        std::optional<uint32_t> require_explicit_policy;
        std::optional<uint32_t> inhibit_policy_mapping;

        size_t offset = 0;
        auto view = seq.value;

        // Try to parse requireExplicitPolicy [0] IMPLICIT INTEGER OPTIONAL
        if (offset < view.size()) {
            auto header = parse_id_len(view.subspan(offset));
            if (header.success && header.value.identifier.tag_class == ASN1Class::ContextSpecific &&
                header.value.identifier.tag_number == 0) {
                auto content = view.subspan(offset + header.value.header_bytes, header.value.length);
                if (content.size() >= 1 && content.size() <= 4) {
                    uint32_t value = 0;
                    for (size_t i = 0; i < content.size(); ++i) {
                        value = (value << 8) | content[i];
                    }
                    require_explicit_policy = value;
                }
                offset += header.bytes_consumed;
            }
        }

        // Try to parse inhibitPolicyMapping [1] IMPLICIT INTEGER OPTIONAL
        if (offset < view.size()) {
            auto header = parse_id_len(view.subspan(offset));
            if (header.success && header.value.identifier.tag_class == ASN1Class::ContextSpecific &&
                header.value.identifier.tag_number == 1) {
                auto content = view.subspan(offset + header.value.header_bytes, header.value.length);
                if (content.size() >= 1 && content.size() <= 4) {
                    uint32_t value = 0;
                    for (size_t i = 0; i < content.size(); ++i) {
                        value = (value << 8) | content[i];
                    }
                    inhibit_policy_mapping = value;
                }
            }
        }

        // RFC 5280: MUST NOT issue certificates where policyConstraints is an empty sequence
        if (!require_explicit_policy && !inhibit_policy_mapping) {
            return std::nullopt;
        }

        return PolicyConstraintsExtension(ext->critical, require_explicit_policy, inhibit_policy_mapping);
    }

    inline std::optional<uint32_t> Certificate::inhibit_any_policy() const {
        auto ext = find_extension(ExtensionId::InhibitAnyPolicy);
        if (!ext) {
            return std::nullopt;
        }

        // MUST be critical per RFC 5280
        // Extension value is just a plain INTEGER (SkipCerts)
        auto int_result = parse_integer(ByteSpan(ext->value.data(), ext->value.size()));
        if (!int_result.success) {
            return std::nullopt;
        }

        // Convert bytes to uint32_t
        const auto &int_bytes = int_result.value;
        if (int_bytes.size() > 4) {
            return std::nullopt; // Too large
        }

        uint32_t value = 0;
        for (uint8_t byte : int_bytes) {
            value = (value << 8) | byte;
        }

        // RFC 5280: Reasonable limit (x509-parser uses 64)
        constexpr uint32_t MAX_SKIP_CERTS = 64;
        if (value > MAX_SKIP_CERTS) {
            return std::nullopt;
        }

        return value;
    }

    inline bool Certificate::verify_key_usage(uint16_t required_bits) const {
        auto bits = key_usage_bits();
        if (!bits) {
            return required_bits == 0;
        }
        return (bits.value() & required_bits) == required_bits;
    }

    inline bool Certificate::verify_extensions(CertificatePurpose purpose) const {
        auto eku = extended_key_usage();

        // Helper to check if purpose is allowed
        // If EKU is not present, all purposes are allowed (per RFC 5280)
        auto require_eku = [&](ExtendedKeyUsageExtension::KeyPurposeId purpose_id) {
            if (!eku.has_value()) {
                return true; // EKU not present, treat as any usage
            }
            return eku->has_purpose(purpose_id);
        };

        switch (purpose) {
        case CertificatePurpose::TLSServer: {
            if (!require_eku(ExtendedKeyUsageExtension::KeyPurposeId::ServerAuth)) {
                return false;
            }
            // For TLS Server: DigitalSignature is required for ECDSA/EdDSA
            // KeyEncipherment is only needed for RSA key exchange (TLS < 1.3)
            // We accept either DigitalSignature OR KeyEncipherment
            auto ku = key_usage_bits();
            if (!ku.has_value()) {
                return true; // No KeyUsage extension means any usage is allowed
            }
            return ((*ku & KeyUsageExtension::DigitalSignature) != 0) ||
                   ((*ku & KeyUsageExtension::KeyEncipherment) != 0);
        }
        case CertificatePurpose::TLSClient: {
            if (!require_eku(ExtendedKeyUsageExtension::KeyPurposeId::ClientAuth)) {
                return false;
            }
            constexpr uint16_t required = KeyUsageExtension::DigitalSignature;
            return verify_key_usage(required);
        }
        case CertificatePurpose::CodeSigning: {
            if (!require_eku(ExtendedKeyUsageExtension::KeyPurposeId::CodeSigning)) {
                return false;
            }
            constexpr uint16_t required = KeyUsageExtension::DigitalSignature | KeyUsageExtension::NonRepudiation;
            return verify_key_usage(required);
        }
        }
        return true;
    }

    inline bool Certificate::match_hostname(std::string_view hostname) const {
        auto names = subject_alt_names();
        const bool has_san = !names.empty();

        // If hostname is an IPv4 literal, only match against IPAddress SANs
        std::array<uint8_t, 4> ip4{};
        if (detail::is_ipv4_literal(hostname)) {
            detail::parse_ipv4(hostname, ip4);
            for (const auto &name : names) {
                if (name.type == SubjectAltNameExtension::GeneralNameType::IPAddress) {
                    if (detail::ipv4_equal_bytes(name.value, ip4)) {
                        return true;
                    }
                }
            }
            // If SANs exist, do not fall back to CN
            return false;
        }

        // Otherwise, match against DNSName SANs (RFC 6125)
        bool saw_dns_san = false;
        for (const auto &name : names) {
            if (name.type == SubjectAltNameExtension::GeneralNameType::DNSName) {
                saw_dns_san = true;
                if (detail::wildcard_match(name.value, hostname)) {
                    return true;
                }
            }
        }
        if (has_san) {
            // SAN present but no match
            return false;
        }

        // No SAN extension: fall back to Common Name
        if (auto cn = tbs_.subject.first(DistinguishedNameAttribute::CommonName)) {
            return detail::wildcard_match(*cn, hostname);
        }
        return false;
    }

    inline bool Certificate::match_subject(const DistinguishedName &dn) const { return tbs_.subject.der() == dn.der(); }

    inline std::vector<uint8_t> Certificate::fingerprint(::keylock::hash::Algorithm algo) const {
        auto result = ::keylock::hash::digest(algo, der_);
        if (!result.success) {
            throw std::runtime_error("Failed to compute certificate fingerprint: " + result.error_message);
        }
        return result.data;
    }

    inline void Certificate::print_info(std::ostream &os) const {
        auto to_string_time = [](std::chrono::system_clock::time_point tp) {
            auto t = std::chrono::system_clock::to_time_t(tp);
            std::tm tm{};
#if defined(_WIN32)
            gmtime_s(&tm, &t);
#else
            gmtime_r(&t, &tm);
#endif
            std::ostringstream ss;
            ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%SZ");
            return ss.str();
        };

        os << "Subject: " << tbs_.subject.to_string() << "\n";
        os << "Issuer: " << tbs_.issuer.to_string() << "\n";
        os << "Serial:";
        for (auto byte : tbs_.serial_number) {
            os << ' ' << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        os << std::dec << "\n";
        os << "Validity:\n"
           << "  Not Before: " << to_string_time(tbs_.validity.not_before) << "\n"
           << "  Not After : " << to_string_time(tbs_.validity.not_after) << "\n";
    }

    inline std::string Certificate::to_json() const {
        std::ostringstream oss;
        oss << "{" << "\"subject\":\"" << tbs_.subject.to_string() << "\"," << "\"issuer\":\""
            << tbs_.issuer.to_string() << "\"" << "}";
        return oss.str();
    }

    inline bool Certificate::equals_identity(const Certificate &other) const {
        return tbs_.subject.der() == other.tbs_.subject.der() &&
               tbs_.subject_public_key_info.public_key == other.tbs_.subject_public_key_info.public_key;
    }

    inline std::vector<uint8_t> Certificate::public_key_der() const {
        const auto &spki = tbs_.subject_public_key_info;
        std::vector<std::vector<uint8_t>> fields;
        auto oid = oid_for_signature(spki.algorithm.signature);
        if (!oid) {
            throw std::runtime_error("Failed to get OID for signature algorithm in subject public key info");
        }
        fields.push_back(der::encode_sequence(der::encode_oid(*oid)));
        fields.push_back(
            der::encode_bit_string(ByteSpan(spki.public_key.data(), spki.public_key.size()), spki.unused_bits));
        return der::encode_sequence(der::concat(fields));
    }

    // ExtendedKeyUsageExtension implementation

    inline Oid ExtendedKeyUsageExtension::purpose_to_oid(KeyPurposeId purpose) {
        switch (purpose) {
        case KeyPurposeId::ServerAuth:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}};
        case KeyPurposeId::ClientAuth:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 2}};
        case KeyPurposeId::CodeSigning:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 3}};
        case KeyPurposeId::EmailProtection:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 4}};
        case KeyPurposeId::TimeStamping:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 8}};
        case KeyPurposeId::OCSPSigning:
            return Oid{{1, 3, 6, 1, 5, 5, 7, 3, 9}};
        case KeyPurposeId::AnyExtendedKeyUsage:
            return Oid{{2, 5, 29, 37, 0}};
        default:
            return Oid{};
        }
    }

    inline ExtendedKeyUsageExtension::KeyPurposeId ExtendedKeyUsageExtension::oid_to_purpose(const Oid &oid) {
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 1}) {
            return KeyPurposeId::ServerAuth;
        }
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 2}) {
            return KeyPurposeId::ClientAuth;
        }
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 3}) {
            return KeyPurposeId::CodeSigning;
        }
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 4}) {
            return KeyPurposeId::EmailProtection;
        }
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 8}) {
            return KeyPurposeId::TimeStamping;
        }
        if (oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 9}) {
            return KeyPurposeId::OCSPSigning;
        }
        if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 37, 0}) {
            return KeyPurposeId::AnyExtendedKeyUsage;
        }
        return KeyPurposeId::Unknown;
    }

    inline bool ExtendedKeyUsageExtension::has_purpose(KeyPurposeId purpose) const noexcept {
        if (purpose == KeyPurposeId::Unknown) {
            return false;
        }
        auto target_oid = purpose_to_oid(purpose);
        return has_purpose(target_oid);
    }

    inline bool ExtendedKeyUsageExtension::has_purpose(const Oid &purpose_oid) const noexcept {
        // anyExtendedKeyUsage means all purposes are allowed
        for (const auto &oid : purpose_oids_) {
            if (oid.nodes == std::vector<uint32_t>{2, 5, 29, 37, 0}) {
                return true;
            }
        }
        // Check for exact match
        for (const auto &oid : purpose_oids_) {
            if (oid.nodes == purpose_oid.nodes) {
                return true;
            }
        }
        return false;
    }

    inline std::vector<ExtendedKeyUsageExtension::KeyPurposeId>
    ExtendedKeyUsageExtension::recognized_purposes() const noexcept {
        std::vector<KeyPurposeId> purposes;
        for (const auto &oid : purpose_oids_) {
            auto purpose = oid_to_purpose(oid);
            if (purpose != KeyPurposeId::Unknown) {
                purposes.push_back(purpose);
            }
        }
        return purposes;
    }

} // namespace authbox::pik

// NOTE: is_revoked() and validate_chain() implementations require complete Crl and TrustStore types.
// They are defined in crl.hpp and trust_store.hpp respectively, after those headers include certificate.hpp.
// Users who need these methods should include crl.hpp and/or trust_store.hpp.
