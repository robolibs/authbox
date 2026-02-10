#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <keylock/crypto/context.hpp>
#include <keylock/crypto/rng/randombytes.hpp>
#include <pki/asn1_writer.hpp>
#include <pki/certificate.hpp>
#include <pki/distinguished_name.hpp>
#include <pki/oid_registry.hpp>

namespace authbox::pik {

    namespace detail {

        inline std::vector<uint8_t> make_random_serial() {
            std::vector<uint8_t> serial(16);
            ::keylock::crypto::rng::randombytes_buf(serial.data(), serial.size());
            serial[0] &= 0x7FU; // ensure positive
            return serial;
        }

        inline Oid get_extension_oid(ExtensionId id) {
            if (auto oid = oid_for_extension(id)) {
                return *oid;
            }
            return {};
        }

        inline Oid get_signature_oid(SignatureAlgorithmId id) {
            if (auto oid = oid_for_signature(id)) {
                return *oid;
            }
            throw std::runtime_error("Failed to get OID for signature algorithm ID");
        }

        inline bool is_utctime(const std::tm &tm_value) {
            const int year = tm_value.tm_year + 1900;
            return year >= 1950 && year <= 2049;
        }

        inline std::tm to_gmtime(std::chrono::system_clock::time_point tp) {
            auto time = std::chrono::system_clock::to_time_t(tp);
            std::tm result{};
#if defined(_WIN32)
            gmtime_s(&result, &time);
#else
            gmtime_r(&time, &result);
#endif
            return result;
        }

    } // namespace detail

    class CertificateBuilder {
      public:
        inline CertificateBuilder &set_version(int version) {
            version_ = std::clamp(version, 1, 3);
            return *this;
        }

        inline CertificateBuilder &set_serial(const std::vector<uint8_t> &serial) {
            serial_number_ = serial;
            if (!serial_number_.empty()) {
                serial_number_[0] &= 0x7FU;
            }
            return *this;
        }

        inline CertificateBuilder &set_serial(uint64_t serial) {
            std::vector<uint8_t> buffer;
            bool started = false;
            for (int i = 7; i >= 0; --i) {
                uint8_t byte = static_cast<uint8_t>((serial >> (i * 8)) & 0xFFU);
                if (!started && byte == 0) {
                    continue;
                }
                started = true;
                buffer.push_back(byte);
            }
            if (buffer.empty()) {
                buffer.push_back(0);
            }
            return set_serial(buffer);
        }

        inline CertificateBuilder &
        set_signature_algorithm(SignatureAlgorithmId algorithm,
                                keylock::hash::Algorithm hash_alg = keylock::hash::Algorithm::SHA256) {
            signature_algorithm_.signature = algorithm;
            signature_algorithm_.hash = hash_alg;
            if (algorithm == SignatureAlgorithmId::Ed25519) {
                signature_algorithm_.curve = CurveId::Ed25519;
            }
            return *this;
        }

        inline CertificateBuilder &set_issuer(const DistinguishedName &dn) {
            issuer_ = dn;
            issuer_explicit_ = true;
            return *this;
        }

        inline CertificateBuilder &set_subject(const DistinguishedName &dn) {
            subject_ = dn;
            subject_explicit_ = true;
            return *this;
        }

        inline CertificateBuilder &set_subject_from_string(std::string_view dn) {
            auto parsed = DistinguishedName::from_string(dn);
            if (parsed.success) {
                subject_ = parsed.value;
                subject_explicit_ = true;
            }
            return *this;
        }

        inline CertificateBuilder &set_issuer_from_string(std::string_view dn) {
            auto parsed = DistinguishedName::from_string(dn);
            if (parsed.success) {
                issuer_ = parsed.value;
                issuer_explicit_ = true;
            }
            return *this;
        }

        inline CertificateBuilder &set_validity(std::chrono::system_clock::time_point not_before,
                                                std::chrono::system_clock::time_point not_after) {
            validity_.not_before = not_before;
            validity_.not_after = not_after;
            return *this;
        }

        inline CertificateBuilder &set_subject_public_key_info(const SubjectPublicKeyInfo &spki) {
            subject_public_key_info_ = spki;
            return *this;
        }

        inline CertificateBuilder &set_subject_public_key_ed25519(const std::vector<uint8_t> &public_key) {
            SubjectPublicKeyInfo spki{};
            spki.algorithm.signature = SignatureAlgorithmId::Ed25519;
            spki.algorithm.curve = CurveId::Ed25519;
            spki.algorithm.hash = keylock::hash::Algorithm::SHA256;
            spki.public_key = public_key;
            spki.unused_bits = 0;
            return set_subject_public_key_info(spki);
        }

        inline CertificateBuilder &set_subject_public_key_ecdsa_p256(const std::vector<uint8_t> &public_key_xy) {
            SubjectPublicKeyInfo spki{};
            spki.algorithm.signature = SignatureAlgorithmId::EcdsaSha256;
            spki.algorithm.curve = CurveId::Secp256r1;
            spki.algorithm.hash = keylock::hash::Algorithm::SHA256;
            spki.public_key = public_key_xy;
            spki.unused_bits = 0;
            return set_subject_public_key_info(spki);
        }

        inline CertificateBuilder &
        set_subject_public_key_rsa(const std::vector<uint8_t> &rsa_public_blob,
                                   keylock::hash::Algorithm hash_alg = keylock::hash::Algorithm::SHA256,
                                   bool pss = false) {
            SubjectPublicKeyInfo spki{};
            if (pss) {
                spki.algorithm.signature = hash_alg == keylock::hash::Algorithm::SHA512
                                               ? SignatureAlgorithmId::RsaPssSha512
                                               : SignatureAlgorithmId::RsaPssSha256;
            } else {
                spki.algorithm.signature = hash_alg == keylock::hash::Algorithm::SHA512
                                               ? SignatureAlgorithmId::RsaPkcs1Sha512
                                               : SignatureAlgorithmId::RsaPkcs1Sha256;
            }
            spki.algorithm.hash = hash_alg;
            spki.public_key = rsa_public_blob;
            spki.unused_bits = 0;
            return set_subject_public_key_info(spki);
        }

        inline CertificateBuilder &add_extension(const RawExtension &extension) {
            auto existing = std::find_if(extensions_.begin(), extensions_.end(),
                                         [&](const RawExtension &ext) { return ext.id == extension.id; });
            if (existing != extensions_.end()) {
                *existing = extension;
            } else {
                extensions_.push_back(extension);
            }
            return *this;
        }

        inline CertificateBuilder &set_basic_constraints(bool is_ca, std::optional<uint32_t> path_length,
                                                         bool critical = true) {
            return add_extension(build_basic_constraints_extension(is_ca, path_length, critical));
        }

        inline CertificateBuilder &set_key_usage(uint16_t bits, bool critical = true) {
            return add_extension(build_key_usage_extension(bits, critical));
        }

        inline CertificateBuilder &set_extended_key_usage(const std::vector<Oid> &purpose_oids, bool critical = false) {
            if (purpose_oids.empty()) {
                return *this;
            }
            return add_extension(build_extended_key_usage_extension(purpose_oids, critical));
        }

        inline CertificateBuilder &set_subject_alt_name(const std::vector<SubjectAltNameExtension::GeneralName> &names,
                                                        bool critical = false) {
            if (names.empty()) {
                return *this;
            }
            return add_extension(build_subject_alt_name_extension(names, critical));
        }

        inline CertificateBuilder &set_subject_key_identifier(const std::vector<uint8_t> &key_id,
                                                              bool critical = false) {
            return add_extension(build_key_identifier_extension(key_id, critical, ExtensionId::SubjectKeyIdentifier));
        }

        inline CertificateBuilder &set_authority_key_identifier(const std::vector<uint8_t> &key_id,
                                                                bool critical = false) {
            return add_extension(build_key_identifier_extension(key_id, critical, ExtensionId::AuthorityKeyIdentifier));
        }

        inline CertificateResult<Certificate> build(const keylock::crypto::Context::KeyPair &issuer_key,
                                                    bool self_signed = false) const {
            auto algorithm = detail::keylock_signature_algorithm(signature_algorithm_.signature);
            if (!algorithm.has_value()) {
                return CertificateResult<Certificate>::failure("Unsupported signature algorithm for builder");
            }
            return build_with_algorithm(issuer_key, self_signed, *algorithm);
        }

        inline CertificateResult<Certificate> build_ed25519(const keylock::crypto::Context::KeyPair &issuer_key,
                                                            bool self_signed = false) const {
            return build_with_algorithm(issuer_key, self_signed, keylock::crypto::Context::Algorithm::Ed25519);
        }

      private:
        inline CertificateResult<Certificate>
        build_with_algorithm(const keylock::crypto::Context::KeyPair &issuer_key, bool self_signed,
                             keylock::crypto::Context::Algorithm algorithm) const {
            if (auto err = validate_inputs(self_signed)) {
                return CertificateResult<Certificate>::failure(*err);
            }

            keylock::crypto::Context signer(algorithm);
            auto serial = serial_number_.empty() ? detail::make_random_serial() : serial_number_;

            CertificateBuilder builder_copy(*this);
            builder_copy.serial_number_ = serial;

            auto issuer_dn = self_signed
                                 ? builder_copy.subject_
                                 : (builder_copy.issuer_explicit_ ? builder_copy.issuer_ : builder_copy.subject_);
            auto tbs_der = builder_copy.encode_tbs_certificate(issuer_dn);

            auto sig = signer.sign(tbs_der, issuer_key.private_key);
            if (!sig.success) {
                return CertificateResult<Certificate>::failure(sig.error_message);
            }

            auto encoded_sig = detail::normalize_signature_for_emit(sig.data, signature_algorithm_.signature);
            if (!encoded_sig.success) {
                return CertificateResult<Certificate>::failure(encoded_sig.error);
            }

            AlgorithmIdentifier signature_alg = builder_copy.signature_algorithm_;
            auto alg_der = builder_copy.encode_algorithm_identifier(signature_alg);
            auto sig_bit = der::encode_bit_string(ByteSpan(encoded_sig.value.data(), encoded_sig.value.size()), 0);

            std::vector<std::vector<uint8_t>> cert_fields;
            cert_fields.push_back(tbs_der);
            cert_fields.push_back(alg_der);
            cert_fields.push_back(sig_bit);
            auto cert_der = der::encode_sequence(der::concat(cert_fields));

            TBSCertificate tbs_struct{};
            tbs_struct.version = builder_copy.version_;
            tbs_struct.serial_number = builder_copy.serial_number_;
            tbs_struct.signature = signature_alg;
            tbs_struct.issuer = issuer_dn;
            tbs_struct.validity = builder_copy.validity_;
            tbs_struct.subject = builder_copy.subject_;
            tbs_struct.subject_public_key_info = builder_copy.subject_public_key_info_;
            tbs_struct.extensions = builder_copy.extensions_;

            Certificate certificate(tbs_struct, signature_alg, encoded_sig.value, cert_der, tbs_der);
            return CertificateResult<Certificate>::ok(std::move(certificate));
        }
        inline std::optional<std::string> validate_inputs(bool self_signed) const {
            if (!subject_explicit_) {
                return "Subject not set";
            }
            if (!issuer_explicit_ && !self_signed) {
                return "Issuer not set";
            }
            if (subject_public_key_info_.public_key.empty()) {
                return "Subject public key not provided";
            }
            if (validity_.not_after <= validity_.not_before) {
                return "Invalid validity range";
            }
            return std::nullopt;
        }

        inline RawExtension build_basic_constraints_extension(bool is_ca, std::optional<uint32_t> path_length,
                                                              bool critical) const {
            std::vector<std::vector<uint8_t>> fields;
            if (is_ca) {
                fields.push_back(der::encode_boolean(true));
                if (path_length.has_value()) {
                    fields.push_back(der::encode_integer(path_length.value()));
                }
            } else if (path_length.has_value()) {
                fields.push_back(der::encode_integer(path_length.value()));
            }
            auto seq = der::encode_sequence(der::concat(fields));
            RawExtension ext{};
            ext.id = ExtensionId::BasicConstraints;
            ext.oid = detail::get_extension_oid(ExtensionId::BasicConstraints);
            ext.critical = critical;
            ext.value = seq;
            return ext;
        }

        inline RawExtension build_key_usage_extension(uint16_t bits, bool critical) const {
            std::vector<uint8_t> buffer;
            if (bits > 0xFFU) {
                buffer.push_back(static_cast<uint8_t>((bits >> 8) & 0xFFU));
            }
            buffer.push_back(static_cast<uint8_t>(bits & 0xFFU));
            auto bit_string = der::encode_bit_string(ByteSpan(buffer.data(), buffer.size()), 0);
            RawExtension ext{};
            ext.id = ExtensionId::KeyUsage;
            ext.oid = detail::get_extension_oid(ExtensionId::KeyUsage);
            ext.critical = critical;
            ext.value = bit_string;
            return ext;
        }

        inline RawExtension build_extended_key_usage_extension(const std::vector<Oid> &purpose_oids,
                                                               bool critical) const {
            std::vector<std::vector<uint8_t>> encoded_oids;
            for (const auto &oid : purpose_oids) {
                encoded_oids.push_back(der::encode_oid(oid));
            }
            auto oid_sequence = der::concat(encoded_oids);
            RawExtension ext{};
            ext.id = ExtensionId::ExtendedKeyUsage;
            ext.oid = detail::get_extension_oid(ExtensionId::ExtendedKeyUsage);
            ext.critical = critical;
            ext.value = der::encode_sequence(oid_sequence);
            return ext;
        }

        inline RawExtension
        build_subject_alt_name_extension(const std::vector<SubjectAltNameExtension::GeneralName> &names,
                                         bool critical) const {
            auto encoded = encode_general_names(names);
            RawExtension ext{};
            ext.id = ExtensionId::SubjectAltName;
            ext.oid = detail::get_extension_oid(ExtensionId::SubjectAltName);
            ext.critical = critical;
            ext.value = der::encode_sequence(encoded);
            return ext;
        }

        inline RawExtension build_key_identifier_extension(const std::vector<uint8_t> &key_id, bool critical,
                                                           ExtensionId id) const {
            auto value = der::encode_octet_string(ByteSpan(key_id.data(), key_id.size()));
            RawExtension ext{};
            ext.id = id;
            ext.oid = detail::get_extension_oid(id);
            ext.critical = critical;
            ext.value = value;
            return ext;
        }

        inline std::vector<uint8_t> encode_tbs_certificate(const DistinguishedName &issuer_dn) const {
            std::vector<std::vector<uint8_t>> fields;

            if (version_ != 1) {
                auto version_value = der::encode_integer(static_cast<uint64_t>(version_ - 1));
                auto explicit_version = der::encode_tlv(ASN1Class::ContextSpecific, true, 0,
                                                        ByteSpan(version_value.data(), version_value.size()));
                fields.push_back(explicit_version);
            }

            auto serial_value =
                serialize_serial(serial_number_.empty() ? detail::make_random_serial() : serial_number_);
            fields.push_back(serial_value);
            fields.push_back(encode_algorithm_identifier(signature_algorithm_));
            fields.push_back(issuer_dn.der());
            fields.push_back(encode_validity(validity_));
            fields.push_back(subject_.der());
            fields.push_back(encode_subject_public_key_info(subject_public_key_info_));

            if (!extensions_.empty()) {
                auto body = encode_extensions(extensions_);
                auto explicit_ext =
                    der::encode_tlv(ASN1Class::ContextSpecific, true, 3, ByteSpan(body.data(), body.size()));
                fields.push_back(explicit_ext);
            }

            return der::encode_sequence(der::concat(fields));
        }

        inline std::vector<uint8_t> encode_algorithm_identifier(const AlgorithmIdentifier &alg) const {
            auto oid = detail::get_signature_oid(alg.signature);
            auto oid_der = der::encode_oid(oid);
            std::vector<std::vector<uint8_t>> fields;
            fields.push_back(oid_der);
            return der::encode_sequence(der::concat(fields));
        }

        inline std::vector<uint8_t> encode_validity(const Validity &validity) const {
            std::vector<std::vector<uint8_t>> fields;
            fields.push_back(serialize_time(validity.not_before));
            fields.push_back(serialize_time(validity.not_after));
            return der::encode_sequence(der::concat(fields));
        }

        inline std::vector<uint8_t> encode_subject_public_key_info(const SubjectPublicKeyInfo &spki) const {
            std::vector<std::vector<uint8_t>> fields;
            fields.push_back(encode_algorithm_identifier(spki.algorithm));
            fields.push_back(
                der::encode_bit_string(ByteSpan(spki.public_key.data(), spki.public_key.size()), spki.unused_bits));
            return der::encode_sequence(der::concat(fields));
        }

        inline std::vector<uint8_t> encode_extensions(const std::vector<RawExtension> &extensions) const {
            std::vector<std::vector<uint8_t>> encoded;
            encoded.reserve(extensions.size());
            for (const auto &ext : extensions) {
                encoded.push_back(encode_extension(ext));
            }
            return der::encode_sequence(der::concat(encoded));
        }

        inline std::vector<uint8_t>
        encode_general_names(const std::vector<SubjectAltNameExtension::GeneralName> &names) const {
            std::vector<std::vector<uint8_t>> encoded;
            for (const auto &name : names) {
                std::vector<uint8_t> value(name.value.begin(), name.value.end());
                ByteSpan span(value.data(), value.size());
                uint32_t tag = 0;
                switch (name.type) {
                case SubjectAltNameExtension::GeneralNameType::DNSName:
                    tag = 2;
                    break;
                case SubjectAltNameExtension::GeneralNameType::URI:
                    tag = 6;
                    break;
                case SubjectAltNameExtension::GeneralNameType::Email:
                    tag = 1;
                    break;
                case SubjectAltNameExtension::GeneralNameType::IPAddress: {
                    auto ip = encode_ip_address(name.value);
                    span = ByteSpan(ip.data(), ip.size());
                    tag = 7;
                    encoded.push_back(der::encode_tlv(ASN1Class::ContextSpecific, false, tag, span));
                    continue;
                }
                default:
                    continue;
                }
                encoded.push_back(der::encode_tlv(ASN1Class::ContextSpecific, false, tag, span));
            }
            return der::concat(encoded);
        }

        static inline std::vector<uint8_t> format_time(std::chrono::system_clock::time_point tp, bool utc_time) {
            auto tm_value = detail::to_gmtime(tp);
            std::ostringstream oss;
            oss << std::setfill('0');
            if (utc_time) {
                int year = tm_value.tm_year + 1900;
                int yy = year % 100;
                oss << std::setw(2) << yy;
            } else {
                oss << std::setw(4) << (tm_value.tm_year + 1900);
            }
            oss << std::setw(2) << (tm_value.tm_mon + 1) << std::setw(2) << tm_value.tm_mday << std::setw(2)
                << tm_value.tm_hour << std::setw(2) << tm_value.tm_min << std::setw(2) << tm_value.tm_sec << 'Z';
            std::string str = oss.str();
            if (utc_time) {
                return der::encode_utctime(str);
            }
            return der::encode_generalized_time(str);
        }

        static inline std::vector<uint8_t> serialize_time(std::chrono::system_clock::time_point tp) {
            auto tm_value = detail::to_gmtime(tp);
            const bool utc = detail::is_utctime(tm_value);
            return format_time(tp, utc);
        }

        static inline std::vector<uint8_t> serialize_serial(const std::vector<uint8_t> &serial) {
            if (serial.empty()) {
                auto random_serial = detail::make_random_serial();
                return der::encode_integer(random_serial);
            }
            return der::encode_integer(serial);
        }

        static inline std::vector<uint8_t> encode_extension(const RawExtension &extension) {
            std::vector<std::vector<uint8_t>> fields;
            fields.push_back(der::encode_oid(extension.oid));
            if (extension.critical) {
                fields.push_back(der::encode_boolean(true));
            }
            fields.push_back(der::encode_octet_string(ByteSpan(extension.value.data(), extension.value.size())));
            return der::encode_sequence(der::concat(fields));
        }

        static inline std::vector<uint8_t> encode_ip_address(const std::string &ip) {
            std::vector<uint8_t> bytes;
            if (ip.find(':') != std::string::npos) {
                // Very simple IPv6 parser (no compression support)
                std::istringstream iss(ip);
                std::string segment;
                while (std::getline(iss, segment, ':')) {
                    if (segment.empty()) {
                        continue;
                    }
                    uint16_t value = static_cast<uint16_t>(std::stoi(segment, nullptr, 16));
                    bytes.push_back(static_cast<uint8_t>((value >> 8) & 0xFFU));
                    bytes.push_back(static_cast<uint8_t>(value & 0xFFU));
                }
            } else {
                std::istringstream iss(ip);
                std::string octet;
                while (std::getline(iss, octet, '.')) {
                    bytes.push_back(static_cast<uint8_t>(std::stoi(octet)));
                }
            }
            return bytes;
        }

        int version_{3};
        std::vector<uint8_t> serial_number_;
        bool issuer_explicit_{false};
        bool subject_explicit_{false};
        DistinguishedName issuer_;
        DistinguishedName subject_;
        Validity validity_{};
        SubjectPublicKeyInfo subject_public_key_info_{};
        AlgorithmIdentifier signature_algorithm_{SignatureAlgorithmId::Ed25519, keylock::hash::Algorithm::SHA256,
                                                 CurveId::Ed25519};
        std::vector<RawExtension> extensions_;
    };

} // namespace authbox::pik
