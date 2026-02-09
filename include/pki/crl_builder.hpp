#pragma once

#include <optional>
#include <stdexcept>
#include <vector>

#include <pki/asn1_writer.hpp>
#include <pki/crl.hpp>
#include <pki/oid_registry.hpp>

namespace authbox::pik {

    class CrlBuilder {
      public:
        inline CrlBuilder &set_issuer(const DistinguishedName &dn) {
            issuer_ = dn;
            issuer_set_ = true;
            return *this;
        }

        inline CrlBuilder &set_issuer_from_string(std::string_view dn) {
            auto parsed = DistinguishedName::from_string(dn);
            if (parsed.success) {
                issuer_ = parsed.value;
                issuer_set_ = true;
            }
            return *this;
        }

        inline CrlBuilder &set_this_update(std::chrono::system_clock::time_point tp) {
            this_update_ = tp;
            return *this;
        }

        inline CrlBuilder &set_next_update(std::chrono::system_clock::time_point tp) {
            next_update_ = tp;
            return *this;
        }

        inline CrlBuilder &add_revoked(const RevokedCertificate &entry) {
            entries_.push_back(entry);
            return *this;
        }

        inline CrlBuilder &add_revoked(std::vector<uint8_t> serial, std::chrono::system_clock::time_point when,
                                       std::optional<CrlReason> reason = std::nullopt,
                                       std::optional<std::chrono::system_clock::time_point> invalidity = std::nullopt) {
            RevokedCertificate entry{};
            entry.serial_number = std::move(serial);
            entry.revocation_date = when;
            entry.reason = reason;
            entry.invalidity_date = invalidity;
            entries_.push_back(std::move(entry));
            return *this;
        }

        inline CertificateResult<Crl> build_ed25519(const keylock::crypto::Context::KeyPair &issuer_key) const {
            return build(issuer_key);
        }

      private:
        inline CertificateResult<Crl> build(const keylock::crypto::Context::KeyPair &issuer_key) const {
            if (auto validation = validate_inputs()) {
                return CertificateResult<Crl>::failure(*validation);
            }

            auto tbs = encode_tbs();
            keylock::crypto::Context signer(keylock::crypto::Context::Algorithm::Ed25519);
            auto sig = signer.sign(tbs, issuer_key.private_key);
            if (!sig.success) {
                return CertificateResult<Crl>::failure(sig.error_message);
            }

            AlgorithmIdentifier alg{};
            alg.signature = SignatureAlgorithmId::Ed25519;

            Crl crl{};
            crl.version = 2;
            crl.signature = alg;
            crl.issuer = issuer_;
            crl.this_update = this_update_;
            crl.next_update = next_update_;
            crl.revoked = entries_;
            crl.outer_signature = alg;
            crl.signature_value = sig.data;
            crl.tbs_der = tbs;
            std::vector<std::vector<uint8_t>> cert_fields;
            cert_fields.push_back(tbs);
            cert_fields.push_back(der::encode_sequence(der::encode_oid(*oid_for_signature(alg.signature))));
            cert_fields.push_back(der::encode_bit_string(ByteSpan(sig.data.data(), sig.data.size())));
            crl.der = der::encode_sequence(der::concat(cert_fields));

            return CertificateResult<Crl>::ok(std::move(crl));
        }

        inline std::optional<std::string> validate_inputs() const {
            if (!issuer_set_) {
                return "issuer not set";
            }
            if (this_update_ == std::chrono::system_clock::time_point{}) {
                return "thisUpdate not set";
            }
            return std::nullopt;
        }

        inline std::vector<uint8_t> encode_tbs() const {
            std::vector<std::vector<uint8_t>> fields;

            // Version is OPTIONAL in CRLs. If present, it MUST be v2 (encoded as INTEGER 1)
            // Unlike certificates, CRL version is NOT wrapped in [0] EXPLICIT
            // For now, we always include version=1 (v2) to support extensions
            fields.push_back(der::encode_integer(1)); // v2

            AlgorithmIdentifier alg{};
            alg.signature = SignatureAlgorithmId::Ed25519;
            auto sig_oid = oid_for_signature(alg.signature);
            if (!sig_oid) {
                throw std::runtime_error("Failed to get OID for Ed25519 signature algorithm");
            }
            fields.push_back(der::encode_sequence(der::encode_oid(*sig_oid)));
            fields.push_back(issuer_.der());
            fields.push_back(der::serialize_time(this_update_));
            if (next_update_) {
                fields.push_back(der::serialize_time(*next_update_));
            }
            if (!entries_.empty()) {
                fields.push_back(encode_revoked_entries());
            }
            return der::encode_sequence(der::concat(fields));
        }

        inline std::vector<uint8_t> encode_revoked_entries() const {
            std::vector<std::vector<uint8_t>> entries;
            for (const auto &revoked : entries_) {
                std::vector<std::vector<uint8_t>> fields;
                fields.push_back(der::encode_integer(revoked.serial_number));
                fields.push_back(der::serialize_time(revoked.revocation_date));

                // Encode crlEntryExtensions if present
                std::vector<std::vector<uint8_t>> extensions;
                if (revoked.reason) {
                    // ReasonCode extension: OID 2.5.29.21
                    std::vector<std::vector<uint8_t>> ext_fields;
                    Oid reason_oid;
                    reason_oid.nodes = {2, 5, 29, 21};
                    ext_fields.push_back(der::encode_oid(reason_oid));

                    // extnValue: OCTET STRING containing ENUMERATED
                    std::vector<uint8_t> enumerated;
                    enumerated.push_back(0x0a); // ENUMERATED tag
                    enumerated.push_back(0x01); // length
                    enumerated.push_back(static_cast<uint8_t>(*revoked.reason));
                    ext_fields.push_back(der::encode_octet_string(ByteSpan(enumerated.data(), enumerated.size())));

                    extensions.push_back(der::encode_sequence(der::concat(ext_fields)));
                }
                if (revoked.invalidity_date) {
                    // InvalidityDate extension: OID 2.5.29.24
                    std::vector<std::vector<uint8_t>> ext_fields;
                    Oid invalidity_oid;
                    invalidity_oid.nodes = {2, 5, 29, 24};
                    ext_fields.push_back(der::encode_oid(invalidity_oid));

                    // extnValue: OCTET STRING containing GeneralizedTime
                    auto time = der::encode_generalized_time(der::format_time(*revoked.invalidity_date, false));
                    ext_fields.push_back(der::encode_octet_string(ByteSpan(time.data(), time.size())));

                    extensions.push_back(der::encode_sequence(der::concat(ext_fields)));
                }

                if (!extensions.empty()) {
                    fields.push_back(der::encode_sequence(der::concat(extensions)));
                }
                entries.push_back(der::encode_sequence(der::concat(fields)));
            }
            return der::encode_sequence(der::concat(entries));
        }

        DistinguishedName issuer_;
        bool issuer_set_{false};
        std::chrono::system_clock::time_point this_update_{};
        std::optional<std::chrono::system_clock::time_point> next_update_;
        std::vector<RevokedCertificate> entries_;
    };

} // namespace authbox::pik
