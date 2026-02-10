#pragma once

#include <optional>
#include <stdexcept>

#include <pki/asn1_writer.hpp>
#include <pki/csr.hpp>
#include <pki/oid_registry.hpp>

namespace authbox::pik {

    class CsrBuilder {
      public:
        inline CsrBuilder &set_subject(const DistinguishedName &dn) {
            info_.subject = dn;
            subject_set_ = true;
            return *this;
        }

        inline CsrBuilder &set_subject_from_string(std::string_view dn) {
            auto parsed = DistinguishedName::from_string(dn);
            if (parsed.success) {
                info_.subject = parsed.value;
                subject_set_ = true;
            }
            return *this;
        }

        inline CsrBuilder &set_subject_public_key(const SubjectPublicKeyInfo &spki) {
            info_.subject_public_key_info = spki;
            spki_set_ = true;
            return *this;
        }

        inline CsrBuilder &set_subject_public_key_ed25519(const std::vector<uint8_t> &public_key) {
            SubjectPublicKeyInfo spki;
            spki.algorithm.signature = SignatureAlgorithmId::Ed25519;
            spki.algorithm.curve = CurveId::Ed25519;
            spki.public_key = public_key;
            spki.unused_bits = 0;
            return set_subject_public_key(spki);
        }

        inline CsrBuilder &set_signature_algorithm(SignatureAlgorithmId algorithm) {
            signature_algorithm_.signature = algorithm;
            return *this;
        }

        inline CsrBuilder &add_extension(const RawExtension &extension) {
            info_.extensions.push_back(extension);
            return *this;
        }

        inline CertificateResult<CertificateRequest> build_ed25519(const keylock::crypto::Context::KeyPair &key) const {
            return build(key, SignatureAlgorithmId::Ed25519);
        }

        inline CertificateResult<CertificateRequest> build(const keylock::crypto::Context::KeyPair &key) const {
            return build(key, signature_algorithm_.signature);
        }

      private:
        inline CertificateResult<CertificateRequest> build(const keylock::crypto::Context::KeyPair &key,
                                                           SignatureAlgorithmId algorithm_id) const {
            if (auto err = validate_inputs()) {
                return CertificateResult<CertificateRequest>::failure(*err);
            }
            auto cri = encode_cri();
            if (cri.empty()) {
                return CertificateResult<CertificateRequest>::failure("failed to encode CRI");
            }

            auto algorithm = detail::keylock_signature_algorithm(algorithm_id);
            if (!algorithm.has_value()) {
                return CertificateResult<CertificateRequest>::failure("Unsupported CSR signature algorithm");
            }

            keylock::crypto::Context signer(*algorithm);
            auto sig = signer.sign(cri, key.private_key);
            if (!sig.success) {
                return CertificateResult<CertificateRequest>::failure(sig.error_message);
            }

            auto encoded_sig = detail::normalize_signature_for_emit(sig.data, algorithm_id);
            if (!encoded_sig.success) {
                return CertificateResult<CertificateRequest>::failure(encoded_sig.error);
            }

            AlgorithmIdentifier alg{};
            alg.signature = algorithm_id;

            CertificateRequest csr{};
            csr.info = info_;
            csr.signature_algorithm = alg;
            csr.signature = encoded_sig.value;
            csr.cri_der = cri;
            std::vector<std::vector<uint8_t>> fields;
            fields.push_back(cri);
            fields.push_back(der::encode_sequence(der::encode_oid(*oid_for_signature(alg.signature))));
            fields.push_back(der::encode_bit_string(ByteSpan(csr.signature.data(), csr.signature.size())));
            csr.der = der::encode_sequence(der::concat(fields));
            return CertificateResult<CertificateRequest>::ok(std::move(csr));
        }
        inline std::optional<std::string> validate_inputs() const {
            if (!subject_set_) {
                return "subject not set";
            }
            if (!spki_set_) {
                return "subject public key not set";
            }
            return std::nullopt;
        }

        inline std::vector<uint8_t> encode_cri() const {
            std::vector<std::vector<uint8_t>> fields;
            fields.push_back(der::encode_integer(info_.version));
            fields.push_back(info_.subject.der());
            std::vector<std::vector<uint8_t>> spki_fields;
            auto alg_oid = oid_for_signature(info_.subject_public_key_info.algorithm.signature);
            if (!alg_oid) {
                throw std::runtime_error("Failed to get OID for signature algorithm");
            }
            spki_fields.push_back(der::encode_sequence(der::encode_oid(*alg_oid)));
            spki_fields.push_back(der::encode_bit_string(ByteSpan(info_.subject_public_key_info.public_key.data(),
                                                                  info_.subject_public_key_info.public_key.size()),
                                                         info_.subject_public_key_info.unused_bits));
            fields.push_back(der::encode_sequence(der::concat(spki_fields)));
            if (!info_.extensions.empty()) {
                std::vector<std::vector<uint8_t>> ext_fields;
                for (const auto &ext : info_.extensions) {
                    ext_fields.push_back(der::encode_sequence(der::encode_oid(ext.oid)));
                }
                fields.push_back(der::encode_sequence(der::concat(ext_fields)));
            }
            return der::encode_sequence(der::concat(fields));
        }

        CertificationRequestInfo info_{};
        bool subject_set_{false};
        bool spki_set_{false};
        AlgorithmIdentifier signature_algorithm_{SignatureAlgorithmId::Ed25519, keylock::hash::Algorithm::SHA256,
                                                 CurveId::Ed25519};
    };

} // namespace authbox::pik
