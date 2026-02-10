#pragma once

#include <optional>
#include <vector>

#include <pki/asn1_utils.hpp>
#include <pki/certificate.hpp>
#include <pki/files.hpp>
#include <pki/parser_utils.hpp>
#include <pki/pem.hpp>

namespace authbox::pik {

    struct CertificationRequestInfo {
        int version{0};
        DistinguishedName subject{};
        SubjectPublicKeyInfo subject_public_key_info{};
        std::vector<RawExtension> extensions;
    };

    struct CertificateRequest {
        CertificationRequestInfo info{};
        AlgorithmIdentifier signature_algorithm{};
        std::vector<uint8_t> signature;
        std::vector<uint8_t> der;
        std::vector<uint8_t> cri_der;

        inline CertificateSignatureResult sign(const keylock::crypto::Context::KeyPair &key) const {
            auto algorithm = detail::keylock_signature_algorithm(signature_algorithm.signature);
            if (!algorithm.has_value()) {
                return CertificateSignatureResult::failure("Unsupported CSR signature algorithm");
            }

            keylock::crypto::Context signer(*algorithm);
            auto sig = signer.sign(cri_der, key.private_key);
            if (!sig.success) {
                return CertificateSignatureResult::failure(sig.error_message);
            }

            auto encoded = detail::normalize_signature_for_emit(sig.data, signature_algorithm.signature);
            if (!encoded.success) {
                return CertificateSignatureResult::failure(encoded.error);
            }

            return CertificateSignatureResult::ok(encoded.value);
        }
    };

    inline CertificateResult<CertificateRequest> parse_csr(ByteSpan der) {
        using detail::DerCursor;
        auto seq = parse_sequence(der);
        if (!seq.success) {
            return CertificateResult<CertificateRequest>::failure(seq.error);
        }
        DerCursor cursor(seq.value);
        auto cri_seq = parse_sequence(cursor.remaining());
        if (!cri_seq.success) {
            return CertificateResult<CertificateRequest>::failure(cri_seq.error);
        }
        auto cri_bytes = cursor.remaining().first(cri_seq.bytes_consumed);
        cursor.advance(cri_seq.bytes_consumed);

        auto sig_alg = detail::parse_algorithm_identifier(cursor.remaining());
        if (!sig_alg.success) {
            return CertificateResult<CertificateRequest>::failure(sig_alg.error);
        }
        cursor.advance(sig_alg.bytes_consumed);

        auto sig = parse_bit_string(cursor.remaining());
        if (!sig.success) {
            return CertificateResult<CertificateRequest>::failure(sig.error);
        }

        CertificationRequestInfo info{};
        DerCursor cri_cursor(cri_seq.value);
        auto version = parse_integer(cri_cursor.remaining());
        if (!version.success) {
            return CertificateResult<CertificateRequest>::failure(version.error);
        }
        info.version = static_cast<int>(version.value.back());
        cri_cursor.advance(version.bytes_consumed);

        auto subject = detail::parse_name(cri_cursor.remaining());
        if (!subject.success) {
            return CertificateResult<CertificateRequest>::failure(subject.error);
        }
        info.subject = subject.value;
        cri_cursor.advance(subject.bytes_consumed);

        auto spki = detail::parse_subject_public_key_info(cri_cursor.remaining());
        if (!spki.success) {
            return CertificateResult<CertificateRequest>::failure(spki.error);
        }
        info.subject_public_key_info = spki.value;
        cri_cursor.advance(spki.bytes_consumed);

        CertificateRequest csr{};
        csr.info = std::move(info);
        csr.signature_algorithm = sig_alg.value;
        csr.signature.assign(sig.value.bytes.begin(), sig.value.bytes.end());
        csr.der.assign(der.begin(), der.end());
        csr.cri_der.assign(cri_bytes.begin(), cri_bytes.end());

        return CertificateResult<CertificateRequest>::ok(std::move(csr));
    }

    inline CertificateResult<CertificateRequest> load_csr(const std::string &path) {
        auto file = authbox::io::read_binary(path);
        if (!file.success) {
            return CertificateResult<CertificateRequest>::failure(file.error_message);
        }
        const std::string_view contents(reinterpret_cast<const char *>(file.data.data()), file.data.size());
        if (contents.find("-----BEGIN") != std::string_view::npos) {
            auto pem = pem_decode(contents, "CERTIFICATE REQUEST");
            if (!pem.success) {
                return CertificateResult<CertificateRequest>::failure(pem.error);
            }
            return parse_csr(ByteSpan(pem.block.data.data(), pem.block.data.size()));
        }
        return parse_csr(ByteSpan(file.data.data(), file.data.size()));
    }

} // namespace authbox::pik
