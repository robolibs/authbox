#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <pki/asn1_common.hpp>
#include <pki/asn1_utils.hpp>
#include <pki/distinguished_name.hpp>
#include <pki/oid_registry.hpp>
#include <pki/parser_utils.hpp>

namespace authbox::pik {

    struct CertificateContext {
        std::vector<uint8_t> der;
        std::vector<uint8_t> tbs_certificate;
        int version{1};
        std::vector<uint8_t> serial_number;
        AlgorithmIdentifier tbs_signature{};
        DistinguishedName issuer{};
        DistinguishedName subject{};
        std::chrono::system_clock::time_point not_before{};
        std::chrono::system_clock::time_point not_after{};
        SubjectPublicKeyInfo subject_public_key_info{};
        std::vector<RawExtension> extensions;
        AlgorithmIdentifier outer_signature{};
        std::vector<uint8_t> signature_value;
    };

    struct ParseResult {
        bool success{};
        CertificateContext certificate{};
        std::string error{};
    };

    namespace detail {

        struct ValidityRange {
            std::chrono::system_clock::time_point not_before{};
            std::chrono::system_clock::time_point not_after{};
        };

        inline std::vector<uint8_t> copy_bytes(ByteSpan span) {
            std::vector<uint8_t> out(span.size());
            std::copy(span.begin(), span.end(), out.begin());
            return out;
        }

        inline ASN1Result<int> parse_version(ByteSpan input) {
            auto header = parse_id_len(input);
            if (!header.success) {
                return ASN1Result<int>::failure(header.error);
            }
            const auto &identifier = header.value.identifier;
            if (identifier.tag_class != ASN1Class::ContextSpecific || identifier.tag_number != 0 ||
                !identifier.constructed) {
                return ASN1Result<int>::failure("expected [0] EXPLICIT version");
            }
            const auto inner = input.subspan(header.value.header_bytes, header.value.length);
            auto int_result = parse_integer(inner);
            if (!int_result.success) {
                return ASN1Result<int>::failure(int_result.error);
            }
            if (int_result.value.empty()) {
                return ASN1Result<int>::failure("version INTEGER empty");
            }
            int value = 0;
            for (auto byte : int_result.value) {
                value = (value << 8) | byte;
            }
            if (value < 0 || value > 2) {
                return ASN1Result<int>::failure("version out of range");
            }
            return ASN1Result<int>::ok(value + 1, header.value.header_bytes + header.value.length);
        }

        inline ASN1Result<AlgorithmIdentifier> parse_algorithm_identifier_full(ByteSpan input) {
            auto seq_result = parse_sequence(input);
            if (!seq_result.success) {
                return ASN1Result<AlgorithmIdentifier>::failure(seq_result.error);
            }
            DerCursor cursor(seq_result.value);

            const auto oid_result = parse_oid(cursor.remaining());
            if (!oid_result.success) {
                return ASN1Result<AlgorithmIdentifier>::failure(oid_result.error);
            }
            cursor.advance(oid_result.bytes_consumed);

            AlgorithmIdentifier identifier{};
            identifier.signature = find_sig_alg_by_oid(oid_result.value);
            if (auto hash_algo = find_hash_by_oid(oid_result.value)) {
                identifier.hash = *hash_algo;
            }

            std::optional<Oid> parameter_oid;
            if (!cursor.empty()) {
                auto param_header = parse_id_len(cursor.remaining());
                if (!param_header.success) {
                    return ASN1Result<AlgorithmIdentifier>::failure(param_header.error);
                }

                const auto &id = param_header.value.identifier;
                if (id.tag_class == ASN1Class::Universal &&
                    id.tag_number == static_cast<uint32_t>(ASN1Tag::ObjectIdentifier)) {
                    auto param_oid_result = parse_oid(cursor.remaining());
                    if (!param_oid_result.success) {
                        return ASN1Result<AlgorithmIdentifier>::failure(param_oid_result.error);
                    }
                    parameter_oid = param_oid_result.value;
                    cursor.advance(param_oid_result.bytes_consumed);
                } else {
                    cursor.advance(param_header.value.header_bytes + param_header.value.length);
                }
            }

            if (parameter_oid) {
                identifier.curve = find_curve_by_oid(*parameter_oid);
            }

            return ASN1Result<AlgorithmIdentifier>::ok(identifier, seq_result.bytes_consumed);
        }

        inline ASN1Result<DistinguishedName> parse_name_full(ByteSpan input) {
            auto seq_result = parse_sequence(input);
            if (!seq_result.success) {
                return ASN1Result<DistinguishedName>::failure(seq_result.error);
            }
            if (input.size() < seq_result.bytes_consumed) {
                return ASN1Result<DistinguishedName>::failure("Name smaller than expected");
            }
            const auto encoded = input.first(seq_result.bytes_consumed);
            DistinguishedName view{copy_bytes(encoded)};
            return ASN1Result<DistinguishedName>::ok(view, seq_result.bytes_consumed);
        }

        inline ASN1Result<std::chrono::system_clock::time_point> parse_time_choice_full(ByteSpan input) {
            if (input.empty()) {
                return ASN1Result<std::chrono::system_clock::time_point>::failure("missing time field");
            }
            const uint8_t first = input[0];
            const ASN1Class tag_class = static_cast<ASN1Class>(first & 0xC0U);
            const uint8_t tag_number = first & 0x1FU;
            if (tag_class != ASN1Class::Universal) {
                return ASN1Result<std::chrono::system_clock::time_point>::failure("invalid time tag class");
            }
            if (tag_number == static_cast<uint8_t>(ASN1Tag::UTCTime)) {
                return parse_utc_time(input);
            }
            if (tag_number == static_cast<uint8_t>(ASN1Tag::GeneralizedTime)) {
                return parse_generalized_time(input);
            }
            return ASN1Result<std::chrono::system_clock::time_point>::failure("unsupported time tag");
        }

        inline ASN1Result<ValidityRange> parse_validity(ByteSpan input) {
            auto seq_result = parse_sequence(input);
            if (!seq_result.success) {
                return ASN1Result<ValidityRange>::failure(seq_result.error);
            }
            DerCursor cursor(seq_result.value);
            auto not_before_result = parse_time_choice_full(cursor.remaining());
            if (!not_before_result.success) {
                return ASN1Result<ValidityRange>::failure(not_before_result.error);
            }
            cursor.advance(not_before_result.bytes_consumed);

            auto not_after_result = parse_time_choice_full(cursor.remaining());
            if (!not_after_result.success) {
                return ASN1Result<ValidityRange>::failure(not_after_result.error);
            }
            cursor.advance(not_after_result.bytes_consumed);

            if (!cursor.empty()) {
                return ASN1Result<ValidityRange>::failure("extra data in Validity");
            }

            ValidityRange validity{not_before_result.value, not_after_result.value};
            return ASN1Result<ValidityRange>::ok(validity, seq_result.bytes_consumed);
        }

        inline ASN1Result<SubjectPublicKeyInfo> parse_subject_public_key_info_full(ByteSpan input) {
            auto seq_result = parse_sequence(input);
            if (!seq_result.success) {
                return ASN1Result<SubjectPublicKeyInfo>::failure(seq_result.error);
            }
            DerCursor cursor(seq_result.value);

            auto alg_result = parse_algorithm_identifier_full(cursor.remaining());
            if (!alg_result.success) {
                return ASN1Result<SubjectPublicKeyInfo>::failure(alg_result.error);
            }
            cursor.advance(alg_result.bytes_consumed);

            auto bit_string_result = parse_bit_string(cursor.remaining());
            if (!bit_string_result.success) {
                return ASN1Result<SubjectPublicKeyInfo>::failure(bit_string_result.error);
            }
            cursor.advance(bit_string_result.bytes_consumed);

            if (!cursor.empty()) {
                return ASN1Result<SubjectPublicKeyInfo>::failure("extra data in SubjectPublicKeyInfo");
            }

            SubjectPublicKeyInfo info{};
            info.algorithm = alg_result.value;
            info.public_key = copy_bytes(bit_string_result.value.bytes);
            info.unused_bits = bit_string_result.value.unused_bits;
            return ASN1Result<SubjectPublicKeyInfo>::ok(info, seq_result.bytes_consumed);
        }

        inline ASN1Result<std::vector<RawExtension>> parse_extension_sequence(ByteSpan input) {
            auto seq_result = parse_sequence(input);
            if (!seq_result.success) {
                return ASN1Result<std::vector<RawExtension>>::failure(seq_result.error);
            }

            std::vector<RawExtension> extensions;
            DerCursor cursor(seq_result.value);
            while (!cursor.empty()) {
                auto ext_seq = parse_sequence(cursor.remaining());
                if (!ext_seq.success) {
                    return ASN1Result<std::vector<RawExtension>>::failure(ext_seq.error);
                }

                DerCursor ext_cursor(ext_seq.value);
                auto oid_result = parse_oid(ext_cursor.remaining());
                if (!oid_result.success) {
                    return ASN1Result<std::vector<RawExtension>>::failure(oid_result.error);
                }
                ext_cursor.advance(oid_result.bytes_consumed);

                bool critical = false;
                if (!ext_cursor.empty()) {
                    auto next_header = parse_id_len(ext_cursor.remaining());
                    if (!next_header.success) {
                        return ASN1Result<std::vector<RawExtension>>::failure(next_header.error);
                    }
                    if (next_header.value.identifier.tag_class == ASN1Class::Universal &&
                        next_header.value.identifier.tag_number == static_cast<uint32_t>(ASN1Tag::Boolean)) {
                        auto critical_result = parse_boolean(ext_cursor.remaining());
                        if (!critical_result.success) {
                            return ASN1Result<std::vector<RawExtension>>::failure(critical_result.error);
                        }
                        critical = critical_result.value;
                        ext_cursor.advance(critical_result.bytes_consumed);
                    }
                }

                if (ext_cursor.empty()) {
                    return ASN1Result<std::vector<RawExtension>>::failure("extension missing value");
                }

                auto value_result = parse_octet_string(ext_cursor.remaining());
                if (!value_result.success) {
                    return ASN1Result<std::vector<RawExtension>>::failure(value_result.error);
                }
                ext_cursor.advance(value_result.bytes_consumed);

                if (!ext_cursor.empty()) {
                    return ASN1Result<std::vector<RawExtension>>::failure("extra data inside extension");
                }

                RawExtension ext{};
                ext.oid = oid_result.value;
                ext.id = find_extension_by_oid(ext.oid);
                ext.critical = critical;
                ext.value = copy_bytes(value_result.value);
                extensions.push_back(std::move(ext));

                cursor.advance(ext_seq.bytes_consumed);
            }

            return ASN1Result<std::vector<RawExtension>>::ok(extensions, seq_result.bytes_consumed);
        }

        inline ASN1Result<std::vector<RawExtension>> parse_extensions_full(ByteSpan input) {
            auto header = parse_id_len(input);
            if (!header.success) {
                return ASN1Result<std::vector<RawExtension>>::failure(header.error);
            }
            const auto &identifier = header.value.identifier;
            if (identifier.tag_class != ASN1Class::ContextSpecific || identifier.tag_number != 3 ||
                !identifier.constructed) {
                return ASN1Result<std::vector<RawExtension>>::failure("expected [3] EXPLICIT extensions");
            }
            const auto content = input.subspan(header.value.header_bytes, header.value.length);
            auto sequence_result = parse_extension_sequence(content);
            if (!sequence_result.success) {
                return ASN1Result<std::vector<RawExtension>>::failure(sequence_result.error);
            }
            sequence_result.bytes_consumed = header.value.header_bytes + header.value.length;
            return sequence_result;
        }

        inline ParseResult make_error(std::string message) { return ParseResult{false, {}, std::move(message)}; }

        inline ParseResult parse_certificate(ByteSpan input, bool relaxed) {
            if (input.empty()) {
                return make_error("empty certificate buffer");
            }

            CertificateContext context{};
            context.der.assign(input.begin(), input.end());
            ByteSpan owned_span(context.der.data(), context.der.size());

            auto top_sequence = parse_sequence(owned_span);
            if (!top_sequence.success) {
                return make_error(top_sequence.error);
            }
            if (top_sequence.bytes_consumed != owned_span.size() && !relaxed) {
                return make_error("extra data after certificate");
            }

            DerCursor cert_cursor(top_sequence.value);

            auto tbs_sequence = parse_sequence(cert_cursor.remaining());
            if (!tbs_sequence.success) {
                return make_error(tbs_sequence.error);
            }
            const auto tbs_full = cert_cursor.remaining().first(tbs_sequence.bytes_consumed);
            context.tbs_certificate = copy_bytes(tbs_full);
            cert_cursor.advance(tbs_sequence.bytes_consumed);

            auto outer_signature = parse_algorithm_identifier_full(cert_cursor.remaining());
            if (!outer_signature.success) {
                return make_error(outer_signature.error);
            }
            context.outer_signature = outer_signature.value;
            cert_cursor.advance(outer_signature.bytes_consumed);

            auto signature_value = parse_bit_string(cert_cursor.remaining());
            if (!signature_value.success) {
                return make_error(signature_value.error);
            }
            if (signature_value.value.unused_bits != 0 && !relaxed) {
                return make_error("signature BIT STRING has unused bits");
            }
            context.signature_value = copy_bytes(signature_value.value.bytes);
            cert_cursor.advance(signature_value.bytes_consumed);

            if (!cert_cursor.empty() && !relaxed) {
                return make_error("extra fields after signatureValue");
            }

            DerCursor tbs_cursor(tbs_sequence.value);

            // Version (optional)
            if (!tbs_cursor.empty()) {
                auto version_check = parse_id_len(tbs_cursor.remaining());
                if (!version_check.success) {
                    return make_error(version_check.error);
                }
                const auto &identifier = version_check.value.identifier;
                if (identifier.tag_class == ASN1Class::ContextSpecific && identifier.tag_number == 0) {
                    auto version_res = parse_version(tbs_cursor.remaining());
                    if (!version_res.success) {
                        return make_error(version_res.error);
                    }
                    context.version = version_res.value;
                    tbs_cursor.advance(version_res.bytes_consumed);
                } else {
                    context.version = 1;
                }
            }

            // Serial Number
            auto serial_number = parse_integer(tbs_cursor.remaining());
            if (!serial_number.success) {
                return make_error(serial_number.error);
            }
            context.serial_number = copy_bytes(serial_number.value);
            tbs_cursor.advance(serial_number.bytes_consumed);

            // Signature Algorithm (inside TBSCertificate)
            auto tbs_signature = parse_algorithm_identifier_full(tbs_cursor.remaining());
            if (!tbs_signature.success) {
                return make_error(tbs_signature.error);
            }
            context.tbs_signature = tbs_signature.value;
            tbs_cursor.advance(tbs_signature.bytes_consumed);

            // Issuer
            auto issuer = parse_name_full(tbs_cursor.remaining());
            if (!issuer.success) {
                return make_error(issuer.error);
            }
            context.issuer = issuer.value;
            tbs_cursor.advance(issuer.bytes_consumed);

            // Validity
            auto validity = parse_validity(tbs_cursor.remaining());
            if (!validity.success) {
                return make_error(validity.error);
            }
            context.not_before = validity.value.not_before;
            context.not_after = validity.value.not_after;
            tbs_cursor.advance(validity.bytes_consumed);

            // Subject
            auto subject = parse_name_full(tbs_cursor.remaining());
            if (!subject.success) {
                return make_error(subject.error);
            }
            context.subject = subject.value;
            tbs_cursor.advance(subject.bytes_consumed);

            // SubjectPublicKeyInfo
            auto spki = parse_subject_public_key_info_full(tbs_cursor.remaining());
            if (!spki.success) {
                return make_error(spki.error);
            }
            context.subject_public_key_info = spki.value;
            tbs_cursor.advance(spki.bytes_consumed);

            // Optional fields: issuerUniqueID [1], subjectUniqueID [2], extensions [3]
            while (!tbs_cursor.empty()) {
                auto next = parse_id_len(tbs_cursor.remaining());
                if (!next.success) {
                    return make_error(next.error);
                }
                const auto &identifier = next.value.identifier;

                if (identifier.tag_class == ASN1Class::ContextSpecific) {
                    if (identifier.tag_number == 3 && context.version < 3 && !relaxed) {
                        return make_error("extensions present but version < 3");
                    }
                    if (identifier.tag_number == 3) {
                        auto extensions_result = parse_extensions_full(tbs_cursor.remaining());
                        if (!extensions_result.success) {
                            return make_error(extensions_result.error);
                        }
                        context.extensions = extensions_result.value;
                        tbs_cursor.advance(extensions_result.bytes_consumed);
                        continue;
                    }

                    // issuerUniqueID [1] and subjectUniqueID [2] are skipped but validated as BIT STRINGs
                    if (identifier.tag_number == 1 || identifier.tag_number == 2) {
                        auto bit_result = parse_bit_string(tbs_cursor.remaining());
                        if (!bit_result.success) {
                            return make_error(bit_result.error);
                        }
                        tbs_cursor.advance(bit_result.bytes_consumed);
                        continue;
                    }
                }

                if (!relaxed) {
                    return make_error("unexpected field in TBSCertificate");
                }
                break;
            }

            return ParseResult{true, std::move(context), {}};
        }

    } // namespace detail

    inline ParseResult parse_x509_cert(ByteSpan input) { return detail::parse_certificate(input, false); }

    inline ParseResult parse_x509_cert_relaxed(ByteSpan input) { return detail::parse_certificate(input, true); }

} // namespace authbox::pik
