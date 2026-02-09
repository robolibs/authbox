#pragma once

#include <pki/asn1_utils.hpp>
#include <pki/distinguished_name.hpp>
#include <pki/oid_registry.hpp>

namespace authbox::pik::detail {

    class DerCursor {
      public:
        explicit DerCursor(ByteSpan span) : data_(span) {}
        ByteSpan remaining() const { return data_.subspan(offset_); }
        bool empty() const { return offset_ >= data_.size(); }
        bool advance(size_t count) {
            if (offset_ + count > data_.size()) {
                return false;
            }
            offset_ += count;
            return true;
        }

      private:
        ByteSpan data_;
        size_t offset_{0};
    };

    inline std::vector<uint8_t> copy_span(ByteSpan span) { return std::vector<uint8_t>(span.begin(), span.end()); }

    inline ASN1Result<DistinguishedName> parse_name(ByteSpan input);
    inline ASN1Result<AlgorithmIdentifier> parse_algorithm_identifier(ByteSpan input);
    inline ASN1Result<SubjectPublicKeyInfo> parse_subject_public_key_info(ByteSpan input);
    inline ASN1Result<std::vector<RawExtension>> parse_extensions(ByteSpan input);
    inline ASN1Result<std::chrono::system_clock::time_point> parse_time_choice(ByteSpan input);

} // namespace authbox::pik::detail

namespace authbox::pik::detail {

    inline ASN1Result<DistinguishedName> parse_name(ByteSpan input) {
        auto seq = parse_sequence(input);
        if (!seq.success) {
            return ASN1Result<DistinguishedName>::failure(seq.error);
        }
        auto encoded = copy_span(input.first(seq.bytes_consumed));
        DistinguishedName dn(encoded);
        return ASN1Result<DistinguishedName>::ok(dn, seq.bytes_consumed);
    }

    inline ASN1Result<AlgorithmIdentifier> parse_algorithm_identifier(ByteSpan input) {
        auto seq = parse_sequence(input);
        if (!seq.success) {
            return ASN1Result<AlgorithmIdentifier>::failure(seq.error);
        }
        DerCursor cursor(seq.value);
        auto oid = parse_oid(cursor.remaining());
        if (!oid.success) {
            return ASN1Result<AlgorithmIdentifier>::failure(oid.error);
        }
        cursor.advance(oid.bytes_consumed);

        AlgorithmIdentifier identifier{};
        identifier.signature = find_sig_alg_by_oid(oid.value);
        if (auto hash_alg = find_hash_by_oid(oid.value)) {
            identifier.hash = *hash_alg;
        }

        return ASN1Result<AlgorithmIdentifier>::ok(identifier, seq.bytes_consumed);
    }

    inline ASN1Result<SubjectPublicKeyInfo> parse_subject_public_key_info(ByteSpan input) {
        auto seq = parse_sequence(input);
        if (!seq.success) {
            return ASN1Result<SubjectPublicKeyInfo>::failure(seq.error);
        }
        DerCursor cursor(seq.value);
        auto alg = parse_algorithm_identifier(cursor.remaining());
        if (!alg.success) {
            return ASN1Result<SubjectPublicKeyInfo>::failure(alg.error);
        }
        cursor.advance(alg.bytes_consumed);

        auto bit_string = parse_bit_string(cursor.remaining());
        if (!bit_string.success) {
            return ASN1Result<SubjectPublicKeyInfo>::failure(bit_string.error);
        }

        SubjectPublicKeyInfo spki{};
        spki.algorithm = alg.value;
        spki.public_key.assign(bit_string.value.bytes.begin(), bit_string.value.bytes.end());
        spki.unused_bits = bit_string.value.unused_bits;
        return ASN1Result<SubjectPublicKeyInfo>::ok(spki, seq.bytes_consumed);
    }

    inline ASN1Result<std::vector<RawExtension>> parse_extensions(ByteSpan input) {
        auto header = parse_id_len(input);
        if (!header.success) {
            return ASN1Result<std::vector<RawExtension>>::failure(header.error);
        }
        if (header.value.identifier.tag_class != ASN1Class::ContextSpecific || !header.value.identifier.constructed) {
            return ASN1Result<std::vector<RawExtension>>::failure("expected extensions");
        }
        auto seq = parse_sequence(input.subspan(header.value.header_bytes, header.value.length));
        if (!seq.success) {
            return ASN1Result<std::vector<RawExtension>>::failure(seq.error);
        }
        std::vector<RawExtension> extensions;
        DerCursor cursor(seq.value);
        while (!cursor.empty()) {
            auto ext_seq = parse_sequence(cursor.remaining());
            if (!ext_seq.success) {
                break;
            }
            DerCursor ext_cursor(ext_seq.value);
            auto oid = parse_oid(ext_cursor.remaining());
            if (!oid.success) {
                break;
            }
            ext_cursor.advance(oid.bytes_consumed);
            bool critical = false;
            auto maybe_bool = parse_boolean(ext_cursor.remaining());
            if (maybe_bool.success) {
                critical = maybe_bool.value;
                ext_cursor.advance(maybe_bool.bytes_consumed);
            }
            auto value = parse_octet_string(ext_cursor.remaining());
            if (!value.success) {
                break;
            }
            RawExtension ext{};
            ext.oid = oid.value;
            ext.id = find_extension_by_oid(ext.oid);
            ext.critical = critical;
            ext.value.assign(value.value.begin(), value.value.end());
            extensions.push_back(std::move(ext));
            cursor.advance(ext_seq.bytes_consumed);
        }
        return ASN1Result<std::vector<RawExtension>>::ok(extensions, header.value.header_bytes + header.value.length);
    }

    inline ASN1Result<std::chrono::system_clock::time_point> parse_time_choice(ByteSpan input) {
        if (input.empty()) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("empty time");
        }
        const uint8_t tag = input[0] & 0x1FU;
        if (tag == static_cast<uint8_t>(ASN1Tag::UTCTime)) {
            return parse_utc_time(input);
        }
        if (tag == static_cast<uint8_t>(ASN1Tag::GeneralizedTime)) {
            return parse_generalized_time(input);
        }
        return ASN1Result<std::chrono::system_clock::time_point>::failure("invalid time tag");
    }

} // namespace authbox::pik::detail
