#pragma once

#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <pki/asn1_common.hpp>

namespace authbox::pik {

    using ByteSpan = std::span<const uint8_t>;

    template <typename T> struct ASN1Result {
        bool success{};
        T value{};
        size_t bytes_consumed{};
        std::string error{};

        static ASN1Result<T> failure(std::string message) { return ASN1Result<T>{false, {}, 0, std::move(message)}; }

        static ASN1Result<T> ok(T value, size_t consumed) {
            return ASN1Result<T>{true, std::move(value), consumed, {}};
        }
    };

    struct ParsedHeader {
        ASN1Identifier identifier{};
        size_t length{};
        size_t header_bytes{};
    };

    struct BitStringView {
        uint8_t unused_bits{};
        ByteSpan bytes{};
    };

    namespace detail {
        constexpr size_t kMaxLengthOctets = sizeof(size_t);

        inline bool is_digit(char c) { return c >= '0' && c <= '9'; }

        inline bool parse_decimal(std::string_view view, int &value) {
            value = 0;
            if (view.empty()) {
                return false;
            }
            for (char c : view) {
                if (!is_digit(c)) {
                    return false;
                }
                value = (value * 10) + (c - '0');
            }
            return true;
        }

        inline ASN1Result<std::chrono::system_clock::time_point> make_time_point(int year, int month, int day, int hour,
                                                                                 int minute, int second) {
            using namespace std::chrono;
            if (month < 1 || month > 12 || day < 1 || day > 31 || hour < 0 || hour > 23 || minute < 0 || minute > 59 ||
                second < 0 || second > 60) {
                return ASN1Result<std::chrono::system_clock::time_point>::failure("invalid time component");
            }

            const auto y = std::chrono::year{year};
            const auto m = std::chrono::month{static_cast<unsigned>(month)};
            const auto d = std::chrono::day{static_cast<unsigned>(day)};
            const std::chrono::year_month_day ymd{y / m / d};
            if (!ymd.ok()) {
                return ASN1Result<std::chrono::system_clock::time_point>::failure("invalid calendar date");
            }

            const sys_days days{ymd};
            auto tp = days + hours{hour} + minutes{minute} + seconds{second};
            return ASN1Result<std::chrono::system_clock::time_point>::ok(tp, 0);
        }
    } // namespace detail

    inline ASN1Result<size_t> get_length(ByteSpan input) {
        if (input.empty()) {
            return ASN1Result<size_t>::failure("missing length field");
        }

        const uint8_t first = input[0];
        if ((first & 0x80U) == 0) {
            return ASN1Result<size_t>::ok(first, 1);
        }

        const size_t octet_count = first & 0x7FU;
        if (octet_count == 0) {
            return ASN1Result<size_t>::failure("indefinite lengths are not supported in DER");
        }
        if (octet_count > detail::kMaxLengthOctets) {
            return ASN1Result<size_t>::failure("length uses more bytes than supported");
        }
        if (input.size() < 1 + octet_count) {
            return ASN1Result<size_t>::failure("insufficient data for long-form length");
        }

        size_t length = 0;
        for (size_t i = 0; i < octet_count; ++i) {
            length = (length << 8) | input[1 + i];
        }
        return ASN1Result<size_t>::ok(length, 1 + octet_count);
    }

    inline ASN1Result<ParsedHeader> parse_id_len(ByteSpan input) {
        if (input.empty()) {
            return ASN1Result<ParsedHeader>::failure("input too small for ASN.1 header");
        }

        size_t offset = 0;
        const uint8_t first_octet = input[offset++];

        ASN1Identifier identifier{};
        identifier.tag_class = static_cast<ASN1Class>(first_octet & 0xC0U);
        identifier.constructed = (first_octet & 0x20U) != 0;

        uint32_t tag_number = first_octet & 0x1FU;
        if (tag_number == 0x1FU) {
            tag_number = 0;
            bool more = true;
            size_t iterations = 0;
            while (more) {
                if (offset >= input.size()) {
                    return ASN1Result<ParsedHeader>::failure("unterminated long-form tag number");
                }
                const uint8_t byte = input[offset++];
                more = (byte & 0x80U) != 0;
                tag_number = (tag_number << 7U) | (byte & 0x7FU);
                ++iterations;
                if (iterations > 4 || tag_number > ASN1_MAX_TAG_NUMBER) {
                    return ASN1Result<ParsedHeader>::failure("tag number exceeds supported range");
                }
            }
        }
        identifier.tag_number = tag_number;

        const auto length_res = get_length(input.subspan(offset));
        if (!length_res.success) {
            return ASN1Result<ParsedHeader>::failure(length_res.error);
        }

        const size_t header_bytes = offset + length_res.bytes_consumed;
        if (header_bytes + length_res.value > input.size()) {
            return ASN1Result<ParsedHeader>::failure("value length exceeds buffer");
        }

        ParsedHeader header{identifier, length_res.value, header_bytes};
        return ASN1Result<ParsedHeader>::ok(header, header_bytes + length_res.value);
    }

    inline ASN1Result<ByteSpan> parse_integer(ByteSpan input) {
        const auto header = parse_id_len(input);
        if (!header.success) {
            return ASN1Result<ByteSpan>::failure(header.error);
        }
        const auto &identifier = header.value.identifier;
        if (identifier.tag_class != ASN1Class::Universal ||
            identifier.tag_number != static_cast<uint32_t>(ASN1Tag::Integer)) {
            return ASN1Result<ByteSpan>::failure("expected INTEGER");
        }
        if (identifier.constructed) {
            return ASN1Result<ByteSpan>::failure("INTEGER must be primitive");
        }
        const auto content = input.subspan(header.value.header_bytes, header.value.length);
        return ASN1Result<ByteSpan>::ok(content, header.value.header_bytes + header.value.length);
    }

    inline ASN1Result<BitStringView> parse_bit_string(ByteSpan input) {
        const auto header = parse_id_len(input);
        if (!header.success) {
            return ASN1Result<BitStringView>::failure(header.error);
        }
        const auto &identifier = header.value.identifier;
        if (identifier.tag_class != ASN1Class::Universal ||
            identifier.tag_number != static_cast<uint32_t>(ASN1Tag::BitString)) {
            return ASN1Result<BitStringView>::failure("expected BIT STRING");
        }
        if (identifier.constructed) {
            return ASN1Result<BitStringView>::failure("BIT STRING must be primitive");
        }
        if (header.value.length == 0) {
            return ASN1Result<BitStringView>::failure("BIT STRING missing unused-bits byte");
        }
        const auto value = input.subspan(header.value.header_bytes, header.value.length);
        const uint8_t unused_bits = value[0];
        if (unused_bits > 7) {
            return ASN1Result<BitStringView>::failure("invalid unused bits");
        }
        const auto bytes = value.subspan(1);
        BitStringView view{unused_bits, bytes};
        return ASN1Result<BitStringView>::ok(view, header.value.header_bytes + header.value.length);
    }

    inline ASN1Result<ByteSpan> parse_octet_string(ByteSpan input) {
        const auto header = parse_id_len(input);
        if (!header.success) {
            return ASN1Result<ByteSpan>::failure(header.error);
        }
        const auto &identifier = header.value.identifier;
        if (identifier.tag_class != ASN1Class::Universal ||
            identifier.tag_number != static_cast<uint32_t>(ASN1Tag::OctetString)) {
            return ASN1Result<ByteSpan>::failure("expected OCTET STRING");
        }
        if (identifier.constructed) {
            return ASN1Result<ByteSpan>::failure("OCTET STRING must be primitive");
        }
        const auto content = input.subspan(header.value.header_bytes, header.value.length);
        return ASN1Result<ByteSpan>::ok(content, header.value.header_bytes + header.value.length);
    }

    inline ASN1Result<Oid> parse_oid(ByteSpan input) {
        const auto header = parse_id_len(input);
        if (!header.success) {
            return ASN1Result<Oid>::failure(header.error);
        }
        const auto &identifier = header.value.identifier;
        if (identifier.tag_class != ASN1Class::Universal ||
            identifier.tag_number != static_cast<uint32_t>(ASN1Tag::ObjectIdentifier)) {
            return ASN1Result<Oid>::failure("expected OBJECT IDENTIFIER");
        }
        if (identifier.constructed) {
            return ASN1Result<Oid>::failure("OBJECT IDENTIFIER must be primitive");
        }
        const auto content = input.subspan(header.value.header_bytes, header.value.length);
        if (content.empty()) {
            return ASN1Result<Oid>::failure("OBJECT IDENTIFIER has empty body");
        }

        Oid oid{};
        oid.nodes.reserve(content.size());

        const uint8_t first = content[0];
        uint32_t first_arc = first / 40U;
        if (first_arc > 2) {
            first_arc = 2;
        }
        uint32_t second_arc = first - (first_arc * 40U);
        oid.nodes.push_back(first_arc);
        oid.nodes.push_back(second_arc);

        size_t offset = 1;
        while (offset < content.size()) {
            uint32_t value = 0;
            do {
                const uint8_t byte = content[offset++];
                if (value > (std::numeric_limits<uint32_t>::max() >> 7U)) {
                    return ASN1Result<Oid>::failure("OBJECT IDENTIFIER arc overflow");
                }
                value = (value << 7U) | (byte & 0x7FU);
                if ((byte & 0x80U) == 0) {
                    break;
                }
                if (offset >= content.size()) {
                    return ASN1Result<Oid>::failure("truncated OBJECT IDENTIFIER arc");
                }
            } while (true);
            oid.nodes.push_back(value);
        }

        return ASN1Result<Oid>::ok(oid, header.value.header_bytes + header.value.length);
    }

    inline ASN1Result<ByteSpan> parse_sequence(ByteSpan input) {
        const auto header = parse_id_len(input);
        if (!header.success) {
            return ASN1Result<ByteSpan>::failure(header.error);
        }
        const auto &identifier = header.value.identifier;
        if (identifier.tag_class != ASN1Class::Universal ||
            identifier.tag_number != static_cast<uint32_t>(ASN1Tag::Sequence)) {
            return ASN1Result<ByteSpan>::failure("expected SEQUENCE");
        }
        if (!identifier.constructed) {
            return ASN1Result<ByteSpan>::failure("SEQUENCE must be constructed");
        }
        const auto content = input.subspan(header.value.header_bytes, header.value.length);
        return ASN1Result<ByteSpan>::ok(content, header.value.header_bytes + header.value.length);
    }

    inline ASN1Result<ByteSpan> parse_set(ByteSpan input) {
        const auto header = parse_id_len(input);
        if (!header.success) {
            return ASN1Result<ByteSpan>::failure(header.error);
        }
        const auto &identifier = header.value.identifier;
        if (identifier.tag_class != ASN1Class::Universal ||
            identifier.tag_number != static_cast<uint32_t>(ASN1Tag::Set)) {
            return ASN1Result<ByteSpan>::failure("expected SET");
        }
        if (!identifier.constructed) {
            return ASN1Result<ByteSpan>::failure("SET must be constructed");
        }
        const auto content = input.subspan(header.value.header_bytes, header.value.length);
        return ASN1Result<ByteSpan>::ok(content, header.value.header_bytes + header.value.length);
    }

    inline ASN1Result<bool> parse_boolean(ByteSpan input) {
        const auto header = parse_id_len(input);
        if (!header.success) {
            return ASN1Result<bool>::failure(header.error);
        }
        const auto &identifier = header.value.identifier;
        if (identifier.tag_class != ASN1Class::Universal ||
            identifier.tag_number != static_cast<uint32_t>(ASN1Tag::Boolean)) {
            return ASN1Result<bool>::failure("expected BOOLEAN");
        }
        if (identifier.constructed) {
            return ASN1Result<bool>::failure("BOOLEAN must be primitive");
        }
        if (header.value.length != 1) {
            return ASN1Result<bool>::failure("BOOLEAN length must be 1");
        }
        const auto content = input.subspan(header.value.header_bytes, 1);
        return ASN1Result<bool>::ok(content[0] != 0, header.value.header_bytes + header.value.length);
    }

    inline ASN1Result<std::chrono::system_clock::time_point> parse_utc_time(ByteSpan input) {
        const auto header = parse_id_len(input);
        if (!header.success) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure(header.error);
        }
        const auto &identifier = header.value.identifier;
        if (identifier.tag_class != ASN1Class::Universal ||
            identifier.tag_number != static_cast<uint32_t>(ASN1Tag::UTCTime)) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("expected UTCTime");
        }
        if (identifier.constructed) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("UTCTime must be primitive");
        }
        const auto content = input.subspan(header.value.header_bytes, header.value.length);
        if (content.size() < 11) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("UTCTime too short");
        }
        const auto str = std::string_view(reinterpret_cast<const char *>(content.data()), content.size());
        if (str.back() != 'Z') {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("UTCTime must end with Z");
        }
        const size_t digits = str.size() - 1;
        if (digits != 10 && digits != 12) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("UTCTime must have 10 or 12 digits");
        }

        int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
        if (!detail::parse_decimal(str.substr(0, 2), year) || !detail::parse_decimal(str.substr(2, 2), month) ||
            !detail::parse_decimal(str.substr(4, 2), day) || !detail::parse_decimal(str.substr(6, 2), hour) ||
            !detail::parse_decimal(str.substr(8, 2), minute)) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("invalid UTCTime digits");
        }
        if (digits == 12) {
            if (!detail::parse_decimal(str.substr(10, 2), second)) {
                return ASN1Result<std::chrono::system_clock::time_point>::failure("invalid UTCTime seconds");
            }
        } else {
            second = 0;
        }

        const int full_year = (year >= 50) ? (1900 + year) : (2000 + year);
        auto tp_result = detail::make_time_point(full_year, month, day, hour, minute, second);
        if (!tp_result.success) {
            return tp_result;
        }
        tp_result.bytes_consumed = header.value.header_bytes + header.value.length;
        return tp_result;
    }

    inline ASN1Result<std::chrono::system_clock::time_point> parse_generalized_time(ByteSpan input) {
        const auto header = parse_id_len(input);
        if (!header.success) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure(header.error);
        }
        const auto &identifier = header.value.identifier;
        if (identifier.tag_class != ASN1Class::Universal ||
            identifier.tag_number != static_cast<uint32_t>(ASN1Tag::GeneralizedTime)) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("expected GeneralizedTime");
        }
        if (identifier.constructed) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("GeneralizedTime must be primitive");
        }
        const auto content = input.subspan(header.value.header_bytes, header.value.length);
        if (content.size() < 13) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("GeneralizedTime too short");
        }
        const auto str = std::string_view(reinterpret_cast<const char *>(content.data()), content.size());
        if (str.back() != 'Z') {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("GeneralizedTime must end with Z");
        }
        const size_t digits = str.size() - 1;
        if (digits != 12 && digits != 14) { // allow optional seconds
            return ASN1Result<std::chrono::system_clock::time_point>::failure(
                "GeneralizedTime must have 12 or 14 digits");
        }

        int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
        if (!detail::parse_decimal(str.substr(0, 4), year) || !detail::parse_decimal(str.substr(4, 2), month) ||
            !detail::parse_decimal(str.substr(6, 2), day) || !detail::parse_decimal(str.substr(8, 2), hour) ||
            !detail::parse_decimal(str.substr(10, 2), minute)) {
            return ASN1Result<std::chrono::system_clock::time_point>::failure("invalid GeneralizedTime digits");
        }
        if (digits == 14) {
            if (!detail::parse_decimal(str.substr(12, 2), second)) {
                return ASN1Result<std::chrono::system_clock::time_point>::failure("invalid GeneralizedTime seconds");
            }
        } else {
            second = 0;
        }

        auto tp_result = detail::make_time_point(year, month, day, hour, minute, second);
        if (!tp_result.success) {
            return tp_result;
        }
        tp_result.bytes_consumed = header.value.header_bytes + header.value.length;
        return tp_result;
    }

    inline ASN1Result<std::string> parse_directory_string(ByteSpan input) {
        const auto header = parse_id_len(input);
        if (!header.success) {
            return ASN1Result<std::string>::failure(header.error);
        }
        const auto &identifier = header.value.identifier;
        if (identifier.tag_class != ASN1Class::Universal) {
            return ASN1Result<std::string>::failure("directory string invalid tag class");
        }
        const auto tag = static_cast<ASN1Tag>(identifier.tag_number);
        const auto content = input.subspan(header.value.header_bytes, header.value.length);

        auto make_ascii = [&]() -> std::string {
            return std::string(reinterpret_cast<const char *>(content.data()), content.size());
        };

        switch (tag) {
        case ASN1Tag::PrintableString:
        case ASN1Tag::IA5String:
        case ASN1Tag::UTF8String:
        case ASN1Tag::T61String:
            return ASN1Result<std::string>::ok(make_ascii(), header.value.header_bytes + header.value.length);
        case ASN1Tag::BMPString: {
            if (content.size() % 2 != 0) {
                return ASN1Result<std::string>::failure("BMPString must have even length");
            }
            std::string utf8;
            utf8.reserve(content.size());
            for (size_t i = 0; i < content.size(); i += 2) {
                const uint16_t codepoint =
                    (static_cast<uint16_t>(content[i]) << 8U) | static_cast<uint16_t>(content[i + 1]);
                if (codepoint <= 0x7F) {
                    utf8.push_back(static_cast<char>(codepoint));
                } else if (codepoint <= 0x7FF) {
                    utf8.push_back(static_cast<char>(0xC0 | ((codepoint >> 6) & 0x1F)));
                    utf8.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
                } else {
                    utf8.push_back(static_cast<char>(0xE0 | ((codepoint >> 12) & 0x0F)));
                    utf8.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
                    utf8.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
                }
            }
            return ASN1Result<std::string>::ok(utf8, header.value.header_bytes + header.value.length);
        }
        default:
            return ASN1Result<std::string>::failure("unsupported directory string tag");
        }
    }

} // namespace authbox::pik
