#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <pki/asn1_common.hpp>
#include <pki/asn1_utils.hpp>

namespace authbox::pik::der {

    namespace detail {

        inline void append_identifier(std::vector<uint8_t> &out, ASN1Class cls, bool constructed, uint32_t tag) {
            uint8_t first = static_cast<uint8_t>(cls) | (constructed ? 0x20U : 0x00U);
            if (tag < 31) {
                first |= static_cast<uint8_t>(tag & 0x1FU);
                out.push_back(first);
                return;
            }
            first |= 0x1FU;
            out.push_back(first);
            uint32_t value = tag;
            std::array<uint8_t, 5> buffer{};
            int idx = 4;
            buffer[idx] = static_cast<uint8_t>(value & 0x7FU);
            value >>= 7U;
            while (value > 0 && idx > 0) {
                buffer[--idx] = static_cast<uint8_t>((value & 0x7FU) | 0x80U);
                value >>= 7U;
            }
            for (int i = idx; i < 5; ++i) {
                out.push_back(buffer[i]);
            }
        }

        inline void append_length(std::vector<uint8_t> &out, size_t length) {
            if (length < 0x80U) {
                out.push_back(static_cast<uint8_t>(length));
                return;
            }
            std::array<uint8_t, sizeof(size_t)> buffer{};
            int idx = static_cast<int>(buffer.size());
            size_t value = length;
            while (value > 0) {
                buffer[--idx] = static_cast<uint8_t>(value & 0xFFU);
                value >>= 8U;
            }
            const size_t octets = buffer.size() - static_cast<size_t>(idx);
            out.push_back(static_cast<uint8_t>(0x80U | octets));
            for (size_t i = static_cast<size_t>(idx); i < buffer.size(); ++i) {
                out.push_back(buffer[i]);
            }
        }

        inline std::vector<uint8_t> encode_string(std::string_view str, ASN1Tag tag) {
            std::vector<uint8_t> result;
            append_identifier(result, ASN1Class::Universal, false, static_cast<uint32_t>(tag));
            append_length(result, str.size());
            result.insert(result.end(), str.begin(), str.end());
            return result;
        }

        inline std::vector<uint8_t> encode_time_string(std::string_view str, ASN1Tag tag) {
            return encode_string(str, tag);
        }

    } // namespace detail

    inline std::vector<uint8_t> concat(const std::vector<std::vector<uint8_t>> &parts) {
        size_t total = 0;
        for (const auto &part : parts) {
            total += part.size();
        }
        std::vector<uint8_t> out;
        out.reserve(total);
        for (const auto &part : parts) {
            out.insert(out.end(), part.begin(), part.end());
        }
        return out;
    }

    inline std::vector<uint8_t> encode_tlv(ASN1Class cls, bool constructed, uint32_t tag, ByteSpan content) {
        std::vector<uint8_t> out;
        detail::append_identifier(out, cls, constructed, tag);
        detail::append_length(out, content.size());
        out.insert(out.end(), content.begin(), content.end());
        return out;
    }

    inline std::vector<uint8_t> encode_sequence(const std::vector<uint8_t> &content) {
        return encode_tlv(ASN1Class::Universal, true, static_cast<uint32_t>(ASN1Tag::Sequence), content);
    }

    inline std::vector<uint8_t> encode_set(const std::vector<uint8_t> &content) {
        return encode_tlv(ASN1Class::Universal, true, static_cast<uint32_t>(ASN1Tag::Set), content);
    }

    inline std::vector<uint8_t> encode_integer(const std::vector<uint8_t> &value) {
        std::vector<uint8_t> sanitized = value;
        while (sanitized.size() > 1 && sanitized[0] == 0x00 && (sanitized[1] & 0x80U) == 0) {
            sanitized.erase(sanitized.begin());
        }
        if (sanitized.empty()) {
            sanitized.push_back(0);
        }
        if (sanitized[0] & 0x80U) {
            sanitized.insert(sanitized.begin(), 0x00);
        }
        return encode_tlv(ASN1Class::Universal, false, static_cast<uint32_t>(ASN1Tag::Integer),
                          ByteSpan(sanitized.data(), sanitized.size()));
    }

    inline std::vector<uint8_t> encode_integer(uint64_t value) {
        std::vector<uint8_t> buffer;
        do {
            buffer.insert(buffer.begin(), static_cast<uint8_t>(value & 0xFFU));
            value >>= 8U;
        } while (value);
        if (buffer[0] & 0x80U) {
            buffer.insert(buffer.begin(), 0x00);
        }
        return encode_integer(buffer);
    }

    inline std::vector<uint8_t> encode_bit_string(ByteSpan bits, uint8_t unused_bits = 0) {
        std::vector<uint8_t> content;
        content.push_back(unused_bits);
        content.insert(content.end(), bits.begin(), bits.end());
        return encode_tlv(ASN1Class::Universal, false, static_cast<uint32_t>(ASN1Tag::BitString), content);
    }

    inline std::vector<uint8_t> encode_octet_string(ByteSpan bytes) {
        return encode_tlv(ASN1Class::Universal, false, static_cast<uint32_t>(ASN1Tag::OctetString), bytes);
    }

    inline std::vector<uint8_t> encode_boolean(bool value) {
        uint8_t byte = value ? 0xFF : 0x00;
        return encode_tlv(ASN1Class::Universal, false, static_cast<uint32_t>(ASN1Tag::Boolean), ByteSpan(&byte, 1));
    }

    inline std::vector<uint8_t> encode_oid(const Oid &oid) {
        std::vector<uint8_t> body;
        if (oid.nodes.size() < 2) {
            body.push_back(0);
        } else {
            const uint32_t first = oid.nodes[0];
            const uint32_t second = oid.nodes[1];
            body.push_back(static_cast<uint8_t>((first * 40U) + second));
            for (size_t i = 2; i < oid.nodes.size(); ++i) {
                uint32_t value = oid.nodes[i];
                std::array<uint8_t, 5> buffer{};
                int idx = 4;
                buffer[idx] = static_cast<uint8_t>(value & 0x7FU);
                value >>= 7U;
                while (value > 0 && idx > 0) {
                    buffer[--idx] = static_cast<uint8_t>((value & 0x7FU) | 0x80U);
                    value >>= 7U;
                }
                for (int j = idx; j < 5; ++j) {
                    body.push_back(buffer[j]);
                }
            }
        }
        return encode_tlv(ASN1Class::Universal, false, static_cast<uint32_t>(ASN1Tag::ObjectIdentifier), body);
    }

    inline std::vector<uint8_t> encode_utf8_string(std::string_view str) {
        return detail::encode_string(str, ASN1Tag::UTF8String);
    }

    inline std::vector<uint8_t> encode_printable_string(std::string_view str) {
        return detail::encode_string(str, ASN1Tag::PrintableString);
    }

    inline std::vector<uint8_t> encode_ia5_string(std::string_view str) {
        return detail::encode_string(str, ASN1Tag::IA5String);
    }

    inline std::vector<uint8_t> encode_utctime(const std::string &view) {
        return detail::encode_time_string(view, ASN1Tag::UTCTime);
    }

    inline std::vector<uint8_t> encode_generalized_time(const std::string &view) {
        return detail::encode_time_string(view, ASN1Tag::GeneralizedTime);
    }

    inline std::string format_time(std::chrono::system_clock::time_point tp, bool utc_time) {
        auto t = std::chrono::system_clock::to_time_t(tp);
        std::tm tm{};
#if defined(_WIN32)
        gmtime_s(&tm, &t);
#else
        gmtime_r(&t, &tm);
#endif
        std::ostringstream oss;
        oss << std::setfill('0');
        if (utc_time) {
            oss << std::setw(2) << ((tm.tm_year + 1900) % 100);
        } else {
            oss << std::setw(4) << (tm.tm_year + 1900);
        }
        oss << std::setw(2) << (tm.tm_mon + 1) << std::setw(2) << tm.tm_mday << std::setw(2) << tm.tm_hour
            << std::setw(2) << tm.tm_min << std::setw(2) << tm.tm_sec << 'Z';
        return oss.str();
    }

    inline std::vector<uint8_t> serialize_time(std::chrono::system_clock::time_point tp) {
        auto t = std::chrono::system_clock::to_time_t(tp);
        std::tm tm{};
#if defined(_WIN32)
        gmtime_s(&tm, &t);
#else
        gmtime_r(&t, &tm);
#endif
        const int year = tm.tm_year + 1900;
        const bool use_utc = (year >= 1950 && year <= 2049);
        auto formatted = format_time(tp, use_utc);
        return use_utc ? encode_utctime(formatted) : encode_generalized_time(formatted);
    }

} // namespace authbox::pik::der
