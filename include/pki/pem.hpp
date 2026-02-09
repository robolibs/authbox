#pragma once

#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <pki/asn1_utils.hpp>

namespace authbox::pik {

    struct PemBlock {
        std::string label;
        std::vector<uint8_t> data;
    };

    struct PemResult {
        bool success{};
        PemBlock block{};
        std::string error{};
    };

    namespace detail {

        constexpr std::string_view kBeginMarker = "-----BEGIN ";
        constexpr std::string_view kEndMarker = "-----END ";
        constexpr std::string_view kTrailer = "-----";
        constexpr char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        inline int decode_base64_char(char c) {
            if (c >= 'A' && c <= 'Z') {
                return c - 'A';
            }
            if (c >= 'a' && c <= 'z') {
                return c - 'a' + 26;
            }
            if (c >= '0' && c <= '9') {
                return c - '0' + 52;
            }
            if (c == '+') {
                return 62;
            }
            if (c == '/') {
                return 63;
            }
            if (c == '=') {
                return -2;
            }
            return -1;
        }

        inline std::string encode_base64(ByteSpan data) {
            std::string out;
            out.reserve(((data.size() + 2) / 3) * 4);
            size_t i = 0;
            while (i + 3 <= data.size()) {
                const uint32_t chunk = (static_cast<uint32_t>(data[i]) << 16U) |
                                       (static_cast<uint32_t>(data[i + 1]) << 8U) | static_cast<uint32_t>(data[i + 2]);
                out.push_back(kBase64Alphabet[(chunk >> 18U) & 0x3F]);
                out.push_back(kBase64Alphabet[(chunk >> 12U) & 0x3F]);
                out.push_back(kBase64Alphabet[(chunk >> 6U) & 0x3F]);
                out.push_back(kBase64Alphabet[chunk & 0x3F]);
                i += 3;
            }

            const size_t remaining = data.size() - i;
            if (remaining == 1) {
                const uint32_t chunk = static_cast<uint32_t>(data[i]) << 16U;
                out.push_back(kBase64Alphabet[(chunk >> 18U) & 0x3F]);
                out.push_back(kBase64Alphabet[(chunk >> 12U) & 0x3F]);
                out.push_back('=');
                out.push_back('=');
            } else if (remaining == 2) {
                const uint32_t chunk =
                    (static_cast<uint32_t>(data[i]) << 16U) | (static_cast<uint32_t>(data[i + 1]) << 8U);
                out.push_back(kBase64Alphabet[(chunk >> 18U) & 0x3F]);
                out.push_back(kBase64Alphabet[(chunk >> 12U) & 0x3F]);
                out.push_back(kBase64Alphabet[(chunk >> 6U) & 0x3F]);
                out.push_back('=');
            }

            return out;
        }

        inline bool decode_base64(const std::string &input, std::vector<uint8_t> &output) {
            if (input.empty() || (input.size() % 4U) != 0U) {
                return false;
            }
            output.clear();
            output.reserve((input.size() / 4U) * 3U);

            for (size_t i = 0; i < input.size(); i += 4) {
                int values[4]{};
                for (size_t j = 0; j < 4; ++j) {
                    const int decoded = decode_base64_char(input[i + j]);
                    if (decoded == -1) {
                        return false;
                    }
                    values[j] = decoded;
                }

                if (values[0] < 0 || values[1] < 0) {
                    return false;
                }

                const bool pad2 = values[2] == -2;
                const bool pad3 = values[3] == -2;
                if (pad2 && !pad3) {
                    return false;
                }

                const int v2 = pad2 ? 0 : (values[2] & 0x3F);
                const int v3 = pad3 ? 0 : (values[3] & 0x3F);

                const uint32_t block = (static_cast<uint32_t>(values[0] & 0x3F) << 18U) |
                                       (static_cast<uint32_t>(values[1] & 0x3F) << 12U) |
                                       (static_cast<uint32_t>(v2) << 6U) | static_cast<uint32_t>(v3);

                output.push_back(static_cast<uint8_t>((block >> 16U) & 0xFF));
                if (!pad2) {
                    output.push_back(static_cast<uint8_t>((block >> 8U) & 0xFF));
                }
                if (!pad3) {
                    output.push_back(static_cast<uint8_t>(block & 0xFF));
                }
            }

            return true;
        }

        inline std::string strip_whitespace(std::string_view view, size_t start, size_t end) {
            std::string sanitized;
            sanitized.reserve(end - start);
            for (size_t i = start; i < end; ++i) {
                const char c = view[i];
                if (c == '\r' || c == '\n' || c == ' ' || c == '\t') {
                    continue;
                }
                sanitized.push_back(c);
            }
            return sanitized;
        }

        inline PemResult error_result(std::string message) { return PemResult{false, {}, std::move(message)}; }

        inline std::string build_block(std::string_view label, std::string body, size_t line_length) {
            std::ostringstream oss;
            oss << kBeginMarker << label << kTrailer << "\n";
            if (line_length == 0) {
                oss << body << "\n";
            } else {
                for (size_t i = 0; i < body.size(); i += line_length) {
                    oss << body.substr(i, line_length) << "\n";
                }
            }
            oss << kEndMarker << label << kTrailer << "\n";
            return oss.str();
        }

    } // namespace detail

    inline PemResult pem_decode(std::string_view pem, std::optional<std::string_view> expected_label = std::nullopt) {
        const auto begin_pos = pem.find(detail::kBeginMarker);
        if (begin_pos == std::string_view::npos) {
            return detail::error_result("missing PEM BEGIN marker");
        }

        const size_t label_start = begin_pos + detail::kBeginMarker.size();
        const auto label_end = pem.find(detail::kTrailer, label_start);
        if (label_end == std::string_view::npos) {
            return detail::error_result("unterminated PEM header");
        }
        const std::string label(pem.substr(label_start, label_end - label_start));

        if (expected_label && label != *expected_label) {
            return detail::error_result("unexpected PEM label");
        }

        size_t content_start = pem.find_first_of("\r\n", label_end + detail::kTrailer.size());
        if (content_start == std::string_view::npos) {
            return detail::error_result("PEM header missing newline");
        }
        while (content_start < pem.size() && (pem[content_start] == '\r' || pem[content_start] == '\n')) {
            ++content_start;
        }

        const std::string end_label = std::string(detail::kEndMarker) + label + std::string(detail::kTrailer);
        const auto footer_pos = pem.find(end_label, content_start);
        if (footer_pos == std::string_view::npos) {
            return detail::error_result("missing PEM END marker");
        }

        const auto base64_data = detail::strip_whitespace(pem, content_start, footer_pos);
        if (base64_data.empty()) {
            return detail::error_result("empty PEM body");
        }

        std::vector<uint8_t> decoded;
        if (!detail::decode_base64(base64_data, decoded)) {
            return detail::error_result("invalid base64 content");
        }

        PemBlock block{label, std::move(decoded)};
        return PemResult{true, std::move(block), {}};
    }

    inline std::string pem_encode(ByteSpan der, std::string_view label, size_t line_length = 64) {
        auto body = detail::encode_base64(der);
        return detail::build_block(label, std::move(body), line_length);
    }

    inline PemResult pem_decode_certificate(std::string_view pem) { return pem_decode(pem, "CERTIFICATE"); }

    inline PemResult pem_decode_private_key(std::string_view pem) { return pem_decode(pem, "PRIVATE KEY"); }

    inline std::string pem_encode_certificate(ByteSpan der) { return pem_encode(der, "CERTIFICATE"); }

    inline std::string pem_encode_private_key(ByteSpan der) { return pem_encode(der, "PRIVATE KEY"); }

} // namespace authbox::pik
