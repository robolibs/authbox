#pragma once

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <datapod/datapod.hpp>
#include <echo/echo.hpp>

namespace authbox::did {

    using DidError = dp::String;
    template <typename T> using DidResult = dp::Result<T, DidError>;

    struct Did {
        dp::String uri;
        dp::String method;
        dp::String method_id;
    };

    struct DidUrl {
        Did did;
        dp::String path;
        dp::String query;
        dp::String fragment;
    };

    inline dp::String to_dp_string(std::string_view value) { return dp::String(value.data(), value.size()); }

    inline bool is_method_char(char ch) {
        return std::islower(static_cast<unsigned char>(ch)) || std::isdigit(static_cast<unsigned char>(ch));
    }

    inline bool is_method_id_char(char ch) {
        if (std::isalnum(static_cast<unsigned char>(ch))) {
            return true;
        }
        switch (ch) {
        case '.':
        case '_':
        case ':':
        case '-':
        case '%':
            return true;
        default:
            return false;
        }
    }

    inline bool is_hex_char(char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    }

    inline bool is_did_uri(std::string_view candidate) {
        if (!candidate.starts_with("did:")) {
            return false;
        }

        const size_t second_colon = candidate.find(':', 4);
        if (second_colon == std::string_view::npos || second_colon == candidate.size() - 1U) {
            return false;
        }

        const std::string_view method = candidate.substr(4, second_colon - 4);
        if (method.empty()) {
            return false;
        }

        for (const char ch : method) {
            if (!is_method_char(ch)) {
                return false;
            }
        }

        const std::string_view method_id = candidate.substr(second_colon + 1);
        if (method_id.empty()) {
            return false;
        }
        for (size_t i = 0; i < method_id.size(); ++i) {
            const char ch = method_id[i];
            if (!is_method_id_char(ch)) {
                return false;
            }
            if (ch == '%') {
                if ((i + 2U) >= method_id.size() || !is_hex_char(method_id[i + 1]) || !is_hex_char(method_id[i + 2])) {
                    return false;
                }
                i += 2U;
            }
        }

        return true;
    }

    inline DidResult<Did> parse(std::string_view uri) {
        echo::debug("did::parse called with uri=", uri);

        if (!is_did_uri(uri)) {
            echo::warn("did::parse rejected malformed DID uri");
            return DidResult<Did>::err(to_dp_string("Malformed DID URI"));
        }

        const size_t second_colon = uri.find(':', 4);
        Did parsed{};
        parsed.uri = to_dp_string(uri);
        parsed.method = to_dp_string(uri.substr(4, second_colon - 4));
        parsed.method_id = to_dp_string(uri.substr(second_colon + 1));

        echo::info("did::parse method=", parsed.method.c_str(), " id_len=", parsed.method_id.size());
        return DidResult<Did>::ok(std::move(parsed));
    }

    inline DidResult<DidUrl> parse_url(std::string_view did_url) {
        const size_t hash_pos = did_url.find('#');
        const size_t query_pos = did_url.find('?');
        const size_t path_pos = did_url.find('/', 4);

        size_t did_end = did_url.size();
        if (path_pos != std::string_view::npos) {
            did_end = std::min(did_end, path_pos);
        }
        if (query_pos != std::string_view::npos) {
            did_end = std::min(did_end, query_pos);
        }
        if (hash_pos != std::string_view::npos) {
            did_end = std::min(did_end, hash_pos);
        }

        const auto did_only = did_url.substr(0, did_end);
        auto parsed_did = parse(did_only);
        if (parsed_did.is_err()) {
            return DidResult<DidUrl>::err(parsed_did.error());
        }

        DidUrl out{};
        out.did = parsed_did.value();

        if (path_pos != std::string_view::npos) {
            const size_t path_end = std::min(query_pos == std::string_view::npos ? did_url.size() : query_pos,
                                             hash_pos == std::string_view::npos ? did_url.size() : hash_pos);
            out.path = to_dp_string(did_url.substr(path_pos, path_end - path_pos));
        }

        if (query_pos != std::string_view::npos) {
            const size_t query_end = hash_pos == std::string_view::npos ? did_url.size() : hash_pos;
            out.query = to_dp_string(did_url.substr(query_pos + 1, query_end - (query_pos + 1)));
        }

        if (hash_pos != std::string_view::npos) {
            out.fragment = to_dp_string(did_url.substr(hash_pos + 1));
        }

        return DidResult<DidUrl>::ok(std::move(out));
    }

    inline DidResult<std::string> percent_decode(std::string_view input) {
        std::string out;
        out.reserve(input.size());
        for (size_t i = 0; i < input.size(); ++i) {
            if (input[i] != '%') {
                out.push_back(input[i]);
                continue;
            }

            if ((i + 2U) >= input.size() || !is_hex_char(input[i + 1]) || !is_hex_char(input[i + 2])) {
                return DidResult<std::string>::err(to_dp_string("Invalid percent encoding"));
            }

            auto hex_value = [](char c) -> uint8_t {
                if (c >= '0' && c <= '9') {
                    return static_cast<uint8_t>(c - '0');
                }
                if (c >= 'a' && c <= 'f') {
                    return static_cast<uint8_t>(10 + (c - 'a'));
                }
                return static_cast<uint8_t>(10 + (c - 'A'));
            };

            const uint8_t byte = static_cast<uint8_t>((hex_value(input[i + 1]) << 4U) | hex_value(input[i + 2]));
            out.push_back(static_cast<char>(byte));
            i += 2U;
        }
        return DidResult<std::string>::ok(std::move(out));
    }

    inline DidResult<std::string> did_web_document_url(std::string_view did_uri) {
        auto parsed = parse(did_uri);
        if (parsed.is_err()) {
            return DidResult<std::string>::err(parsed.error());
        }
        if (parsed.value().method != "web") {
            return DidResult<std::string>::err(to_dp_string("DID method must be web"));
        }

        const std::string method_id(parsed.value().method_id.data(), parsed.value().method_id.size());
        std::vector<std::string_view> raw_segments;
        size_t start = 0;
        while (start <= method_id.size()) {
            const size_t sep = method_id.find(':', start);
            if (sep == std::string::npos) {
                raw_segments.push_back(std::string_view(method_id).substr(start));
                break;
            }
            raw_segments.push_back(std::string_view(method_id).substr(start, sep - start));
            start = sep + 1;
        }
        if (raw_segments.empty() || raw_segments.front().empty()) {
            return DidResult<std::string>::err(to_dp_string("did:web method-id is empty"));
        }

        auto decoded_host = percent_decode(raw_segments.front());
        if (decoded_host.is_err()) {
            return DidResult<std::string>::err(decoded_host.error());
        }

        std::string url = "https://";
        url += decoded_host.value();

        if (raw_segments.size() == 1U) {
            url += "/.well-known/did.json";
            return DidResult<std::string>::ok(std::move(url));
        }

        for (size_t i = 1; i < raw_segments.size(); ++i) {
            auto decoded = percent_decode(raw_segments[i]);
            if (decoded.is_err()) {
                return DidResult<std::string>::err(decoded.error());
            }
            url.push_back('/');
            url += decoded.value();
        }
        url += "/did.json";
        return DidResult<std::string>::ok(std::move(url));
    }

    inline bool is_supported_method(std::string_view method) { return method == "key" || method == "web"; }

} // namespace authbox::did
