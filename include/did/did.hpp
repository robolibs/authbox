#pragma once

#include <cctype>
#include <string_view>

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

    inline dp::String to_dp_string(std::string_view value) { return dp::String(value.data(), value.size()); }

    inline bool is_did_uri(std::string_view candidate) {
        if (!candidate.starts_with("did:")) {
            return false;
        }

        const size_t second_colon = candidate.find(':', 4);
        if (second_colon == std::string_view::npos || second_colon == candidate.size() - 1) {
            return false;
        }

        const std::string_view method = candidate.substr(4, second_colon - 4);
        if (method.empty()) {
            return false;
        }

        for (const char ch : method) {
            if (!(std::islower(static_cast<unsigned char>(ch)) || std::isdigit(static_cast<unsigned char>(ch)))) {
                return false;
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

    inline bool is_supported_method(std::string_view method) { return method == "key" || method == "web"; }

} // namespace authbox::did
