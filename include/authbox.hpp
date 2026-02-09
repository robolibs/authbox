#pragma once

#include <echo/echo.hpp>

#include <did/did.hpp>
#include <pki/pki.hpp>

namespace authbox {

    inline constexpr const char *VERSION = "0.0.1";

    inline void log_startup() { echo::info("authbox initialized, version=", VERSION); }

} // namespace authbox

namespace autbox = authbox;
