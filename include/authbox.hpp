#pragma once

#include <echo/echo.hpp>

#include <did/dereference.hpp>
#include <did/did.hpp>
#include <did/dns.hpp>
#include <did/document.hpp>
#include <did/jwk.hpp>
#include <did/key.hpp>
#include <did/peer.hpp>
#include <did/pkh.hpp>
#include <did/resolver.hpp>
#include <did/rpc.hpp>
#include <did/web_fetch_netpipe.hpp>
#include <did/x509.hpp>
#include <pki/pki.hpp>

namespace authbox {

    inline constexpr const char *VERSION = "0.0.1";

    inline void log_startup() { echo::info("authbox initialized, version=", VERSION); }

} // namespace authbox

namespace ab = authbox;
