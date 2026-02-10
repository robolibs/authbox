#pragma once

#include <pki/certificate.hpp>

namespace keylock {
    namespace cert {
        using Certificate = authbox::pik::Certificate;
        using CertificateParseResult = authbox::pik::CertificateParseResult;
    } // namespace cert
} // namespace keylock
