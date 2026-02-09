#include <doctest/doctest.h>

#include <cstdlib>
#include <optional>
#include <string>

#include <pki/trust_store.hpp>

TEST_SUITE("cert/trust_store_system") {
    TEST_CASE("load_from_system respects SSL_CERT_FILE when set (negative path)") {
        using namespace authbox::pik;

        // Save original environment variables
        std::optional<std::string> orig_cert_file;
        std::optional<std::string> orig_cert_dir;
        if (const char *v = std::getenv("SSL_CERT_FILE")) {
            orig_cert_file = v;
        }
        if (const char *v = std::getenv("SSL_CERT_DIR")) {
            orig_cert_dir = v;
        }

        // Point to a non-existent file to ensure failure path is exercised
        setenv("SSL_CERT_FILE", "/nonexistent/doesnotexist.pem", 1);
        unsetenv("SSL_CERT_DIR");
        auto res = TrustStore::load_from_system();
        CHECK_FALSE(res.success);

        // Restore original environment variables
        if (orig_cert_file) {
            setenv("SSL_CERT_FILE", orig_cert_file->c_str(), 1);
        } else {
            unsetenv("SSL_CERT_FILE");
        }
        if (orig_cert_dir) {
            setenv("SSL_CERT_DIR", orig_cert_dir->c_str(), 1);
        }
    }
}
