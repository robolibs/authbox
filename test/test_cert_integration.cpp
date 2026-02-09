#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"

#include <filesystem>
#include <fstream>

#include <pki/crl_builder.hpp>
#include <pki/csr_builder.hpp>
#include <pki/parser.hpp>
#include <pki/pem.hpp>
#include <pki/trust_store.hpp>

using namespace authbox::pik;

namespace {

    void write_file(const std::filesystem::path &path, const std::string &content) {
        std::ofstream os(path, std::ios::binary);
        REQUIRE(os.good());
        os << content;
    }

    bool has_openssl() { return std::system("openssl version > /dev/null 2>&1") == 0; }

} // namespace

TEST_SUITE("cert/integration") {
    TEST_CASE("parse certificate with extensions") {
        // Create a test certificate with Ed25519 (supported algorithm)
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();
        auto dn = cert_test::dn_from_string("CN=Test Certificate,O=Test Org,C=US");

        CertificateBuilder builder;
        builder.set_serial(12345)
            .set_subject(dn)
            .set_issuer(dn)
            .set_validity(std::chrono::system_clock::now() - std::chrono::hours(1),
                          std::chrono::system_clock::now() + std::chrono::hours(24 * 365))
            .set_subject_public_key_ed25519(key.public_key)
            .set_basic_constraints(true, 0)
            .set_key_usage(KeyUsageExtension::KeyCertSign | KeyUsageExtension::DigitalSignature);

        auto cert_result = builder.build_ed25519(key, true);
        REQUIRE(cert_result.success);

        // Encode to PEM and re-parse
        auto pem = pem_encode(cert_result.value.der(), "CERTIFICATE");
        auto decoded = pem_decode(pem, "CERTIFICATE");
        REQUIRE(decoded.success);

        auto parsed = parse_x509_cert(ByteSpan(decoded.block.data.data(), decoded.block.data.size()));
        REQUIRE(parsed.success);
        CHECK(parsed.certificate.subject.to_string().find("Test Certificate") != std::string::npos);
        CHECK(parsed.certificate.subject.to_string().find("Test Org") != std::string::npos);
    }

    TEST_CASE("OpenSSL interoperability") {
        if (!has_openssl()) {
            WARN("openssl not available; skipping");
            return;
        }
        namespace fs = std::filesystem;
        auto temp_dir = fs::temp_directory_path() / "keylock_openssl";
        fs::create_directories(temp_dir);
        auto key_path = temp_dir / "key.pem";
        auto cert_path = temp_dir / "cert.pem";
        std::string cmd = "openssl req -x509 -newkey ed25519 -keyout " + key_path.string() + " -out " +
                          cert_path.string() + " -days 1 -nodes -subj /CN=InteropTest >/dev/null 2>&1";
        REQUIRE(std::system(cmd.c_str()) == 0);
        auto certs = Certificate::load(cert_path.string());
        REQUIRE(certs.success);
        REQUIRE(!certs.value.empty());
        CHECK(certs.value[0].tbs().subject.to_string().find("InteropTest") != std::string::npos);
    }

    TEST_CASE("Certificate chain from PEM files") {
        keylock::crypto::Context::KeyPair root_key, intermediate_key, leaf_key;
        auto [root_cert, intermediate_cert, leaf_cert] = cert_test::make_chain(root_key, intermediate_key, leaf_key);

        namespace fs = std::filesystem;
        auto dir = fs::temp_directory_path() / "keylock_chain";
        fs::create_directories(dir);
        auto root_pem = dir / "root.pem";
        auto intermediate_pem = dir / "intermediate.pem";
        write_file(root_pem, root_cert.to_pem());
        write_file(intermediate_pem, intermediate_cert.to_pem());

        TrustStore store;
        auto root_store = TrustStore::load_from_file(root_pem.string());
        REQUIRE(root_store.success);
        store = root_store.value;

        auto parsed_intermediate = Certificate::load(intermediate_pem.string());
        REQUIRE(parsed_intermediate.success);

        auto result = leaf_cert.validate_chain(parsed_intermediate.value, store);
        CHECK(result.success);
        CHECK(result.value);
    }

    TEST_CASE("Expired and revoked certificates") {
        keylock::crypto::Context ctx(keylock::crypto::Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();
        auto now = std::chrono::system_clock::now();
        CertificateBuilder builder;
        auto dn = cert_test::dn_from_string("CN=Expired");
        builder.set_serial(999)
            .set_subject(dn)
            .set_issuer(dn)
            .set_validity(now - std::chrono::hours(48), now - std::chrono::hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_basic_constraints(false, std::nullopt, false);
        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);
        CHECK_FALSE(cert.value.check_validity());

        CrlBuilder crl_builder;
        crl_builder.set_issuer(dn).set_this_update(now).add_revoked(cert.value.tbs().serial_number, now,
                                                                    CrlReason::Superseded);
        auto crl = crl_builder.build_ed25519(key);
        REQUIRE(crl.success);
        CHECK(cert.value.is_revoked(crl.value));
    }
}
