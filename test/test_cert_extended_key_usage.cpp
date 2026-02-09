#include <doctest/doctest.h>

#include "cert_test_helpers.hpp"
#include <pki/builder.hpp>
#include <pki/certificate.hpp>
#include <keylock/crypto/context.hpp>

using namespace authbox::pik;
using namespace keylock::crypto;

TEST_SUITE("cert/extended_key_usage") {

    TEST_CASE("ExtendedKeyUsageExtension - Basic construction") {
        std::vector<Oid> oids = {
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}}, // serverAuth
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 2}}  // clientAuth
        };

        ExtendedKeyUsageExtension eku(false, oids);

        CHECK(eku.id() == ExtensionId::ExtendedKeyUsage);
        CHECK_FALSE(eku.critical());
        CHECK(eku.purpose_oids().size() == 2);
    }

    TEST_CASE("ExtendedKeyUsageExtension - OID to purpose conversion") {
        SUBCASE("ServerAuth") {
            Oid oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}};
            CHECK(ExtendedKeyUsageExtension::oid_to_purpose(oid) ==
                  ExtendedKeyUsageExtension::KeyPurposeId::ServerAuth);
        }

        SUBCASE("ClientAuth") {
            Oid oid{{1, 3, 6, 1, 5, 5, 7, 3, 2}};
            CHECK(ExtendedKeyUsageExtension::oid_to_purpose(oid) ==
                  ExtendedKeyUsageExtension::KeyPurposeId::ClientAuth);
        }

        SUBCASE("CodeSigning") {
            Oid oid{{1, 3, 6, 1, 5, 5, 7, 3, 3}};
            CHECK(ExtendedKeyUsageExtension::oid_to_purpose(oid) ==
                  ExtendedKeyUsageExtension::KeyPurposeId::CodeSigning);
        }

        SUBCASE("EmailProtection") {
            Oid oid{{1, 3, 6, 1, 5, 5, 7, 3, 4}};
            CHECK(ExtendedKeyUsageExtension::oid_to_purpose(oid) ==
                  ExtendedKeyUsageExtension::KeyPurposeId::EmailProtection);
        }

        SUBCASE("TimeStamping") {
            Oid oid{{1, 3, 6, 1, 5, 5, 7, 3, 8}};
            CHECK(ExtendedKeyUsageExtension::oid_to_purpose(oid) ==
                  ExtendedKeyUsageExtension::KeyPurposeId::TimeStamping);
        }

        SUBCASE("OCSPSigning") {
            Oid oid{{1, 3, 6, 1, 5, 5, 7, 3, 9}};
            CHECK(ExtendedKeyUsageExtension::oid_to_purpose(oid) ==
                  ExtendedKeyUsageExtension::KeyPurposeId::OCSPSigning);
        }

        SUBCASE("AnyExtendedKeyUsage") {
            Oid oid{{2, 5, 29, 37, 0}};
            CHECK(ExtendedKeyUsageExtension::oid_to_purpose(oid) ==
                  ExtendedKeyUsageExtension::KeyPurposeId::AnyExtendedKeyUsage);
        }

        SUBCASE("Unknown OID") {
            Oid oid{{1, 2, 3, 4, 5}};
            CHECK(ExtendedKeyUsageExtension::oid_to_purpose(oid) == ExtendedKeyUsageExtension::KeyPurposeId::Unknown);
        }
    }

    TEST_CASE("ExtendedKeyUsageExtension - Purpose to OID conversion") {
        using KeyPurposeId = ExtendedKeyUsageExtension::KeyPurposeId;

        auto server_oid = ExtendedKeyUsageExtension::purpose_to_oid(KeyPurposeId::ServerAuth);
        CHECK(server_oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 1});

        auto client_oid = ExtendedKeyUsageExtension::purpose_to_oid(KeyPurposeId::ClientAuth);
        CHECK(client_oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 2});

        auto code_oid = ExtendedKeyUsageExtension::purpose_to_oid(KeyPurposeId::CodeSigning);
        CHECK(code_oid.nodes == std::vector<uint32_t>{1, 3, 6, 1, 5, 5, 7, 3, 3});
    }

    TEST_CASE("ExtendedKeyUsageExtension - has_purpose with KeyPurposeId") {
        std::vector<Oid> oids = {
            ExtendedKeyUsageExtension::purpose_to_oid(ExtendedKeyUsageExtension::KeyPurposeId::ServerAuth),
            ExtendedKeyUsageExtension::purpose_to_oid(ExtendedKeyUsageExtension::KeyPurposeId::ClientAuth)};

        ExtendedKeyUsageExtension eku(false, oids);

        CHECK(eku.has_purpose(ExtendedKeyUsageExtension::KeyPurposeId::ServerAuth));
        CHECK(eku.has_purpose(ExtendedKeyUsageExtension::KeyPurposeId::ClientAuth));
        CHECK_FALSE(eku.has_purpose(ExtendedKeyUsageExtension::KeyPurposeId::CodeSigning));
        CHECK_FALSE(eku.has_purpose(ExtendedKeyUsageExtension::KeyPurposeId::EmailProtection));
    }

    TEST_CASE("ExtendedKeyUsageExtension - has_purpose with OID") {
        std::vector<Oid> oids = {
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}} // serverAuth
        };

        ExtendedKeyUsageExtension eku(false, oids);

        CHECK(eku.has_purpose(Oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}}));
        CHECK_FALSE(eku.has_purpose(Oid{{1, 3, 6, 1, 5, 5, 7, 3, 2}}));
    }

    TEST_CASE("ExtendedKeyUsageExtension - anyExtendedKeyUsage allows all") {
        std::vector<Oid> oids = {
            Oid{{2, 5, 29, 37, 0}} // anyExtendedKeyUsage
        };

        ExtendedKeyUsageExtension eku(false, oids);

        CHECK(eku.allows_any());
        // anyExtendedKeyUsage should allow any purpose check
        CHECK(eku.has_purpose(ExtendedKeyUsageExtension::KeyPurposeId::ServerAuth));
        CHECK(eku.has_purpose(ExtendedKeyUsageExtension::KeyPurposeId::ClientAuth));
        CHECK(eku.has_purpose(ExtendedKeyUsageExtension::KeyPurposeId::CodeSigning));
        CHECK(eku.has_purpose(Oid{{1, 2, 3, 4, 5}})); // Even unknown OIDs
    }

    TEST_CASE("ExtendedKeyUsageExtension - Helper methods") {
        std::vector<Oid> oids = {
            ExtendedKeyUsageExtension::purpose_to_oid(ExtendedKeyUsageExtension::KeyPurposeId::ServerAuth),
            ExtendedKeyUsageExtension::purpose_to_oid(ExtendedKeyUsageExtension::KeyPurposeId::CodeSigning)};

        ExtendedKeyUsageExtension eku(false, oids);

        CHECK(eku.allows_server_auth());
        CHECK_FALSE(eku.allows_client_auth());
        CHECK(eku.allows_code_signing());
        CHECK_FALSE(eku.allows_email_protection());
        CHECK_FALSE(eku.allows_any());
    }

    TEST_CASE("ExtendedKeyUsageExtension - recognized_purposes") {
        std::vector<Oid> oids = {
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}}, // serverAuth
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 2}}, // clientAuth
            Oid{{9, 9, 9, 9, 9}}              // unknown
        };

        ExtendedKeyUsageExtension eku(false, oids);

        auto purposes = eku.recognized_purposes();
        CHECK(purposes.size() == 2); // Unknown should not be included
        CHECK(std::find(purposes.begin(), purposes.end(), ExtendedKeyUsageExtension::KeyPurposeId::ServerAuth) !=
              purposes.end());
        CHECK(std::find(purposes.begin(), purposes.end(), ExtendedKeyUsageExtension::KeyPurposeId::ClientAuth) !=
              purposes.end());
    }

    TEST_CASE("CertificateBuilder - set_extended_key_usage with OIDs") {
        Context ctx(Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();

        std::vector<Oid> purposes = {
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}}, // serverAuth
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 2}}  // clientAuth
        };

        CertificateBuilder builder;
        builder.set_serial(12345)
            .set_subject_from_string("CN=Test Server")
            .set_issuer_from_string("CN=Test CA")
            .set_validity(std::chrono::system_clock::now(), std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_extended_key_usage(purposes);

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);

        auto eku = cert.value.extended_key_usage();
        REQUIRE(eku.has_value());
        CHECK(eku->purpose_oids().size() == 2);
        CHECK(eku->allows_server_auth());
        CHECK(eku->allows_client_auth());
    }

    TEST_CASE("CertificateBuilder - set_extended_key_usage empty list") {
        Context ctx(Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();

        CertificateBuilder builder;
        builder.set_serial(12345)
            .set_subject_from_string("CN=Test")
            .set_issuer_from_string("CN=Test CA")
            .set_validity(std::chrono::system_clock::now(), std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_extended_key_usage(std::vector<Oid>{}); // Empty

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);

        // Empty list should not add the extension
        auto eku = cert.value.extended_key_usage();
        CHECK_FALSE(eku.has_value());
    }

    TEST_CASE("Certificate - extended_key_usage accessor") {
        Context ctx(Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();

        SUBCASE("Certificate with EKU extension") {
            std::vector<Oid> purposes = {
                Oid{{1, 3, 6, 1, 5, 5, 7, 3, 3}} // codeSigning
            };

            CertificateBuilder builder;
            builder.set_serial(100)
                .set_subject_from_string("CN=Code Signer")
                .set_issuer_from_string("CN=CA")
                .set_validity(std::chrono::system_clock::now(),
                              std::chrono::system_clock::now() + std::chrono::hours(24))
                .set_subject_public_key_ed25519(key.public_key)
                .set_extended_key_usage(purposes);

            auto cert = builder.build_ed25519(key, true);
            REQUIRE(cert.success);

            auto eku = cert.value.extended_key_usage();
            REQUIRE(eku.has_value());
            CHECK(eku->allows_code_signing());
            CHECK_FALSE(eku->allows_server_auth());
        }

        SUBCASE("Certificate without EKU extension") {
            CertificateBuilder builder;
            builder.set_serial(101)
                .set_subject_from_string("CN=No EKU")
                .set_issuer_from_string("CN=CA")
                .set_validity(std::chrono::system_clock::now(),
                              std::chrono::system_clock::now() + std::chrono::hours(24))
                .set_subject_public_key_ed25519(key.public_key);

            auto cert = builder.build_ed25519(key, true);
            REQUIRE(cert.success);

            auto eku = cert.value.extended_key_usage();
            CHECK_FALSE(eku.has_value());
        }
    }

    TEST_CASE("Certificate - TLS Server certificate with EKU") {
        Context ctx(Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();

        std::vector<Oid> purposes = {
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}} // serverAuth
        };

        CertificateBuilder builder;
        builder.set_serial(200)
            .set_subject_from_string("CN=example.com")
            .set_issuer_from_string("CN=CA")
            .set_validity(std::chrono::system_clock::now(),
                          std::chrono::system_clock::now() + std::chrono::hours(24 * 365))
            .set_subject_public_key_ed25519(key.public_key)
            .set_key_usage(KeyUsageExtension::DigitalSignature)
            .set_extended_key_usage(purposes)
            .set_subject_alt_name({{SubjectAltNameExtension::GeneralNameType::DNSName, "example.com"}});

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);

        CHECK(cert.value.verify_extensions(CertificatePurpose::TLSServer));
        CHECK(cert.value.match_hostname("example.com"));

        auto eku = cert.value.extended_key_usage();
        REQUIRE(eku.has_value());
        CHECK(eku->allows_server_auth());
    }

    TEST_CASE("Certificate - TLS Client certificate with EKU") {
        Context ctx(Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();

        std::vector<Oid> purposes = {
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 2}} // clientAuth
        };

        CertificateBuilder builder;
        builder.set_serial(201)
            .set_subject_from_string("CN=Client Certificate")
            .set_issuer_from_string("CN=CA")
            .set_validity(std::chrono::system_clock::now(),
                          std::chrono::system_clock::now() + std::chrono::hours(24 * 365))
            .set_subject_public_key_ed25519(key.public_key)
            .set_key_usage(KeyUsageExtension::DigitalSignature)
            .set_extended_key_usage(purposes);

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);

        CHECK(cert.value.verify_extensions(CertificatePurpose::TLSClient));

        auto eku = cert.value.extended_key_usage();
        REQUIRE(eku.has_value());
        CHECK(eku->allows_client_auth());
        CHECK_FALSE(eku->allows_server_auth());
    }

    TEST_CASE("Certificate - Multi-purpose certificate") {
        Context ctx(Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();

        std::vector<Oid> purposes = {
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}}, // serverAuth
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 2}}, // clientAuth
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 4}}  // emailProtection
        };

        CertificateBuilder builder;
        builder.set_serial(300)
            .set_subject_from_string("CN=Multi Purpose")
            .set_issuer_from_string("CN=CA")
            .set_validity(std::chrono::system_clock::now(), std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_extended_key_usage(purposes);

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);

        auto eku = cert.value.extended_key_usage();
        REQUIRE(eku.has_value());
        CHECK(eku->allows_server_auth());
        CHECK(eku->allows_client_auth());
        CHECK(eku->allows_email_protection());
        CHECK_FALSE(eku->allows_code_signing());

        auto recognized = eku->recognized_purposes();
        CHECK(recognized.size() == 3);
    }

    TEST_CASE("Certificate - Critical EKU extension") {
        Context ctx(Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();

        std::vector<Oid> purposes = {Oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}}};

        CertificateBuilder builder;
        builder.set_serial(400)
            .set_subject_from_string("CN=Critical EKU")
            .set_issuer_from_string("CN=CA")
            .set_validity(std::chrono::system_clock::now(), std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_extended_key_usage(purposes, true); // Critical = true

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);

        auto eku = cert.value.extended_key_usage();
        REQUIRE(eku.has_value());
        CHECK(eku->critical());
    }

    TEST_CASE("Certificate - Round-trip: Build, serialize, parse") {
        Context ctx(Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();

        std::vector<Oid> purposes = {Oid{{1, 3, 6, 1, 5, 5, 7, 3, 1}}, Oid{{1, 3, 6, 1, 5, 5, 7, 3, 3}}};

        CertificateBuilder builder;
        builder.set_serial(500)
            .set_subject_from_string("CN=Round Trip")
            .set_issuer_from_string("CN=CA")
            .set_validity(std::chrono::system_clock::now(), std::chrono::system_clock::now() + std::chrono::hours(24))
            .set_subject_public_key_ed25519(key.public_key)
            .set_extended_key_usage(purposes);

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);

        // Serialize to DER
        auto der = cert.value.to_der();

        // Parse back
        auto parsed = Certificate::parse(der);
        REQUIRE(parsed.success);

        // Verify EKU is preserved
        auto eku = parsed.value.extended_key_usage();
        REQUIRE(eku.has_value());
        CHECK(eku->purpose_oids().size() == 2);
        CHECK(eku->allows_server_auth());
        CHECK(eku->allows_code_signing());
    }

    TEST_CASE("Certificate - OCSP Signing purpose") {
        Context ctx(Context::Algorithm::Ed25519);
        auto key = ctx.generate_keypair();

        std::vector<Oid> purposes = {
            Oid{{1, 3, 6, 1, 5, 5, 7, 3, 9}} // OCSPSigning
        };

        CertificateBuilder builder;
        builder.set_serial(600)
            .set_subject_from_string("CN=OCSP Responder")
            .set_issuer_from_string("CN=CA")
            .set_validity(std::chrono::system_clock::now(),
                          std::chrono::system_clock::now() + std::chrono::hours(24 * 30))
            .set_subject_public_key_ed25519(key.public_key)
            .set_extended_key_usage(purposes);

        auto cert = builder.build_ed25519(key, true);
        REQUIRE(cert.success);

        auto eku = cert.value.extended_key_usage();
        REQUIRE(eku.has_value());
        CHECK(eku->has_purpose(ExtendedKeyUsageExtension::KeyPurposeId::OCSPSigning));
    }
}
