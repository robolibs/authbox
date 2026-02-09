#include <doctest/doctest.h>

#include <keylock/keylock.hpp>
#include <pki/verify/wire_format.hpp>

TEST_SUITE("verify/wire_format") {
    TEST_CASE("serialize and deserialize VerifyRequest") {
        using namespace authbox::pik::verify::wire;

        // Create a request
        VerifyRequest req;

        // Add a dummy certificate
        CertificateData cert;
        cert.der_bytes = {0x30, 0x82, 0x01, 0x00}; // Fake DER data
        req.certificate_chain.push_back(cert);

        req.validation_timestamp = std::chrono::system_clock::now();
        req.flags = RequestFlags::NONE;

        // Serialize
        auto serialized = Serializer::serialize(req);

        // Check header
        REQUIRE(serialized.size() >= 6);
        CHECK(serialized[0] == MAGIC[0]);
        CHECK(serialized[1] == MAGIC[1]);
        CHECK(serialized[2] == MAGIC[2]);
        CHECK(serialized[3] == MAGIC[3]);
        CHECK(serialized[4] == VERSION);
        CHECK(serialized[5] == static_cast<uint8_t>(MessageType::VERIFY_REQUEST));

        // Deserialize
        VerifyRequest deserialized;
        bool success = Serializer::deserialize(serialized, deserialized);

        REQUIRE(success);
        CHECK(deserialized.certificate_chain.size() == 1);
        CHECK(deserialized.certificate_chain[0].der_bytes == cert.der_bytes);
        CHECK(deserialized.nonce.size() == 32);
    }

    TEST_CASE("serialize and deserialize VerifyResponse") {
        using namespace authbox::pik::verify::wire;

        // Create a response
        VerifyResponse resp;
        resp.status = VerifyStatus::GOOD;
        resp.reason = "Certificate is valid";
        resp.revocation_time = std::chrono::system_clock::now();
        resp.this_update = std::chrono::system_clock::now();
        resp.next_update = std::chrono::system_clock::now() + std::chrono::hours(24);

        // Generate signature (64 bytes for Ed25519)
        resp.signature.resize(64);
        randombytes_buf(resp.signature.data(), resp.signature.size());

        // Generate nonce
        resp.nonce.resize(32);
        randombytes_buf(resp.nonce.data(), resp.nonce.size());

        // Serialize
        auto serialized = Serializer::serialize(resp);

        // Check header
        REQUIRE(serialized.size() >= 6);
        CHECK(serialized[0] == MAGIC[0]);
        CHECK(serialized[1] == MAGIC[1]);
        CHECK(serialized[2] == MAGIC[2]);
        CHECK(serialized[3] == MAGIC[3]);
        CHECK(serialized[4] == VERSION);
        CHECK(serialized[5] == static_cast<uint8_t>(MessageType::VERIFY_RESPONSE));

        // Deserialize
        VerifyResponse deserialized;
        bool success = Serializer::deserialize(serialized, deserialized);

        REQUIRE(success);
        CHECK(deserialized.status == VerifyStatus::GOOD);
        CHECK(deserialized.reason == "Certificate is valid");
        CHECK(deserialized.signature.size() == 64);
        CHECK(deserialized.nonce.size() == 32);
        CHECK(deserialized.signature == resp.signature);
        CHECK(deserialized.nonce == resp.nonce);
    }

    TEST_CASE("serialize and deserialize HealthCheckRequest") {
        using namespace authbox::pik::verify::wire;

        HealthCheckRequest req;

        // Serialize
        auto serialized = Serializer::serialize(req);

        // Should only be header
        CHECK(serialized.size() == 6);
        CHECK(serialized[5] == static_cast<uint8_t>(MessageType::HEALTH_CHECK));

        // Deserialize
        HealthCheckRequest deserialized;
        bool success = Serializer::deserialize(serialized, deserialized);
        CHECK(success);
    }

    TEST_CASE("serialize and deserialize HealthCheckResponse") {
        using namespace authbox::pik::verify::wire;

        HealthCheckResponse resp;
        resp.status = HealthCheckResponse::ServingStatus::SERVING;

        // Serialize
        auto serialized = Serializer::serialize(resp);

        // Should be header + 1 byte status
        CHECK(serialized.size() == 7);

        // Deserialize
        HealthCheckResponse deserialized;
        bool success = Serializer::deserialize(serialized, deserialized);

        REQUIRE(success);
        CHECK(deserialized.status == HealthCheckResponse::ServingStatus::SERVING);
    }

    TEST_CASE("invalid magic bytes rejected") {
        using namespace authbox::pik::verify::wire;

        std::vector<uint8_t> bad_data = {0xFF, 0xFF, 0xFF, 0xFF, VERSION, 0x01};

        VerifyRequest req;
        bool success = Serializer::deserialize(bad_data, req);
        CHECK_FALSE(success);
    }

    TEST_CASE("invalid version rejected") {
        using namespace authbox::pik::verify::wire;

        std::vector<uint8_t> bad_data = {MAGIC[0],
                                         MAGIC[1],
                                         MAGIC[2],
                                         MAGIC[3],
                                         0xFF, // Bad version
                                         static_cast<uint8_t>(MessageType::VERIFY_REQUEST)};

        VerifyRequest req;
        bool success = Serializer::deserialize(bad_data, req);
        CHECK_FALSE(success);
    }

    TEST_CASE("request flags operations") {
        using namespace authbox::pik::verify::wire;

        RequestFlags flags = RequestFlags::NONE;
        CHECK(static_cast<uint8_t>(flags) == 0x00);

        flags = RequestFlags::INCLUDE_RESPONDER_CERT;
        CHECK(static_cast<uint8_t>(flags) == 0x01);

        // Test bitwise OR
        auto combined = RequestFlags::NONE | RequestFlags::INCLUDE_RESPONDER_CERT;
        CHECK(static_cast<uint8_t>(combined) == 0x01);

        // Test bitwise AND
        auto masked = flags & RequestFlags::INCLUDE_RESPONDER_CERT;
        CHECK(static_cast<uint8_t>(masked) == 0x01);
    }

    TEST_CASE("multiple certificates in chain") {
        using namespace authbox::pik::verify::wire;

        VerifyRequest req;

        // Add multiple certificates
        for (int i = 0; i < 3; ++i) {
            CertificateData cert;
            cert.der_bytes.resize(100 + i * 10);
            for (size_t j = 0; j < cert.der_bytes.size(); ++j) {
                cert.der_bytes[j] = static_cast<uint8_t>(i + j);
            }
            req.certificate_chain.push_back(cert);
        }

        req.validation_timestamp = std::chrono::system_clock::now();
        req.flags = RequestFlags::NONE;

        // Serialize
        auto serialized = Serializer::serialize(req);

        // Deserialize
        VerifyRequest deserialized;
        bool success = Serializer::deserialize(serialized, deserialized);

        REQUIRE(success);
        CHECK(deserialized.certificate_chain.size() == 3);

        for (size_t i = 0; i < 3; ++i) {
            CHECK(deserialized.certificate_chain[i].der_bytes == req.certificate_chain[i].der_bytes);
        }
    }
}
