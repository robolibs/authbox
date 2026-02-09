/**
 * Test: Verification Server
 * Tests the verification server implementation (RequestProcessor and Verifier)
 */

#include <doctest/doctest.h>

#include <chrono>
#include <keylock/keylock.hpp>
#include <pki/builder.hpp>
#include <keylock/crypto/context.hpp>
#include <pki/verify/client.hpp>
#include <pki/verify/direct_transport.hpp>
#include <pki/verify/server.hpp>

using namespace keylock;

TEST_CASE("SimpleRevocationHandler - Basic Operations") {
    authbox::pik::verify::SimpleRevocationHandler handler;

    SUBCASE("Initially empty") {
        std::vector<uint8_t> serial = {0x01, 0x02, 0x03};
        CHECK_FALSE(handler.is_revoked(serial));
    }

    SUBCASE("Add and check revoked certificate") {
        std::vector<uint8_t> serial = {0x01, 0x02, 0x03};
        handler.add_revoked_certificate(serial, "Key compromise");

        CHECK(handler.is_revoked(serial));

        // Different serial should not be revoked
        std::vector<uint8_t> other_serial = {0x04, 0x05, 0x06};
        CHECK_FALSE(handler.is_revoked(other_serial));
    }

    SUBCASE("Remove revoked certificate") {
        std::vector<uint8_t> serial = {0x01, 0x02, 0x03};
        handler.add_revoked_certificate(serial);
        CHECK(handler.is_revoked(serial));

        handler.remove_revoked_certificate(serial);
        CHECK_FALSE(handler.is_revoked(serial));
    }

    SUBCASE("Clear all revocations") {
        handler.add_revoked_certificate({0x01, 0x02}, "reason1");
        handler.add_revoked_certificate({0x03, 0x04}, "reason2");

        handler.clear();

        CHECK_FALSE(handler.is_revoked({0x01, 0x02}));
        CHECK_FALSE(handler.is_revoked({0x03, 0x04}));
    }
}

TEST_CASE("SimpleRevocationHandler - Verify Chain") {
    authbox::pik::verify::SimpleRevocationHandler handler;

    // Generate a test certificate
    crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
    auto ca_keys = ctx.generate_keypair();

    auto dn_result = authbox::pik::DistinguishedName::from_string("CN=Test CA,O=keylock Test");
    REQUIRE(dn_result.success);

    auto not_before = std::chrono::system_clock::now();
    auto not_after = not_before + std::chrono::hours(24 * 365);

    authbox::pik::CertificateBuilder ca_builder;
    ca_builder.set_version(3)
        .set_serial(1)
        .set_subject(dn_result.value)
        .set_issuer(dn_result.value)
        .set_validity(not_before, not_after)
        .set_subject_public_key_ed25519(ca_keys.public_key)
        .set_basic_constraints(true, std::nullopt, true);

    auto ca_cert_result = ca_builder.build_ed25519(ca_keys, true);
    REQUIRE(ca_cert_result.success);
    auto ca_cert = ca_cert_result.value;

    SUBCASE("Good certificate") {
        std::vector<authbox::pik::Certificate> chain = {ca_cert};
        auto response = handler.verify_chain(chain, std::chrono::system_clock::now());

        CHECK(response.status == authbox::pik::verify::wire::VerifyStatus::GOOD);
        CHECK(response.reason == "Certificate is valid");
    }

    SUBCASE("Revoked certificate") {
        // Add certificate to revocation list
        handler.add_revoked_certificate(ca_cert.tbs().serial_number, "Test revocation");

        std::vector<authbox::pik::Certificate> chain = {ca_cert};
        auto response = handler.verify_chain(chain, std::chrono::system_clock::now());

        CHECK(response.status == authbox::pik::verify::wire::VerifyStatus::REVOKED);
        CHECK(response.reason == "Test revocation");
    }

    SUBCASE("Empty chain") {
        std::vector<authbox::pik::Certificate> empty_chain;
        auto response = handler.verify_chain(empty_chain, std::chrono::system_clock::now());

        CHECK(response.status == authbox::pik::verify::wire::VerifyStatus::UNKNOWN);
        CHECK(response.reason == "Empty certificate chain");
    }
}

TEST_CASE("RequestProcessor - Construction and Configuration") {
    auto handler = std::make_shared<authbox::pik::verify::SimpleRevocationHandler>();

    SUBCASE("Basic construction") {
        authbox::pik::verify::RequestProcessor processor(handler);
        auto stats = processor.get_stats();
        CHECK(stats.total_requests == 0);
    }

    SUBCASE("Set signing key") {
        authbox::pik::verify::RequestProcessor processor(handler);

        // Generate Ed25519 key
        std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
        std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
        crypto_sign_keypair(pk.data(), sk.data());

        CHECK_NOTHROW(processor.set_signing_key(sk));

        // Invalid key size should throw
        std::vector<uint8_t> bad_key(32);
        CHECK_THROWS(processor.set_signing_key(bad_key));
    }

    SUBCASE("Set responder certificate") {
        authbox::pik::verify::RequestProcessor processor(handler);

        // Generate a test certificate
        crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
        auto keys = ctx.generate_keypair();

        auto dn_result = authbox::pik::DistinguishedName::from_string("CN=Responder");
        REQUIRE(dn_result.success);

        auto not_before = std::chrono::system_clock::now();
        auto not_after = not_before + std::chrono::hours(24 * 365);

        authbox::pik::CertificateBuilder builder;
        builder.set_version(3)
            .set_serial(1)
            .set_subject(dn_result.value)
            .set_issuer(dn_result.value)
            .set_validity(not_before, not_after)
            .set_subject_public_key_ed25519(keys.public_key)
            .set_basic_constraints(true, std::nullopt, true);

        auto cert_result = builder.build_ed25519(keys, true);
        REQUIRE(cert_result.success);

        CHECK_NOTHROW(processor.set_responder_certificate(cert_result.value));
    }
}

TEST_CASE("RequestProcessor - Statistics") {
    auto handler = std::make_shared<authbox::pik::verify::SimpleRevocationHandler>();
    authbox::pik::verify::RequestProcessor processor(handler);

    auto stats = processor.get_stats();
    CHECK(stats.total_requests == 0);
    CHECK(stats.total_batch_requests == 0);
    CHECK(stats.total_health_checks == 0);
    CHECK(stats.good_responses == 0);
    CHECK(stats.revoked_responses == 0);
    CHECK(stats.unknown_responses == 0);
}

TEST_CASE("RequestProcessor - Process Requests") {
    auto handler = std::make_shared<authbox::pik::verify::SimpleRevocationHandler>();
    authbox::pik::verify::RequestProcessor processor(handler);

    // Generate a test certificate
    crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
    auto keys = ctx.generate_keypair();

    auto dn_result = authbox::pik::DistinguishedName::from_string("CN=Test Cert");
    REQUIRE(dn_result.success);

    auto not_before = std::chrono::system_clock::now();
    auto not_after = not_before + std::chrono::hours(24 * 365);

    authbox::pik::CertificateBuilder builder;
    builder.set_version(3)
        .set_serial(12345)
        .set_subject(dn_result.value)
        .set_issuer(dn_result.value)
        .set_validity(not_before, not_after)
        .set_subject_public_key_ed25519(keys.public_key)
        .set_basic_constraints(true, std::nullopt, true);

    auto cert_result = builder.build_ed25519(keys, true);
    REQUIRE(cert_result.success);
    auto test_cert = cert_result.value;

    SUBCASE("Health check") {
        authbox::pik::verify::wire::HealthCheckRequest req;
        auto req_data = authbox::pik::verify::wire::Serializer::serialize(req);
        auto resp_data = processor.process(authbox::pik::verify::methods::HEALTH_CHECK, req_data);

        authbox::pik::verify::wire::HealthCheckResponse resp;
        REQUIRE(authbox::pik::verify::wire::Serializer::deserialize(resp_data, resp));
        CHECK(resp.status == authbox::pik::verify::wire::HealthCheckResponse::ServingStatus::SERVING);

        auto stats = processor.get_stats();
        CHECK(stats.total_health_checks == 1);
    }

    SUBCASE("Verify good certificate") {
        authbox::pik::verify::wire::VerifyRequest req;
        authbox::pik::verify::wire::CertificateData cert_data;
        cert_data.der_bytes = test_cert.to_der();
        req.certificate_chain.push_back(std::move(cert_data));
        req.validation_timestamp = std::chrono::system_clock::now();
        req.flags = authbox::pik::verify::wire::RequestFlags::NONE;
        req.nonce.resize(32);
        randombytes_buf(req.nonce.data(), req.nonce.size());

        auto req_data = authbox::pik::verify::wire::Serializer::serialize(req);
        auto resp_data = processor.process(authbox::pik::verify::methods::CHECK_CERTIFICATE, req_data);

        authbox::pik::verify::wire::VerifyResponse resp;
        REQUIRE(authbox::pik::verify::wire::Serializer::deserialize(resp_data, resp));
        CHECK(resp.status == authbox::pik::verify::wire::VerifyStatus::GOOD);
        CHECK(resp.nonce == req.nonce);

        auto stats = processor.get_stats();
        CHECK(stats.total_requests == 1);
        CHECK(stats.good_responses == 1);
    }

    SUBCASE("Verify revoked certificate") {
        // Add certificate to revocation list
        handler->add_revoked_certificate(test_cert.tbs().serial_number, "Test revocation");

        authbox::pik::verify::wire::VerifyRequest req;
        authbox::pik::verify::wire::CertificateData cert_data;
        cert_data.der_bytes = test_cert.to_der();
        req.certificate_chain.push_back(std::move(cert_data));
        req.validation_timestamp = std::chrono::system_clock::now();
        req.flags = authbox::pik::verify::wire::RequestFlags::NONE;
        req.nonce.resize(32);
        randombytes_buf(req.nonce.data(), req.nonce.size());

        auto req_data = authbox::pik::verify::wire::Serializer::serialize(req);
        auto resp_data = processor.process(authbox::pik::verify::methods::CHECK_CERTIFICATE, req_data);

        authbox::pik::verify::wire::VerifyResponse resp;
        REQUIRE(authbox::pik::verify::wire::Serializer::deserialize(resp_data, resp));
        CHECK(resp.status == authbox::pik::verify::wire::VerifyStatus::REVOKED);
        CHECK(resp.reason == "Test revocation");
    }
}

TEST_CASE("DirectTransport - Basic Operations") {
    auto handler = std::make_shared<authbox::pik::verify::SimpleRevocationHandler>();
    auto processor = std::make_shared<authbox::pik::verify::RequestProcessor>(handler);
    authbox::pik::verify::DirectTransport transport(processor);

    CHECK(transport.is_ready());
    CHECK(transport.last_error().empty());

    SUBCASE("Health check via transport") {
        authbox::pik::verify::wire::HealthCheckRequest req;
        auto req_data = authbox::pik::verify::wire::Serializer::serialize(req);
        auto resp_data = transport.call(authbox::pik::verify::methods::HEALTH_CHECK, req_data);

        CHECK_FALSE(resp_data.empty());

        authbox::pik::verify::wire::HealthCheckResponse resp;
        REQUIRE(authbox::pik::verify::wire::Serializer::deserialize(resp_data, resp));
        CHECK(resp.status == authbox::pik::verify::wire::HealthCheckResponse::ServingStatus::SERVING);
    }
}

TEST_CASE("Verifier - Integration Test") {
    authbox::pik::verify::Verifier verifier;

    CHECK(verifier.as_revocation_handler() != nullptr);

    // Generate a test certificate
    crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
    auto keys = ctx.generate_keypair();

    auto dn_result = authbox::pik::DistinguishedName::from_string("CN=Test Cert");
    REQUIRE(dn_result.success);

    auto not_before = std::chrono::system_clock::now();
    auto not_after = not_before + std::chrono::hours(24 * 365);

    authbox::pik::CertificateBuilder builder;
    builder.set_version(3)
        .set_serial(12345)
        .set_subject(dn_result.value)
        .set_issuer(dn_result.value)
        .set_validity(not_before, not_after)
        .set_subject_public_key_ed25519(keys.public_key)
        .set_basic_constraints(true, std::nullopt, true);

    auto cert_result = builder.build_ed25519(keys, true);
    REQUIRE(cert_result.success);
    auto test_cert = cert_result.value;

    SUBCASE("Health check") {
        auto result = verifier.health_check();
        CHECK(result.success);
        CHECK(result.value == true);
    }

    SUBCASE("Verify good certificate") {
        std::vector<authbox::pik::Certificate> chain = {test_cert};
        auto result = verifier.verify_chain(chain);

        CHECK(result.success);
        CHECK(result.value.status == authbox::pik::verify::wire::VerifyStatus::GOOD);
        CHECK(result.value.valid == true);
    }

    SUBCASE("Verify revoked certificate") {
        // Add to revocation list
        verifier.as_revocation_handler()->add_revoked_certificate(test_cert.tbs().serial_number, "Test revocation");

        std::vector<authbox::pik::Certificate> chain = {test_cert};
        auto result = verifier.verify_chain(chain);

        CHECK(result.success);
        CHECK(result.value.status == authbox::pik::verify::wire::VerifyStatus::REVOKED);
        CHECK(result.value.valid == false);
        CHECK(result.value.reason == "Test revocation");
    }

    // Note: Batch verification test skipped - batch wire format deserialization
    // needs to be fully implemented in wire_format.cpp
}

TEST_CASE("Client - With DirectTransport") {
    auto handler = std::make_shared<authbox::pik::verify::SimpleRevocationHandler>();
    auto processor = std::make_shared<authbox::pik::verify::RequestProcessor>(handler);
    auto transport = std::make_shared<authbox::pik::verify::DirectTransport>(processor);

    authbox::pik::verify::Client client(transport);

    CHECK(client.is_ready());

    // Generate a test certificate
    crypto::Context ctx(crypto::Context::Algorithm::Ed25519);
    auto keys = ctx.generate_keypair();

    auto dn_result = authbox::pik::DistinguishedName::from_string("CN=Test Cert");
    REQUIRE(dn_result.success);

    auto not_before = std::chrono::system_clock::now();
    auto not_after = not_before + std::chrono::hours(24 * 365);

    authbox::pik::CertificateBuilder builder;
    builder.set_version(3)
        .set_serial(99999)
        .set_subject(dn_result.value)
        .set_issuer(dn_result.value)
        .set_validity(not_before, not_after)
        .set_subject_public_key_ed25519(keys.public_key)
        .set_basic_constraints(true, std::nullopt, true);

    auto cert_result = builder.build_ed25519(keys, true);
    REQUIRE(cert_result.success);
    auto test_cert = cert_result.value;

    SUBCASE("Health check") {
        auto result = client.health_check();
        CHECK(result.success);
        CHECK(result.value == true);
    }

    SUBCASE("Verify chain") {
        std::vector<authbox::pik::Certificate> chain = {test_cert};
        auto result = client.verify_chain(chain);

        CHECK(result.success);
        CHECK(result.value.status == authbox::pik::verify::wire::VerifyStatus::GOOD);
        CHECK(result.value.nonce.size() == 32);
    }

    SUBCASE("Empty chain error") {
        std::vector<authbox::pik::Certificate> chain;
        auto result = client.verify_chain(chain);

        CHECK_FALSE(result.success);
        CHECK(result.error == "Certificate chain is empty");
    }
}
