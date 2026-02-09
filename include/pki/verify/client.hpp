#pragma once

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <keylock/crypto/rng/randombytes.hpp>
#include <keylock/crypto/sign_ed25519/ed25519.hpp>
#include <pki/certificate.hpp>
#include <pki/verify/server.hpp>
#include <pki/verify/transport.hpp>
#include <pki/verify/wire_format.hpp>

namespace authbox::pik::verify {

    // Client configuration
    struct ClientConfig {
        std::chrono::seconds timeout{5};
        int max_retry_attempts{3};

        ClientConfig() = default;
    };

    // Verification client for checking certificate revocation status
    class Client {
      public:
        // Response from verification service
        struct Response {
            bool valid{false};
            std::string reason;
            wire::VerifyStatus status{wire::VerifyStatus::UNKNOWN};
            std::chrono::system_clock::time_point revocation_time;
            std::chrono::system_clock::time_point this_update;
            std::chrono::system_clock::time_point next_update;
            std::vector<uint8_t> signature; // Ed25519 signature
            std::vector<uint8_t> nonce;

            Response() = default;
        };

        // Result type for operations
        template <typename T> struct Result {
            bool success{false};
            T value{};
            std::string error;

            static Result<T> ok(T val) { return Result<T>{true, std::move(val), ""}; }

            static Result<T> failure(std::string err) { return Result<T>{false, {}, std::move(err)}; }
        };

        // Constructor with transport
        inline explicit Client(std::shared_ptr<Transport> transport, const ClientConfig &config = ClientConfig{});

        inline ~Client();

        // Disable copy
        Client(const Client &) = delete;
        Client &operator=(const Client &) = delete;

        // Enable move
        inline Client(Client &&) noexcept;
        inline Client &operator=(Client &&) noexcept;

        // Single certificate chain verification
        inline Result<Response>
        verify_chain(const std::vector<authbox::pik::Certificate> &chain,
                     std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now());

        // Batch verification for efficiency
        inline Result<std::vector<Response>>
        verify_batch(const std::vector<std::vector<authbox::pik::Certificate>> &chains);

        // Set responder certificate for signature verification
        inline void set_responder_cert(const authbox::pik::Certificate &cert);

        // Health check
        inline Result<bool> health_check();

        // Check if transport is ready
        inline bool is_ready() const;

      private:
        class Impl;
        std::unique_ptr<Impl> impl_;

        // Verify response signature using responder certificate
        inline bool verify_response_signature(const Response &response);
    };

    // PIMPL implementation
    class Client::Impl {
      public:
        std::shared_ptr<Transport> transport;
        ClientConfig config;
        std::optional<authbox::pik::Certificate> responder_cert;

        explicit Impl(std::shared_ptr<Transport> t, const ClientConfig &cfg) : transport(std::move(t)), config(cfg) {}

        ~Impl() = default;
    };

    // Constructor
    inline Client::Client(std::shared_ptr<Transport> transport, const ClientConfig &config)
        : impl_(std::make_unique<Impl>(std::move(transport), config)) {}

    // Destructor
    inline Client::~Client() = default;

    // Move constructor
    inline Client::Client(Client &&) noexcept = default;

    // Move assignment
    inline Client &Client::operator=(Client &&) noexcept = default;

    inline bool Client::is_ready() const { return impl_->transport && impl_->transport->is_ready(); }

    // Verify single certificate chain
    inline Client::Result<Client::Response>
    Client::verify_chain(const std::vector<authbox::pik::Certificate> &chain,
                         std::chrono::system_clock::time_point validation_time) {

        if (chain.empty()) {
            return Result<Response>::failure("Certificate chain is empty");
        }

        if (!is_ready()) {
            return Result<Response>::failure("Transport is not ready");
        }

        // Build wire format request
        wire::VerifyRequest wire_req;
        for (const auto &cert : chain) {
            wire::CertificateData cert_data;
            cert_data.der_bytes = cert.to_der();
            wire_req.certificate_chain.push_back(std::move(cert_data));
        }
        wire_req.validation_timestamp = validation_time;
        wire_req.flags = wire::RequestFlags::NONE;

        // Generate nonce
        wire_req.nonce.resize(32);
        keylock::crypto::rng::randombytes_buf(wire_req.nonce.data(), wire_req.nonce.size());

        // Serialize request
        auto request_data = wire::Serializer::serialize(wire_req);

        // Call via transport
        auto response_data = impl_->transport->call(methods::CHECK_CERTIFICATE, request_data);

        if (response_data.empty()) {
            return Result<Response>::failure("Transport call failed: " + impl_->transport->last_error());
        }

        // Deserialize response
        wire::VerifyResponse wire_resp;
        if (!wire::Serializer::deserialize(response_data, wire_resp)) {
            return Result<Response>::failure("Failed to deserialize response");
        }

        // Verify nonce matches
        if (wire_resp.nonce != wire_req.nonce) {
            return Result<Response>::failure("Nonce mismatch - possible replay attack");
        }

        // Convert to client response
        Response response;
        response.status = wire_resp.status;
        response.valid = (wire_resp.status == wire::VerifyStatus::GOOD);
        response.reason = wire_resp.reason;
        response.revocation_time = wire_resp.revocation_time;
        response.this_update = wire_resp.this_update;
        response.next_update = wire_resp.next_update;
        response.signature = wire_resp.signature;
        response.nonce = wire_resp.nonce;

        // Verify signature if responder cert is set
        if (impl_->responder_cert.has_value()) {
            if (!verify_response_signature(response)) {
                return Result<Response>::failure("Response signature verification failed");
            }
        }

        return Result<Response>::ok(std::move(response));
    }

    // Batch verification
    inline Client::Result<std::vector<Client::Response>>
    Client::verify_batch(const std::vector<std::vector<authbox::pik::Certificate>> &chains) {

        if (chains.empty()) {
            return Result<std::vector<Response>>::failure("No chains provided");
        }

        if (!is_ready()) {
            return Result<std::vector<Response>>::failure("Transport is not ready");
        }

        // Build batch request
        wire::BatchVerifyRequest batch_req;
        for (const auto &chain : chains) {
            if (chain.empty()) {
                continue;
            }

            wire::VerifyRequest wire_req;
            for (const auto &cert : chain) {
                wire::CertificateData cert_data;
                cert_data.der_bytes = cert.to_der();
                wire_req.certificate_chain.push_back(std::move(cert_data));
            }
            wire_req.validation_timestamp = std::chrono::system_clock::now();
            wire_req.flags = wire::RequestFlags::NONE;

            // Generate unique nonce for each request
            wire_req.nonce.resize(32);
            keylock::crypto::rng::randombytes_buf(wire_req.nonce.data(), wire_req.nonce.size());

            batch_req.requests.push_back(std::move(wire_req));
        }

        // Serialize request
        auto request_data = wire::Serializer::serialize(batch_req);

        // Call via transport
        auto response_data = impl_->transport->call(methods::CHECK_BATCH, request_data);

        if (response_data.empty()) {
            return Result<std::vector<Response>>::failure("Transport call failed: " + impl_->transport->last_error());
        }

        // Deserialize response
        wire::BatchVerifyResponse batch_resp;
        if (!wire::Serializer::deserialize(response_data, batch_resp)) {
            return Result<std::vector<Response>>::failure("Failed to deserialize batch response");
        }

        // Convert to client responses
        std::vector<Response> responses;
        responses.reserve(batch_resp.responses.size());

        for (const auto &wire_resp : batch_resp.responses) {
            Response response;
            response.status = wire_resp.status;
            response.valid = (wire_resp.status == wire::VerifyStatus::GOOD);
            response.reason = wire_resp.reason;
            response.revocation_time = wire_resp.revocation_time;
            response.this_update = wire_resp.this_update;
            response.next_update = wire_resp.next_update;
            response.signature = wire_resp.signature;
            response.nonce = wire_resp.nonce;

            responses.push_back(std::move(response));
        }

        return Result<std::vector<Response>>::ok(std::move(responses));
    }

    // Set responder certificate
    inline void Client::set_responder_cert(const authbox::pik::Certificate &cert) { impl_->responder_cert = cert; }

    // Health check
    inline Client::Result<bool> Client::health_check() {
        if (!is_ready()) {
            return Result<bool>::failure("Transport is not ready");
        }

        wire::HealthCheckRequest req;

        // Serialize request
        auto request_data = wire::Serializer::serialize(req);

        // Call via transport
        auto response_data = impl_->transport->call(methods::HEALTH_CHECK, request_data);

        if (response_data.empty()) {
            return Result<bool>::failure("Health check failed: " + impl_->transport->last_error());
        }

        // Deserialize response
        wire::HealthCheckResponse resp;
        if (!wire::Serializer::deserialize(response_data, resp)) {
            return Result<bool>::failure("Failed to deserialize health check response");
        }

        bool healthy = (resp.status == wire::HealthCheckResponse::ServingStatus::SERVING);
        return Result<bool>::ok(healthy);
    }

    // Verify response signature
    inline bool Client::verify_response_signature(const Response &response) {
        if (!impl_->responder_cert.has_value()) {
            return false;
        }

        if (response.signature.size() != keylock::crypto::ed25519::BYTES) {
            return false;
        }

        // Build message to verify (concatenate fields in order)
        std::vector<uint8_t> message;

        // Status
        message.push_back(static_cast<uint8_t>(response.status));

        // Reason
        message.insert(message.end(), response.reason.begin(), response.reason.end());

        // Timestamps (as Unix timestamps)
        auto rev_time =
            std::chrono::duration_cast<std::chrono::seconds>(response.revocation_time.time_since_epoch()).count();
        auto this_time =
            std::chrono::duration_cast<std::chrono::seconds>(response.this_update.time_since_epoch()).count();
        auto next_time =
            std::chrono::duration_cast<std::chrono::seconds>(response.next_update.time_since_epoch()).count();

        for (int i = 7; i >= 0; --i) {
            message.push_back(static_cast<uint8_t>((rev_time >> (i * 8)) & 0xFF));
        }
        for (int i = 7; i >= 0; --i) {
            message.push_back(static_cast<uint8_t>((this_time >> (i * 8)) & 0xFF));
        }
        for (int i = 7; i >= 0; --i) {
            message.push_back(static_cast<uint8_t>((next_time >> (i * 8)) & 0xFF));
        }

        // Nonce
        message.insert(message.end(), response.nonce.begin(), response.nonce.end());

        // Get public key from responder certificate
        const auto &pub_key = impl_->responder_cert->tbs().subject_public_key_info.public_key;
        if (pub_key.size() != keylock::crypto::ed25519::PUBLICKEYBYTES) {
            return false;
        }

        // Verify Ed25519 signature
        int verify_result = keylock::crypto::ed25519::verify_detached(response.signature.data(), message.data(),
                                                                      message.size(), pub_key.data());

        return (verify_result == 0);
    }

} // namespace authbox::pik::verify
