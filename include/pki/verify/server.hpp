#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <keylock/crypto/sign_ed25519/ed25519.hpp>
#include <pki/certificate.hpp>
#include <pki/verify/wire_format.hpp>

namespace authbox::pik::verify {

    // Method IDs for RPC routing
    namespace methods {
        constexpr uint32_t CHECK_CERTIFICATE = 1;
        constexpr uint32_t CHECK_BATCH = 2;
        constexpr uint32_t HEALTH_CHECK = 3;
    } // namespace methods

    // Verification handler interface - implement this to provide verification logic
    class VerificationHandler {
      public:
        virtual ~VerificationHandler() = default;

        // Verify a single certificate chain
        // Returns the verification status, reason, and timestamps
        virtual wire::VerifyResponse verify_chain(const std::vector<authbox::pik::Certificate> &chain,
                                                  std::chrono::system_clock::time_point validation_time) = 0;

        // Optional: Override for batch optimization
        virtual std::vector<wire::VerifyResponse>
        verify_batch(const std::vector<std::vector<authbox::pik::Certificate>> &chains) {
            std::vector<wire::VerifyResponse> responses;
            responses.reserve(chains.size());
            for (const auto &chain : chains) {
                responses.push_back(verify_chain(chain, std::chrono::system_clock::now()));
            }
            return responses;
        }

        // Optional: Health check logic
        virtual bool is_healthy() const { return true; }
    };

    // Simple in-memory revocation list handler
    class SimpleRevocationHandler : public VerificationHandler {
      public:
        SimpleRevocationHandler() = default;

        // Add a revoked certificate by serial number
        inline void add_revoked_certificate(
            const std::vector<uint8_t> &serial_number, const std::string &reason = "unspecified",
            std::chrono::system_clock::time_point revocation_time = std::chrono::system_clock::now());

        // Remove a certificate from revocation list (if it was added by mistake)
        inline void remove_revoked_certificate(const std::vector<uint8_t> &serial_number);

        // Check if a certificate is revoked
        inline bool is_revoked(const std::vector<uint8_t> &serial_number) const;

        // Clear all revocations
        inline void clear();

        // VerificationHandler interface implementation
        inline wire::VerifyResponse verify_chain(const std::vector<authbox::pik::Certificate> &chain,
                                                 std::chrono::system_clock::time_point validation_time) override;

      private:
        struct RevocationInfo {
            std::string reason;
            std::chrono::system_clock::time_point revocation_time;
            std::chrono::system_clock::time_point this_update;
            std::chrono::system_clock::time_point next_update;
        };

        std::map<std::vector<uint8_t>, RevocationInfo> revoked_certs_;
        mutable std::mutex mutex_;
    };

    // Request processor - handles wire format requests and dispatches to handler
    // This can be used to build custom server implementations
    class RequestProcessor {
      public:
        inline explicit RequestProcessor(std::shared_ptr<VerificationHandler> handler);
        inline ~RequestProcessor();

        // Process a raw request and return a raw response
        // method_id: The RPC method ID (CHECK_CERTIFICATE, CHECK_BATCH, HEALTH_CHECK)
        // request_data: Serialized wire format request
        // Returns: Serialized wire format response
        inline std::vector<uint8_t> process(uint32_t method_id, const std::vector<uint8_t> &request_data);

        // Set the signing key for response signatures (Ed25519)
        inline void set_signing_key(const std::vector<uint8_t> &ed25519_private_key);

        // Set the responder certificate (included in responses if requested)
        inline void set_responder_certificate(const authbox::pik::Certificate &cert);

        // Statistics
        struct Stats {
            uint64_t total_requests{0};
            uint64_t total_batch_requests{0};
            uint64_t total_health_checks{0};
            uint64_t good_responses{0};
            uint64_t revoked_responses{0};
            uint64_t unknown_responses{0};
            std::chrono::system_clock::time_point start_time;
        };

        inline Stats get_stats() const;

      private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

    // SimpleRevocationHandler implementation

    inline void
    SimpleRevocationHandler::add_revoked_certificate(const std::vector<uint8_t> &serial_number,
                                                     const std::string &reason,
                                                     std::chrono::system_clock::time_point revocation_time) {

        std::lock_guard<std::mutex> lock(mutex_);
        RevocationInfo info;
        info.reason = reason;
        info.revocation_time = revocation_time;
        info.this_update = std::chrono::system_clock::now();
        info.next_update = info.this_update + std::chrono::hours(24);
        revoked_certs_[serial_number] = info;
    }

    inline void SimpleRevocationHandler::remove_revoked_certificate(const std::vector<uint8_t> &serial_number) {
        std::lock_guard<std::mutex> lock(mutex_);
        revoked_certs_.erase(serial_number);
    }

    inline bool SimpleRevocationHandler::is_revoked(const std::vector<uint8_t> &serial_number) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return revoked_certs_.find(serial_number) != revoked_certs_.end();
    }

    inline void SimpleRevocationHandler::clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        revoked_certs_.clear();
    }

    inline wire::VerifyResponse
    SimpleRevocationHandler::verify_chain(const std::vector<authbox::pik::Certificate> &chain,
                                          std::chrono::system_clock::time_point /*validation_time*/) {

        wire::VerifyResponse response;
        if (chain.empty()) {
            response.status = wire::VerifyStatus::UNKNOWN;
            response.reason = "Empty certificate chain";
            return response;
        }

        const auto &cert = chain[0];
        const auto &serial = cert.tbs().serial_number;

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = revoked_certs_.find(serial);

        if (it != revoked_certs_.end()) {
            response.status = wire::VerifyStatus::REVOKED;
            response.reason = it->second.reason;
            response.revocation_time = it->second.revocation_time;
            response.this_update = it->second.this_update;
            response.next_update = it->second.next_update;
        } else {
            response.status = wire::VerifyStatus::GOOD;
            response.reason = "Certificate is valid";
            response.this_update = std::chrono::system_clock::now();
            response.next_update = response.this_update + std::chrono::hours(24);
        }
        return response;
    }

    // RequestProcessor implementation

    class RequestProcessor::Impl {
      public:
        std::shared_ptr<VerificationHandler> handler;

        std::vector<uint8_t> signing_key;
        std::optional<authbox::pik::Certificate> responder_cert;

        RequestProcessor::Stats stats;
        mutable std::mutex stats_mutex;

        explicit Impl(std::shared_ptr<VerificationHandler> h) : handler(std::move(h)) {
            stats.start_time = std::chrono::system_clock::now();
        }

        inline void sign_response(wire::VerifyResponse &response);

        inline std::vector<uint8_t> handle_verify_request(const std::vector<uint8_t> &request_data);
        inline std::vector<uint8_t> handle_batch_request(const std::vector<uint8_t> &request_data);
        inline std::vector<uint8_t> handle_health_check(const std::vector<uint8_t> &request_data);
    };

    inline void RequestProcessor::Impl::sign_response(wire::VerifyResponse &response) {
        if (signing_key.size() != keylock::crypto::ed25519::SECRETKEYBYTES) {
            return;
        }

        std::vector<uint8_t> message;
        message.push_back(static_cast<uint8_t>(response.status));
        message.insert(message.end(), response.reason.begin(), response.reason.end());

        auto rev_time = std::chrono::system_clock::to_time_t(response.revocation_time);
        auto this_time = std::chrono::system_clock::to_time_t(response.this_update);
        auto next_time = std::chrono::system_clock::to_time_t(response.next_update);

        for (int i = 0; i < 8; i++) {
            message.push_back(static_cast<uint8_t>((rev_time >> (i * 8)) & 0xFF));
        }
        for (int i = 0; i < 8; i++) {
            message.push_back(static_cast<uint8_t>((this_time >> (i * 8)) & 0xFF));
        }
        for (int i = 0; i < 8; i++) {
            message.push_back(static_cast<uint8_t>((next_time >> (i * 8)) & 0xFF));
        }

        message.insert(message.end(), response.nonce.begin(), response.nonce.end());

        response.signature.resize(keylock::crypto::ed25519::BYTES);
        keylock::crypto::ed25519::sign_detached(response.signature.data(), nullptr, message.data(), message.size(),
                                                signing_key.data());
    }

    inline std::vector<uint8_t>
    RequestProcessor::Impl::handle_verify_request(const std::vector<uint8_t> &request_data) {
        wire::VerifyRequest wire_req;

        if (!wire::Serializer::deserialize(request_data, wire_req)) {
            wire::VerifyResponse error_resp;
            error_resp.status = wire::VerifyStatus::UNKNOWN;
            error_resp.reason = "Failed to deserialize request";
            return wire::Serializer::serialize(error_resp);
        }

        std::vector<authbox::pik::Certificate> chain;
        for (const auto &cert_data : wire_req.certificate_chain) {
            auto parse_result = authbox::pik::Certificate::parse(cert_data.der_bytes);
            if (!parse_result.success) {
                wire::VerifyResponse error_resp;
                error_resp.status = wire::VerifyStatus::UNKNOWN;
                error_resp.reason = "Failed to parse certificate: " + parse_result.error;
                error_resp.nonce = wire_req.nonce;
                return wire::Serializer::serialize(error_resp);
            }
            chain.push_back(std::move(parse_result.value));
        }

        auto response = handler->verify_chain(chain, wire_req.validation_timestamp);
        response.nonce = wire_req.nonce;

        if ((wire_req.flags & wire::RequestFlags::INCLUDE_RESPONDER_CERT) != wire::RequestFlags::NONE) {
            if (responder_cert.has_value()) {
                response.responder_cert_der = responder_cert->der();
            }
        }

        sign_response(response);

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.total_requests++;
            switch (response.status) {
            case wire::VerifyStatus::GOOD:
                stats.good_responses++;
                break;
            case wire::VerifyStatus::REVOKED:
                stats.revoked_responses++;
                break;
            case wire::VerifyStatus::UNKNOWN:
                stats.unknown_responses++;
                break;
            }
        }

        return wire::Serializer::serialize(response);
    }

    inline std::vector<uint8_t> RequestProcessor::Impl::handle_batch_request(const std::vector<uint8_t> &request_data) {
        wire::BatchVerifyRequest batch_req;

        if (!wire::Serializer::deserialize(request_data, batch_req)) {
            wire::BatchVerifyResponse error_resp;
            return wire::Serializer::serialize(error_resp);
        }

        std::vector<std::vector<authbox::pik::Certificate>> chains;
        for (const auto &req : batch_req.requests) {
            std::vector<authbox::pik::Certificate> chain;
            for (const auto &cert_data : req.certificate_chain) {
                auto parse_result = authbox::pik::Certificate::parse(cert_data.der_bytes);
                if (parse_result.success) {
                    chain.push_back(std::move(parse_result.value));
                }
            }
            chains.push_back(std::move(chain));
        }

        auto responses = handler->verify_batch(chains);

        for (size_t i = 0; i < responses.size() && i < batch_req.requests.size(); i++) {
            responses[i].nonce = batch_req.requests[i].nonce;
            sign_response(responses[i]);
        }

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.total_batch_requests++;
            for (const auto &resp : responses) {
                switch (resp.status) {
                case wire::VerifyStatus::GOOD:
                    stats.good_responses++;
                    break;
                case wire::VerifyStatus::REVOKED:
                    stats.revoked_responses++;
                    break;
                case wire::VerifyStatus::UNKNOWN:
                    stats.unknown_responses++;
                    break;
                }
            }
        }

        wire::BatchVerifyResponse batch_resp;
        batch_resp.responses = std::move(responses);
        return wire::Serializer::serialize(batch_resp);
    }

    inline std::vector<uint8_t>
    RequestProcessor::Impl::handle_health_check(const std::vector<uint8_t> & /*request_data*/) {
        wire::HealthCheckResponse health_resp;
        health_resp.status = handler->is_healthy() ? wire::HealthCheckResponse::ServingStatus::SERVING
                                                   : wire::HealthCheckResponse::ServingStatus::NOT_SERVING;

        {
            std::lock_guard<std::mutex> lock(stats_mutex);
            stats.total_health_checks++;
        }

        return wire::Serializer::serialize(health_resp);
    }

    // RequestProcessor public interface
    inline RequestProcessor::RequestProcessor(std::shared_ptr<VerificationHandler> handler)
        : impl_(std::make_unique<Impl>(std::move(handler))) {}

    inline RequestProcessor::~RequestProcessor() = default;

    inline std::vector<uint8_t> RequestProcessor::process(uint32_t method_id,
                                                          const std::vector<uint8_t> &request_data) {
        switch (method_id) {
        case methods::CHECK_CERTIFICATE:
            return impl_->handle_verify_request(request_data);
        case methods::CHECK_BATCH:
            return impl_->handle_batch_request(request_data);
        case methods::HEALTH_CHECK:
            return impl_->handle_health_check(request_data);
        default:
            // Unknown method - return empty response
            return {};
        }
    }

    inline void RequestProcessor::set_signing_key(const std::vector<uint8_t> &ed25519_private_key) {
        if (ed25519_private_key.size() != keylock::crypto::ed25519::SECRETKEYBYTES) {
            throw std::invalid_argument("Invalid Ed25519 private key size");
        }
        impl_->signing_key = ed25519_private_key;
    }

    inline void RequestProcessor::set_responder_certificate(const authbox::pik::Certificate &cert) {
        impl_->responder_cert = cert;
    }

    inline RequestProcessor::Stats RequestProcessor::get_stats() const {
        std::lock_guard<std::mutex> lock(impl_->stats_mutex);
        return impl_->stats;
    }

} // namespace authbox::pik::verify
