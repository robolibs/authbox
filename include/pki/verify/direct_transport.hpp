#pragma once

#include <pki/verify/client.hpp>
#include <pki/verify/server.hpp>
#include <pki/verify/transport.hpp>

namespace authbox::pik::verify {

    // Direct transport - connects client to request processor in-process (no networking)
    // This is useful for local verification without any network overhead
    class DirectTransport : public Transport {
      public:
        inline explicit DirectTransport(std::shared_ptr<RequestProcessor> processor);
        inline ~DirectTransport() override;

        // Transport interface
        inline std::vector<uint8_t> call(uint32_t method_id, const std::vector<uint8_t> &request) override;
        inline bool is_ready() const override;
        inline std::string last_error() const override;

      private:
        std::shared_ptr<RequestProcessor> processor_;
        std::string last_error_;
    };

    // Helper function to create a verification client with direct (in-process) transport
    // This is the simplest way to use the verification system without networking
    class Verifier {
      public:
        // Create a verifier with a custom handler
        inline explicit Verifier(std::shared_ptr<VerificationHandler> handler);

        // Create a verifier with a SimpleRevocationHandler
        inline Verifier();

        inline ~Verifier();

        // Disable copy
        Verifier(const Verifier &) = delete;
        Verifier &operator=(const Verifier &) = delete;

        // Enable move
        inline Verifier(Verifier &&) noexcept;
        inline Verifier &operator=(Verifier &&) noexcept;

        // Get the underlying handler (for adding revocations, etc.)
        inline VerificationHandler &handler();
        inline const VerificationHandler &handler() const;

        // Get as SimpleRevocationHandler (returns nullptr if not a SimpleRevocationHandler)
        inline SimpleRevocationHandler *as_revocation_handler();

        // Get the client for performing verifications
        inline Client &client();

        // Set the signing key for response signatures
        inline void set_signing_key(const std::vector<uint8_t> &ed25519_private_key);

        // Set the responder certificate
        inline void set_responder_certificate(const authbox::pik::Certificate &cert);

        // Convenience method: verify a single chain directly
        inline Client::Result<Client::Response>
        verify_chain(const std::vector<authbox::pik::Certificate> &chain,
                     std::chrono::system_clock::time_point validation_time = std::chrono::system_clock::now());

        // Convenience method: verify batch
        inline Client::Result<std::vector<Client::Response>>
        verify_batch(const std::vector<std::vector<authbox::pik::Certificate>> &chains);

        // Convenience method: health check
        inline Client::Result<bool> health_check();

      private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

    // DirectTransport implementation
    inline DirectTransport::DirectTransport(std::shared_ptr<RequestProcessor> processor)
        : processor_(std::move(processor)) {}

    inline DirectTransport::~DirectTransport() = default;

    inline std::vector<uint8_t> DirectTransport::call(uint32_t method_id, const std::vector<uint8_t> &request) {
        if (!processor_) {
            last_error_ = "No processor configured";
            return {};
        }

        try {
            auto response = processor_->process(method_id, request);
            last_error_.clear();
            return response;
        } catch (const std::exception &e) {
            last_error_ = e.what();
            return {};
        }
    }

    inline bool DirectTransport::is_ready() const { return processor_ != nullptr; }

    inline std::string DirectTransport::last_error() const { return last_error_; }

    // Verifier implementation
    class Verifier::Impl {
      public:
        std::shared_ptr<VerificationHandler> handler;
        std::shared_ptr<RequestProcessor> processor;
        std::shared_ptr<DirectTransport> transport;
        std::unique_ptr<Client> client;

        explicit Impl(std::shared_ptr<VerificationHandler> h) : handler(std::move(h)) {
            processor = std::make_shared<RequestProcessor>(handler);
            transport = std::make_shared<DirectTransport>(processor);
            client = std::make_unique<Client>(transport);
        }
    };

    inline Verifier::Verifier(std::shared_ptr<VerificationHandler> handler)
        : impl_(std::make_unique<Impl>(std::move(handler))) {}

    inline Verifier::Verifier() : Verifier(std::make_shared<SimpleRevocationHandler>()) {}

    inline Verifier::~Verifier() = default;

    inline Verifier::Verifier(Verifier &&) noexcept = default;
    inline Verifier &Verifier::operator=(Verifier &&) noexcept = default;

    inline VerificationHandler &Verifier::handler() { return *impl_->handler; }

    inline const VerificationHandler &Verifier::handler() const { return *impl_->handler; }

    inline SimpleRevocationHandler *Verifier::as_revocation_handler() {
        return dynamic_cast<SimpleRevocationHandler *>(impl_->handler.get());
    }

    inline Client &Verifier::client() { return *impl_->client; }

    inline void Verifier::set_signing_key(const std::vector<uint8_t> &ed25519_private_key) {
        impl_->processor->set_signing_key(ed25519_private_key);
    }

    inline void Verifier::set_responder_certificate(const authbox::pik::Certificate &cert) {
        impl_->processor->set_responder_certificate(cert);
        impl_->client->set_responder_cert(cert);
    }

    inline Client::Result<Client::Response>
    Verifier::verify_chain(const std::vector<authbox::pik::Certificate> &chain,
                           std::chrono::system_clock::time_point validation_time) {
        return impl_->client->verify_chain(chain, validation_time);
    }

    inline Client::Result<std::vector<Client::Response>>
    Verifier::verify_batch(const std::vector<std::vector<authbox::pik::Certificate>> &chains) {
        return impl_->client->verify_batch(chains);
    }

    inline Client::Result<bool> Verifier::health_check() { return impl_->client->health_check(); }

} // namespace authbox::pik::verify
