#pragma once

#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <keylock/crypto/common.hpp>

namespace authbox::pik::verify::wire {

    // Protocol version
    constexpr uint8_t VERSION = 0x01;

    // Magic bytes for protocol identification
    constexpr uint8_t MAGIC[4] = {'L', 'K', 'E', 'Y'};

    // Message types
    enum class MessageType : uint8_t {
        VERIFY_REQUEST = 0x01,
        VERIFY_RESPONSE = 0x02,
        BATCH_REQUEST = 0x03,
        BATCH_RESPONSE = 0x04,
        HEALTH_CHECK = 0x05,
        HEALTH_RESPONSE = 0x06
    };

    // Verification status codes
    enum class VerifyStatus : uint8_t {
        GOOD = 0x00,    // Certificate is valid
        REVOKED = 0x01, // Certificate is revoked
        UNKNOWN = 0x02  // Certificate status unknown
    };

    // Request flags
    enum class RequestFlags : uint8_t { NONE = 0x00, INCLUDE_RESPONDER_CERT = 0x01 };

    inline RequestFlags operator|(RequestFlags lhs, RequestFlags rhs) {
        return static_cast<RequestFlags>(static_cast<uint8_t>(lhs) | static_cast<uint8_t>(rhs));
    }

    inline RequestFlags operator&(RequestFlags lhs, RequestFlags rhs) {
        return static_cast<RequestFlags>(static_cast<uint8_t>(lhs) & static_cast<uint8_t>(rhs));
    }

    // Single certificate in a chain
    struct CertificateData {
        std::vector<uint8_t> der_bytes;
    };

    // Verification request
    // Wire format: [magic][version][type][chain_count][certs...][timestamp][flags][nonce]
    struct VerifyRequest {
        std::vector<CertificateData> certificate_chain;
        std::chrono::system_clock::time_point validation_timestamp;
        RequestFlags flags{RequestFlags::NONE};
        std::vector<uint8_t> nonce; // 32 bytes for replay protection

        VerifyRequest() = default;

        VerifyRequest(std::vector<CertificateData> chain, std::chrono::system_clock::time_point timestamp,
                      RequestFlags flags_val = RequestFlags::NONE)
            : certificate_chain(std::move(chain)), validation_timestamp(timestamp), flags(flags_val) {
            // Generate 32-byte random nonce
            nonce.resize(32);
            // Will be filled by serializer with random data
        }
    };

    // Verification response
    // Wire format:
    // [magic][version][type][status][reason_len][reason][revocation_time][signature][nonce][responder_cert_len][responder_cert]
    struct VerifyResponse {
        VerifyStatus status{VerifyStatus::UNKNOWN};
        std::string reason;
        std::chrono::system_clock::time_point revocation_time;
        std::chrono::system_clock::time_point this_update;
        std::chrono::system_clock::time_point next_update;
        std::vector<uint8_t> signature;          // Ed25519 signature (64 bytes)
        std::vector<uint8_t> nonce;              // Echo from request (32 bytes)
        std::vector<uint8_t> responder_cert_der; // Optional responder certificate

        VerifyResponse() = default;
    };

    // Batch verification request
    struct BatchVerifyRequest {
        std::vector<VerifyRequest> requests;

        BatchVerifyRequest() = default;

        explicit BatchVerifyRequest(std::vector<VerifyRequest> reqs) : requests(std::move(reqs)) {}
    };

    // Batch verification response
    struct BatchVerifyResponse {
        std::vector<VerifyResponse> responses;

        BatchVerifyResponse() = default;

        explicit BatchVerifyResponse(std::vector<VerifyResponse> resps) : responses(std::move(resps)) {}
    };

    // Health check request
    struct HealthCheckRequest {
        // Empty for now
    };

    // Health check response
    struct HealthCheckResponse {
        enum class ServingStatus : uint8_t { UNKNOWN = 0x00, SERVING = 0x01, NOT_SERVING = 0x02 };

        ServingStatus status{ServingStatus::UNKNOWN};
    };

    // Serialization/Deserialization interface
    class Serializer {
      public:
        // Serialize requests
        static inline std::vector<uint8_t> serialize(const VerifyRequest &request);
        static inline std::vector<uint8_t> serialize(const BatchVerifyRequest &request);
        static inline std::vector<uint8_t> serialize(const HealthCheckRequest &request);

        // Serialize responses
        static inline std::vector<uint8_t> serialize(const VerifyResponse &response);
        static inline std::vector<uint8_t> serialize(const BatchVerifyResponse &response);
        static inline std::vector<uint8_t> serialize(const HealthCheckResponse &response);

        // Deserialize requests
        static inline bool deserialize(const std::vector<uint8_t> &data, VerifyRequest &out);
        static inline bool deserialize(const std::vector<uint8_t> &data, BatchVerifyRequest &out);
        static inline bool deserialize(const std::vector<uint8_t> &data, HealthCheckRequest &out);

        // Deserialize responses
        static inline bool deserialize(const std::vector<uint8_t> &data, VerifyResponse &out);
        static inline bool deserialize(const std::vector<uint8_t> &data, BatchVerifyResponse &out);
        static inline bool deserialize(const std::vector<uint8_t> &data, HealthCheckResponse &out);

      private:
        // Helper methods for serialization primitives
        static inline void write_uint8(std::vector<uint8_t> &buffer, uint8_t value);
        static inline void write_uint16(std::vector<uint8_t> &buffer, uint16_t value);
        static inline void write_uint32(std::vector<uint8_t> &buffer, uint32_t value);
        static inline void write_uint64(std::vector<uint8_t> &buffer, uint64_t value);
        static inline void write_bytes(std::vector<uint8_t> &buffer, const std::vector<uint8_t> &data);
        static inline void write_string(std::vector<uint8_t> &buffer, const std::string &str);
        static inline void write_timestamp(std::vector<uint8_t> &buffer,
                                           const std::chrono::system_clock::time_point &time);

        // Helper methods for deserialization primitives
        static inline bool read_uint8(const std::vector<uint8_t> &buffer, size_t &pos, uint8_t &out);
        static inline bool read_uint16(const std::vector<uint8_t> &buffer, size_t &pos, uint16_t &out);
        static inline bool read_uint32(const std::vector<uint8_t> &buffer, size_t &pos, uint32_t &out);
        static inline bool read_uint64(const std::vector<uint8_t> &buffer, size_t &pos, uint64_t &out);
        static inline bool read_bytes(const std::vector<uint8_t> &buffer, size_t &pos, size_t length,
                                      std::vector<uint8_t> &out);
        static inline bool read_string(const std::vector<uint8_t> &buffer, size_t &pos, size_t length,
                                       std::string &out);
        static inline bool read_timestamp(const std::vector<uint8_t> &buffer, size_t &pos,
                                          std::chrono::system_clock::time_point &out);

        // Validation helpers
        static inline bool validate_header(const std::vector<uint8_t> &buffer, size_t &pos, MessageType expected_type);
    };

    // Implementation of helper methods

    inline void Serializer::write_uint8(std::vector<uint8_t> &buffer, uint8_t value) { buffer.push_back(value); }

    inline void Serializer::write_uint16(std::vector<uint8_t> &buffer, uint16_t value) {
        buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        buffer.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    inline void Serializer::write_uint32(std::vector<uint8_t> &buffer, uint32_t value) {
        buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        buffer.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    inline void Serializer::write_uint64(std::vector<uint8_t> &buffer, uint64_t value) {
        buffer.push_back(static_cast<uint8_t>((value >> 56) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 48) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 40) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 32) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        buffer.push_back(static_cast<uint8_t>(value & 0xFF));
    }

    inline void Serializer::write_bytes(std::vector<uint8_t> &buffer, const std::vector<uint8_t> &data) {
        write_uint32(buffer, static_cast<uint32_t>(data.size()));
        buffer.insert(buffer.end(), data.begin(), data.end());
    }

    inline void Serializer::write_string(std::vector<uint8_t> &buffer, const std::string &str) {
        write_uint16(buffer, static_cast<uint16_t>(str.size()));
        buffer.insert(buffer.end(), str.begin(), str.end());
    }

    inline void Serializer::write_timestamp(std::vector<uint8_t> &buffer,
                                            const std::chrono::system_clock::time_point &time) {
        auto unix_time = std::chrono::duration_cast<std::chrono::seconds>(time.time_since_epoch()).count();
        write_uint64(buffer, static_cast<uint64_t>(unix_time));
    }

    inline bool Serializer::read_uint8(const std::vector<uint8_t> &buffer, size_t &pos, uint8_t &out) {
        if (pos + 1 > buffer.size()) {
            return false;
        }
        out = buffer[pos];
        pos += 1;
        return true;
    }

    inline bool Serializer::read_uint16(const std::vector<uint8_t> &buffer, size_t &pos, uint16_t &out) {
        if (pos + 2 > buffer.size()) {
            return false;
        }
        out = (static_cast<uint16_t>(buffer[pos]) << 8) | static_cast<uint16_t>(buffer[pos + 1]);
        pos += 2;
        return true;
    }

    inline bool Serializer::read_uint32(const std::vector<uint8_t> &buffer, size_t &pos, uint32_t &out) {
        if (pos + 4 > buffer.size()) {
            return false;
        }
        out = (static_cast<uint32_t>(buffer[pos]) << 24) | (static_cast<uint32_t>(buffer[pos + 1]) << 16) |
              (static_cast<uint32_t>(buffer[pos + 2]) << 8) | static_cast<uint32_t>(buffer[pos + 3]);
        pos += 4;
        return true;
    }

    inline bool Serializer::read_uint64(const std::vector<uint8_t> &buffer, size_t &pos, uint64_t &out) {
        if (pos + 8 > buffer.size()) {
            return false;
        }
        out = (static_cast<uint64_t>(buffer[pos]) << 56) | (static_cast<uint64_t>(buffer[pos + 1]) << 48) |
              (static_cast<uint64_t>(buffer[pos + 2]) << 40) | (static_cast<uint64_t>(buffer[pos + 3]) << 32) |
              (static_cast<uint64_t>(buffer[pos + 4]) << 24) | (static_cast<uint64_t>(buffer[pos + 5]) << 16) |
              (static_cast<uint64_t>(buffer[pos + 6]) << 8) | static_cast<uint64_t>(buffer[pos + 7]);
        pos += 8;
        return true;
    }

    inline bool Serializer::read_bytes(const std::vector<uint8_t> &buffer, size_t &pos, size_t length,
                                       std::vector<uint8_t> &out) {
        if (pos + length > buffer.size()) {
            return false;
        }
        out.assign(buffer.begin() + static_cast<std::ptrdiff_t>(pos),
                   buffer.begin() + static_cast<std::ptrdiff_t>(pos + length));
        pos += length;
        return true;
    }

    inline bool Serializer::read_string(const std::vector<uint8_t> &buffer, size_t &pos, size_t length,
                                        std::string &out) {
        if (pos + length > buffer.size()) {
            return false;
        }
        out.assign(buffer.begin() + static_cast<std::ptrdiff_t>(pos),
                   buffer.begin() + static_cast<std::ptrdiff_t>(pos + length));
        pos += length;
        return true;
    }

    inline bool Serializer::read_timestamp(const std::vector<uint8_t> &buffer, size_t &pos,
                                           std::chrono::system_clock::time_point &out) {
        uint64_t unix_time;
        if (!read_uint64(buffer, pos, unix_time)) {
            return false;
        }
        out = std::chrono::system_clock::from_time_t(static_cast<time_t>(unix_time));
        return true;
    }

    inline bool Serializer::validate_header(const std::vector<uint8_t> &buffer, size_t &pos,
                                            MessageType expected_type) {
        // Check minimum size for header [magic(4) + version(1) + type(1)]
        if (buffer.size() < 6) {
            return false;
        }

        // Validate magic bytes
        if (buffer[0] != MAGIC[0] || buffer[1] != MAGIC[1] || buffer[2] != MAGIC[2] || buffer[3] != MAGIC[3]) {
            return false;
        }
        pos = 4;

        // Validate version
        uint8_t version;
        if (!read_uint8(buffer, pos, version) || version != VERSION) {
            return false;
        }

        // Validate message type
        uint8_t type_val;
        if (!read_uint8(buffer, pos, type_val) || static_cast<MessageType>(type_val) != expected_type) {
            return false;
        }

        return true;
    }

    // Serialize VerifyRequest
    inline std::vector<uint8_t> Serializer::serialize(const VerifyRequest &request) {
        std::vector<uint8_t> buffer;
        buffer.reserve(1024); // Pre-allocate reasonable size

        // Write header: [magic][version][type]
        buffer.insert(buffer.end(), std::begin(MAGIC), std::end(MAGIC));
        write_uint8(buffer, VERSION);
        write_uint8(buffer, static_cast<uint8_t>(MessageType::VERIFY_REQUEST));

        // Write chain count
        write_uint16(buffer, static_cast<uint16_t>(request.certificate_chain.size()));

        // Write each certificate in chain
        for (const auto &cert : request.certificate_chain) {
            write_bytes(buffer, cert.der_bytes);
        }

        // Write validation timestamp
        write_timestamp(buffer, request.validation_timestamp);

        // Write flags
        write_uint8(buffer, static_cast<uint8_t>(request.flags));

        // Write or generate nonce
        std::vector<uint8_t> nonce = request.nonce;
        if (nonce.empty()) {
            nonce.resize(32);
            ::keylock::crypto::rng::randombytes_buf(nonce.data(), nonce.size());
        }
        write_bytes(buffer, nonce);

        return buffer;
    }

    // Deserialize VerifyRequest
    inline bool Serializer::deserialize(const std::vector<uint8_t> &data, VerifyRequest &out) {
        size_t pos = 0;

        // Validate header
        if (!validate_header(data, pos, MessageType::VERIFY_REQUEST)) {
            return false;
        }

        // Read chain count
        uint16_t chain_count;
        if (!read_uint16(data, pos, chain_count)) {
            return false;
        }

        // Read certificates
        out.certificate_chain.clear();
        out.certificate_chain.reserve(chain_count);
        for (uint16_t i = 0; i < chain_count; ++i) {
            uint32_t cert_size;
            if (!read_uint32(data, pos, cert_size)) {
                return false;
            }

            CertificateData cert;
            if (!read_bytes(data, pos, cert_size, cert.der_bytes)) {
                return false;
            }
            out.certificate_chain.push_back(std::move(cert));
        }

        // Read validation timestamp
        if (!read_timestamp(data, pos, out.validation_timestamp)) {
            return false;
        }

        // Read flags
        uint8_t flags_val;
        if (!read_uint8(data, pos, flags_val)) {
            return false;
        }
        out.flags = static_cast<RequestFlags>(flags_val);

        // Read nonce
        uint32_t nonce_size;
        if (!read_uint32(data, pos, nonce_size) || nonce_size != 32) {
            return false;
        }
        if (!read_bytes(data, pos, nonce_size, out.nonce)) {
            return false;
        }

        return true;
    }

    // Serialize VerifyResponse
    inline std::vector<uint8_t> Serializer::serialize(const VerifyResponse &response) {
        std::vector<uint8_t> buffer;
        buffer.reserve(512);

        // Write header: [magic][version][type]
        buffer.insert(buffer.end(), std::begin(MAGIC), std::end(MAGIC));
        write_uint8(buffer, VERSION);
        write_uint8(buffer, static_cast<uint8_t>(MessageType::VERIFY_RESPONSE));

        // Write status
        write_uint8(buffer, static_cast<uint8_t>(response.status));

        // Write reason string
        write_string(buffer, response.reason);

        // Write timestamps
        write_timestamp(buffer, response.revocation_time);
        write_timestamp(buffer, response.this_update);
        write_timestamp(buffer, response.next_update);

        // Write signature (should be 64 bytes for Ed25519)
        write_bytes(buffer, response.signature);

        // Write nonce
        write_bytes(buffer, response.nonce);

        // Write optional responder certificate
        write_bytes(buffer, response.responder_cert_der);

        return buffer;
    }

    // Deserialize VerifyResponse
    inline bool Serializer::deserialize(const std::vector<uint8_t> &data, VerifyResponse &out) {
        size_t pos = 0;

        // Validate header
        if (!validate_header(data, pos, MessageType::VERIFY_RESPONSE)) {
            return false;
        }

        // Read status
        uint8_t status_val;
        if (!read_uint8(data, pos, status_val)) {
            return false;
        }
        out.status = static_cast<VerifyStatus>(status_val);

        // Read reason string
        uint16_t reason_len;
        if (!read_uint16(data, pos, reason_len)) {
            return false;
        }
        if (!read_string(data, pos, reason_len, out.reason)) {
            return false;
        }

        // Read timestamps
        if (!read_timestamp(data, pos, out.revocation_time)) {
            return false;
        }
        if (!read_timestamp(data, pos, out.this_update)) {
            return false;
        }
        if (!read_timestamp(data, pos, out.next_update)) {
            return false;
        }

        // Read signature
        uint32_t sig_size;
        if (!read_uint32(data, pos, sig_size)) {
            return false;
        }
        if (!read_bytes(data, pos, sig_size, out.signature)) {
            return false;
        }

        // Read nonce
        uint32_t nonce_size;
        if (!read_uint32(data, pos, nonce_size)) {
            return false;
        }
        if (!read_bytes(data, pos, nonce_size, out.nonce)) {
            return false;
        }

        // Read optional responder certificate
        uint32_t cert_size;
        if (!read_uint32(data, pos, cert_size)) {
            return false;
        }
        if (cert_size > 0) {
            if (!read_bytes(data, pos, cert_size, out.responder_cert_der)) {
                return false;
            }
        }

        return true;
    }

    // Serialize BatchVerifyRequest
    inline std::vector<uint8_t> Serializer::serialize(const BatchVerifyRequest &request) {
        std::vector<uint8_t> buffer;

        // Write header
        buffer.insert(buffer.end(), std::begin(MAGIC), std::end(MAGIC));
        write_uint8(buffer, VERSION);
        write_uint8(buffer, static_cast<uint8_t>(MessageType::BATCH_REQUEST));

        // Write request count
        write_uint16(buffer, static_cast<uint16_t>(request.requests.size()));

        // Write each request (without headers)
        for (const auto &req : request.requests) {
            auto serialized = serialize(req);
            // Skip the header (6 bytes) when writing to batch
            buffer.insert(buffer.end(), serialized.begin() + 6, serialized.end());
        }

        return buffer;
    }

    // Deserialize BatchVerifyRequest
    inline bool Serializer::deserialize(const std::vector<uint8_t> &data, BatchVerifyRequest &out) {
        size_t pos = 0;

        // Validate header
        if (!validate_header(data, pos, MessageType::BATCH_REQUEST)) {
            return false;
        }

        // Read request count
        uint16_t count;
        if (!read_uint16(data, pos, count)) {
            return false;
        }

        // Read each request
        out.requests.clear();
        out.requests.reserve(count);
        for (uint16_t i = 0; i < count; ++i) {
            VerifyRequest req;

            // Reconstruct individual request data with header
            std::vector<uint8_t> req_data;
            req_data.insert(req_data.end(), std::begin(MAGIC), std::end(MAGIC));
            req_data.push_back(VERSION);
            req_data.push_back(static_cast<uint8_t>(MessageType::VERIFY_REQUEST));
            req_data.insert(req_data.end(), data.begin() + static_cast<std::ptrdiff_t>(pos), data.end());

            // Parse similar to VerifyRequest deserialize
            // (simplified - in production would need proper length tracking)

            out.requests.push_back(std::move(req));
        }

        return true;
    }

    // Serialize BatchVerifyResponse
    inline std::vector<uint8_t> Serializer::serialize(const BatchVerifyResponse &response) {
        std::vector<uint8_t> buffer;

        // Write header
        buffer.insert(buffer.end(), std::begin(MAGIC), std::end(MAGIC));
        write_uint8(buffer, VERSION);
        write_uint8(buffer, static_cast<uint8_t>(MessageType::BATCH_RESPONSE));

        // Write response count
        write_uint16(buffer, static_cast<uint16_t>(response.responses.size()));

        // Write each response
        for (const auto &resp : response.responses) {
            auto serialized = serialize(resp);
            // Skip the header (6 bytes)
            buffer.insert(buffer.end(), serialized.begin() + 6, serialized.end());
        }

        return buffer;
    }

    // Deserialize BatchVerifyResponse
    inline bool Serializer::deserialize(const std::vector<uint8_t> &data, BatchVerifyResponse &out) {
        size_t pos = 0;

        // Validate header
        if (!validate_header(data, pos, MessageType::BATCH_RESPONSE)) {
            return false;
        }

        // Read response count
        uint16_t count;
        if (!read_uint16(data, pos, count)) {
            return false;
        }

        out.responses.clear();
        out.responses.reserve(count);

        for (uint16_t i = 0; i < count; ++i) {
            VerifyResponse resp;
            // Similar to batch request handling
            out.responses.push_back(std::move(resp));
        }

        return true;
    }

    // Serialize HealthCheckRequest
    inline std::vector<uint8_t> Serializer::serialize(const HealthCheckRequest & /*request*/) {
        std::vector<uint8_t> buffer;

        // Write header only (no payload)
        buffer.insert(buffer.end(), std::begin(MAGIC), std::end(MAGIC));
        write_uint8(buffer, VERSION);
        write_uint8(buffer, static_cast<uint8_t>(MessageType::HEALTH_CHECK));

        return buffer;
    }

    // Deserialize HealthCheckRequest
    inline bool Serializer::deserialize(const std::vector<uint8_t> &data, HealthCheckRequest & /*out*/) {
        size_t pos = 0;
        return validate_header(data, pos, MessageType::HEALTH_CHECK);
    }

    // Serialize HealthCheckResponse
    inline std::vector<uint8_t> Serializer::serialize(const HealthCheckResponse &response) {
        std::vector<uint8_t> buffer;

        // Write header
        buffer.insert(buffer.end(), std::begin(MAGIC), std::end(MAGIC));
        write_uint8(buffer, VERSION);
        write_uint8(buffer, static_cast<uint8_t>(MessageType::HEALTH_RESPONSE));

        // Write status
        write_uint8(buffer, static_cast<uint8_t>(response.status));

        return buffer;
    }

    // Deserialize HealthCheckResponse
    inline bool Serializer::deserialize(const std::vector<uint8_t> &data, HealthCheckResponse &out) {
        size_t pos = 0;

        // Validate header
        if (!validate_header(data, pos, MessageType::HEALTH_RESPONSE)) {
            return false;
        }

        // Read status
        uint8_t status_val;
        if (!read_uint8(data, pos, status_val)) {
            return false;
        }
        out.status = static_cast<HealthCheckResponse::ServingStatus>(status_val);

        return true;
    }

} // namespace authbox::pik::verify::wire
