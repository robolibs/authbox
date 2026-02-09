#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace authbox::pik::verify {

    // Abstract transport interface for client-server communication
    // Users can implement this interface to provide custom transport mechanisms
    // (e.g., Unix domain sockets, shared memory, message queues, or even network if needed)
    class Transport {
      public:
        virtual ~Transport() = default;

        // Send a request and receive a response
        // method_id: The RPC method identifier
        // request: The serialized request data
        // Returns: The serialized response data, or empty vector on failure
        virtual std::vector<uint8_t> call(uint32_t method_id, const std::vector<uint8_t> &request) = 0;

        // Check if the transport is connected/ready
        virtual bool is_ready() const = 0;

        // Get the last error message (if any)
        virtual std::string last_error() const = 0;
    };

    // Request handler function type for server-side transport
    using RequestHandler = std::function<std::vector<uint8_t>(uint32_t method_id, const std::vector<uint8_t> &request)>;

} // namespace authbox::pik::verify
