#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "did.hpp"
#include "errors.hpp"
#include "options.hpp"

namespace authbox::did {

    // Forward declaration
    class MethodRegistry;

    // Handler function signature - takes DID URI and resolve options, returns document JSON
    using MethodHandler =
        std::function<DidResult<std::string>(std::string_view did_uri, const ResolveOptions &options)>;

    // Method registry for dispatching DID resolution by method
    class MethodRegistry {
      public:
        MethodRegistry() = default;

        // Register a handler for a specific DID method
        void register_method(std::string_view method, MethodHandler handler) {
            handlers_[std::string(method)] = std::move(handler);
        }

        // Check if a method is registered
        bool is_registered(std::string_view method) const {
            return handlers_.find(std::string(method)) != handlers_.end();
        }

        // Resolve a DID using the registered handler for its method
        DidResult<std::string> resolve_to_document(std::string_view did_uri, const ResolveOptions &options = {}) const {
            auto parsed = parse(did_uri);
            if (parsed.is_err()) {
                return DidResult<std::string>::err(parsed.error());
            }

            const std::string method(parsed.value().method.data(), parsed.value().method.size());
            auto it = handlers_.find(method);
            if (it == handlers_.end()) {
                return DidResult<std::string>::err(error::method_not_registered(method));
            }

            return it->second(did_uri, options);
        }

        // Get a list of all registered methods
        std::vector<std::string> list_methods() const {
            std::vector<std::string> methods;
            methods.reserve(handlers_.size());
            for (const auto &pair : handlers_) {
                methods.push_back(pair.first);
            }
            return methods;
        }

        // Clear all registered handlers
        void clear() { handlers_.clear(); }

        // Get the default global registry instance
        static MethodRegistry &get_global() {
            static MethodRegistry instance;
            return instance;
        }

      private:
        std::unordered_map<std::string, MethodHandler> handlers_;
    };

} // namespace authbox::did
