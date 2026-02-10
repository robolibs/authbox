#include <iostream>
#include <string>
#include <string_view>

#include <authbox.hpp>

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <did:web:...> [--allow-http] [--skip-tls-verify]\n";
        return 1;
    }

    const std::string did_uri = argv[1];
    if (!std::string_view(did_uri).starts_with("did:web:")) {
        std::cerr << "Expected a did:web URI, got: " << did_uri << "\n";
        return 1;
    }

    authbox::did::NetpipeHttpFetchOptions options{};
    for (int i = 2; i < argc; ++i) {
        const std::string flag = argv[i];
        if (flag == "--allow-http") {
            options.allow_insecure_http = true;
        } else if (flag == "--skip-tls-verify") {
            options.skip_tls_certificate_verification_for_testing = true;
        } else {
            std::cerr << "Unknown flag: " << flag << "\n";
            return 1;
        }
    }

    auto resolver = authbox::did::make_netpipe_http11_resolver(options);
    auto resolved = resolver.resolve(did_uri);
    if (resolved.is_err()) {
        std::cerr << "Resolve failed: " << resolved.error().c_str() << "\n";
        return 1;
    }

    std::cout << "DID: " << resolved.value().did.uri.c_str() << "\n";
    std::cout << "Source: " << resolved.value().source_url.c_str() << "\n";
    std::cout << "Methods: " << resolved.value().document.verification_methods.size() << "\n";
    std::cout << "Authentication refs: " << resolved.value().document.authentication.size() << "\n";
    std::cout << "Assertion refs: " << resolved.value().document.assertion_method.size() << "\n";
    std::cout << "\nRaw DID document:\n";
    std::cout << resolved.value().raw_document_json.c_str() << "\n";
    return 0;
}
