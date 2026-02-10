#include <iostream>
#include <string>

#include <authbox.hpp>

using namespace authbox::did;

int main() {
    std::cout << "=== did:jwk Roundtrip Example ===\n\n";

    // Example 1: Ed25519 key (authentication)
    {
        std::cout << "Example 1: Ed25519 Key (Authentication)\n";

        const std::string jwk_json =
            R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";

        std::cout << "  Original JWK: " << jwk_json << "\n";

        // Encode to did:jwk
        auto did_result = encode_did_jwk(jwk_json);
        if (did_result.is_err()) {
            std::cerr << "  Failed to encode did:jwk: " << did_result.error().c_str() << "\n";
            return 1;
        }

        std::cout << "  Generated DID: " << did_result.value() << "\n";

        // Parse it back
        auto parsed = parse_did_jwk(did_result.value());
        if (parsed.is_err()) {
            std::cerr << "  Failed to parse did:jwk: " << parsed.error().c_str() << "\n";
            return 1;
        }

        std::cout << "  Parsed JWK back: " << parsed.value() << "\n";

        // Resolve to DID document
        auto doc_result = resolve_did_jwk_document_json(did_result.value());
        if (doc_result.is_err()) {
            std::cerr << "  Failed to resolve DID document: " << doc_result.error().c_str() << "\n";
            return 1;
        }

        std::cout << "  DID Document:\n" << doc_result.value() << "\n";

        // Parse and validate document
        auto document = parse_document(doc_result.value());
        if (document.is_err()) {
            std::cerr << "  Failed to parse DID document: " << document.error().c_str() << "\n";
            return 1;
        }

        std::cout << "  Verification methods: " << document.value().verification_methods.size() << "\n";
        std::cout << "  Authentication methods: " << document.value().authentication.size() << "\n";
        std::cout << "  Key agreement methods: " << document.value().key_agreement.size() << "\n\n";
    }

    // Example 2: X25519 key (key agreement)
    {
        std::cout << "Example 2: X25519 Key (Key Agreement)\n";

        const std::string jwk_json =
            R"({"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"})";

        std::cout << "  Original JWK: " << jwk_json << "\n";

        auto did_result = encode_did_jwk(jwk_json);
        if (did_result.is_err()) {
            std::cerr << "  Failed to encode did:jwk: " << did_result.error().c_str() << "\n";
            return 1;
        }

        std::cout << "  Generated DID: " << did_result.value() << "\n";

        auto doc_result = resolve_did_jwk_document_json(did_result.value());
        if (doc_result.is_err()) {
            std::cerr << "  Failed to resolve DID document: " << doc_result.error().c_str() << "\n";
            return 1;
        }

        auto document = parse_document(doc_result.value());
        if (document.is_err()) {
            std::cerr << "  Failed to parse DID document: " << document.error().c_str() << "\n";
            return 1;
        }

        std::cout << "  Verification methods: " << document.value().verification_methods.size() << "\n";
        std::cout << "  Authentication methods: " << document.value().authentication.size() << "\n";
        std::cout << "  Key agreement methods: " << document.value().key_agreement.size() << "\n\n";
    }

    // Example 3: P-256 EC key
    {
        std::cout << "Example 3: P-256 EC Key\n";

        const std::string jwk_json =
            R"({"kty":"EC","crv":"P-256","x":"fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI","y":"hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU"})";

        std::cout << "  Original JWK: " << jwk_json << "\n";

        auto did_result = encode_did_jwk(jwk_json);
        if (did_result.is_err()) {
            std::cerr << "  Failed to encode did:jwk: " << did_result.error().c_str() << "\n";
            return 1;
        }

        std::cout << "  Generated DID: " << did_result.value() << "\n";

        auto doc_result = resolve_did_jwk_document_json(did_result.value());
        if (doc_result.is_err()) {
            std::cerr << "  Failed to resolve DID document: " << doc_result.error().c_str() << "\n";
            return 1;
        }

        auto document = parse_document(doc_result.value());
        if (document.is_err()) {
            std::cerr << "  Failed to parse DID document: " << document.error().c_str() << "\n";
            return 1;
        }

        std::cout << "  Verification methods: " << document.value().verification_methods.size() << "\n";
        std::cout << "  Authentication methods: " << document.value().authentication.size() << "\n";
        std::cout << "  Key agreement methods: " << document.value().key_agreement.size() << "\n\n";
    }

    // Example 4: Demonstrate canonicalization (deterministic encoding)
    {
        std::cout << "Example 4: Canonicalization Test\n";

        const std::string jwk_v1 = R"({"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kty":"OKP","crv":"Ed25519"})";
        const std::string jwk_v2 = R"({"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";

        std::cout << "  JWK Version 1: " << jwk_v1 << "\n";
        std::cout << "  JWK Version 2: " << jwk_v2 << "\n";

        auto did1 = encode_did_jwk(jwk_v1);
        auto did2 = encode_did_jwk(jwk_v2);

        if (did1.is_ok() && did2.is_ok()) {
            if (did1.value() == did2.value()) {
                std::cout << "  ✓ Both versions produce the same DID (deterministic)\n";
                std::cout << "  DID: " << did1.value() << "\n";
            } else {
                std::cout << "  ✗ DIDs differ (non-deterministic)\n";
                std::cout << "  DID 1: " << did1.value() << "\n";
                std::cout << "  DID 2: " << did2.value() << "\n";
            }
        }
        std::cout << "\n";
    }

    // Example 5: Use with Resolver
    {
        std::cout << "Example 5: Resolver Integration\n";

        const std::string jwk_json =
            R"({"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"})";

        auto did_result = encode_did_jwk(jwk_json);
        if (did_result.is_err()) {
            std::cerr << "  Failed to encode did:jwk: " << did_result.error().c_str() << "\n";
            return 1;
        }

        // Create resolver and register did:jwk handler
        Resolver resolver;
        resolver.registry().register_method("jwk", [](std::string_view did_uri, const ResolveOptions &) {
            return resolve_did_jwk_document_json(did_uri);
        });

        std::cout << "  Registered did:jwk handler in resolver\n";

        // Resolve the DID
        auto resolution = resolver.resolve(did_result.value());
        if (resolution.is_err()) {
            std::cerr << "  Failed to resolve DID: " << resolution.error().c_str() << "\n";
            return 1;
        }

        std::cout << "  Resolved DID: " << resolution.value().did.uri.c_str() << "\n";
        std::cout << "  Document ID: " << resolution.value().document.id.c_str() << "\n";
        std::cout << "  Source: " << resolution.value().source_url.c_str() << "\n";
        std::cout << "  Verification methods: " << resolution.value().document.verification_methods.size() << "\n";
    }

    std::cout << "\n=== All examples completed successfully ===\n";

    return 0;
}
