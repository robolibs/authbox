#include <chrono>
#include <iostream>
#include <optional>

#include <authbox.hpp>
#include <pki/builder.hpp>
#include <pki/key_utils.hpp>

namespace {

    struct LoopbackRemote {
        authbox::did::rpc::Service *service{nullptr};

        dp::Res<netpipe::Message> call(dp::u32 method_id, const netpipe::Message &request, dp::u32) {
            if (!service) {
                return dp::result::err(dp::Error::not_found("service not configured"));
            }
            return service->dispatch(method_id, request);
        }
    };

} // namespace

int main() {
    const std::string did_uri = "did:web:example.com";

    auto keypair = authbox::pik::generate_ed25519_keypair();
    authbox::pik::CertificateBuilder builder;
    const auto now = std::chrono::system_clock::now();

    authbox::pik::SubjectAltNameExtension::GeneralName did_name{};
    did_name.type = authbox::pik::SubjectAltNameExtension::GeneralNameType::URI;
    did_name.value = did_uri;

    auto cert = builder.set_subject_from_string("CN=example.com,O=Example")
                    .set_issuer_from_string("CN=example.com,O=Example")
                    .set_validity(now - std::chrono::hours(1), now + std::chrono::hours(24))
                    .set_subject_public_key_ed25519(keypair.public_key)
                    .set_basic_constraints(false, std::nullopt)
                    .set_subject_alt_name({did_name})
                    .build_ed25519(keypair, true);
    if (!cert.success) {
        std::cerr << "Failed to create certificate: " << cert.error << "\n";
        return 1;
    }

    auto generated = authbox::did::generate_did_web_document("example.com", cert.value);
    if (generated.is_err()) {
        std::cerr << "Failed to generate did document: " << generated.error().c_str() << "\n";
        return 1;
    }

    authbox::did::Resolver resolver([&generated](std::string_view url) -> authbox::did::DidResult<std::string> {
        if (url != "https://example.com/.well-known/did.json") {
            return authbox::did::DidResult<std::string>::err(authbox::did::to_dp_string("unexpected URL"));
        }
        return authbox::did::DidResult<std::string>::ok(
            std::string(generated.value().did_document_json.data(), generated.value().did_document_json.size()));
    });

    authbox::did::rpc::Service service(resolver);
    LoopbackRemote remote{&service};
    authbox::did::rpc::Client<LoopbackRemote> client(remote);

    auto resolved = client.resolve(did_uri);
    if (resolved.is_err()) {
        std::cerr << "RPC resolve failed: " << resolved.error().c_str() << "\n";
        return 1;
    }

    auto verified = client.verify_binding(
        did_uri,
        std::string_view(generated.value().did_document_json.data(), generated.value().did_document_json.size()),
        cert.value.to_pem());
    if (verified.is_err() || !verified.value()) {
        std::cerr << "RPC verify failed: " << (verified.is_err() ? verified.error().c_str() : "invalid") << "\n";
        return 1;
    }

    std::cout << "RPC resolve source: " << resolved.value().source_url.c_str() << "\n";
    std::cout << "RPC verify: OK\n";
    return 0;
}
