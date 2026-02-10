#include <atomic>
#include <chrono>
#include <thread>

#include <doctest/doctest.h>

#include <authbox.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

    struct LocalHttpServer {
        int listen_fd{-1};
        uint16_t port{0};
        std::thread worker;
        std::atomic<bool> ready{false};

        explicit LocalHttpServer(const std::string &body) {
            listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
            CHECK(listen_fd >= 0);

            int opt = 1;
            ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            CHECK(::bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
            CHECK(::listen(listen_fd, 1) == 0);

            socklen_t len = sizeof(addr);
            CHECK(::getsockname(listen_fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
            port = ntohs(addr.sin_port);

            worker = std::thread([this, body] {
                ready.store(true);
                sockaddr_in client_addr{};
                socklen_t client_len = sizeof(client_addr);
                const int client_fd = ::accept(listen_fd, reinterpret_cast<sockaddr *>(&client_addr), &client_len);
                if (client_fd < 0) {
                    return;
                }

                std::string req;
                req.resize(1024);
                (void)::recv(client_fd, req.data(), req.size(), 0);

                std::string response = "HTTP/1.1 200 OK\r\n";
                response += "Content-Type: application/json\r\n";
                response += "Content-Length: " + std::to_string(body.size()) + "\r\n";
                response += "Connection: close\r\n\r\n";
                response += body;

                (void)::send(client_fd, response.data(), response.size(), 0);
                ::close(client_fd);
            });
        }

        ~LocalHttpServer() {
            if (worker.joinable()) {
                worker.join();
            }
            if (listen_fd >= 0) {
                ::close(listen_fd);
            }
        }
    };

} // namespace

TEST_SUITE("did/web-fetch") {

    TEST_CASE("netpipe fetch rejects insecure http by default") {
        authbox::did::NetpipeHttpFetchOptions options{};
        auto result =
            authbox::did::fetch_did_document_netpipe_http11("http://example.com/.well-known/did.json", options);
        CHECK(result.is_err());
    }

    TEST_CASE("netpipe http1 fetches did document over local http") {
        const std::string body =
            R"({"id":"did:web:127.0.0.1","verificationMethod":[{"id":"did:web:127.0.0.1#0","type":"JsonWebKey2020","controller":"did:web:127.0.0.1","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":"AA"}}],"authentication":["did:web:127.0.0.1#0"]})";

        LocalHttpServer server(body);
        while (!server.ready.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        authbox::did::NetpipeHttpFetchOptions options{};
        options.allow_insecure_http = true;

        const std::string url = "http://127.0.0.1:" + std::to_string(server.port) + "/.well-known/did.json";
        auto fetched = authbox::did::fetch_did_document_netpipe_http11(url, options);
        REQUIRE(fetched.is_ok());
        CHECK(fetched.value() == body);
    }
}
