#pragma once

#include <cerrno>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <netpipe/core/endpoint.hpp>
#include <netpipe/core/stream.hpp>
#include <netpipe/protocol/http1.hpp>
#include <netpipe/security/tls/session.hpp>

#include "did.hpp"
#include "resolver.hpp"

namespace authbox::did {

    struct NetpipeHttpFetchOptions {
        bool allow_insecure_http{false};
        bool skip_tls_certificate_verification_for_testing{false};
        size_t max_response_bytes{1024 * 1024};
        dp::String user_agent{"authbox-did/0.1"};
        dp::u32 recv_timeout_ms{5000};
    };

    namespace detail {

        struct ParsedUrl {
            dp::String scheme;
            dp::String host;
            uint16_t port{0};
            dp::String target{"/"};
        };

        class RawTcpStream final : public netpipe::Stream {
          public:
            RawTcpStream() = default;
            ~RawTcpStream() override { close(); }

            dp::Res<void> connect(const netpipe::TcpEndpoint &endpoint) override {
                struct addrinfo hints{};
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;

                struct addrinfo *resolved = nullptr;
                const std::string port = std::to_string(endpoint.port);
                if (::getaddrinfo(endpoint.host.c_str(), port.c_str(), &hints, &resolved) != 0) {
                    return dp::result::err(dp::Error::io_error("getaddrinfo failed"));
                }

                for (addrinfo *p = resolved; p != nullptr; p = p->ai_next) {
                    const int fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
                    if (fd < 0) {
                        continue;
                    }
                    if (::connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
                        ::freeaddrinfo(resolved);
                        fd_ = fd;
                        connected_ = true;
                        set_recv_timeout(recv_timeout_ms_);
                        return dp::result::ok();
                    }
                    ::close(fd);
                }

                ::freeaddrinfo(resolved);
                return dp::result::err(dp::Error::io_error("connect failed"));
            }

            dp::Res<void> listen(const netpipe::TcpEndpoint &) override {
                return dp::result::err(dp::Error::invalid_argument("RawTcpStream listen not supported"));
            }

            dp::Res<std::unique_ptr<netpipe::Stream>> accept() override {
                return dp::result::err(dp::Error::invalid_argument("RawTcpStream accept not supported"));
            }

            dp::Res<void> send(const netpipe::Message &msg) override {
                if (!connected_ || fd_ < 0) {
                    return dp::result::err(dp::Error::not_found("not connected"));
                }
                size_t sent = 0;
                while (sent < msg.size()) {
                    const ssize_t wrote = ::send(fd_, msg.data() + sent, msg.size() - sent, 0);
                    if (wrote <= 0) {
                        return dp::result::err(dp::Error::io_error("socket send failed"));
                    }
                    sent += static_cast<size_t>(wrote);
                }
                return dp::result::ok();
            }

            dp::Res<netpipe::Message> recv() override {
                if (!connected_ || fd_ < 0) {
                    return dp::result::err(dp::Error::not_found("not connected"));
                }

                netpipe::Message out;
                std::vector<uint8_t> buffer(16 * 1024);
                const ssize_t first = ::recv(fd_, buffer.data(), buffer.size(), 0);
                if (first < 0) {
                    return dp::result::err(dp::Error::io_error("socket recv failed"));
                }
                if (first == 0) {
                    connected_ = false;
                    return dp::result::err(dp::Error::not_found("connection closed by peer"));
                }
                out.insert(out.end(), buffer.begin(), buffer.begin() + first);

                while (true) {
                    fd_set read_fds;
                    FD_ZERO(&read_fds);
                    FD_SET(fd_, &read_fds);
                    timeval tv{};
                    tv.tv_sec = 0;
                    tv.tv_usec = 20 * 1000;
                    const int ready = ::select(fd_ + 1, &read_fds, nullptr, nullptr, &tv);
                    if (ready <= 0) {
                        break;
                    }
                    const ssize_t n = ::recv(fd_, buffer.data(), buffer.size(), MSG_DONTWAIT);
                    if (n <= 0) {
                        break;
                    }
                    out.insert(out.end(), buffer.begin(), buffer.begin() + n);
                }

                return dp::result::ok(std::move(out));
            }

            dp::Res<void> set_recv_timeout(dp::u32 timeout_ms) override {
                recv_timeout_ms_ = timeout_ms;
                if (fd_ < 0) {
                    return dp::result::ok();
                }

                timeval tv{};
                tv.tv_sec = static_cast<time_t>(timeout_ms / 1000);
                tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);
                if (::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
                    return dp::result::err(dp::Error::io_error("setsockopt SO_RCVTIMEO failed"));
                }
                return dp::result::ok();
            }

            void close() override {
                if (fd_ >= 0) {
                    ::close(fd_);
                    fd_ = -1;
                }
                connected_ = false;
            }

            bool is_connected() const override { return connected_; }

          private:
            int fd_{-1};
            bool connected_{false};
            dp::u32 recv_timeout_ms_{5000};
        };

        inline DidResult<uint16_t> parse_port(std::string_view text) {
            try {
                const int value = std::stoi(std::string(text));
                if (value <= 0 || value > 65535) {
                    return DidResult<uint16_t>::err(to_dp_string("Invalid URL port"));
                }
                return DidResult<uint16_t>::ok(static_cast<uint16_t>(value));
            } catch (...) {
                return DidResult<uint16_t>::err(to_dp_string("Invalid URL port"));
            }
        }

        inline DidResult<ParsedUrl> parse_http_url(std::string_view url) {
            const auto scheme_end = url.find("://");
            if (scheme_end == std::string_view::npos) {
                return DidResult<ParsedUrl>::err(to_dp_string("URL is missing scheme"));
            }

            ParsedUrl out{};
            out.scheme = to_dp_string(url.substr(0, scheme_end));

            const std::string_view rest = url.substr(scheme_end + 3);
            const size_t path_start = rest.find('/');
            const std::string_view authority = path_start == std::string_view::npos ? rest : rest.substr(0, path_start);
            out.target = to_dp_string(path_start == std::string_view::npos ? "/" : rest.substr(path_start));

            if (authority.empty()) {
                return DidResult<ParsedUrl>::err(to_dp_string("URL authority is empty"));
            }

            if (authority.front() == '[') {
                const size_t close = authority.find(']');
                if (close == std::string_view::npos) {
                    return DidResult<ParsedUrl>::err(to_dp_string("Invalid IPv6 authority"));
                }
                out.host = to_dp_string(authority.substr(1, close - 1));
                if (close + 1 < authority.size()) {
                    if (authority[close + 1] != ':') {
                        return DidResult<ParsedUrl>::err(to_dp_string("Invalid authority after IPv6 host"));
                    }
                    const auto port_str = authority.substr(close + 2);
                    auto port = parse_port(port_str);
                    if (port.is_err()) {
                        return DidResult<ParsedUrl>::err(port.error());
                    }
                    out.port = port.value();
                }
            } else {
                const size_t last_colon = authority.rfind(':');
                if (last_colon != std::string_view::npos && authority.find(':') == last_colon) {
                    out.host = to_dp_string(authority.substr(0, last_colon));
                    auto port = parse_port(authority.substr(last_colon + 1));
                    if (port.is_err()) {
                        return DidResult<ParsedUrl>::err(port.error());
                    }
                    out.port = port.value();
                } else {
                    out.host = to_dp_string(authority);
                }
            }

            if (out.host.empty()) {
                return DidResult<ParsedUrl>::err(to_dp_string("URL host is empty"));
            }

            if (out.port == 0) {
                out.port = out.scheme == "https" ? 443 : 80;
            }

            return DidResult<ParsedUrl>::ok(std::move(out));
        }

        inline DidResult<netpipe::Message> read_http_response_over_tls(RawTcpStream &stream,
                                                                       netpipe::tls::Session &session,
                                                                       const NetpipeHttpFetchOptions &options) {
            netpipe::Message response_bytes;
            while (true) {
                auto recv = session.recv(stream);
                if (recv.is_err()) {
                    const std::string msg = recv.error().message.c_str();
                    if (msg.find("connection closed by peer") != std::string::npos) {
                        break;
                    }
                    return DidResult<netpipe::Message>::err(to_dp_string(msg));
                }

                response_bytes.insert(response_bytes.end(), recv.value().begin(), recv.value().end());
                if (response_bytes.size() > options.max_response_bytes) {
                    return DidResult<netpipe::Message>::err(to_dp_string("DID document response exceeded max size"));
                }
            }
            return DidResult<netpipe::Message>::ok(std::move(response_bytes));
        }

    } // namespace detail

    inline DidResult<std::string> fetch_did_document_netpipe_http11(std::string_view url,
                                                                    const NetpipeHttpFetchOptions &options = {}) {
        auto parsed = detail::parse_http_url(url);
        if (parsed.is_err()) {
            return DidResult<std::string>::err(parsed.error());
        }

        if (parsed.value().scheme == "http") {
            if (!options.allow_insecure_http) {
                return DidResult<std::string>::err(to_dp_string("Insecure HTTP is disabled for DID document fetch"));
            }
        } else if (parsed.value().scheme != "https") {
            return DidResult<std::string>::err(to_dp_string("Unsupported URL scheme"));
        }

        detail::RawTcpStream stream;
        auto connect = stream.connect(netpipe::TcpEndpoint{parsed.value().host, parsed.value().port});
        if (connect.is_err()) {
            return DidResult<std::string>::err(to_dp_string(connect.error().message.c_str()));
        }
        stream.set_recv_timeout(options.recv_timeout_ms);

        const bool use_tls = parsed.value().scheme == "https";
        std::unique_ptr<netpipe::tls::Session> tls_session;
        if (use_tls) {
            netpipe::tls::SessionConfig tls_config{};
            tls_config.server_name = parsed.value().host;
            tls_config.skip_cert_verification = options.skip_tls_certificate_verification_for_testing;
            tls_config.alpn_protocols = {"http/1.1"};

            tls_session = std::make_unique<netpipe::tls::Session>(tls_config);
            auto hs = tls_session->handshake_client(stream);
            if (hs.is_err()) {
                return DidResult<std::string>::err(to_dp_string(hs.error().message.c_str()));
            }
        }

        netpipe::http1::Request request{};
        request.method = netpipe::http::Method::Get;
        request.target = parsed.value().target;
        dp::String host_header = parsed.value().host;
        const bool default_port = (use_tls && parsed.value().port == 443) || (!use_tls && parsed.value().port == 80);
        if (!default_port) {
            host_header += ":";
            host_header += std::to_string(parsed.value().port).c_str();
        }
        request.headers.push_back(netpipe::http::HeaderField{"Host", host_header});
        request.headers.push_back(netpipe::http::HeaderField{"Accept", "application/json"});
        request.headers.push_back(netpipe::http::HeaderField{"Connection", "close"});
        request.headers.push_back(netpipe::http::HeaderField{"User-Agent", options.user_agent});

        netpipe::http1::ClientConnection client;
        auto encoded = client.encode_request(request);
        if (encoded.is_err()) {
            return DidResult<std::string>::err(to_dp_string(encoded.error().message.c_str()));
        }

        netpipe::Message response_bytes;
        if (use_tls) {
            dp::Vector<dp::u8> payload(encoded.value().begin(), encoded.value().end());
            auto send = tls_session->send(stream, payload);
            if (send.is_err()) {
                return DidResult<std::string>::err(to_dp_string(send.error().message.c_str()));
            }

            auto recv = detail::read_http_response_over_tls(stream, *tls_session, options);
            if (recv.is_err()) {
                return DidResult<std::string>::err(recv.error());
            }
            response_bytes = std::move(recv.value());
        } else {
            auto send = stream.send(encoded.value());
            if (send.is_err()) {
                return DidResult<std::string>::err(to_dp_string(send.error().message.c_str()));
            }

            while (true) {
                auto recv = stream.recv();
                if (recv.is_err()) {
                    const std::string msg = recv.error().message.c_str();
                    if (msg.find("connection closed by peer") != std::string::npos) {
                        break;
                    }
                    return DidResult<std::string>::err(to_dp_string(msg));
                }
                response_bytes.insert(response_bytes.end(), recv.value().begin(), recv.value().end());
            }

            if (response_bytes.size() > options.max_response_bytes) {
                return DidResult<std::string>::err(to_dp_string("DID document response exceeded max size"));
            }
        }

        auto response = client.decode_response(response_bytes);
        if (response.is_err()) {
            return DidResult<std::string>::err(to_dp_string(response.error().message.c_str()));
        }

        if (response.value().status_code != 200) {
            return DidResult<std::string>::err(to_dp_string("DID document endpoint returned non-200 status"));
        }

        return DidResult<std::string>::ok(
            std::string(reinterpret_cast<const char *>(response.value().body.data()), response.value().body.size()));
    }

    inline Resolver make_netpipe_http11_resolver(const NetpipeHttpFetchOptions &options = {}) {
        return Resolver([options](std::string_view url) { return fetch_did_document_netpipe_http11(url, options); });
    }

} // namespace authbox::did
