// Minimal HTTP/1.0 mock server for the vtapi tests. A worker thread accepts
// connections on 127.0.0.1:0, parses each request, feeds it to a handler, and
// answers with the handler's response. No external dependencies beyond sockets.
#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #if defined(_MSC_VER)
  #pragma comment(lib, "ws2_32.lib")
  #endif
#else
  #include <arpa/inet.h>
  #include <netinet/in.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

// MSVC's WinSock headers use `int` where POSIX uses `socklen_t`; MinGW already
// provides the typedef, so only define it for the Microsoft toolchain.
#if defined(_MSC_VER)
using socklen_t = int;
#endif

#include "vtapi/detail/http.hpp"

// Thin socket shim: the mock server must compile with both POSIX sockets and
// WinSock (MSVC has no ssize_t and needs WSAStartup).
namespace mock {
namespace platform {

#ifdef _WIN32
using socket_t = SOCKET;
inline const socket_t kInvalidSocket = INVALID_SOCKET;
inline void close_socket(socket_t s) { closesocket(s); }
inline void shutdown_socket(socket_t s) { shutdown(s, SD_BOTH); }
inline void ensure_initialized() {
    static struct WinsockInit {
        WinsockInit() {
            WSADATA data;
            if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
                throw std::runtime_error("mock server: WSAStartup failed");
        }
        ~WinsockInit() { WSACleanup(); }
    } init;
    (void)init;
}
#else
using socket_t = int;
inline const socket_t kInvalidSocket = -1;
inline void close_socket(socket_t s) { ::close(s); }
inline void shutdown_socket(socket_t s) { ::shutdown(s, SHUT_RDWR); }
inline void ensure_initialized() {}
#endif

} // namespace platform

// Opens a loopback socket with no listener and returns the port it held. Used
// by tests that assert a connection refused error.
inline int unused_local_port() {
    platform::ensure_initialized();
    const platform::socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == platform::kInvalidSocket)
        return 0;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    bind(s, reinterpret_cast<sockaddr*>(&addr), static_cast<int>(sizeof(addr)));
    socklen_t len = static_cast<socklen_t>(sizeof(addr));
    getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len);
    const int port = ntohs(addr.sin_port);
    platform::close_socket(s);
    return port;
}

} // namespace mock

struct MockRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
    std::map<std::string, std::string> form_fields;   // multipart text parts
    std::vector<vtapi::detail::MultipartFile> files;  // multipart file parts
};

struct MockResponse {
    int status = 200;
    std::string body;
    std::string content_type = "text/plain";
    // When non-empty, sent as a Location header (used to simulate redirects).
    std::string location;
};

namespace mock {

inline std::string status_reason(int status) {
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 302: return "Found";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        default: return "Unknown";
    }
}

inline std::string trim(std::string s) {
    std::size_t first = s.find_first_not_of(" \r\n");
    if (first == std::string::npos)
        return {};
    std::size_t last = s.find_last_not_of(" \r\n");
    return s.substr(first, last - first + 1);
}

// Parses a multipart/form-data body into text fields and file parts, matching
// the structure curl_mime produces: \r\n--BOUNDARY\r\n + part headers (incl.
// Content-Disposition with name/filename) + \r\n\r\n + content + \r\n.
inline void parse_multipart(const std::string& boundary, const std::string& body,
                            MockRequest& req) {
    const std::string marker = "--" + boundary;
    std::size_t pos = 0;
    for (;;) {
        std::size_t part_start = body.find(marker, pos);
        if (part_start == std::string::npos)
            break;
        part_start += marker.size();
        if (body.compare(part_start, 2, "--") == 0) // closing delimiter
            break;
        if (body.compare(part_start, 2, "\r\n") == 0)
            part_start += 2;
        std::size_t header_end = body.find("\r\n\r\n", part_start);
        if (header_end == std::string::npos)
            break;
        const std::string part_head = body.substr(part_start, header_end - part_start);
        const std::size_t content_start = header_end + 4;
        std::size_t content_end = body.find(marker, content_start);
        if (content_end == std::string::npos)
            break;
        if (content_end > content_start + 2)
            content_end -= 2; // strip trailing CRLF

        std::string name;
        std::string filename;
        // extract name="..." and optional filename="..." from the disposition line
        std::size_t disp = part_head.find("Content-Disposition:");
        if (disp != std::string::npos) {
            std::size_t name_pos = part_head.find("name=\"", disp);
            if (name_pos != std::string::npos) {
                name_pos += 6;
                name = part_head.substr(name_pos, part_head.find('"', name_pos) - name_pos);
            }
            std::size_t file_pos = part_head.find("filename=\"");
            if (file_pos != std::string::npos) {
                file_pos += 10;
                filename = part_head.substr(file_pos,
                                            part_head.find('"', file_pos) - file_pos);
            }
        }

        if (!filename.empty()) {
            const std::string content = body.substr(content_start, content_end - content_start);
            req.files.push_back({name, filename,
                                 std::vector<uint8_t>(content.begin(), content.end())});
        } else if (!name.empty()) {
            req.form_fields[name] =
                body.substr(content_start, content_end - content_start);
        }
        pos = content_end + 2; // resume after the CRLF that precedes the next marker
    }
}

} // namespace mock

class MockServer {
public:
    using Handler = std::function<MockResponse(const MockRequest&)>;

    explicit MockServer(Handler handler)
        : handler_(std::move(handler)),
          fd_(open_listener()) {
        if (fd_ == mock::platform::kInvalidSocket)
            throw std::runtime_error("mock server: socket() failed");

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        const int one = 1;
        setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&one),
                   static_cast<int>(sizeof(one)));
        if (bind(fd_, reinterpret_cast<sockaddr*>(&addr),
                 static_cast<int>(sizeof(addr))) != 0 ||
            listen(fd_, 16) != 0) {
            mock::platform::close_socket(fd_);
            fd_ = mock::platform::kInvalidSocket;
            throw std::runtime_error("mock server: bind/listen failed");
        }

        socklen_t len = static_cast<socklen_t>(sizeof(addr));
        getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);

        thread_ = std::thread([this] { serve(); });
    }

    ~MockServer() {
        stop();
    }

    MockServer(const MockServer&) = delete;
    MockServer& operator=(const MockServer&) = delete;

    int port() const { return port_; }

    std::string url(const std::string& path) const {
        return "http://127.0.0.1:" + std::to_string(port_) + path;
    }

private:
    static mock::platform::socket_t open_listener() {
        mock::platform::ensure_initialized();
        return socket(AF_INET, SOCK_STREAM, 0);
    }

    void stop() {
        if (!running_)
            return;
        running_ = false;
        mock::platform::shutdown_socket(fd_);
        mock::platform::close_socket(fd_);
        if (thread_.joinable())
            thread_.join();
    }

    void serve() {
        while (running_) {
            const mock::platform::socket_t client = accept(fd_, nullptr, nullptr);
            if (client == mock::platform::kInvalidSocket) {
                if (running_)
                    continue;
                break;
            }
            handle_client(client);
            mock::platform::close_socket(client);
        }
    }

    void handle_client(mock::platform::socket_t client) {
        std::string raw;
        char buf[4096];
        std::size_t header_end = std::string::npos;
        while (header_end == std::string::npos) {
            const int n = recv(client, buf, static_cast<int>(sizeof(buf)), 0);
            if (n <= 0)
                return;
            raw.append(buf, static_cast<std::size_t>(n));
            header_end = raw.find("\r\n\r\n");
        }

        MockRequest req;
        const std::string head = raw.substr(0, header_end);
        std::size_t lp = 0;
        std::size_t nl = head.find("\r\n");
        if (nl == std::string::npos)
            return;
        {
            const std::string request_line = head.substr(0, nl);
            const std::size_t s1 = request_line.find(' ');
            const std::size_t s2 = request_line.find(' ', s1 + 1);
            req.method = request_line.substr(0, s1);
            req.path = request_line.substr(s1 + 1, s2 - s1 - 1);
        }
        lp = nl + 2;
        while (lp <= head.size()) {
            nl = head.find("\r\n", lp);
            const std::string line =
                head.substr(lp, nl == std::string::npos ? std::string::npos : nl - lp);
            lp = nl == std::string::npos ? head.size() + 1 : nl + 2;
            const std::size_t colon = line.find(':');
            if (colon != std::string::npos)
                req.headers[mock::trim(line.substr(0, colon))] =
                    mock::trim(line.substr(colon + 1));
        }

        std::size_t content_length = 0;
        const auto cl = req.headers.find("Content-Length");
        if (cl != req.headers.end()) {
            try {
                content_length = static_cast<std::size_t>(std::stoul(cl->second));
            } catch (...) {
            }
        }
        while (raw.size() < header_end + 4 + content_length) {
            const int n = recv(client, buf, static_cast<int>(sizeof(buf)), 0);
            if (n <= 0)
                return;
            raw.append(buf, static_cast<std::size_t>(n));
        }
        req.body = raw.substr(header_end + 4, content_length);

        const auto ct = req.headers.find("Content-Type");
        if (ct != req.headers.end()) {
            const std::size_t b = ct->second.find("boundary=");
            if (ct->second.find("multipart/form-data") != std::string::npos &&
                b != std::string::npos) {
                mock::parse_multipart(ct->second.substr(b + 9), req.body, req);
            }
        }

        if (!handler_) {
            send_error(client, 500);
            return;
        }
        const MockResponse out = handler_(req);
        send_response(client, out);
    }

    void send_response(mock::platform::socket_t client, const MockResponse& resp) {
        const std::string head =
            "HTTP/1.1 " + std::to_string(resp.status) + " " +
            mock::status_reason(resp.status) + "\r\n" +
            "Content-Type: " + resp.content_type + "\r\n" +
            "Content-Length: " + std::to_string(resp.body.size()) + "\r\n" +
            (resp.location.empty() ? "" : "Location: " + resp.location + "\r\n") +
            "Connection: close\r\n\r\n";
        const std::string payload = head + resp.body;
        send(client, payload.data(), static_cast<int>(payload.size()), 0);
    }

    void send_error(mock::platform::socket_t client, int status) {
        send_response(client, {status, "mock server error"});
    }

    Handler handler_;
    mock::platform::socket_t fd_ = mock::platform::kInvalidSocket;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::thread thread_;
};