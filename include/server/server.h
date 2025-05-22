#ifndef INCLUDE_SERVER_SERVER_H_
#define INCLUDE_SERVER_SERVER_H_

#include <boost/asio/ip/tcp.hpp>

#include <string>

namespace aid::server {

namespace net = boost::asio;

class Server {
public:
    using ReqCallback = std::function<bool(const std::string&, std::string&)>;
    explicit Server(uint16_t port);
    void start(ReqCallback callback);
private:
    using tcp = net::ip::tcp;
    void handleSession(tcp::socket& socket, ReqCallback callback);
    net::io_context m_ctx;
    tcp::acceptor m_acceptor;
}; // class Server

bool handleRequest(const std::string& req, std::string& resp);

} // namespace aid::server

#endif // INCLUDE_SERVER_SERVER_H_
