#include "server/server.h"

#include "graph/conn.h"
#include "graph/dalvik.h"
#include "obfus.h"

#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/http.hpp>

#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

#include <nlohmann/json.hpp>

#include <iostream>
#include <stdexcept>

// just to make things easier
using namespace aid::graph;

namespace aid::server {

namespace beast = boost::beast;
namespace http = beast::http;
using tcp = net::ip::tcp;
using json = nlohmann::json;

Server::Server(uint16_t port) : m_ctx{}, m_acceptor{m_ctx, {tcp::v4(), port}} {
    std::cout << "Server started at port " << port << std::endl;
}

void Server::start(Server::ReqCallback callback) {
    while (true) {
        tcp::socket socket{m_ctx};
        m_acceptor.accept(socket);
        handleSession(socket, callback);
    }
}

void Server::handleSession(tcp::socket& socket, Server::ReqCallback callback) {
    try {
        while (true) {
            beast::flat_buffer buffer;
            http::request<http::string_body> req;
            http::read(socket, buffer, req);

            http::response<http::string_body> res{http::status::ok, req.version()};
            res.set(http::field::server, "Beast");
            res.set(http::field::content_type, "application/json");

            std::string body = req.body(), resp = "{}";
            if (callback(body, resp)) {
                res.keep_alive(req.keep_alive());
            } else {
                 res.result(http::status::bad_request);
                 res.keep_alive(false);
            }
            res.body() = resp;
            http::write(socket, res);

            if (!res.keep_alive())
                break;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in session: " << e.what() << std::endl;
    }
}

std::vector<uint8_t> b64decode(const std::string& encoded_str) {
    using namespace boost::archive::iterators;

    std::string encoded = encoded_str;
    boost::trim(encoded);
    std::vector<uint8_t> result;

    try {
        typedef transform_width<binary_from_base64<std::string::const_iterator>, 8, 6> ItBinary;

        result = std::vector<uint8_t>(ItBinary(encoded.begin()), ItBinary(encoded.end()));
    } catch (const std::exception&) {
    }
    return result;
}

bool hasClasses(DexGraph& g, std::unordered_set<std::string> const& ep) {
    auto [vi, vi_end] = boost::vertices(g);
    auto map = boost::get(&ClassVertex::name, g);
    for (auto it = vi; it != vi_end; ++it) {
        if (ep.contains(map[*it]))
            return true;
    }
    return false;
}

double classAnomaly(LIEF::DEX::Class const& clz) {
    double score = 0;
    double cnt = 0;
    for (const auto& m : clz.methods()) {
        if (m.bytecode().empty())
            continue;
        cnt = cnt + 1;
        if (aid::isAbnormal(m))
            score = score + 1;
    }
    return score / cnt;
}

double totalAnomaly(const std::unique_ptr<LIEF::DEX::File>& dex, DexGraph& g) {
    auto [vi, vi_end] = boost::vertices(g);
    auto map = boost::get(&ClassVertex::classId, g);
    double score = 0.0;
    for (auto it = vi; it != vi_end; ++it) {
        const auto classId = map[*it];
        const auto& clz = dex->classes()[classId];
        score += classAnomaly(clz);
    }
    return score;
}

double maxAnomaly(std::unordered_set<std::string> const& ep, std::vector<uint8_t> const& code) {
    auto dex = LIEF::DEX::Parser::parse(code);
    if (dex == nullptr)
        return 0.0;

    double score = 0.0;
    auto graph = createCallGraph(dex);
    auto subs = twoConnectedSubgraphs(graph);
    for (auto& g : subs) {
        if (hasClasses(g, ep))
            continue;

        auto curr = totalAnomaly(dex, g);
        if (curr >= score)
            score = curr;
    }
    return score;
}

bool handleRequest(const std::string& req, std::string& resp) {
    json arr = json::parse(req);
    /*
        looking for an array of the following JSONs:
        {
            "package": <package>,
            "entrypoints": [ "" ],
            "code": <base64>
        }
        will respond with the following array of JSONs
        {
            "package": "",
            "score": 0.1234
        }
    */
    json res;
    if (!arr.is_array()) {
        res["error"] = "Invalid data";
        resp = res.dump();
        return false;
    }

    res = json::array();
    for (auto it = arr.begin(); it != arr.end(); ++it) {
        if (!(*it).contains("package") || !(*it).contains("entrypoints") || !(*it).contains("code"))
            continue;

        std::string pkg = (*it)["package"].get<std::string>();
        std::unordered_set<std::string> ep = (*it)["entrypoints"].get<std::unordered_set<std::string>>();
        auto code = b64decode((*it)["code"].get<std::string>());
        if (code.empty())
            continue;

        auto score = maxAnomaly(ep, code);
        json tmp = {
            { "package", pkg },
            { "score", score }
        };
        res.push_back(tmp);
    }
    resp = res.dump();

    return true;
}

} // namespace aid::server
