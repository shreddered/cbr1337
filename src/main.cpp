#include "server/server.h"

#include <iostream>
#include <string>
#include <vector>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <port>" << std::endl;
        return -1;
    }
    const auto portStr = std::string(argv[1]);
    const uint16_t port = static_cast<uint16_t>(stoi(portStr));
    aid::server::Server server(port);
    server.start(aid::server::handleRequest);
    return 0;
}

