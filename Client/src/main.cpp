#include "Utils.h"
#include "Connection.h"
#include "Protocol.h"
#include <iostream>
#include <cstring>

int main() {
    std::string ip;
    uint16_t port;
    if (!Utils::readServerInfo(ip, port)) {
        std::cerr << "Failed to read server.info\n";
        return 1;
    }

    Connection conn;
    if (!conn.connectToServer(ip, port)) {
        std::cerr << "Connection failed.\n";
        return 1;
    }

    std::cout << "Connected to " << ip << ":" << port << "\n";

    // ===== Dummy header send test =====
    RequestHeader header{};
    std::memset(&header, 0, sizeof(header));
    std::memcpy(header.clientID, "0123456789ABCDEF", 16);
    header.version = 1;
    header.code = 600;        // Register request
    header.payloadSize = 0;   // no payload for now

    if (!conn.sendAll(reinterpret_cast<uint8_t*>(&header), sizeof(header))) {
        std::cerr << "Failed to send header.\n";
    }

    conn.closeConnection();
    return 0;
}
