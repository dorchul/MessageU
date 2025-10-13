#include "Utils.h"
#include "Connection.h"
#include <iostream>

int main() {
    std::string ip;
    uint16_t port;
    if (!Utils::readServerInfo(ip, port)) {
        std::cerr << "Failed to read server.info\n";
        return 1;
    }

    Connection conn;
    if (conn.connectToServer(ip, port))
        std::cout << "Connected to " << ip << ":" << port << "\n";
    else
        std::cerr << "Connection failed.\n";

    conn.closeConnection();
    return 0;
}
