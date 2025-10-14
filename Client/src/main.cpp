#include "Connection.h"
#include "Client.h"
#include "Utils.h"

#include <iostream>
#include <vector>
#include <string>

int main() {
    std::string ip;
    uint16_t port;

    if (!Utils::readServerInfo(ip, port)) {
        std::cerr << "Failed to read server.info" << std::endl;
        return 1;
    }

    Connection conn;
    if (!conn.connectToServer(ip, port)) {
        std::cerr << "Failed to connect to server" << std::endl;
        return 1;
    }

    Client client(conn);

    // For now, use dummy name + dummy public key (160 bytes of zeros)
    std::string name = "Alice";
    std::vector<uint8_t> dummyKey(160, 0);

    std::cout << "Sending registration..." << std::endl;
    if (client.doRegister(name, dummyKey)) {
        std::cout << "Registration succeeded!" << std::endl;
    }
    else {
        std::cerr << "Registration failed!" << std::endl;
    }

    conn.closeConnection();
    return 0;
}
