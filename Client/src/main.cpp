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

    // Dummy name + key for now
    std::string name = "Bob";
    std::vector<uint8_t> dummyKey(160, 0);

    std::cout << "Sending registration..." << std::endl;
    if (client.doRegister(name, dummyKey)) {
        std::cout << "Registration succeeded!\n";

        // === New: request clients list ===
        std::cout << "Requesting clients list..." << std::endl;
        if (client.requestClientsList()) {
            std::cout << "Clients list request completed successfully.\n";
        }
        else {
            std::cerr << "Clients list request failed.\n";
        }
    }
    else {
        std::cerr << "Registration failed!" << std::endl;
    }

    conn.closeConnection();
    return 0;
}
