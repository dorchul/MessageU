#include "Connection.h"
#include "Client.h"
#include "Utils.h"
#include "Protocol.h"

#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <algorithm>

// Helper: compare UUIDs
static bool uuidsEqual(const std::array<uint8_t, 16>& a, const std::array<uint8_t, 16>& b) {
    return std::equal(a.begin(), a.end(), b.begin());
}

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

    // You can change this name to "Alice" for the second run
    std::string name = "Alice";
    std::vector<uint8_t> dummyKey(160, 0);

    std::cout << "Sending registration..." << std::endl;
    if (!client.doRegister(name, dummyKey)) {
        std::cerr << "Registration failed!" << std::endl;
        conn.closeConnection();
        return 1;
    }

    std::cout << "Registration succeeded!\n";

    std::cout << "Requesting clients list..." << std::endl;
    auto clients = client.requestClientsList();

    if (!clients.empty()) {
        std::cout << "Received " << clients.size() << " clients:\n";
        for (const auto& c : clients)
            std::cout << " - " << c.second << " (" << Utils::uuidToHex(c.first) << ")\n";
    }
    else {
        std::cerr << "No clients received.\n";
    }

    // Request public key for all other clients
    for (const auto& c : clients) {
        std::cout << "\nRequesting public key for " << c.second << "...\n";
        std::string targetUUID(reinterpret_cast<const char*>(c.first.data()), c.first.size());
        std::vector<uint8_t> pubKey = client.requestPublicKey(targetUUID);

        if (!pubKey.empty())
            std::cout << "Public key received (" << pubKey.size() << " bytes) for " << c.second << ".\n";
        else
            std::cerr << "Failed to retrieve key for " << c.second << ".\n";
    }

    // Send a test message to the first other client
    for (const auto& c : clients) {
        if (c.second == name) continue;

        std::string msg = "Hello from " + name + "!";
        std::vector<uint8_t> content(msg.begin(), msg.end());

        std::cout << "\nSending message to " << c.second << "...\n";
        if (client.sendMessage(c.first, MessageType::TEXT, content))
            std::cout << "[OK] Message sent successfully.\n";
        else
            std::cout << "[ERR] Failed to send message.\n";

        break; // send only once for testing
    }

    std::cout << "\nAll tests completed.\n";
    conn.closeConnection();
    return 0;
}
