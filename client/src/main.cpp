#include "Client.h"
#include "Connection.h"
#include "Utils.h"
#include <iostream>
#include <vector>
#include <iomanip>

void testClient(const std::string& name)
{
    std::string dataDir = "data/test_data/" + name;
    std::string ip;
    uint16_t port = 0;

    if (!Utils::readServerInfo(ip, port)) {
        std::cerr << "Failed to read server.info\n";
        return;
    }

    Connection conn;
    if (!conn.connectToServer(ip, port)) {
        std::cerr << "[" << name << "] Connection failed.\n";
        return;
    }

    Client client(conn, dataDir);

    // === Register ===
    if (!client.doRegister(name, dataDir)) {
        std::cerr << "[" << name << "] Registration failed.\n";
        return;
    }

    std::cout << "[" << name << "] Registration OK.\n";

    // === Request clients list ===
    auto list = client.requestClientsList();
    std::cout << "[" << name << "] Clients list:\n";
    if (list.empty()) {
        std::cout << "  (empty)\n";
    }
    else {
        for (const auto& entry : list) {
            const auto& uuid = entry.first;
            const auto& uname = entry.second;
            std::cout << "  - " << uname
                << "  (UUID: " << Utils::uuidToHex(uuid) << ")\n";
        }

        // === Test public key request (602) ===
        std::string targetUUIDHex = Utils::uuidToHex(list.front().first);
        std::cout << "[" << name << "] Requesting public key for "
            << list.front().second << "...\n";

        std::vector<uint8_t> pubKey = client.requestPublicKey(targetUUIDHex);
        if (!pubKey.empty()) {
            std::cout << "[" << name << "] Received public key ("
                << pubKey.size() << " bytes)\n";
        }
        else {
            std::cout << "[" << name << "] Failed to retrieve public key.\n";
        }
    }

    conn.closeConnection();
    std::cout << "-----------------------------------\n";
}

int main()
{
    try {
        std::vector<std::string> testNames = { "Alice", "Bob", "Charlie" };
        for (const auto& name : testNames) {
            testClient(name);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }
    return 0;
}
