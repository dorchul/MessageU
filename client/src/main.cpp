#include "Client.h"
#include "Connection.h"
#include "Utils.h"
#include "Protocol.h"
#include "Menu.h"

#include <iostream>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <sstream>
#include <iomanip>

// ===================================================
// main()
// ===================================================
int main() {
    try {
        std::cout << "=== MessageU Client ===\n";

        std::string ip;
        uint16_t port;
        Utils::readServerInfo(ip, port);   // throws if missing or malformed

        // === Prompt for user name ===
        std::string username;
        std::cout << "Enter user name: ";
        std::getline(std::cin, username);
        if (username.empty()) {
            throw std::runtime_error("User name cannot be empty.");
        }

        std::string dataDir = "data/" + username;
        std::filesystem::create_directories(dataDir);

        Connection conn;
        conn.connectToServer(ip, port);     // throws on socket or connection error

        Client client(conn, username, dataDir);
        runMenu(client, dataDir);

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "[Fatal Error] " << e.what() << "\n";
        return 1;
    }
    catch (...) {
        std::cerr << "[Fatal Error] Unknown exception occurred.\n";
        return 1;
    }
}
