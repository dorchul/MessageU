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
        if (!Utils::readServerInfo(ip, port)) {
            std::cerr << "Failed to read data/server.info\n";
            return 1;
        }

        // === Prompt for user name ===
        std::string username;
        std::cout << "Enter user name: ";
        std::getline(std::cin, username);
        if (username.empty()) {
            std::cerr << "User name cannot be empty.\n";
            return 1;
        }

        std::string dataDir = "data/" + username;
        std::filesystem::create_directories(dataDir);

        Connection conn;
        Client client(conn, username, dataDir);
        runMenu(client, dataDir);

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}

