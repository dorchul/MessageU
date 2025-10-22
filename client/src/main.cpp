#include "Client.h"
#include "Connection.h"
#include "Utils.h"
#include "Protocol.h"
#include "Menu.h"

#include <regex> 
#include <iostream>
#include <filesystem>


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

        // Basic validation
        if (username.empty() || username.size() >= NAME_SIZE)
            throw std::runtime_error("Invalid user name length.");
        
        static const std::regex validName("^[A-Za-z0-9_.-]+$");
        if (!std::regex_match(username, validName))
            throw std::runtime_error("User name contains invalid characters (use letters, digits, _, ., - only).");



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
        std::cerr << "Client terminated safely.\n";
        return 1;
    }
    catch (...) {
        std::cerr << "[Fatal Error] Unknown exception occurred.\n";
        std::cerr << "Client terminated safely.\n";
        return 1;
    }
}
