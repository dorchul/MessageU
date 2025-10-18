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

        std::string ip; uint16_t port;
        if (!Utils::readServerInfo(ip, port)) {
            std::cerr << "Failed to read data/server.info\n";
            return 1;
        }

        std::string dataDir = "data/user";
        std::filesystem::create_directories(dataDir);

        Connection conn;
        if (!conn.connectToServer(ip, port)) {
            std::cerr << "Failed to connect to server.\n";
            return 1;
        }

        Client client(conn, dataDir);
        runMenu(client, dataDir);

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}
